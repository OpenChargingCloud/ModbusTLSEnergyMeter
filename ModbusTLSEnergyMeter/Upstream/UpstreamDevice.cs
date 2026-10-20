/*
 * Copyright (c) 2014-2026 GraphDefined GmbH <achim.friedland@graphdefined.com>
 * This file is part of the Modbus/TLS Energy Meter <https://github.com/OpenChargingCloud/ModbusTLSEnergyMeter>
 *
 * Licensed under the Affero GPL license, Version 3.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.gnu.org/licenses/agpl.html
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#region Usings

using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// Whom this meter is to the meter in front of which it stands, over
    /// Modbus/TLS: a certificate with its private key, and the CAs it is sent
    /// along with.
    /// </summary>
    public sealed record UpstreamIdentity(X509Certificate2                       Certificate,
                                          IReadOnlyCollection<X509Certificate2>  Intermediates,
                                          String                                 Role,
                                          String                                 Label,
                                          String                                 Id) : IDisposable
    {

        public JObject ToJSON()

            => new (
                   new JProperty("id",       Id),
                   new JProperty("label",    Label),
                   new JProperty("role",     Role),
                   new JProperty("subject",  Certificate.Subject)
               );

        public void Dispose()
        {
            Certificate.Dispose();
            foreach (var intermediate in Intermediates)
                intermediate.Dispose();
        }

    }


    /// <summary>
    /// What the certificate of the meter in front of which this one stands was
    /// judged: believed or not, as what, and - where not - why.
    /// </summary>
    public sealed record UpstreamJudgement(Boolean  Accepted,
                                           String   Outcome,
                                           String?  Why);


    /// <summary>
    /// The meter in front of which this one stands, as the Modbus backend
    /// every request is passed on to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One connection, for every client: a meter is asked one thing at a time
    /// anyway, and a meter in a cabinet that is asked by a gateway once and by
    /// each of its clients again is a meter some of whose clients are refused.
    /// The unit address a client asked is not passed on; the meter's is.
    /// </para>
    /// <para>
    /// What cannot be passed on is answered as a gateway answers it: 0x0A
    /// where the meter cannot be reached or not believed, 0x0B where it was
    /// reached and did not answer. Connecting again is tried at most every few
    /// seconds, so that a meter that is gone is not dialled once for every
    /// request of every client.
    /// </para>
    /// </remarks>
    public sealed class UpstreamDevice : IModbusBackendFactory, IModbusBackend
    {

        #region Data

        /// <summary>How long a connection, a handshake or an answer may take.</summary>
        public static readonly TimeSpan  DefaultTimeout     = TimeSpan.FromSeconds(5);

        /// <summary>How long after a failure connecting is not tried again.</summary>
        public static readonly TimeSpan  DefaultRetryAfter  = TimeSpan.FromSeconds(3);

        private readonly SemaphoreSlim                                                              gate        = new (1, 1);
        private readonly Func<(UpstreamIdentity? Identity, String? Why)>                           identityOf;
        private readonly Func<X509Certificate2?, X509Chain?, SslPolicyErrors, UpstreamJudgement>  judge;
        private readonly TimeProvider                                                               timeProvider;
        private readonly Action<String, Boolean>                                                    said;

        private UpstreamConnection?  connection;
        private UpstreamIdentity?    shownAs;
        private DateTimeOffset       triedAt   = DateTimeOffset.MinValue;
        private String               state     = "notConnected";
        private DateTimeOffset       since;
        private String?              error;
        private UpstreamJudgement?   judged;
        private String?              lastSaid;
        private Int32                disposed;

        #endregion

        #region Properties

        /// <summary>Where and how it is reached.</summary>
        public UpstreamConfiguration  Configuration  { get; }

        /// <summary>How long a connection, a handshake or an answer may take.</summary>
        public TimeSpan               Timeout        { get; init; } = DefaultTimeout;

        /// <summary>How long after a failure connecting is not tried again.</summary>
        public TimeSpan               RetryAfter     { get; init; } = DefaultRetryAfter;

        /// <summary>
        /// "connected", or what is in the way: "notConnected", "unreachable",
        /// "untrusted", "refused", "noIdentity", "noAnswer".
        /// </summary>
        public String                 State
            => state;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The meter at the given place, reached as it says.
        /// </summary>
        /// <param name="Configuration">Where and how it is reached.</param>
        /// <param name="IdentityOf">Over TLS, whom this meter is to it - or why it is nobody.</param>
        /// <param name="Judge">Over TLS, what its certificate comes to.</param>
        /// <param name="TimeProvider">Where the time is read.</param>
        /// <param name="Said">Where news about it is said: what, and whether it is a failure.</param>
        public UpstreamDevice(UpstreamConfiguration                                                       Configuration,
                              Func<(UpstreamIdentity? Identity, String? Why)>                            IdentityOf,
                              Func<X509Certificate2?, X509Chain?, SslPolicyErrors, UpstreamJudgement>   Judge,
                              TimeProvider?                                                               TimeProvider   = null,
                              Action<String, Boolean>?                                                    Said           = null)
        {

            this.Configuration  = Configuration;
            this.identityOf     = IdentityOf;
            this.judge          = Judge;
            this.timeProvider   = TimeProvider ?? System.TimeProvider.System;
            this.said           = Said ?? ((_, _) => { });
            this.since          = this.timeProvider.GetUtcNow();

        }

        #endregion


        #region IModbusBackendFactory

        public Task<IModbusBackend> CreateAsync(Int64              ConnectionId,
                                                String?            Role,
                                                CancellationToken  CancellationToken)

            => Task.FromResult<IModbusBackend>(this);

        #endregion

        #region ProcessRequestAsync(UnitId, RequestPDU, CancellationToken)

        /// <summary>
        /// Pass a request on, and its answer back.
        /// </summary>
        public async Task<Byte[]> ProcessRequestAsync(Byte                  UnitId,
                                                      ReadOnlyMemory<Byte>  RequestPDU,
                                                      CancellationToken     CancellationToken)
        {

            var request  = RequestPDU.ToArray();
            var function = (ModbusFunctionCodes) request[0];

            await gate.WaitAsync(CancellationToken);

            try
            {

                if (connection is null)
                {

                    // Let go of for good: reached another way now.
                    if (disposed == 1 || timeProvider.GetUtcNow() - triedAt < RetryAfter)
                        return ModbusPDU.BuildException(function, ModbusExceptionCode.GatewayPathUnavailable);

                    if (!await Connect(CancellationToken))
                        return ModbusPDU.BuildException(function, ModbusExceptionCode.GatewayPathUnavailable);

                }

                try
                {
                    var answer = await connection!.Exchange(Configuration.Unit, request, Timeout, CancellationToken);
                    Became("connected", null);
                    return answer;
                }
                catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
                {
                    throw;
                }
                catch (Exception e)
                {

                    await Drop();

                    Became("noAnswer", $"The meter at {Configuration.Server} did not answer: {e.GetBaseException().Message}");

                    return ModbusPDU.BuildException(function, ModbusExceptionCode.GatewayTargetFailed);

                }

            }
            finally
            {
                gate.Release();
            }

        }

        #endregion

        #region StatusJSON()

        /// <summary>
        /// How it stands: connected or what is in the way, since when, over
        /// what, as whom, and what its certificate was judged.
        /// </summary>
        public JObject StatusJSON()

            => new (
                   new JProperty("server",      Configuration.Server),
                   new JProperty("unit",        Configuration.Unit),
                   new JProperty("tls",         Configuration.TLS),
                   new JProperty("state",       state),
                   new JProperty("since",       since.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ss.fffZ")),
                   new JProperty("error",       error),
                   new JProperty("protocol",    connection?.Protocol?.ToString()),
                   new JProperty("cipherSuite", connection?.CipherSuite),
                   new JProperty("identity",    shownAs?.ToJSON()),
                   new JProperty("judged",      judged is null
                                                    ? null
                                                    : new JObject(
                                                          new JProperty("accepted",  judged.Accepted),
                                                          new JProperty("outcome",   judged.Outcome),
                                                          new JProperty("why",       judged.Why)
                                                      ))
               );

        #endregion


        #region (private) Connect(CancellationToken)

        private async Task<Boolean> Connect(CancellationToken CancellationToken)
        {

            triedAt = timeProvider.GetUtcNow();

            UpstreamIdentity? identity = null;

            if (Configuration.TLS)
            {

                var (chosen, why) = identityOf();

                if (chosen is null)
                {
                    Became("noIdentity", why ?? $"There is no TLS identity to show the meter at {Configuration.Server}.");
                    return false;
                }

                identity = chosen;

            }

            UpstreamJudgement? judgement = null;

            try
            {

                connection = await UpstreamConnection.Open(
                                       Configuration.Host,
                                       Configuration.Port,
                                       identity?.Certificate,
                                       identity?.Intermediates,
                                       Configuration.TLS
                                           ? (sender, certificate, chain, errors) => {
                                                 judgement = judge(certificate as X509Certificate2, chain, errors);
                                                 return judgement.Accepted;
                                             }
                                           : null,
                                       Configuration.TLS,
                                       Timeout,
                                       CancellationToken
                                   );

                shownAs?.Dispose();
                shownAs  = identity;
                identity = null;
                judged   = judgement;

                return true;

            }
            catch (OperationCanceledException) when (CancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (Exception) when (judgement is { Accepted: false })
            {
                judged = judgement;
                Became("untrusted", $"The meter at {Configuration.Server} is not believed: {judgement.Why ?? judgement.Outcome}");
            }
            catch (AuthenticationException e)
            {
                judged = judgement;
                Became("refused", $"The TLS handshake with the meter at {Configuration.Server} failed: {e.GetBaseException().Message}");
            }
            catch (Exception e) when (e is SocketException or IOException or OperationCanceledException or TimeoutException)
            {
                Became("unreachable", $"The meter at {Configuration.Server} cannot be reached: {e.GetBaseException().Message}");
            }
            catch (Exception e)
            {
                Became("unreachable", $"Connecting to the meter at {Configuration.Server} failed: {e.GetBaseException().Message}");
            }
            finally
            {
                identity?.Dispose();
            }

            return false;

        }

        #endregion

        #region (private) Drop()

        private async Task Drop()
        {

            if (connection is not null)
                await connection.DisposeAsync();

            connection = null;
            triedAt    = timeProvider.GetUtcNow();

        }

        #endregion

        #region (private) Became(State, Error)

        /// <summary>
        /// It stands differently now: kept for the page, and said where it is
        /// news.
        /// </summary>
        private void Became(String   State,
                            String?  Error)
        {

            if (state != State || error != Error)
                since = timeProvider.GetUtcNow();

            state = State;
            error = Error;

            var news = Error ?? $"The meter at {Configuration.Server} answers, over {(Configuration.TLS ? "Modbus/TLS" : "Modbus/TCP")}.";

            if (news == lastSaid)
                return;

            lastSaid = news;

            said(news, Error is not null);

        }

        #endregion

        #region DisposeAsync()

        /// <summary>
        /// Let go of the connection.
        /// </summary>
        public async ValueTask DisposeAsync()
        {

            // Every connection a client has is handed this same backend, and
            // each lets go of it when it closes; only the meter lets go of it
            // for good.
            await Task.CompletedTask;

        }

        /// <summary>
        /// Let go of the connection for good: the meter is reached another way
        /// now, or stops.
        /// </summary>
        public async Task Close()
        {

            if (Interlocked.Exchange(ref disposed, 1) == 1)
                return;

            await gate.WaitAsync();

            try
            {
                await Drop();
                shownAs?.Dispose();
                shownAs = null;
            }
            finally
            {
                gate.Release();
            }

        }

        #endregion

    }

}
