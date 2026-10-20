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

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// One connection to the meter in front of which this one stands: plain
    /// Modbus/TCP, or Modbus/TLS as an identity of the store.
    /// </summary>
    /// <remarks>
    /// One request at a time, each matched to its answer by its transaction
    /// id: what this meter passes on are the requests of several clients, and
    /// an answer that went to the wrong one would be a reading of somebody
    /// else's question.
    /// </remarks>
    internal sealed class UpstreamConnection : IAsyncDisposable
    {

        #region Data

        private readonly TcpClient      tcp;
        private readonly Stream         stream;
        private readonly SemaphoreSlim  exchange = new (1, 1);
        private          UInt16         transactionId;

        #endregion

        #region Properties

        /// <summary>The TLS version, over Modbus/TLS.</summary>
        public SslProtocols?       Protocol            { get; }

        /// <summary>The cipher suite, over Modbus/TLS.</summary>
        public String?             CipherSuite         { get; }

        /// <summary>The certificate the meter showed, over Modbus/TLS.</summary>
        public X509Certificate2?   MeterCertificate    { get; }

        #endregion

        #region Constructor(s)

        private UpstreamConnection(TcpClient   TCP,
                                   Stream      Stream,
                                   SslStream?  TLS)
        {

            this.tcp     = TCP;
            this.stream  = Stream;

            if (TLS is not null)
            {
                this.Protocol          = TLS.SslProtocol;
                this.CipherSuite       = TLS.NegotiatedCipherSuite.ToString();
                // A copy of its own: the stream's goes with the stream.
                this.MeterCertificate  = TLS.RemoteCertificate is X509Certificate remote
                                             ? X509CertificateLoader.LoadCertificate(remote.GetRawCertData())
                                             : null;
            }

        }

        #endregion


        #region (static) Open(Host, Port, Identity, Intermediates, Judge, Timeout, CancellationToken)

        /// <summary>
        /// Connect - over TLS where an identity is given, judging the meter's
        /// certificate as given.
        /// </summary>
        public static async Task<UpstreamConnection> Open(String                                  Host,
                                                          UInt16                                  Port,
                                                          X509Certificate2?                       Identity,
                                                          IReadOnlyCollection<X509Certificate2>?  Intermediates,
                                                          RemoteCertificateValidationCallback?    Judge,
                                                          Boolean                                 TLS,
                                                          TimeSpan                                Timeout,
                                                          CancellationToken                       CancellationToken)
        {

            var tcp = new TcpClient { NoDelay = true };

            try
            {

                using (var connecting = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken))
                {
                    connecting.CancelAfter(Timeout);
                    await tcp.ConnectAsync(Host, Port, connecting.Token);
                }

                if (!TLS)
                    return new UpstreamConnection(tcp, tcp.GetStream(), null);

                var tls = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);

                try
                {

                    using var handshake = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
                    handshake.CancelAfter(Timeout);

                    // Never a session resumed: the meter behind decides what
                    // this one may do by the role in the certificate it shows,
                    // and a resumed TLS session shows none - it sees a peer
                    // without a role and hangs up. On Linux a session for a
                    // host name is offered to every server of that name whose
                    // tickets can read it.
                    await tls.AuthenticateAsClientAsync(
                              new SslClientAuthenticationOptions {
                                  TargetHost                           = Host,
                                  ClientCertificateContext             = Identity is not null
                                                                             ? SslStreamCertificateContext.Create(Identity, [.. Intermediates ?? []], offline: true)
                                                                             : null,
                                  EnabledSslProtocols                  = SslProtocols.Tls12 | SslProtocols.Tls13,
                                  CertificateRevocationCheckMode       = X509RevocationMode.NoCheck,
                                  AllowRenegotiation                   = false,
                                  AllowTlsResume                       = false,
                                  EncryptionPolicy                     = EncryptionPolicy.RequireEncryption,
                                  RemoteCertificateValidationCallback  = Judge
                              },
                              handshake.Token
                          );

                    return new UpstreamConnection(tcp, tls, tls);

                }
                catch
                {
                    await tls.DisposeAsync();
                    throw;
                }

            }
            catch
            {
                tcp.Dispose();
                throw;
            }

        }

        #endregion

        #region Exchange(Unit, Request, Timeout, CancellationToken)

        /// <summary>
        /// One request, and its answer: a PDU each, without the frame.
        /// </summary>
        public async Task<Byte[]> Exchange(Byte               Unit,
                                           Byte[]             Request,
                                           TimeSpan           Timeout,
                                           CancellationToken  CancellationToken)
        {

            using var waiting = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken);
            waiting.CancelAfter(Timeout);

            await exchange.WaitAsync(waiting.Token);

            try
            {

                var id       = unchecked(++transactionId);
                var request  = new ModbusFrame(id, Unit, Request);

                await stream.WriteAsync(request.ToBytes(), waiting.Token);
                await stream.FlushAsync(waiting.Token);

                var response = await ModbusFrame.ReadAsync(stream, waiting.Token);

                if (response.TransactionId != id || response.UnitId != Unit)
                    throw new InvalidDataException($"The meter answered transaction {response.TransactionId} of unit {response.UnitId}, where {id} of unit {Unit} was asked.");

                return response.Pdu;

            }
            finally
            {
                exchange.Release();
            }

        }

        #endregion


        #region DisposeAsync()

        public async ValueTask DisposeAsync()
        {

            try { await stream.DisposeAsync(); } catch { }

            tcp.Dispose();
            MeterCertificate?.Dispose();
            exchange.Dispose();

        }

        #endregion

    }

}
