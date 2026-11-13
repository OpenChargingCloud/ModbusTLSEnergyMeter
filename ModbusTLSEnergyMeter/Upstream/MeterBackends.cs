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

using System.Collections;
using System.Collections.Concurrent;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// What this meter measures with - its own simulation, or the meter in
    /// front of which it stands - with the session model behind its models,
    /// as the backend every Modbus/TLS connection is handed.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Switched while the meter runs, when somebody says it stands in front of
    /// another meter now or no longer: a connection keeps what it was handed,
    /// and the next one is handed what the meter measures with now.
    /// </para>
    /// <para>
    /// Where the session model goes is where the device's list of models
    /// ends, which is known only once the device answered. Until then a
    /// connection is handed the device alone: a meter that cannot be reached
    /// signs nothing anyway.
    /// </para>
    /// <para>
    /// And it is here that the connections open now are kept: the Modbus/TLS
    /// frontend says when the TLS handshake of one held - with where it comes
    /// from and the certificate its client showed - and when it is over, and
    /// the meter hands both on.
    /// </para>
    /// </remarks>
    public sealed class MeterBackends : IModbusBackendFactory
    {

        #region (class) Target

        /// <summary>
        /// One thing to measure with, and where its models end once that is
        /// known.
        /// </summary>
        /// <param name="Device">Its backends.</param>
        /// <param name="Commanded">What of its own registers a role that may write what is commanded may write.</param>
        /// <param name="Protected">What of its own registers only an administrator may write.</param>
        /// <param name="Upstream">The meter in front of which this one stands, where it is one.</param>
        private sealed class Target(IModbusBackendFactory  Device,
                                    IReadOnlySet<UInt16>   Commanded,
                                    IReadOnlySet<UInt16>   Protected,
                                    UpstreamDevice?        Upstream)
        {

            private readonly SemaphoreSlim                walking = new (1, 1);
            private          SessionModelBackendFactory?  model;
            private          SunSpecChain?                chain;
            private          ReadRegisters?               read;
            private          (String Manufacturer, String Model, String Version, String SerialNumber)?  who;

            public IModbusBackendFactory        Device     { get; } = Device;
            public IReadOnlySet<UInt16>         Commanded  { get; } = Commanded;
            public IReadOnlySet<UInt16>         Protected  { get; } = Protected;
            public UpstreamDevice?              Upstream   { get; } = Upstream;
            public SessionModelBackendFactory?  Model      => model;
            public (String Manufacturer, String Model, String Version, String SerialNumber)?  Who  => who;

            /// <summary>
            /// The session model behind the device's models, once they could be
            /// walked; null while they cannot.
            /// </summary>
            public async Task<SessionModelBackendFactory?> ModelOf(MeterBackends Backends)
            {

                if (model is not null)
                    return model;

                await walking.WaitAsync();

                try
                {

                    if (model is not null)
                        return model;

                    var registers = SunSpecChain.Of(await Device.CreateAsync(0, null, CancellationToken.None));
                    var walked    = await SunSpecChain.Walk(registers);

                    read  = registers;
                    chain = walked;
                    who   = await walked.Common(registers);
                    model = new SessionModelBackendFactory(Device, Backends.Signer, walked.End, Backends.OnDone, Backends.OnRefused);

                    return model;

                }
                catch (Exception e) when (e is EnergyUnreadable or ModbusException or ArgumentException)
                {
                    return null;
                }
                finally
                {
                    walking.Release();
                }

            }

            /// <summary>
            /// What its imported energy counter stands at, in Wh.
            /// </summary>
            public async Task<Decimal> ImportedWh(MeterBackends Backends)
            {

                if (await ModelOf(Backends) is null || chain is null || read is null)
                    throw new EnergyUnreadable(Upstream is not null
                                                   ? $"The meter at {Upstream.Configuration.Server} could not be read: {Upstream.StatusJSON().Value<String>("error") ?? "its list of models could not be walked."}"
                                                   : "The list of models of this meter could not be walked.");

                return await chain.ImportedWh(read);

            }

            /// <summary>
            /// Read registers of the device - not of the session model.
            /// </summary>
            public async Task<UInt16[]> Read(UInt16 First, UInt16 Count)

                => await SunSpecChain.Of(await Device.CreateAsync(0, null, CancellationToken.None))(First, Count);

        }

        #endregion


        #region Data

        private volatile Target  current;

        private readonly ConcurrentDictionary<Int64, ModbusConnection>  connections = new ();

        #endregion

        #region Properties

        /// <summary>Who begins and ends the sessions.</summary>
        public SessionSigner    Signer     { get; private set; } = default!;

        /// <summary>Said when a command to the session model was done.</summary>
        public Action<String>   OnDone     { get; }

        /// <summary>Said when a command to the session model was refused.</summary>
        public Action<String>   OnRefused  { get; }

        /// <summary>
        /// The meter in front of which this one stands now; null while it
        /// measures with its own simulation.
        /// </summary>
        public UpstreamDevice?  Upstream
            => current.Upstream;

        /// <summary>
        /// Who what the meter measures with says it is, once its models were
        /// walked.
        /// </summary>
        public (String Manufacturer, String Model, String Version, String SerialNumber)?  Who
            => current.Who;

        /// <summary>
        /// The session model, where it is known where it goes.
        /// </summary>
        public SessionModelBackendFactory?  SessionModel
            => current.Model;

        /// <summary>
        /// What a role that may write what is commanded may write now: the
        /// device's commanded registers, and the session model's command and
        /// parameters.
        /// </summary>
        public IReadOnlySet<UInt16>  Commanded  { get; }

        /// <summary>
        /// What only an administrator may write now.
        /// </summary>
        public IReadOnlySet<UInt16>  Protected  { get; }

        /// <summary>
        /// The Modbus/TLS connections open now, the oldest first.
        /// </summary>
        public IReadOnlyList<ModbusConnection>  Connections
            => [ .. connections.Values.OrderBy(connection => connection.Id) ];

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Measure with the given device.
        /// </summary>
        /// <param name="Device">Its backends.</param>
        /// <param name="Commanded">What of its registers a role that may write what is commanded may write.</param>
        /// <param name="Protected">What of its registers only an administrator may write.</param>
        /// <param name="OnDone">Said when a command to the session model was done.</param>
        /// <param name="OnRefused">Said when a command to the session model was refused.</param>
        public MeterBackends(IModbusBackendFactory  Device,
                             IReadOnlySet<UInt16>   Commanded,
                             IReadOnlySet<UInt16>   Protected,
                             Action<String>?        OnDone      = null,
                             Action<String>?        OnRefused   = null)
        {

            this.current    = new Target(Device, Commanded, Protected, null);
            this.OnDone     = OnDone    ?? (_ => { });
            this.OnRefused  = OnRefused ?? (_ => { });

            this.Commanded  = new Addresses(() => current.Model is SessionModelBackendFactory model
                                                      ? current.Commanded.Union(model.WritableAddresses).ToHashSet()
                                                      : current.Commanded);

            this.Protected  = new Addresses(() => current.Protected);

        }

        #endregion


        #region SignWith(Signer)

        /// <summary>
        /// Who begins and ends the sessions - which itself reads what the
        /// meter measures with, and so comes after.
        /// </summary>
        public void SignWith(SessionSigner Signer)

            => this.Signer = Signer;

        #endregion

        #region MeasureWith(Device, Commanded, Protected, Upstream)

        /// <summary>
        /// Measure with something else from now on.
        /// </summary>
        /// <returns>The meter in front of which this one stood, to be let go of.</returns>
        public UpstreamDevice? MeasureWith(IModbusBackendFactory  Device,
                                           IReadOnlySet<UInt16>   Commanded,
                                           IReadOnlySet<UInt16>   Protected,
                                           UpstreamDevice?        Upstream)
        {

            var before = current.Upstream;

            current = new Target(Device, Commanded, Protected, Upstream);

            return before;

        }

        #endregion

        #region Locate()

        /// <summary>
        /// Find where the models of what the meter measures with end, and so
        /// where the session model goes - now, rather than at the first
        /// connection.
        /// </summary>
        /// <returns>The session model; null while the models cannot be walked.</returns>
        public Task<SessionModelBackendFactory?> Locate()

            => current.ModelOf(this);

        #endregion

        #region CreateAsync(ConnectionId, Role, CancellationToken)

        public async Task<IModbusBackend> CreateAsync(Int64              ConnectionId,
                                                      String?            Role,
                                                      CancellationToken  CancellationToken)

            => await Direct(ConnectionId, Role, CancellationToken);

        #endregion

        #region Direct(ConnectionId, Role, CancellationToken)

        /// <summary>
        /// The backend a Modbus/TLS connection is handed, for whoever asks
        /// from within this meter and is no connection: its command line.
        /// </summary>
        /// <remarks>
        /// The whole of it - the device and the session model behind its
        /// models - and without the policy of the Modbus/TLS frontend, which
        /// decides by the role in a certificate nobody showed here. Whoever
        /// calls this says who may.
        /// </remarks>
        public async Task<IModbusBackend> Direct(Int64              ConnectionId       = 0,
                                                 String?            Role               = null,
                                                 CancellationToken  CancellationToken  = default)
        {

            var target = current;

            return await target.ModelOf(this) is SessionModelBackendFactory model
                       ? await model.        CreateAsync(ConnectionId, Role, CancellationToken)
                       : await target.Device.CreateAsync(ConnectionId, Role, CancellationToken);

        }

        #endregion

        #region Opened(Connection) / Closed(Connection) / Asked(ConnectionId, Allowed)

        /// <summary>
        /// The TLS handshake of a connection held: it is one of those open
        /// now.
        /// </summary>
        /// <param name="Connection">What the Modbus/TLS frontend said of it.</param>
        public void Opened(ModbusConnectionInfo Connection)

            => connections[Connection.ConnectionId] = new ModbusConnection(Connection);

        /// <summary>
        /// A connection is over.
        /// </summary>
        /// <param name="Connection">What the Modbus/TLS frontend said of it when it began.</param>
        public void Closed(ModbusConnectionInfo Connection)

            => connections.TryRemove(Connection.ConnectionId, out _);

        /// <summary>
        /// A connection made a request, which is counted.
        /// </summary>
        /// <param name="ConnectionId">The number of the connection.</param>
        /// <param name="Allowed">Whether the policy allowed the request.</param>
        public void Asked(Int64    ConnectionId,
                          Boolean  Allowed)
        {

            if (connections.TryGetValue(ConnectionId, out var connection))
                connection.Asked(Allowed, Timestamp.Now);

        }

        #endregion

        #region ImportedWh() / Read(First, Count)

        /// <summary>
        /// What the imported energy counter of what the meter measures with
        /// stands at, in Wh.
        /// </summary>
        /// <exception cref="EnergyUnreadable">With why.</exception>
        public Task<Decimal> ImportedWh()

            => current.ImportedWh(this);

        /// <summary>
        /// Registers of what the meter measures with.
        /// </summary>
        /// <exception cref="ModbusException">What it answered instead.</exception>
        public Task<UInt16[]> Read(UInt16 First, UInt16 Count)

            => current.Read(First, Count);

        #endregion


        #region (class) Addresses

        /// <summary>
        /// A set of register addresses asked anew each time - for the policy of
        /// the Modbus/TLS frontend, which is made once and asks for every write.
        /// </summary>
        private sealed class Addresses(Func<IReadOnlySet<UInt16>> Now) : IReadOnlySet<UInt16>
        {

            public Int32    Count                                   => Now().Count;
            public Boolean  Contains(UInt16 Item)                   => Now().Contains(Item);
            public Boolean  IsProperSubsetOf  (IEnumerable<UInt16> Other) => Now().IsProperSubsetOf  (Other);
            public Boolean  IsProperSupersetOf(IEnumerable<UInt16> Other) => Now().IsProperSupersetOf(Other);
            public Boolean  IsSubsetOf        (IEnumerable<UInt16> Other) => Now().IsSubsetOf        (Other);
            public Boolean  IsSupersetOf      (IEnumerable<UInt16> Other) => Now().IsSupersetOf      (Other);
            public Boolean  Overlaps          (IEnumerable<UInt16> Other) => Now().Overlaps          (Other);
            public Boolean  SetEquals         (IEnumerable<UInt16> Other) => Now().SetEquals         (Other);
            public IEnumerator<UInt16> GetEnumerator()              => Now().GetEnumerator();
            IEnumerator IEnumerable.GetEnumerator()                 => GetEnumerator();

        }

        #endregion

    }

}
