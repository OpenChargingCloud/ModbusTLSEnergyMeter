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

using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;
using System.Net.Sockets;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SSH;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.WebSocket;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Modbus;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.Logins;
using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Connections;
using cloud.charging.open.protocols.WWCP.Node.SecureShell;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;
using cloud.charging.open.EnergyMeters.ModbusTLS.MeterReaders;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// What reads this meter over Modbus without Modbus/TLS: a charging station
    /// or a local controller that connects over a WebSocket of the subprotocol
    /// "modbus", on a port of its own, or over the SSH subsystem
    /// "modbus@open.charging.cloud" of the node's SSH server.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>What connects is written down as a connection</b> of the type
    /// "MeterReader", one the other end makes, in the store of connections
    /// beside the configuration file. Nothing that is not written down gets in,
    /// whatever it signs in with.
    /// </para>
    /// <para>
    /// <b>Who signs in is decided as at the station port of a node of OCPP</b>,
    /// by the same checks (<see cref="WebSocketSignIns"/>) and the same kind of
    /// logins (<see cref="WebSocketLogins"/>): a password, a one-time password,
    /// a TLS client certificate of a chain this meter accepts or the key pin of
    /// one - and over SSH a password, a one-time password bound to the session
    /// or an SSH key.
    /// </para>
    /// <para>
    /// <b>What it may do is the SunSpec role of the group of its login</b>: four
    /// login groups are there from the first start, named after the four roles
    /// Modbus/TLS knows - see <see cref="SunSpecLoginGroups"/>. A login in any
    /// other group has no role, and is answered with exception 01 to everything,
    /// as a certificate without a role is. Asked at every request, so that a
    /// login put into another group has the role of that one at its next
    /// request. The decision itself is the Modbus/TLS frontend's: the same
    /// policy, the same backends, the same log.
    /// </para>
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// What Modbus over SSH is called in what the SSH server says.
        /// </summary>
        public const String ModbusOverSSHLabel = "Modbus";

        /// <summary>
        /// What the port is to the log, where it can not be had.
        /// </summary>
        public static readonly NodePort              MeterReaderServerPort  = new ("The WebSocket server of Modbus");

        /// <summary>
        /// What the door of the WebSocket port calls the port and who comes to it.
        /// </summary>
        public static readonly WebSocketSignInWords  MeterReaderWords       = new () {
                                                                                  Port         = "the WebSocket port of Modbus",
                                                                                  Who          = "What reads this meter",
                                                                                  PinnedLogin  = "what reads this meter",
                                                                                  Realm        = "Modbus",
                                                                                  Tags         = [ "modbus", "reader" ],
                                                                                  InboundTags  = [ "modbus", "reader" ]
                                                                              };

        private MeterReaderServerConfiguration                    readerServerSettings   = new MeterReaderServerConfiguration().Effective();
        private StreamWebSocketServer?                            readerServer;
        private LoginSSHSignIns?                                  readerSSHSignIns;

        private volatile Boolean                                  readerServerStarted;
        private volatile Boolean                                  readerServerTLS;
        private volatile Boolean                                  modbusOverSSHServed;

        /// <summary>
        /// How many connections each connection of the store is in over now, by its id.
        /// </summary>
        private readonly ConcurrentDictionary<String, Int32>      readersIn              = new ();

        private readonly CancellationTokenSource                  readersStopping        = new ();

        #endregion

        #region Properties

        /// <summary>
        /// Which charging stations and local controllers may sign in, with what,
        /// and - by their group - as which SunSpec role.
        /// </summary>
        public WebSocketLogins                 WebSocketLogins           { get; private set; } = default!;

        /// <summary>
        /// Which chains the certificate of what connects over the WebSocket port
        /// of Modbus may lead to.
        /// </summary>
        /// <remarks>
        /// Not the client roots of Modbus/TLS: a certificate there says who it is
        /// and its role, and one here says who it is - its role is its login's.
        /// </remarks>
        public ClientTrustStore                ClientTrust               { get; private set; } = default!;

        /// <summary>
        /// Who comes in at the WebSocket port of Modbus: the sign-in checks of its door.
        /// </summary>
        public WebSocketSignIns                MeterReaderSignIns        { get; private set; } = default!;

        /// <summary>
        /// What the WebSocket port of Modbus presents, out of the node's store:
        /// the listener "websocket".
        /// </summary>
        public ListenerCertificate             MeterReaderCertificate    { get; private set; } = default!;

        /// <summary>
        /// What the WebSocket server of Modbus is configured as, with every
        /// field filled in.
        /// </summary>
        public MeterReaderServerConfiguration  MeterReaderSettings
            => readerServerSettings;

        /// <summary>
        /// The WebSocket server of Modbus, once it is built.
        /// </summary>
        public StreamWebSocketServer?          MeterReaderServer
            => readerServer;

        /// <summary>
        /// Whether the WebSocket server of Modbus is listening right now.
        /// </summary>
        public Boolean                         MeterReaderServerRunning
            => readerServerStarted;

        /// <summary>
        /// Whether the WebSocket port of Modbus speaks TLS, as decided when it started.
        /// </summary>
        public Boolean                         MeterReaderServerTLS
            => readerServerTLS;

        /// <summary>
        /// Whether Modbus is served over SSH right now.
        /// </summary>
        public Boolean                         ModbusOverSSHServed
            => modbusOverSSHServed;

        /// <summary>
        /// The logins in over Modbus now, over a WebSocket or over SSH.
        /// </summary>
        public IReadOnlyList<String>           MeterReadersIn
            => [.. backends.Connections.Where(connection => connection.Login is not null).Select(connection => connection.Login!).Distinct()];

        #endregion


        #region SunSpecRoleOf(Login)

        /// <summary>
        /// The SunSpec role the given login has now: the one of its group, where
        /// that is one of the role groups - see <see cref="SunSpecLoginGroups"/> -,
        /// and none otherwise: none, too, while the login or its group is switched off.
        /// </summary>
        /// <param name="Login">A WebSocket login of this meter.</param>
        public String? SunSpecRoleOf(User_Id Login)

            => WebSocketLogins.TryGet(Login, out var login) && login is not null && login.Enabled &&
               WebSocketLogins.GetGroup(login.GroupId)?.Enabled == true
                   ? SunSpecLoginGroups.RoleOf(login.GroupId)
                   : null;

        #endregion

        #region TryAddMeterReaderSSHKey(Login, Line, Label, GroupId, Description, CreatedBy, out Key, out Error, out NotSaved)

        /// <summary>
        /// Give what reads this meter an SSH key for Modbus over SSH - adding its
        /// login where it is not listed yet.
        /// </summary>
        /// <remarks>
        /// Refused where an account of this meter has the name: both would sign
        /// in to the same SSH server under it, and a name that is both is let in
        /// as neither.
        /// </remarks>
        /// <param name="Login">The login it signs in to SSH as.</param>
        /// <param name="Line">Its public key, as one line of an authorized_keys file.</param>
        /// <param name="Label">What the key is called, if anything.</param>
        /// <param name="GroupId">The group - the role - it should belong to, or null for the one it is in already.</param>
        /// <param name="Description">What reads this meter - in as many languages as it is said in.</param>
        /// <param name="CreatedBy">Who added the key, if anybody said.</param>
        /// <param name="Key">The key, as it was added.</param>
        /// <param name="Error">Why it was refused.</param>
        /// <param name="NotSaved">True where the file could not be written.</param>
        public Boolean TryAddMeterReaderSSHKey(User_Id                               Login,
                                               String?                               Line,
                                               String?                               Label,
                                               String?                               GroupId,
                                               I18NString?                           Description,
                                               String?                               CreatedBy,
                                               [NotNullWhen(true)]  out UserSSHKey?  Key,
                                               [NotNullWhen(false)] out String?      Error,
                                               out Boolean                           NotSaved)
        {

            Key       = null;
            NotSaved  = false;

            if (ExtAPI.TryGetUser(Login, out _))
            {
                Error = $"'{Login}' is an account of this {NodeNoun}. What reads this meter under the same name could not sign in over SSH: " +
                         "both would sign in under one name, and a name that is both is let in as neither.";
                return false;
            }

            return WebSocketLogins.TryAddSSHKey(Login, Line, Label, GroupId, Description, CreatedBy, out Key, out Error, out NotSaved);

        }

        #endregion


        #region (private) BuildMeterReaderServer()

        /// <summary>
        /// The stores of who reads this meter over Modbus without Modbus/TLS, its
        /// WebSocket server and its subsystem over SSH. Nothing listens yet.
        /// </summary>
        private void BuildMeterReaderServer()
        {

            var directory = Path.GetDirectoryName(Path.GetFullPath(ConfigFile.Path)) ?? ".";

            readerServerSettings = (ReadTheMeterReaderServer() ?? new MeterReaderServerConfiguration()).Effective();

            #region The connections: what reads this meter, over Modbus only

            Connections = new ConnectionStore(
                              Path.Combine(directory, ConnectionStore.DefaultDirectoryName),
                              TimeProvider,
                              NodeNoun
                          ) {

                              // What reads this meter, and nothing else: it
                              // connects, and this meter connects to nothing.
                              Rules = new ConnectionRules {
                                          Types                  = [ ConnectionType.MeterReader ],
                                          Outbound               = false,
                                          OCPP1_6                = false,
                                          NamesTheNodeItLeadsTo  = false
                                      }

                          };

            Connections.OnConnectionsChanged += SayWhoIsWaitedFor;
            Connections.OnNotice             += (level, message) => Log.Log(level, message, "modbus", "connections");

            // What every node that keeps connections has, though this one makes
            // none: the key its connections would sign in over SSH with - which
            // the page of the connections names.
            SshKey = new SshClientKey(
                         Path.Combine(Connections.Path, SshClientKey.DirectoryName),
                         $"meter@{Environment.MachineName}",
                         NodeNoun:  NodeNoun
                     );

            SshKey.OnNotice += (level, message) => Log.Log(level, message, "modbus", "connections", "ssh", "security");

            #endregion

            #region What it presents, out of the node's store

            MeterReaderCertificate = ListenerCertificates.For(MeterListeners.WebSocket, "the WebSocket port of Modbus");

            #endregion

            #region The two stores of who signs in

            ClientTrust      = new ClientTrustStore(
                                   Path.Combine(directory, ClientTrustStore.DefaultDirectoryName),
                                   TimeProvider,
                                   NodeNoun,
                                   "meter reader"
                               );

            ClientTrust.OnNotice += (level, message) => Log.Log(level, message, "modbus", "tls", "trust");

            ClientTrust.KeepToItsOwner();

            WebSocketLogins  = new WebSocketLogins(
                                   Path.Combine(directory, WebSocketLogins.DefaultFileName),
                                   TimeProvider,
                                   NodeNoun
                               );

            WebSocketLogins.OnNotice += (level, message) => Log.Log(level, message, "modbus", "reader", "auth");

            if (!WebSocketLogins.TryLoad(out var loginsError))
                throw new InvalidOperationException($"{loginsError} Repair or remove it and start again.");

            // The four groups of the roles, there from the first start.
            foreach (var problem in SunSpecLoginGroups.EnsureIn(WebSocketLogins))
                Log.Error(problem, "modbus", "reader", "auth");

            WebSocketLogins.OnChanged += () => {

                // A group of a role is refused at the JSON API (WhyGroupStays);
                // one removed another way is made again at once: the four
                // roles are what a login is put into to read this meter at all.
                if (SunSpecRoles.AllMandatory.Any(role => WebSocketLogins.GetGroup(SunSpecLoginGroups.GroupOf(role)) is null))
                {

                    Log.Notice("A login group of a SunSpec role was removed, and is made again: the four roles are always there.", "modbus", "reader", "auth");

                    foreach (var problem in SunSpecLoginGroups.EnsureIn(WebSocketLogins))
                        Log.Error(problem, "modbus", "reader", "auth");

                }

                if (readerServer is not null)
                    MeterReaderSignIns.ApplyLogins(readerServer);

                RecheckSSHSessions();

            };

            #endregion

            #region The door of the WebSocket port

            MeterReaderSignIns = new WebSocketSignIns(
                                     Logins:               WebSocketLogins,
                                     ClientTrust:          ClientTrust,
                                     SignInBrake:          SignInBrake,
                                     Log:                  Log,
                                     Authentications:      () => readerServerSettings.ClientAuthentication ?? MeterReaderServerConfiguration.DefaultClientAuthentication,
                                     OverTLS:              () => readerServerTLS,
                                     ChecksRevocation:     () => readerServerSettings.CheckCertificateRevocation == true,
                                     SaysSignIns:          () => true,
                                     InboundConnectionOf:  (server, name) => InboundConnectionOf(ProtocolVersion.Modbus, name),
                                     LetInAsInbound:       LetInAsInbound,
                                     LetInOthers:          (connection, login, how, detail, byCertificate) =>
                                                               $"'{login}' is nothing that reads this meter: no connection is written down that comes under that name",
                                     Words:                MeterReaderWords
                                 );

            #endregion

            #region The server

            readerServer = new StreamWebSocketServer(
                               readerServerSettings.Address,
                               readerServerSettings.TCPPort ?? MeterReaderServerConfiguration.DefaultTCPPort,
                               [ ModbusWireNames.Subprotocol ],
                               $"OpenChargingCloud {Kind.Product} v{Version}",
                               I18NString.Create($"What reads this {NodeNoun} over Modbus"),
                               null,
                               MeterReaderSignIns.ValidateCertificate,
                               true,
                               readerServerSettings.CheckCertificateRevocation
                           );

            // A UDP port is opened by nobody who did not ask for it.
            readerServer.AcceptHTTP3 = false;

            readerServer.OnValidateWebSocketConnection += MeterReaderSignIns.Validate;
            MeterReaderSignIns.ApplyLogins(readerServer);

            readerServer.OnStreamConnection += (connection, stream) => _ = ServeOverWebSocket(connection, stream);

            #endregion

            #region Modbus over SSH, on the node's SSH server

            readerSSHSignIns = new LoginSSHSignIns(
                                   WebSocketLogins,
                                   ModbusWireNames.SshSubsystem,
                                   () => modbusOverSSHServed,
                                   TimeProvider,
                                   () => SSHSubsystems.Select(subsystem => subsystem.Name)
                               );

            readerSSHSignIns.OnNotice += (level, message) => Log.Log(level, message, "modbus", "reader", "auth", "ssh");

            AddSSHSignIns(readerSSHSignIns);

            #endregion

            Log.Info(
                readerServerSettings.IsEnabled
                    ? $"The WebSocket server of Modbus will listen on {readerServerSettings.Address}:{readerServerSettings.TCPPort}, " +
                      $"speaking {ModbusWireNames.Subprotocol}" +
                      (readerServerSettings.TakesSSH ? $", and over the SSH subsystem {ModbusWireNames.SshSubsystem} as well." : ".")
                    : "The WebSocket server of Modbus is switched off; nothing reads this meter over a WebSocket or over SSH.",
                "modbus", "reader"
            );

        }

        #endregion

        #region (private) ReadTheMeterReaderServer()

        /// <summary>
        /// The "webSocketServer" section of the configuration file, as it is when
        /// the meter starts.
        /// </summary>
        /// <exception cref="InvalidOperationException">When the section says something this meter cannot do.</exception>
        private MeterReaderServerConfiguration? ReadTheMeterReaderServer()
        {

            if (!ConfigFile.TryLoadDocument(out var document, out _) ||
                document[MeterReaderServerConfiguration.SectionName] is not JToken section ||
                section.Type == JTokenType.Null)
                return null;

            if (section is not JObject json)
                throw new InvalidOperationException($"'{ConfigFile.Path}': '{MeterReaderServerConfiguration.SectionName}' must be an object: the WebSocket server of Modbus.");

            if (!MeterReaderServerConfiguration.TryParse(json, out var configuration, out var error))
                throw new InvalidOperationException($"'{ConfigFile.Path}': {error}");

            return configuration;

        }

        #endregion

        #region (private) StartMeterReaderServer() / StopMeterReaderServer()

        /// <summary>
        /// Start listening for what reads this meter, where it is meant to - and
        /// serve Modbus over SSH, where the section says so.
        /// </summary>
        private async Task StartMeterReaderServer()
        {

            if (readerServerStarted || !readerServerSettings.IsEnabled || readerServer is null)
            {
                SayWhoIsWaitedFor();
                return;
            }

            var wantsTLS = (readerServerSettings.ClientAuthentication ?? MeterReaderServerConfiguration.DefaultClientAuthentication).Any(authentication => authentication.IsOverTLS());

            readerServerTLS = wantsTLS && MeterReaderCertificate.Choose() is not null;

            readerServer.ServerCertificateChainSelector = readerServerTLS
                                                              ? (server, client) => MeterReaderCertificate.Current
                                                              : null;

            if (wantsTLS && !readerServerTLS)
                Log.Warning(
                    "HTTP authentication over TLS or a TLS client certificate is configured, but there is no server certificate - so the " +
                    "WebSocket port of Modbus is unencrypted and only HTTP authentication without TLS can be used on it. Make a TLS server " +
                    $"identity for the listener '{MeterListeners.WebSocket}'; the port encrypts from the next start.",
                    "modbus", "reader", "tls"
                );

            try
            {
                await readerServer.Start();
            }
            catch (SocketException problem)
            {
                throw new PortUnavailableException(
                          readerServerSettings.TCPPort ?? MeterReaderServerConfiguration.DefaultTCPPort,
                          problem,
                          MeterReaderServerPort
                      );
            }

            readerServerStarted = true;

            Log.Notice(
                $"What reads this meter connects to {(readerServerTLS ? "wss" : "ws")}://{readerServerSettings.Address}:{readerServerSettings.TCPPort}/<its name> " +
                $"({(readerServerTLS ? "TLS" : "unencrypted")}, {WebSocketLogins.EnabledCount} login(s), {ClientTrust.EnabledCount} accepted chain(s)).",
                "modbus", "reader"
            );

            if (readerServerSettings.TakesSSH)
                ServeModbusOverSSH();

            SayWhoIsWaitedFor();

        }

        /// <summary>
        /// Stop listening for what reads this meter: whoever is in is let go of.
        /// </summary>
        private async Task StopMeterReaderServer()
        {

            await readersStopping.CancelAsync();

            if (!readerServerStarted)
                return;

            readerServerStarted = false;

            StopServingModbusOverSSH();

            if (readerServer is not null)
                await readerServer.Shutdown($"The {NodeNoun} is shutting down.");

            Log.Info("The WebSocket server of Modbus has stopped listening.", "modbus", "reader");

        }

        #endregion

        #region (private) ServeModbusOverSSH() / StopServingModbusOverSSH()

        private void ServeModbusOverSSH()
        {

            if (modbusOverSSHServed)
                return;

            modbusOverSSHServed = true;

            try
            {
                AddSSHSubsystem(new SSHSubsystem(
                                    ModbusWireNames.SshSubsystem,
                                    ModbusOverSSHLabel,
                                    ServeOverSSH
                                ));
            }
            catch (Exception e)
            {
                modbusOverSSHServed = false;
                Log.Critical($"Modbus over SSH could not be served: {e.Message}", "modbus", "reader", "ssh");
                return;
            }

            if (!SSHEnabled)
                Log.Warning($"Modbus over SSH is switched on, but the SSH server of this {NodeNoun} is off - so nothing can read it over SSH.",
                            "modbus", "reader", "ssh");

            else
                Log.Notice($"What reads this meter may connect over SSH as well: {SSHURL}, subsystem {ModbusWireNames.SshSubsystem}, host key {SSHHostKey ?? "not known yet"}.",
                           "modbus", "reader", "ssh");

        }

        private void StopServingModbusOverSSH()
        {

            if (!modbusOverSSHServed)
                return;

            modbusOverSSHServed = false;

            RemoveSSHSubsystem(ModbusWireNames.SshSubsystem);

        }

        #endregion


        #region (private) ServeOverSSH(Context, CancellationToken)

        /// <summary>
        /// One session of the subsystem of Modbus: let in where its login is
        /// written down as what reads this meter over SSH, and served until it ends.
        /// </summary>
        private async ValueTask ServeOverSSH(SshSubsystemContext  Context,
                                             CancellationToken    CancellationToken)
        {

            var login  = Context.Session.Username;
            var peer   = Context.Session.Peer?.ToString() ?? "somewhere";

            if (InboundConnectionOf(ProtocolVersion.Modbus, login.ToString()) is not ConnectionEntry entry)
            {
                Log.Warning($"'{login}' asked for Modbus over SSH from {peer}, and is nothing that reads this meter: no connection is written down that comes under that name.",
                            "modbus", "reader", "ssh", "auth");
                return;
            }

            if (!entry.IsSSH)
            {
                Log.Warning($"'{login}' reads this meter over a WebSocket, and came over SSH from {peer}.", "modbus", "reader", "ssh", "auth");
                return;
            }

            if (!entry.AutoConnect)
            {
                Log.Warning($"'{login}' is the name '{entry.Description.FirstText()}' comes under, a connection that is switched off.", "modbus", "reader", "ssh", "auth");
                return;
            }

            using var both = CancellationTokenSource.CreateLinkedTokenSource(CancellationToken, readersStopping.Token);

            await Serve(entry, login, Context.Channel.AsStream(), peer, "SSH", both.Token);

        }

        #endregion

        #region (private) ServeOverWebSocket(Connection, Stream)

        /// <summary>
        /// One WebSocket of Modbus, let in by its door as the connection it came
        /// under: served until it ends.
        /// </summary>
        private async Task ServeOverWebSocket(WebSocketServerConnection  Connection,
                                              WebSocketMessageStream     Stream)
        {

            var peer = Connection.RemoteSocket.ToString();

            if (Connection.TryGetCustomData(InboundConnectionKey) is not String id ||
                Connections.Connections.FirstOrDefault(entry => entry.Id == id) is not ConnectionEntry entry ||
                entry.InboundName is not String name)
            {
                // The door lets in nothing else; should it ever, nothing is served.
                Log.Warning($"A WebSocket of Modbus from {peer} came in as nothing that reads this meter, and is closed.", "modbus", "reader", "auth");
                Stream.Dispose();
                return;
            }

            await Serve(entry, User_Id.Parse(name), Stream, peer, readerServerTLS ? "WebSocket TLS" : "WebSocket", readersStopping.Token);

        }

        #endregion

        #region (private) Serve(Entry, Login, Stream, Peer, Transport, CancellationToken)

        /// <summary>
        /// Serve Modbus over the given stream to what came in as the given
        /// connection, by the role of its login at every request.
        /// </summary>
        private async Task Serve(ConnectionEntry    Entry,
                                 User_Id            Login,
                                 Stream             Stream,
                                 String             Peer,
                                 String             Transport,
                                 CancellationToken  CancellationToken)
        {

            readersIn.AddOrUpdate(Entry.Id, 1, (_, count) => count + 1);

            Record(Entry, ConnectionStatus.Connected, $"'{Login}' reads this {NodeNoun} over {Transport}, as {SunSpecRoleOf(Login) ?? "no SunSpec role"}.");

            Log.Info($"'{Login}' connected from {Peer} over {Transport}, to read this {NodeNoun} over Modbus as {SunSpecRoleOf(Login) ?? "no SunSpec role - every request is refused"}.",
                     "modbus", "reader", "connections");

            try
            {
                await frontend.ServeAsync(
                          Stream,
                          () => SunSpecRoleOf(Login),
                          Peer,
                          Transport,
                          Login.ToString(),
                          CancellationToken
                      );
            }
            finally
            {

                try { await Stream.DisposeAsync(); } catch { }

                var left = readersIn.AddOrUpdate(Entry.Id, 0, (_, count) => Math.Max(count - 1, 0));

                Log.Info($"'{Login}' is no longer connected over {Transport}.", "modbus", "reader", "connections");

                if (left == 0)
                {
                    readersIn.TryRemove(KeyValuePair.Create(Entry.Id, 0));
                    SayWhoIsWaitedFor();
                }

            }

        }

        #endregion

        #region (private) SayWhoIsWaitedFor()

        /// <summary>
        /// Say of every connection of what reads this meter that is not in now
        /// that it is waited for - or why nothing can come.
        /// </summary>
        private void SayWhoIsWaitedFor()
        {

            if (Connections is null)
                return;

            foreach (var entry in Connections.Connections.Where(entry => entry.Inbound).ToArray())
            {

                if (readersIn.ContainsKey(entry.Id))
                    continue;

                var name  = entry.InboundName;

                var what  = !entry.AutoConnect
                                ? $"'{name}' is not let in: this connection is switched off."
                                : entry.IsSSH
                                      ? modbusOverSSHServed && SSHEnabled
                                            ? $"Waiting for '{name}' to connect over SSH."
                                            : $"'{name}' can not connect: this {NodeNoun} serves no Modbus over SSH."
                                      : readerServerStarted
                                            ? $"Waiting for '{name}' to connect."
                                            : $"'{name}' can not connect: the WebSocket server of Modbus of this {NodeNoun} is not listening.";

                if (ConnectionStates.TryGetValue(entry.Id, out var state) && state.Status == ConnectionStatus.Waiting && state.Said == what)
                    continue;

                Record(entry, ConnectionStatus.Waiting, what);

            }

        }

        #endregion

    }

}
