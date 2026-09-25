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

using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;
using org.GraphDefined.Vanaheimr.Norn.NTS;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;
using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;
using cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI;
using cloud.charging.open.EnergyMeters.ModbusTLS.Logging;

using LogLevel             = cloud.charging.open.protocols.WWCP.Node.Logging.LogLevel;
using NetIPAddress         = System.Net.IPAddress;
using NodeCertificateKind  = cloud.charging.open.protocols.WWCP.Node.Certificates.CertificateKind;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// One simulated SunSpec energy meter: a WWCP node - its log, its log book,
    /// its configuration, its clock, its accounts and its web interface - with
    /// a Modbus/TLS frontend beside it that the meter is read through.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two servers on two ports, deliberately. Modbus/TLS is what a charging
    /// station or a local controller speaks to this meter, and its access
    /// control is the SunSpec role in a client certificate - a machine-to-
    /// machine decision, made per request, with no notion of a person. The
    /// HTTP side is the node's: where a person signs in to see and change what
    /// the meter is, and its access control is an account in a role's group.
    /// Putting both through one door would mean one of the two answering
    /// questions it has no vocabulary for.
    /// </para>
    /// <para>
    /// The meter grew the parts a node has - the log, the configuration file,
    /// the clock check, the accounts - before there was a node, and kept its
    /// own copies until it became one. What it had that the node did not came
    /// along: its signed log is the node's log book now, its NTS semantics and
    /// its HTTPS are the node's. What is its own is here: the device and its
    /// registers, the Modbus/TLS frontend, its certificates and the CAs it
    /// accepts, the keys it signs readings with, and the charging sessions.
    /// </para>
    /// <para>
    /// Everything a person reads - the banner, the usage, the console - belongs
    /// to whoever hosts this, not here. This class says what it is doing
    /// through its log and through its properties, so that a CLI, a test and a
    /// service can each present it their own way.
    /// </para>
    /// </remarks>
    public partial class ModbusTLSEnergyMeter : WWCPNode
    {

        #region Data

        /// <summary>
        /// What kind of node a meter is: what it calls itself in a sentence,
        /// its tag, its product name, the organization its accounts are in, and
        /// what its log files are called.
        /// </summary>
        /// <remarks>
        /// The organization and the files are the names the meter used before
        /// it was a node, and must stay them: the accounts of every meter that
        /// has run are in "EnergyMeter", and its signed log - its log book now -
        /// is a chain of "meter-" files that the next line has to carry on.
        /// </remarks>
        public static readonly NodeKind   MeterKind                = new (
                                                                         Name:           "energy meter",
                                                                         Tag:            "meter",
                                                                         Product:        "ModbusTLSEnergyMeter",
                                                                         Organization:   "EnergyMeter",
                                                                         LogFilePrefix:  "meter"
                                                                     );

        /// <summary>
        /// The port IANA registered for Modbus/TLS ("mbaps").
        /// </summary>
        public static readonly Int32      DefaultModbusTLSPort     = 802;

        /// <summary>
        /// The TCP port the web interface listens on, unless another is given.
        /// </summary>
        /// <remarks>
        /// Beside the ports an OpenChargingCloud charging station (2348, 2349)
        /// and local controller (2350) use, and not one of them: a meter, a
        /// station and a controller are often tried out on the same bench, and
        /// two web interfaces fighting over one socket is a confusing way to
        /// find that out.
        /// </remarks>
        public new static readonly IPPort DefaultHTTPPort          = IPPort.Parse(2351);

        /// <summary>
        /// How long a peer has to get through the TLS handshake.
        /// </summary>
        public static readonly TimeSpan   DefaultHandshakeTimeout  = TimeSpan.FromSeconds(10);

        /// <summary>
        /// How long a connection may ask nothing before it is closed.
        /// </summary>
        public static readonly TimeSpan   DefaultIdleTimeout       = TimeSpan.FromMinutes(5);

        /// <summary>
        /// How long a peer may refuse to read an answer before it is closed.
        /// </summary>
        public static readonly TimeSpan   DefaultWriteTimeout      = TimeSpan.FromSeconds(30);

        /// <summary>
        /// How many days of the ordinary log files are kept, unless somebody says
        /// otherwise. The log book is kept whole.
        /// </summary>
        public const           Int32      DefaultLogKeepDays       = 30;

        /// <summary>
        /// The directory below the data path the log files and the log book are
        /// written to: the one the signed log always was in.
        /// </summary>
        public const           String     LogDirectoryName         = "logs";

        /// <summary>
        /// The Modbus/TLS frontend, as a start that cannot have its port names
        /// it.
        /// </summary>
        public static readonly NodePort   ModbusTLSPort            = new ("The Modbus/TLS frontend");

        /// <summary>
        /// What a line the libraries below write is tagged with, needle and tag:
        /// the table the debug bridge of a meter reads by.
        /// </summary>
        /// <remarks>
        /// What a meter overhears is its two doors and its clock: Modbus/TLS and
        /// the TLS under it, the web side, and name resolution and the time
        /// servers. None of the vehicle's ISO 15118, which a meter never hears.
        /// </remarks>
        public static readonly IReadOnlyList<(String Needle, String Tag)> TraceTags = [
            ("modbus",       "modbus"),
            ("sunspec",      "modbus"),
            ("tls",          "tls"),
            ("certificate",  "tls"),
            ("http",         "http"),
            ("dns",          "dns"),
            ("nts",          "nts"),
            ("ntp",          "nts")
        ];

        private readonly  SunSpecMeterDevice       device;
        private readonly  ModbusTlsFrontend        frontend;
        private readonly  CancellationTokenSource  cts            = new();

        private readonly  ILoggerFactory           loggerFactory;
        private readonly  ILogger                  logger;

        private readonly  CertificateStore         modbusCertificates;
        private readonly  CertificateStore         webCertificates;
        private readonly  ClientTrustStore         clientTrust;
        private readonly  MeterKeyStore            signingKeys;
        private readonly  ChargingSessions         sessions;
        private readonly  X509Certificate2         startupCertificate;

        private           ITimer?                  certificateTimer;
        private           ITimer?                  stateTimer;
        private           ITimer?                  logFileTimer;

        private           Task?                    runTask;

        #endregion

        #region Properties

        /// <summary>
        /// The address the Modbus/TLS frontend listens on.
        /// </summary>
        public NetIPAddress        ListenAddress       { get; }

        /// <summary>
        /// The port the Modbus/TLS frontend listens on.
        /// </summary>
        public Int32               ListenPort          { get; }

        /// <summary>
        /// The serial number in SunSpec Common Model 1.
        /// </summary>
        public String              SerialNumber        { get; }

        /// <summary>
        /// Where the accounts of this meter, its log files, its log book, its
        /// keys, its sessions and its energy counters live.
        /// </summary>
        public String              DataPath            { get; }

        /// <summary>
        /// How many days of the ordinary log files are kept, or 0 when this
        /// meter writes no log files at all - and so keeps no log book either.
        /// </summary>
        public Int32               LogKeepDays         { get; }

        /// <summary>
        /// The simulated device behind the frontend: its register map, and the
        /// classification of those registers that the policy is built from.
        /// </summary>
        public SunSpecMeterDevice  Device
            => device;

        /// <summary>
        /// The certificates this meter can show to its Modbus/TLS clients, and
        /// the rule for which of them it shows now.
        /// </summary>
        public CertificateStore    ModbusCertificates
            => modbusCertificates;

        /// <summary>
        /// The certificates the web interface can show a browser.
        /// </summary>
        /// <remarks>
        /// A different store, and deliberately: what a meter shows a charging
        /// station says "I am this device" and comes from a device PKI, and
        /// what it shows a browser says "I am this administrative web server"
        /// and comes from wherever the operator's web certificates come from.
        /// Nothing issues a certificate both of those would accept.
        /// </remarks>
        public CertificateStore    WebCertificates
            => webCertificates;

        /// <summary>
        /// Which CAs a Modbus/TLS client certificate may chain to.
        /// </summary>
        public ClientTrustStore    ClientTrust
            => clientTrust;

        /// <summary>
        /// The keys this meter puts its name to a reading with.
        /// </summary>
        /// <remarks>
        /// A third store, apart from the two above and for the same reason they
        /// are apart from each other: a TLS key says "this listener is this
        /// host" for the length of a connection, and is replaced whenever a CA
        /// issues a new certificate. These say "this meter measured this", and
        /// have to go on meaning it for as long as anybody may want to check a
        /// reading - years after the connection, and after the certificate it
        /// was taken under has expired.
        /// </remarks>
        public MeterKeyStore       SigningKeys
            => signingKeys;

        /// <summary>
        /// The charging session this meter is measuring, and the counters its
        /// signed documents are numbered with.
        /// </summary>
        public ChargingSessions    Sessions
            => sessions;

        /// <summary>
        /// The certificate this meter is showing its Modbus/TLS clients at the
        /// moment, or the one it was started with when the store is empty.
        /// </summary>
        public X509Certificate2    MeterCertificate
            => modbusCertificates.Current?.Certificate ?? startupCertificate;

        /// <summary>
        /// The CA a client certificate must chain to before it is let in.
        /// </summary>
        public X509Certificate2    ClientCA            { get; }

        /// <summary>
        /// The JSON API of this meter at "/api": what it is measuring, how it
        /// is configured, and the few things about it that can be changed.
        /// </summary>
        public MeterHTTPAPI        API                 { get; }

        /// <summary>
        /// Where the parts of this meter that speak ILogger write: the Modbus/TLS
        /// frontend, and whoever a host hands it to. Into the log, like
        /// everything else.
        /// </summary>
        public ILogger             Logger
            => logger;

        /// <summary>
        /// The account a first start made up, when it made one.
        /// </summary>
        public String?             GeneratedUserId
            => GeneratedPassword is not null
                   ? DefaultAdminUser
                   : null;

        /// <summary>
        /// Whether the Modbus/TLS frontend is serving.
        /// </summary>
        public Boolean             IsRunning
            => started && runTask?.IsCompleted == false;

        /// <summary>
        /// The task that serves Modbus/TLS connections, so that a host can wait
        /// on it and notice when it ends on its own.
        /// </summary>
        public Task                RunTask
            => runTask ?? Task.CompletedTask;

        #endregion

        #region Constructor(s)

        #region (private sealed class) Setup

        /// <summary>
        /// What has to exist before the node below a meter is made: where its
        /// data lives, and the store the certificate of its web interface comes
        /// from - which the node's HTTP server asks at every handshake, and so
        /// is handed before the node exists.
        /// </summary>
        private sealed class Setup
        {

            public String            DataPath           { get; }
            public String            CertificatesPath   { get; }
            public String?           LogPath            { get; }
            public Int32             LogKeepDays        { get; }
            public CertificateStore  WebCertificates    { get; }

            /// <summary>
            /// The accounts file that was renamed, to be said once there is a
            /// log to say it in; null when nothing was.
            /// </summary>
            public String?           RenamedAccounts    { get; }

            public Setup(String         SerialNumber,
                         String?        DataPath,
                         String?        CertificatesPath,
                         Int32?         LogKeepDays,
                         Boolean        HTTPS,
                         TimeProvider?  TimeProvider)
            {

                this.DataPath          = Path.GetFullPath(DataPath ?? "data");
                this.CertificatesPath  = CertificatesPath ?? Path.Combine(this.DataPath, "certificates");
                this.LogKeepDays       = Math.Max(LogKeepDays ?? DefaultLogKeepDays, 0);

                // The log files and the log book in the directory the signed log
                // always was in, so that the log book carries on its chain: the
                // first line written as a node points back at the last one
                // written before.
                this.LogPath           = this.LogKeepDays > 0
                                             ? Path.Combine(this.DataPath, LogDirectoryName)
                                             : null;

                this.WebCertificates   = new CertificateStore(Path.Combine(this.CertificatesPath, "web"), "web", TimeProvider ?? System.TimeProvider.System);

                // The web interface has no certificate to inherit - and borrowing
                // the device's would be the very conflation the two stores exist
                // to avoid - so it signs one for itself. A browser will say it
                // does not know who signed it, and it is right; a certificate from
                // a CA simply becomes the newer one later.
                if (HTTPS && WebCertificates.Current is null)
                    // Named so that it cannot be mistaken for the device
                    // certificate in a log line: they are two identities, and the
                    // whole point of two stores is that nobody conflates them.
                    WebCertificates.CreateSelfSigned(
                        $"CN={SerialNumber} web interface",
                        ["localhost", $"{SerialNumber}.local"],
                        ["127.0.0.1", "::1"],
                        "made by this meter at the first start"
                    );

                // The accounts under the name every node gives them. The meter's
                // were called by Hermod's default, and a node that looked for
                // users.db would find none, make a first account and leave every
                // account there was behind - so the file is renamed once, before
                // the node below opens it.
                var accounts  = Path.Combine(this.DataPath, "UsersAPI");
                var before    = Path.Combine(accounts, HTTPExtAPI.DefaultHTTPExtAPI_DatabaseFileName);
                var after     = Path.Combine(accounts, DefaultAccountsDatabaseFile);

                if (File.Exists(before) && !File.Exists(after))
                {
                    File.Move(before, after);
                    this.RenamedAccounts = before;
                }

            }

        }

        #endregion

        /// <summary>
        /// Create a Modbus/TLS energy meter. Nothing listens until
        /// <see cref="WWCPNode.Start"/> is called.
        /// </summary>
        /// <param name="SerialNumber">The serial number in SunSpec Common Model 1.</param>
        /// <param name="ServerPfxPath">The PKCS#12 file holding this meter's certificate and its key.</param>
        /// <param name="ServerPfxPassword">The password of that file.</param>
        /// <param name="ClientCACertPath">The CA that Modbus/TLS client certificates must chain to.</param>
        /// <param name="ListenAddress">The address the Modbus/TLS frontend listens on (default: loopback).</param>
        /// <param name="ListenPort">The port it listens on (default: 802, the registered mbaps port).</param>
        /// <param name="HandshakeTimeout">How long a peer has to get through the TLS handshake.</param>
        /// <param name="IdleTimeout">How long a connection may ask nothing before it is closed.</param>
        /// <param name="WriteTimeout">How long a peer may refuse to read an answer before it is closed.</param>
        /// <param name="MeterMode">Where this meter sits in the simulated site, and therefore which way energy flows through it (default: at the grid connection point).</param>
        /// <param name="SimulatedDayLength">How much real time one simulated day takes (default: a day). Only the load and the sun run faster; the energy counters always count real seconds.</param>
        /// <param name="HTTPHostname">The address the web interface listens on (default: loopback).</param>
        /// <param name="HTTPPort">The port the web interface listens on.</param>
        /// <param name="MeterAPIPath">Where this meter's own JSON API is mounted (default: "/api").</param>
        /// <param name="Frontend">Where the files of the web interface come from (default: the bundle embedded in this assembly).</param>
        /// <param name="HTTPS">Whether the web interface is served over TLS, with a certificate of its own.</param>
        /// <param name="CertificatesPath">Where the certificate stores live (default: certificates/ below the data path).</param>
        /// <param name="DataPath">Where accounts, logs, keys and sessions are written (default: data/ beside the process).</param>
        /// <param name="ConfigFile">Where the name servers and the time servers are read from.</param>
        /// <param name="DNSClient">A ready-made DNS client, for tests and for hosts that share one.</param>
        /// <param name="NTSClient">A ready-made time client, likewise.</param>
        /// <param name="LogKeepDays">How many days of the ordinary log files are kept; 0 to write no log files, and no log book, at all.</param>
        /// <param name="LogToConsole">Whether the log is also written to the console.</param>
        /// <param name="ConsoleLogLevel">How much of it reaches the console.</param>
        /// <param name="BridgeDebugLog">Whether what the libraries below write with DebugX ends up in the log.</param>
        /// <param name="TimeProvider">Where this meter reads the time; the system clock by default.</param>
        public ModbusTLSEnergyMeter(String                 SerialNumber,
                                    String                 ServerPfxPath,
                                    String?                ServerPfxPassword,
                                    String                 ClientCACertPath,
                                    NetIPAddress?          ListenAddress        = null,
                                    Int32?                 ListenPort           = null,
                                    TimeSpan?              HandshakeTimeout     = null,
                                    TimeSpan?              IdleTimeout          = null,
                                    TimeSpan?              WriteTimeout         = null,
                                    SunSpecMeterMode?      MeterMode            = null,
                                    TimeSpan?              SimulatedDayLength   = null,

                                    IIPAddress?            HTTPHostname         = null,
                                    IPPort?                HTTPPort             = null,
                                    HTTPPath?              MeterAPIPath         = null,
                                    IStaticContentSource?  Frontend             = null,
                                    Boolean                HTTPS                = false,
                                    String?                CertificatesPath     = null,
                                    String?                DataPath             = null,

                                    WWCPConfigFile?        ConfigFile           = null,
                                    DNSClient?             DNSClient            = null,
                                    NTSClient?             NTSClient            = null,
                                    Int32?                 LogKeepDays          = null,
                                    Boolean                LogToConsole         = true,
                                    LogLevel               ConsoleLogLevel      = LogLevel.Info,
                                    Boolean                BridgeDebugLog       = true,
                                    TimeProvider?          TimeProvider         = null)

            : this(new Setup(SerialNumber, DataPath, CertificatesPath, LogKeepDays, HTTPS, TimeProvider),
                   SerialNumber, ServerPfxPath, ServerPfxPassword, ClientCACertPath,
                   ListenAddress, ListenPort, HandshakeTimeout, IdleTimeout, WriteTimeout, MeterMode, SimulatedDayLength,
                   HTTPHostname, HTTPPort, MeterAPIPath, Frontend, HTTPS,
                   ConfigFile, DNSClient, NTSClient, LogToConsole, ConsoleLogLevel, BridgeDebugLog, TimeProvider)

        { }

        private ModbusTLSEnergyMeter(Setup                  Setup,
                                     String                 SerialNumber,
                                     String                 ServerPfxPath,
                                     String?                ServerPfxPassword,
                                     String                 ClientCACertPath,
                                     NetIPAddress?          ListenAddress,
                                     Int32?                 ListenPort,
                                     TimeSpan?              HandshakeTimeout,
                                     TimeSpan?              IdleTimeout,
                                     TimeSpan?              WriteTimeout,
                                     SunSpecMeterMode?      MeterMode,
                                     TimeSpan?              SimulatedDayLength,

                                     IIPAddress?            HTTPHostname,
                                     IPPort?                HTTPPort,
                                     HTTPPath?              MeterAPIPath,
                                     IStaticContentSource?  Frontend,
                                     Boolean                HTTPS,

                                     WWCPConfigFile?        ConfigFile,
                                     DNSClient?             DNSClient,
                                     NTSClient?             NTSClient,
                                     Boolean                LogToConsole,
                                     LogLevel               ConsoleLogLevel,
                                     Boolean                BridgeDebugLog,
                                     TimeProvider?          TimeProvider)

            : base(Kind:                            MeterKind,
                   Version:                         typeof(ModbusTLSEnergyMeter).Assembly.GetName().Version?.ToString(3) ?? "0.0.0",
                   HTTPPort:                        HTTPPort ?? DefaultHTTPPort,
                   HTTPHostname:                    HTTPHostname,

                   // The newest web certificate that is valid now, asked for per
                   // connection rather than frozen at the start - the same rule
                   // as the Modbus side, from the other store - and the
                   // intermediates with it, which is what a browser needs to
                   // build a path from this certificate to something it trusts.
                   ServerCertificateSelector:       HTTPS
                                                        ? (tcpServer, tcpClient) => Setup.WebCertificates.Current?.Certificate
                                                                                        ?? throw new InvalidOperationException("This meter has no valid web certificate to show.")
                                                        : null,
                   ServerCertificateChainSelector:  HTTPS
                                                        ? (tcpServer, tcpClient) => Setup.WebCertificates.ChainFor(null)
                                                        : null,

                   HTTPRootPath:                    MeterAPIPath,
                   AccountsPath:                    Setup.DataPath,
                   Roles:                           MeterRole.All.Select(role => role.Name),
                   ConfigFile:                      ConfigFile,
                   DNSClient:                       DNSClient,
                   NTSClient:                       NTSClient,
                   Frontend:                        Frontend ?? new EmbeddedContentSource(MeterHTTPAPI.FrontendResourcePrefix, typeof(ModbusTLSEnergyMeter).Assembly),

                   // The time servers' certificates and roots, for holding a time
                   // server to one, in "roots/tls" and "tls/servers" as on every
                   // node; everything else this meter shows and believes is in
                   // stores of its own beside them - "modbus", "web", "trust".
                   CertificatesPath:                Setup.CertificatesPath,
                   CertificateKinds:                [ NodeCertificateKind.TLSRoot, NodeCertificateKind.TLSServer ],

                   LogToConsole:                    LogToConsole,
                   ConsoleLogLevel:                 ConsoleLogLevel,
                   LogPath:                         Setup.LogPath,
                   MetrologicalLogPath:             Setup.LogPath,
                   BridgeDebugLog:                  BridgeDebugLog,
                   TraceTags:                       TraceTags,
                   TimeProvider:                    TimeProvider)

        {

            this.DataPath        = Setup.DataPath;
            this.LogKeepDays     = Setup.LogKeepDays;

            if (Setup.RenamedAccounts is String renamed)
                this.Log.Notice($"The accounts of this meter were in '{renamed}', and are in '{DefaultAccountsDatabaseFile}' beside it now, as every node calls them.",
                                "web", "auth");

            // Hermod's parts speak ILogger and know nothing of an event log, so
            // they are handed one that writes into it.
            this.loggerFactory   = new EventLogLoggerFactory(this.Log);
            this.logger          = this.loggerFactory.CreateLogger<ModbusTLSEnergyMeter>();

            #region The Modbus/TLS side

            this.SerialNumber    = SerialNumber;
            this.ListenAddress   = ListenAddress ?? NetIPAddress.Loopback;
            this.ListenPort      = ListenPort    ?? DefaultModbusTLSPort;

            // Read before the frontend does, so that a missing or unreadable
            // certificate is an error from the constructor rather than from a
            // background task nobody is awaiting yet. They are also what a host
            // puts on screen, and it should not have to parse files for that a
            // second time.
            this.startupCertificate = X509CertificateLoader.LoadPkcs12FromFile(
                                          ServerPfxPath,
                                          ServerPfxPassword,
                                          X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
                                      );

            this.ClientCA        = X509CertificateLoader.LoadCertificateFromFile(ClientCACertPath);

            #endregion

            #region The certificates, and which of them is shown

            // Three stores and one trust store, all under one directory. The
            // certificate a charging station checks and the certificate a
            // browser checks are different statements, issued by different
            // people, and are never the same file.
            this.modbusCertificates  = new CertificateStore(Path.Combine(Setup.CertificatesPath, "modbus"), "modbus", this.TimeProvider);
            this.webCertificates     = Setup.WebCertificates;
            this.clientTrust         = new ClientTrustStore(Path.Combine(Setup.CertificatesPath, "trust"),            this.TimeProvider);

            // Beside the certificates rather than among them: these are not
            // certificates, nobody issues them, and they outlive every
            // certificate this meter will ever show.
            this.signingKeys         = new MeterKeyStore   (Path.Combine(this.DataPath, "keys"),                 this.TimeProvider);
            this.sessions            = new ChargingSessions(Path.Combine(this.DataPath, "sessions"),             this.TimeProvider);

            foreach (var problem in new[] { modbusCertificates.LastError, webCertificates.LastError, clientTrust.LastError })
                if (problem is not null)
                    this.Log.Warning(problem, "meter", "certificates");

            // What this meter was started with becomes the first entry, so
            // that there is one place that decides what is shown and a meter
            // started the old way needs nothing done to it.
            modbusCertificates.Adopt(startupCertificate, "the certificate this meter was started with");
            clientTrust.       Adopt(ClientCA, "the CA this meter was started with");

            // Who a charging station is talking to, who a browser is talking
            // to, and who may talk to this meter at all: each a change of what
            // the meter is known by or trusts, and so into the log book.
            modbusCertificates.OnCurrentChanged += (before, after) =>
                this.Log.Metrological(
                    LogLevel.Notice,
                    after is not null
                        ? $"Modbus/TLS clients are now shown '{after.Certificate?.Subject}', valid until {after.Certificate?.NotAfter:yyyy-MM-dd}."
                        : "There is no valid certificate left to show Modbus/TLS clients: every handshake will fail.",
                    "certificates", "modbus"
                );

            webCertificates.OnCurrentChanged += (before, after) =>
                this.Log.Metrological(
                    LogLevel.Notice,
                    after is not null
                        ? $"The web interface is now shown as '{after.Certificate?.Subject}', valid until {after.Certificate?.NotAfter:yyyy-MM-dd}."
                        : "There is no valid certificate left for the web interface.",
                    "certificates", "web"
                );

            clientTrust.OnChanged += what => this.Log.Metrological(LogLevel.Notice, what, "certificates", "trust");

            #endregion

            #region The device and its frontend

            this.device          = new SunSpecMeterDevice(
                                       SerialNumber,
                                       MeterMode ?? SunSpecMeterMode.Net,
                                       SimulatedDayLength
                                   );

            // What kind of meter this is can be changed through either door -
            // a Modbus client writing register 40094, or a person on the web
            // page - so it is written down where both of them end up rather
            // than at either of them. Which way the energy counts is what the
            // readings mean, so into the log book.
            this.device.OnModeChanged += (before, after) =>
                this.Log.Metrological(
                    LogLevel.Notice,
                    $"The meter is now {after.Description()}, and was {before.Description()}.",
                    "meter",
                    "simulation"
                );

            this.frontend        = new ModbusTlsFrontend(
                                       new ModbusTlsFrontendOptions(
                                           ListenAddress:      this.ListenAddress,
                                           ListenPort:         this.ListenPort,

                                           // Not a path: asked at every
                                           // handshake, which is what lets a
                                           // certificate be replaced under a
                                           // running meter.
                                           ServerPfxPath:      null,
                                           ServerPfxPassword:  null,
                                           CaCertPath:         null,

                                           HandshakeTimeout:   HandshakeTimeout ?? DefaultHandshakeTimeout,
                                           IdleTimeout:        IdleTimeout      ?? DefaultIdleTimeout,
                                           WriteTimeout:       WriteTimeout     ?? DefaultWriteTimeout,

                                           ServerCertificateSelector:  serverName => modbusCertificates.ChainFor(serverName)
                                                                                         ?? throw new InvalidOperationException("This meter has no valid Modbus/TLS certificate to show."),
                                           ClientTrustAnchors:         clientTrust.Anchors
                                       ),
                                       new SunSpecBackendFactory(device),
                                       new AuthorizationPolicy(device),
                                       loggerFactory.CreateLogger<ModbusTlsFrontend>()
                                   );

            // Every request, allowed or refused, into the log - and the ones
            // that change something or were turned away into the log book. See
            // ModbusTLSEnergyMeter.Audit.cs.
            this.frontend.OnModbusRequest += RecordModbusRequest;

            #endregion

            #region The JSON API

            // Below the node's web interface at "/", and the more specific of
            // the two, so that an unknown /api path answers with this API's JSON
            // 404 instead of the single-page application's stub.
            this.API             = new MeterHTTPAPI(
                                       this,
                                       ExtAPI,
                                       HTTPRootPath
                                   );

            #endregion

        }

        #endregion


        #region (protected override) OnListening()

        /// <summary>
        /// Begin listening for Modbus/TLS, once the web interface has its port.
        /// </summary>
        /// <remarks>
        /// The energy counters and a charging session that was running are
        /// picked up first: both are about where this meter stands, and it does
        /// not stand at zero just because the process is new - so nothing is
        /// read from it before they are.
        ///
        /// TcpListener.Start() happens before the first await inside the
        /// frontend's RunAsync(), so a Modbus port that could not be bound has
        /// already failed by the time that task comes back - and is thrown here,
        /// as the node throws for its own port, naming what the port was for.
        /// </remarks>
        protected override Task OnListening()
        {

            RestoreTheEnergyCounters();
            ResumeTheChargingSession();

            runTask = frontend.RunAsync(cts.Token);

            if (runTask.IsFaulted)
            {

                var problem = runTask.Exception!.GetBaseException();

                if (problem is SocketException socketProblem)
                    throw new PortUnavailableException(IPPort.Parse((UInt16) ListenPort), socketProblem, ModbusTLSPort);

                System.Runtime.ExceptionServices.ExceptionDispatchInfo.Capture(problem).Throw();

            }

            Log.Notice($"Modbus/TLS is listening on {ListenAddress}:{ListenPort}.", "meter", "modbus");

            return Task.CompletedTask;

        }

        #endregion

        #region (protected override) OnStarted()

        /// <summary>
        /// What a meter does once it is up: watch its certificates, say which
        /// key it signs with, keep its energy counters, and thin out its old log
        /// files.
        /// </summary>
        protected override Task OnStarted()
        {

            StartWatchingTheCertificates();
            AnnounceTheSigningKeys();
            StartSavingTheEnergyCounters();
            StartPruningTheLogFiles();

            return Task.CompletedTask;

        }

        #endregion

        #region (protected override) OnStopping()

        /// <summary>
        /// Stop listening for Modbus/TLS and let the connections still open
        /// finish, before the node stops its web interface.
        /// </summary>
        protected override async Task OnStopping()
        {

            certificateTimer?.Dispose();
            certificateTimer = null;

            stateTimer?.Dispose();
            stateTimer = null;

            logFileTimer?.Dispose();
            logFileTimer = null;

            // Once more on the way out, so an orderly stop loses nothing at all.
            SaveTheEnergyCounters();

            await cts.CancelAsync();

            if (runTask is not null)
            {
                try
                {
                    await runTask.WaitAsync(TimeSpan.FromSeconds(5));
                }
                catch (TimeoutException)            { }
                catch (OperationCanceledException)  { }
            }

            // Before the server: an event stream never completes by itself, so a
            // browser with the page still open would otherwise hold the
            // shutdown for as long as it stayed open.
            API.CloseEventStreams();

        }

        #endregion

        #region (override) DisposeAsync()

        /// <summary>
        /// Stop, and let go of the Modbus/TLS side before the node lets go of the
        /// log.
        /// </summary>
        public override async ValueTask DisposeAsync()
        {

            await Stop();

            frontend.OnModbusRequest -= RecordModbusRequest;

            frontend.          Dispose();
            device.            Dispose();
            startupCertificate.Dispose();
            ClientCA.          Dispose();
            cts.               Dispose();

            await base.DisposeAsync();

        }

        #endregion

    }

}
