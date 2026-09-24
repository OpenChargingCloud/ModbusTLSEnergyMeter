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

using System.Net;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.DNS;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;
using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.Monitoring;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;
using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;
using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;
using cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI;
using cloud.charging.open.EnergyMeters.ModbusTLS.Logging;

using NetIPAddress  = System.Net.IPAddress;
using MeterLogLevel = cloud.charging.open.EnergyMeters.ModbusTLS.Logging.LogLevel;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// One simulated SunSpec energy meter: the Modbus/TLS frontend that the
    /// meter is read through, and the HTTP server beside it that the meter is
    /// administered through.
    /// </summary>
    /// <remarks>
    /// Two servers on two ports, deliberately. Modbus/TLS is what a charging
    /// station or a local controller speaks to this meter, and its access
    /// control is the SunSpec role in a client certificate - a machine-to-
    /// machine decision, made per request, with no notion of a person. The
    /// HTTP side is where a person signs in to see and change what the meter
    /// is, and its access control is an account with a role in an
    /// organization. Putting both through one door would mean one of the two
    /// answering questions it has no vocabulary for.
    ///
    /// Everything a person reads - the banner, the usage, the console - belongs
    /// to whoever hosts this, not here. This class says what it is doing
    /// through its <see cref="ILogger"/> and through its properties, so that a
    /// CLI, a test and a service can each present it their own way.
    /// </remarks>
    public partial class ModbusTLSEnergyMeter : IAsyncDisposable
    {

        #region Data

        /// <summary>
        /// The port IANA registered for Modbus/TLS ("mbaps").
        /// </summary>
        public static readonly Int32     DefaultModbusTLSPort     = 802;

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
        public static readonly IPPort    DefaultHTTPPort          = IPPort.Parse(2351);

        /// <summary>
        /// How long a peer has to get through the TLS handshake.
        /// </summary>
        public static readonly TimeSpan  DefaultHandshakeTimeout  = TimeSpan.FromSeconds(10);

        /// <summary>
        /// How long a connection may ask nothing before it is closed.
        /// </summary>
        public static readonly TimeSpan  DefaultIdleTimeout       = TimeSpan.FromMinutes(5);

        /// <summary>
        /// How long a peer may refuse to read an answer before it is closed.
        /// </summary>
        public static readonly TimeSpan  DefaultWriteTimeout      = TimeSpan.FromSeconds(30);

        private readonly  SunSpecMeterDevice              device;
        private readonly  ModbusTlsFrontend               frontend;
        private readonly  CancellationTokenSource         cts       = new();

        private readonly  ILoggerFactory                  loggerFactory;
        private readonly  ILogger                         logger;
        private readonly  ConsoleLog?                     consoleLog;
        private readonly  LogStore?                       logStore;

        private readonly  CertificateStore                modbusCertificates;
        private readonly  CertificateStore                webCertificates;
        private readonly  ClientTrustStore                clientTrust;
        private readonly  MeterKeyStore                   signingKeys;
        private readonly  ChargingSessions                sessions;
        private           ITimer?                         certificateTimer;
        private           ITimer?                         stateTimer;

        private readonly  DNSClient                       dnsClient;
        private           NTSClient                       ntsClient;
        private           TimeSourceGroup                 timeSources;

        /// <summary>
        /// How many of those servers this meter was told must answer: by the
        /// last section that named "minServers", or the default of two.
        /// </summary>
        /// <remarks>
        /// Kept apart from the group's own quorum, which cannot be more than the
        /// servers it has switched on. A lone hostname holds a group to one, and
        /// if that one were all that was remembered, a list of four arriving
        /// afterwards would be held to one as well - where the same file, read
        /// at the next start, holds it to two.
        /// </remarks>
        private           Byte                            ntsQuorum       = NTSConfiguration.DefaultMinServers;

        /// <summary>
        /// Whoever changes the time servers, one at a time: a save checks what
        /// is in effect, then the file, then changes both, and two saves at once
        /// could each find the other's half.
        /// </summary>
        private readonly  Lock                            ntsLock         = new();

        /// <summary>
        /// The name servers this meter would ask, whether or not name
        /// resolution is switched on at the moment.
        /// </summary>
        /// <remarks>
        /// Kept beside the DNS client because switching name resolution off is
        /// done by taking its servers away - which is what being switched off
        /// actually means, for everything holding that client and not only for
        /// the parts of this meter that remember to ask first. Switching it
        /// back on needs the list back, and this is where it waited.
        /// </remarks>
        private           IReadOnlyList<DNSServerConfig>  configuredDNSServers;

        /// <summary>
        /// What the file said about the time client, kept because the parts of
        /// it that are not the client itself - how often to check, and what the
        /// operator claims about the server - are read long afterwards.
        /// </summary>
        private           NTSConfiguration?               ntsSettings;

        /// <summary>
        /// When this meter last managed to check its clock, what it found, and
        /// against whom.
        /// </summary>
        private           DateTimeOffset?                 lastTimeCheck;
        private           TimeSpan?                       lastTimeCheckOffset;
        private           String?                         lastTimeCheckServer;
        private           Int32?                          lastTimeCheckAsked;
        private           Int32?                          lastTimeCheckAnswered;

        /// <summary>
        /// The last synchronisation as it was answered, whichever asked for it -
        /// the page, or the clock check - and whether or not it found a time.
        /// </summary>
        /// <remarks>
        /// Beside the last check above, which is only ever a success: a
        /// synchronisation that found no server left the page showing the one
        /// before it, as if nothing had happened since.
        /// </remarks>
        private           JObject?                        lastTimeSync;

        /// <summary>
        /// What asks the group of time servers and works out what they agree
        /// on.
        /// </summary>
        private readonly  MeasurementEngine               timeEngine;

        /// <summary>
        /// The clock that makes this meter check its own, when NTS is on.
        /// </summary>
        private           ITimer?                         timeCheckTimer;

        private readonly  HTTPServer                      httpServer;

        private           Task?                           runTask;
        private           Boolean                         started;

        #endregion

        #region Properties

        /// <summary>
        /// Where this meter reads the time from, and what it does with what it
        /// finds.
        /// </summary>
        public TimeProvider        TimeProvider        { get; }

        /// <summary>
        /// When this meter was made.
        /// </summary>
        public DateTimeOffset      CreatedAt           { get; }

        /// <summary>
        /// The version of this assembly.
        /// </summary>
        public String              Version             { get; }

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
        /// Whether the web interface is served over TLS.
        /// </summary>
        public Boolean             HTTPSEnabled        { get; }

        /// <summary>
        /// The certificate this meter is showing its Modbus/TLS clients at the
        /// moment, or the one it was started with when the store is empty.
        /// </summary>
        public X509Certificate2    MeterCertificate
            => modbusCertificates.Current?.Certificate ?? startupCertificate;

        private readonly X509Certificate2  startupCertificate;

        /// <summary>
        /// The CA a client certificate must chain to before it is let in.
        /// </summary>
        public X509Certificate2    ClientCA            { get; }

        /// <summary>
        /// The HTTP server the web side is served by.
        /// </summary>
        public HTTPServer          HTTPServer
            => httpServer;

        /// <summary>
        /// Who may sign in here, which organizations they belong to and with
        /// which role - and every HTTP resource that goes with that.
        /// </summary>
        public HTTPExtAPI          HTTPExtAPI          { get; }

        /// <summary>
        /// The JSON API of this meter at "/api": what it is measuring, how it
        /// is configured, and the few things about it that can be changed.
        /// </summary>
        public MeterHTTPAPI        API                 { get; }

        /// <summary>
        /// The page a person opens, at "/".
        /// </summary>
        public MeterWebInterface   WebInterface        { get; }

        /// <summary>
        /// Where the accounts are: signing in, users, organizations.
        /// </summary>
        public HTTPPath            AccountsPath        { get; }

        /// <summary>
        /// Where this meter writes what it is doing.
        /// </summary>
        public ILogger             Logger
            => logger;

        /// <summary>
        /// Everything that happens inside this meter: every Modbus request and
        /// what was decided about it, every clock check, every change somebody
        /// made, and whatever Hermod says while doing its part.
        /// </summary>
        public EventLog            Log                 { get; }

        /// <summary>
        /// Where a person points their browser.
        /// </summary>
        public URL                 WebInterfaceURL     { get; }

        /// <summary>
        /// Where everything this meter can be told in writing lives between
        /// starts: its name resolution and its time source.
        /// </summary>
        public MeterConfigFile     ConfigFile          { get; }

        /// <summary>
        /// How this meter resolves names.
        /// </summary>
        public DNSClient           DNSClient
            => dnsClient;

        /// <summary>
        /// The single time client this meter was handed, or made for the first
        /// of the default servers.
        /// </summary>
        /// <remarks>
        /// Not what the clock is checked against - that is
        /// <see cref="TimeSources"/>, the whole group - and not to be named as
        /// if it were. What it still decides is the group this meter asks when
        /// a caller hands it a client of its own: that client's server, alone.
        ///
        /// Replaced rather than reconfigured when it is pointed at another
        /// server: an NTS client is bound to its host at construction, and the
        /// cookies and keys it holds belong to that host and to no other.
        /// </remarks>
        public NTSClient           NTSClient
            => ntsClient;

        /// <summary>
        /// The time servers this meter checks its clock against: which servers,
        /// in which priority bands, and how many of them have to answer.
        /// </summary>
        public TimeSourceGroup     TimeSources
            => timeSources;

        /// <summary>
        /// Whether this meter resolves names at all.
        /// </summary>
        public Boolean             DNSEnabled          { get; private set; } = true;

        /// <summary>
        /// Whether this meter may ask its time server.
        /// </summary>
        public Boolean             NTSEnabled          { get; private set; } = true;

        /// <summary>
        /// The password of the first administrator, made up because there was
        /// no account database yet, or null when the accounts came from disk.
        /// It is shown once and kept nowhere but in its hash.
        /// </summary>
        public String?             GeneratedPassword   { get; private set; }

        /// <summary>
        /// The account of that first administrator, when one was made.
        /// </summary>
        public String?             GeneratedUserId     { get; private set; }

        /// <summary>
        /// Whether <see cref="StartAsync"/> has been called.
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

        /// <summary>
        /// Create a Modbus/TLS energy meter. Nothing listens until
        /// <see cref="StartAsync"/> is called.
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
        /// <param name="HTTPAPIPath">Where the account API is mounted (default: "/accounts").</param>
        /// <param name="MeterAPIPath">Where this meter's own JSON API is mounted (default: "/api").</param>
        /// <param name="Frontend">Where the files of the web interface come from (default: the bundle embedded in this assembly).</param>
        /// <param name="HTTPS">Whether the web interface is served over TLS, with a certificate of its own.</param>
        /// <param name="CertificatesPath">Where the certificate stores live (default: certificates/ below the data path).</param>
        /// <param name="DataPath">Where accounts and their log are written (default: beside the process).</param>
        /// <param name="ConfigFile">Where the name servers and the time server are read from.</param>
        /// <param name="DNSClient">A ready-made DNS client, for tests and for hosts that share one.</param>
        /// <param name="NTSClient">A ready-made time client, likewise.</param>
        /// <param name="Log">Everything that happens inside this meter; a fresh one by default.</param>
        /// <param name="LogKeepDays">How many days of the log are kept on disk; 0 to keep it in memory only.</param>
        /// <param name="LogToConsole">Whether that log is also written to the console.</param>
        /// <param name="ConsoleLogLevel">How much of it reaches the console.</param>
        /// <param name="LoggerFactory">Where Hermod's own parts write; into the event log by default.</param>
        /// <param name="TimeProvider">Where this meter reads the time; the system clock by default.</param>
        public ModbusTLSEnergyMeter(String            SerialNumber,
                                    String            ServerPfxPath,
                                    String?           ServerPfxPassword,
                                    String            ClientCACertPath,
                                    NetIPAddress?     ListenAddress      = null,
                                    Int32?            ListenPort         = null,
                                    TimeSpan?         HandshakeTimeout   = null,
                                    TimeSpan?         IdleTimeout        = null,
                                    TimeSpan?         WriteTimeout       = null,
                                    SunSpecMeterMode? MeterMode          = null,
                                    TimeSpan?         SimulatedDayLength = null,

                                    IIPAddress?       HTTPHostname       = null,
                                    IPPort?           HTTPPort           = null,
                                    HTTPPath?         HTTPAPIPath        = null,
                                    HTTPPath?         MeterAPIPath       = null,
                                    IStaticContentSource? Frontend       = null,
                                    Boolean           HTTPS              = false,
                                    String?           CertificatesPath   = null,
                                    String?           DataPath           = null,

                                    MeterConfigFile?  ConfigFile         = null,
                                    DNSClient?        DNSClient          = null,
                                    NTSClient?        NTSClient          = null,
                                    EventLog?         Log                = null,
                                    Int32?            LogKeepDays        = null,
                                    Boolean           LogToConsole       = true,
                                    MeterLogLevel     ConsoleLogLevel    = MeterLogLevel.Info,
                                    ILoggerFactory?   LoggerFactory      = null,
                                    TimeProvider?     TimeProvider       = null)
        {

            #region The clock, before anything that wants to know the time

            this.TimeProvider      = TimeProvider ?? System.TimeProvider.System;
            this.CreatedAt         = this.TimeProvider.GetUtcNow();
            this.Version           = typeof(ModbusTLSEnergyMeter).Assembly.GetName().Version?.ToString(3) ?? "0.0.0";

            // Before the log, because the log is read back out of it.
            this.DataPath          = Path.GetFullPath(DataPath ?? "data");

            // A log that outlives the process. Switched off by asking for no
            // days at all, which a test does so that it leaves nothing behind.
            this.logStore          = (LogKeepDays ?? LogStore.DefaultKeepDays) > 0
                                         ? new LogStore(
                                               Path.Combine(this.DataPath, LogStore.DefaultDirectoryName),
                                               LogKeepDays
                                           )
                                         : null;

            // The log next, because everything below may want to say something
            // while it is being built - and an entry written before the log
            // exists is one nobody can read afterwards.
            this.Log               = Log ?? new EventLog(
                                                TimeProvider:  this.TimeProvider,
                                                Store:         logStore
                                            );

            this.consoleLog        = LogToConsole
                                         ? new ConsoleLog(this.Log, ConsoleLogLevel)
                                         : null;

            // Hermod's parts speak ILogger and know nothing of an event log, so
            // they are handed one that writes into it. A host that insists on
            // its own factory gets its way, and its own second log with it.
            this.loggerFactory     = LoggerFactory ?? new EventLogLoggerFactory(this.Log);
            this.logger            = this.loggerFactory.CreateLogger<ModbusTLSEnergyMeter>();

            this.Log.Notice($"SunSpec Modbus/TLS energy meter v{this.Version} starting up.", "meter");

            if (logStore?.LastError is String logProblem)
                this.Log.Warning(logProblem, "meter", "log");

            #endregion

            #region What the configuration file says

            this.ConfigFile        = ConfigFile ?? new MeterConfigFile(MeterConfigFile.DefaultFileName);

            MeterConfiguration? configuration = null;

            if (this.ConfigFile.Exists)
            {

                // A file that is there but cannot be read is not something to
                // paper over with defaults: somebody wrote down what their
                // meter is and got it wrong, and quietly running as something
                // else instead would be worse than stopping.
                if (!this.ConfigFile.TryLoad(out configuration, out var configError))
                    throw new InvalidOperationException($"{configError} Repair or remove '{this.ConfigFile.Path}' and start again.");

                logger.LogInformation("configuration from {Path}: {Configuration}", this.ConfigFile.Path, configuration);

            }

            #endregion

            #region The clients everything below shares

            this.dnsClient             = DNSClient ?? new DNSClient();
            this.configuredDNSServers  = [.. dnsClient.DNSServers];

            // The clock goes to the time client too: a meter that reads one
            // clock itself and disciplines another would have two, which is one
            // more than anything reading it can be told the time by.
            this.ntsClient             = NTSClient ?? new NTSClient(
                                                          DomainName.Parse(NTSConfiguration.DefaultHostname),
                                                          Timeout:       TimeSpan.FromSeconds(10),
                                                          DNSClient:     dnsClient,
                                                          TimeProvider:  this.TimeProvider
                                                      );

            // The four this meter asks when nobody says otherwise - but only
            // when nobody handed it a client either. A caller that named its
            // own server means that server, and a group naming four others
            // beside it would be a report about somebody else's clock.
            this.timeEngine            = new MeasurementEngine(
                                             new MonitoringConfig {
                                                 DroneId       = "energyMeter",
                                                 NTPTimeout    = TimeSpan.FromSeconds(5),
                                                 NTSKETimeout  = TimeSpan.FromSeconds(10)
                                             },
                                             this.TimeProvider
                                         );

            this.timeSources           = NTSClient is null
                                             ? NTSConfiguration.DefaultGroup()
                                             : new TimeSourceGroup(
                                                   "legal",
                                                   [ new NTSServerEndpoint(
                                                         this.ntsClient.Hostname,
                                                         this.ntsClient.NTSKE_Port,
                                                         this.ntsClient.NTP_Port
                                                     ) ]
                                               );

            // Last, and that is the whole precedence rule: what this
            // constructor was handed holds until the file says otherwise, and
            // what the file does not mention is left exactly as it was.
            if (configuration?.DNS is not null)
                ApplyDNSConfiguration(configuration.DNS);

            if (configuration?.NTS is not null)
            {

                // Checked here rather than when the file was read: a quorum
                // on its own is about the servers in effect, and which those
                // are is only known now.
                if (!TryCheckNTSQuorum(configuration.NTS, out var quorumError))
                    throw new InvalidOperationException($"'{this.ConfigFile.Path}': {quorumError} Repair or remove '{this.ConfigFile.Path}' and start again.");

                ApplyNTSConfiguration(configuration.NTS);

            }

            #endregion

            #region The Modbus/TLS side

            this.SerialNumber      = SerialNumber;
            this.ListenAddress     = ListenAddress ?? NetIPAddress.Loopback;
            this.ListenPort        = ListenPort    ?? DefaultModbusTLSPort;

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

            this.ClientCA          = X509CertificateLoader.LoadCertificateFromFile(ClientCACertPath);

            #endregion

            #region The certificates, and which of them is shown

            var certificatesPath   = CertificatesPath ?? Path.Combine(this.DataPath, "certificates");

            // Two stores and one trust store, all under one directory. The
            // certificate a charging station checks and the certificate a
            // browser checks are different statements, issued by different
            // people, and are never the same file.
            this.modbusCertificates = new CertificateStore(Path.Combine(certificatesPath, "modbus"), "modbus", this.TimeProvider);
            this.webCertificates    = new CertificateStore(Path.Combine(certificatesPath, "web"),    "web",    this.TimeProvider);
            this.clientTrust        = new ClientTrustStore(Path.Combine(certificatesPath, "trust"),            this.TimeProvider);

            // Beside the certificates rather than among them: these are not
            // certificates, nobody issues them, and they outlive every
            // certificate this meter will ever show.
            this.signingKeys        = new MeterKeyStore   (Path.Combine(this.DataPath, "keys"),                 this.TimeProvider);
            this.sessions           = new ChargingSessions(Path.Combine(this.DataPath, "sessions"),             this.TimeProvider);

            foreach (var problem in new[] { modbusCertificates.LastError, webCertificates.LastError, clientTrust.LastError })
                if (problem is not null)
                    this.Log.Warning(problem, "meter", "certificates");

            // What this meter was started with becomes the first entry, so
            // that there is one place that decides what is shown and a meter
            // started the old way needs nothing done to it.
            modbusCertificates.Adopt(startupCertificate, "the certificate this meter was started with");
            clientTrust.       Adopt(ClientCA, "the CA this meter was started with");

            // The web interface has no such certificate to inherit - and
            // borrowing the device's would be the very conflation these two
            // stores exist to avoid - so it signs one for itself. A browser
            // will say it does not know who signed it, and it is right; a
            // certificate from a CA simply becomes the newer one later.
            if (HTTPS && webCertificates.Current is null)
                // Named so that it cannot be mistaken for the device
                // certificate in a log line: they are two identities, and the
                // whole point of two stores is that nobody conflates them.
                webCertificates.CreateSelfSigned(
                    $"CN={SerialNumber} web interface",
                    ["localhost", $"{SerialNumber}.local"],
                    ["127.0.0.1", "::1"],
                    "made by this meter at the first start"
                );

            this.HTTPSEnabled       = HTTPS;

            // this.Log rather than Log: this constructor has a parameter of
            // that name, and a lambda written here would capture the parameter
            // - which is null unless a host passed its own log in.
            modbusCertificates.OnCurrentChanged += (before, after) =>
                this.Log.Notice(
                    after is not null
                        ? $"Modbus/TLS clients are now shown '{after.Certificate?.Subject}', valid until {after.Certificate?.NotAfter:yyyy-MM-dd}."
                        : "There is no valid certificate left to show Modbus/TLS clients: every handshake will fail.",
                    "certificates", "modbus"
                );

            webCertificates.OnCurrentChanged += (before, after) =>
                this.Log.Notice(
                    after is not null
                        ? $"The web interface is now shown as '{after.Certificate?.Subject}', valid until {after.Certificate?.NotAfter:yyyy-MM-dd}."
                        : "There is no valid certificate left for the web interface.",
                    "certificates", "web"
                );

            clientTrust.OnChanged += what => this.Log.Notice(what, "certificates", "trust");

            this.device            = new SunSpecMeterDevice(
                                         SerialNumber,
                                         MeterMode ?? SunSpecMeterMode.Net,
                                         SimulatedDayLength
                                     );

            // What kind of meter this is can be changed through either door -
            // a Modbus client writing register 40094, or a person on the web
            // page - so it is written down where both of them end up rather
            // than at either of them.
            this.device.OnModeChanged += (before, after) =>
                this.Log.Notice(
                    $"The meter is now {after.Description()}, and was {before.Description()}.",
                    "meter",
                    "simulation"
                );

            this.frontend          = new ModbusTlsFrontend(
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

            // Every request, allowed or refused, into the event log. Subscribed
            // here rather than where the frontend answers, so that a host which
            // never looks at the log still pays for nothing but a null check.
            this.frontend.OnModbusRequest += RecordModbusRequest;

            #endregion

            #region The web side

            var httpAddress    = HTTPHostname ?? IPv4Address.Localhost;
            var httpPort       = HTTPPort     ?? DefaultHTTPPort;

            this.httpServer    = new HTTPServer(
                                     IPAddress:       httpAddress,
                                     TCPPort:         httpPort,
                                     HTTPServerName:  $"OpenChargingCloud ModbusTLSEnergyMeter v{Version}",

                                     // The same rule as the Modbus side, from
                                     // the other store: the newest certificate
                                     // that is valid now, asked for per
                                     // connection rather than frozen at start.
                                     ServerCertificateSelector:  HTTPS
                                                                     ? (tcpServer, tcpClient) => webCertificates.Current?.Certificate
                                                                                                     ?? throw new InvalidOperationException("This meter has no valid web certificate to show.")
                                                                     : null,

                                     DNSClient:       dnsClient,
                                     LoggerFactory:   loggerFactory
                                 );

            // And the intermediates with it. Hermod asks this one first and
            // falls back to the selector above, so a chain is sent whenever
            // there is one to send - which is what a browser needs to build a
            // path from this certificate to something it trusts.
            if (HTTPS)
                this.httpServer.ServerCertificateChainSelector = (tcpServer, tcpClient) => webCertificates.ChainFor(null);

            // Below a path of its own rather than at the root, because the
            // root is where the page lives. Hermod dispatches to the most
            // specific HTTPAPI first, so each of the three answers for itself.
            this.AccountsPath  = HTTPAPIPath ?? HTTPPath.Parse("/accounts");

            this.HTTPExtAPI    = new HTTPExtAPI(
                                     httpServer,
                                     RootPath:              AccountsPath,
                                     Description:           I18NString.Create($"SunSpec Modbus/TLS energy meter {SerialNumber}"),
                                     HTTPServerName:        $"OpenChargingCloud ModbusTLSEnergyMeter v{Version}",
                                     DisableNotifications:  true,
                                     LoggingPath:           this.DataPath,

                                     // The cookie has to reach the page at "/"
                                     // and the API at "/api", not only the
                                     // accounts it was set by.
                                     HTTPCookiePath:        "/",

                                     // A Secure cookie is only sent back over
                                     // TLS, so it is a login that silently never
                                     // sticks on a meter served over plain HTTP -
                                     // which is what a bench and a reverse proxy
                                     // in front both look like from here.
                                     UseSecureCookies:      HTTPS,

                                     LoggerFactory:         loggerFactory
                                 );

            this.WebInterfaceURL  = URL.Parse($"{(HTTPS ? "https" : "http")}://{httpAddress}:{httpPort}/");

            // Below the account API rather than beside it: Hermod dispatches to
            // the most specific HTTPAPI first, so an unknown /api path answers
            // with this API's JSON 404 instead of falling through to the
            // accounts at "/".
            this.API              = new MeterHTTPAPI(
                                        this,
                                        HTTPExtAPI,
                                        MeterAPIPath,
                                        logger
                                    );

            // Last, and at the root: it answers for every path the two APIs
            // above did not claim, which is what lets a reload on a deep link
            // work.
            this.WebInterface     = new MeterWebInterface(
                                        httpServer,
                                        Version,
                                        Frontend
                                    );

            // A meter whose web interface did not get built still starts, still
            // serves Modbus and still answers its JSON API. Said once, here,
            // rather than left for somebody to work out from a blank browser.
            if (!this.WebInterface.IsAvailable)
                this.Log.Error(
                    $"No web interface to serve ({this.WebInterface.Frontend.Description}): the JSON API answers, " +
                     "the browser gets nothing. Build it with 'npm run build' in the Frontend directory.",
                    "web"
                );

            #endregion

        }

        #endregion


        #region StartAsync()

        /// <summary>
        /// Load the accounts, begin serving the web interface, and begin
        /// listening for Modbus/TLS.
        /// </summary>
        /// <remarks>
        /// TcpListener.Start() happens before the first await inside the
        /// frontend's RunAsync(), so a Modbus port that could not be bound has
        /// already failed by the time that task comes back - and is rethrown
        /// here, where the caller is, instead of surfacing much later out of a
        /// task nobody looked at.
        /// </remarks>
        public async Task StartAsync()
        {

            if (started)
                throw new InvalidOperationException("This Modbus/TLS energy meter is already running!");

            started = true;

            await HTTPExtAPI.LoadDatabase();

            await EnsureFirstAdministratorAsync();

            await httpServer.Start();

            logger.LogInformation("web interface on {URL}", WebInterfaceURL);

            StartCheckingTheClock();

            StartWatchingTheCertificates();
            AnnounceTheSigningKeys();

            // Before the first reading is taken and before any session is
            // resumed: both of those are about where this meter stands, and it
            // does not stand at zero just because the process is new.
            RestoreTheEnergyCounters();
            StartSavingTheEnergyCounters();

            ResumeTheChargingSession();

            runTask = frontend.RunAsync(cts.Token);

            if (runTask.IsFaulted)
            {
                started = false;
                ExceptionDispatchInfo.Capture(runTask.Exception!.GetBaseException()).Throw();
            }

        }

        #endregion

        #region StopAsync(Timeout = null)

        /// <summary>
        /// Stop listening and let the connections still open finish.
        /// </summary>
        /// <param name="Timeout">How long to wait for that (default: 5 seconds).</param>
        public async Task StopAsync(TimeSpan? Timeout = null)
        {

            if (!started)
                return;

            timeCheckTimer?.Dispose();
            timeCheckTimer = null;

            certificateTimer?.Dispose();
            certificateTimer = null;

            stateTimer?.Dispose();
            stateTimer = null;

            // Once more on the way out, so an orderly stop loses nothing at all.
            SaveTheEnergyCounters();

            await cts.CancelAsync();

            if (runTask is not null)
            {
                try
                {
                    await runTask.WaitAsync(Timeout ?? TimeSpan.FromSeconds(5));
                }
                catch (TimeoutException)            { }
                catch (OperationCanceledException)  { }
            }

            // Before the server: an SSE response never completes by itself,
            // so a browser with the page still open would otherwise hold the
            // shutdown for as long as it stayed open.
            API.CloseEventStreams();

            try
            {
                await httpServer.Stop();
            }
            catch (Exception e)
            {
                logger.LogWarning(e, "the web interface did not stop cleanly");
            }

            started = false;

        }

        #endregion

        #region ShareConsoleWith(WriteBlock)

        /// <summary>
        /// Let somebody else decide when this meter's log may write on the
        /// console, because they are writing on it too.
        /// </summary>
        /// <remarks>
        /// A meter at a console assumes the console is its own and writes an
        /// entry whenever one happens, from whichever thread it happened on.
        /// That assumption stops holding the moment somebody is typing a command
        /// on the same screen: an entry arriving mid-word puts half a log line
        /// into the middle of a half-typed command and ruins both.
        ///
        /// So the writing is handed over rather than suppressed. Whoever owns
        /// the line takes the entry, clears what is being typed, writes the
        /// entry as one piece and puts the line back. Nothing is lost and
        /// nothing is delayed, which is what makes this better than the obvious
        /// alternative of going quiet while a command line is open.
        ///
        /// Has no effect on a meter whose log does not reach the console.
        /// </remarks>
        /// <param name="WriteBlock">Runs what it is given with the console to itself.</param>
        public void ShareConsoleWith(Action<Action> WriteBlock)
        {

            if (consoleLog is not null)
                consoleLog.WriteBlock = WriteBlock;

        }

        #endregion

        #region DisposeAsync()

        public async ValueTask DisposeAsync()
        {

            GC.SuppressFinalize(this);

            await StopAsync();

            frontend.OnModbusRequest -= RecordModbusRequest;

            frontend.          Dispose();
            device.            Dispose();
            consoleLog?.       Dispose();
            logStore?.         Dispose();
            startupCertificate.Dispose();
            ClientCA.          Dispose();
            cts.               Dispose();

        }

        #endregion

    }

}
