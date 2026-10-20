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

using System.Buffers.Binary;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.chargy;
using cloud.charging.open.chargy.Formats.OCMF;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;
using cloud.charging.open.EnergyMeters.ModbusTLS.Upstream;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// A meter in front of another meter: everything a client asks passed on to
    /// the meter behind it, over Modbus/TCP or Modbus/TLS, the session model
    /// behind that meter's models, and the sessions signed with what that meter
    /// counted.
    /// </summary>
    [TestFixture]
    public class UpstreamTests
    {

        #region Data

        private String              pki         = default!;
        private String?             directory;
        private SunSpecMeterDevice? behind;

        #endregion

        #region OneTimeSetUp / SetUp / TearDown

        [OneTimeSetUp]
        public async Task MakeTheKeyInfrastructure()
        {
            pki = Path.Combine(Path.GetTempPath(), $"meter-upstream-pki-{Guid.NewGuid().ToString("N")[..12]}");
            await new ModbusPKI().BuildPKI(pki);
        }

        [OneTimeTearDown]
        public void RemoveTheKeyInfrastructure()
        {
            TestAuthorities.RemoveInstalled(pki);
            try { Directory.Delete(pki, true); } catch { }
        }

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(directory);

            // The meter behind: not simulated, so that it stands where a test
            // puts it.
            behind = new SunSpecMeterDevice("meter-behind-01", SunSpecMeterMode.ImportOnly, runSimulation: false);
            Assert.That(behind.RestoreEnergyCounters(50000, 0, 0), Is.True);

        }

        [TearDown]
        public void TearDown()
        {

            behind?.Dispose();

            if (directory is not null && Directory.Exists(directory))
            {
                try { Directory.Delete(directory, recursive: true); }
                catch { /* a file still held is not what is under test */ }
            }

        }

        #endregion


        #region Over Modbus/TCP

        /// <summary>
        /// A client of the meter in front walks the models of the meter behind
        /// it - its common model says it is that meter - and finds the session
        /// model behind them.
        /// </summary>
        [Test]
        public async Task OverModbusTCP_TheMeterBehindIsReadThroughAndTheSessionModelSitsBehindItsModels()
        {

            await using var server = await PlainServer.Serving(new SunSpecBackendFactory(behind!));
            await using var meter  = await Gateway(new JObject(new JProperty("host", "127.0.0.1"), new JProperty("port", server.Port)));

            using var client = await TLSClient.Open(meter.ListenPort, pki, SunSpecRoles.ReadOnly);

            var chain  = await SunSpecChain.Walk(client.Read);
            var who    = await chain.Common(client.Read);

            Assert.Multiple(() => {
                Assert.That(chain.Models.Select(model => model.Id),  Is.EqualTo(new UInt16[] { 1, 213, SessionModel.Id }));
                Assert.That(who?.SerialNumber,                       Is.EqualTo("meter-behind-01"), "it is not the meter behind that answers");
                Assert.That(meter.Backends.Upstream?.State,          Is.EqualTo("connected"));
            });

        }

        /// <summary>
        /// A session begun and ended through the meter in front is signed with
        /// what the meter behind counted, and names it as the meter.
        /// </summary>
        [Test]
        public async Task ASessionThroughTheMeterInFrontIsSignedWithWhatTheMeterBehindCounted()
        {

            await using var server = await PlainServer.Serving(new SunSpecBackendFactory(behind!));
            await using var meter  = await Gateway(new JObject(new JProperty("host", "127.0.0.1"), new JProperty("port", server.Port)));

            await meter.Backends.Locate();

            var command = (UInt16) (meter.SessionModelFactory!.ModelAddress + 2 + SessionModel.Command);

            using (var station = await TLSClient.Open(meter.ListenPort, pki, SunSpecRoles.GridService))
                Assert.That(await station.Write(command, new[] { (UInt16) SessionCommand.Start }), Is.Null, "a station's role may not begin a session through it");

            Assert.That(behind!.RestoreEnergyCounters(62500, 0, 0), Is.True);

            using (var station = await TLSClient.Open(meter.ListenPort, pki, SunSpecRoles.GridService))
                Assert.That(await station.Write(command, new[] { (UInt16) SessionCommand.Stop }), Is.Null);

            var signed  = meter.Sessions.Last!;
            var payload = new OCMFDocumentScanner().Scan([ signed.Document ]).Documents.Single().Payload;

            Assert.Multiple(() => {

                Assert.That(Verify(signed.Document, signed.PublicKey),                             Is.EqualTo(VerificationResult.ValidSignature));
                Assert.That(payload["RD"]!.Select(reading => reading["RV"]!.Value<Decimal>()),     Is.EqualTo(new[] { 50m, 62.5m }));
                Assert.That(payload["MS"]?.Value<String>(),                                        Is.EqualTo("meter-behind-01"), "the meter that measured is not named");
                Assert.That(payload["GS"]?.Value<String>(),                                        Is.EqualTo("meter-in-front"),  "the gateway that signed is not named");

            });

        }

        /// <summary>
        /// A meter behind that cannot be reached is answered as a gateway
        /// answers it, and said to be unreachable.
        /// </summary>
        [Test]
        public async Task AMeterBehindThatCannotBeReachedIsAnsweredAsAGatewayAnswersIt()
        {

            await using var meter  = await Gateway(new JObject(new JProperty("host", "127.0.0.1"), new JProperty("port", TestPorts.Free())));

            using var client = await TLSClient.Open(meter.ListenPort, pki, SunSpecRoles.ReadOnly);

            await Assert.MultipleAsync(async () => {
                Assert.That(await client.TryRead(40000, 2),                     Is.EqualTo(ModbusExceptionCode.GatewayPathUnavailable));
                Assert.That(meter.UpstreamJSON()["state"]!.Value<String>("state"), Is.EqualTo("unreachable"));
                Assert.That(meter.UpstreamJSON()["state"]!.Value<String>("error"), Does.Contain("cannot be reached"));
            });

        }

        /// <summary>
        /// A meter behind that cannot be reached is answered 0x0A where the
        /// connection fails, and again without dialling while it was tried a
        /// moment ago.
        /// </summary>
        [Test]
        public async Task AMeterBehindThatCannotBeReachedIsDialledOnlyEverySoOften()
        {

            var said     = new List<String>();
            var upstream = new UpstreamDevice(new UpstreamConfiguration("127.0.0.1", (UInt16) TestPorts.Free(), 1, false),
                                              () => (null, null),
                                              (_, _, _) => new UpstreamJudgement(false, "refused", null),
                                              Said: (news, _) => said.Add(news)) {
                               RetryAfter = TimeSpan.FromMinutes(1)
                           };

            var read   = ModbusPDU.BuildReadHoldingRegisters(40000, 2);
            var first  = await upstream.ProcessRequestAsync(1, read, default);
            var second = await upstream.ProcessRequestAsync(1, read, default);

            Assert.Multiple(() => {
                Assert.That(ModbusPDU.TryGetException(first),   Is.EqualTo(ModbusExceptionCode.GatewayPathUnavailable), "where the connection failed");
                Assert.That(ModbusPDU.TryGetException(second),  Is.EqualTo(ModbusExceptionCode.GatewayPathUnavailable), "while it was tried a moment ago");
                Assert.That(said,                               Has.Count.EqualTo(1), "it was dialled, or said, twice");
                Assert.That(upstream.State,                     Is.EqualTo("unreachable"));
            });

        }

        #endregion

        #region Over Modbus/TLS

        /// <summary>
        /// Over Modbus/TLS the meter behind is shown an identity of the store,
        /// believed by a root of the store for "upstream", and the certificate
        /// it showed learned the first time.
        /// </summary>
        [Test]
        public async Task OverModbusTLS_TheMeterBehindIsBelievedByItsRootAndItsCertificateLearnedTheFirstTime()
        {

            await using var server = await TLSServer.Serving(pki, new SunSpecBackendFactory(behind!), behind!);
            await using var meter  = await Gateway(null);

            var identity = ImportIdentity(meter, SunSpecRoles.ReadOnly);
            ImportRoot(meter);

            var (success, error, _) = await meter.UpdateUpstream(new JObject(
                                          new JProperty("host",             "127.0.0.1"),
                                          new JProperty("port",             server.Port),
                                          new JProperty("tls",              true),
                                          new JProperty("identity",         identity),
                                          new JProperty("trustOnFirstUse",  "certificate")
                                      ));

            Assert.That(success, Is.True, error);

            var who = await (await SunSpecChain.Walk(meter.Backends.Read)).Common(meter.Backends.Read);

            var file = JObject.Parse(File.ReadAllText(Path.Combine(directory!, "configuration.json")))[UpstreamConfiguration.SectionName];

            Assert.Multiple(() => {
                Assert.That(who?.SerialNumber,                    Is.EqualTo("meter-behind-01"));
                Assert.That(meter.Backends.Upstream?.State,       Is.EqualTo("connected"));
                Assert.That(meter.UpstreamJSON()["state"]!["identity"]!.Value<String>("role"), Is.EqualTo(SunSpecRoles.ReadOnly));
                Assert.That(file?["certificateFingerprint"]?.Value<String>(),
                            Is.EqualTo(CertificateEntry.ThumbprintOf(X509CertificateLoader.LoadCertificateFromFile(Path.Combine(pki, "server.crt")))),
                            "the certificate it showed was not learned into the file");
            });

        }

        /// <summary>
        /// A meter behind that shows another certificate than the one it is
        /// held to is not believed, and nothing is passed on to it.
        /// </summary>
        [Test]
        public async Task OverModbusTLS_AMeterBehindHeldToAnotherCertificateIsNotBelieved()
        {

            await using var server = await TLSServer.Serving(pki, new SunSpecBackendFactory(behind!), behind!);
            await using var meter  = await Gateway(null);

            var identity = ImportIdentity(meter, SunSpecRoles.ReadOnly);
            ImportRoot(meter);

            var (success, error, _) = await meter.UpdateUpstream(new JObject(
                                          new JProperty("host",                    "127.0.0.1"),
                                          new JProperty("port",                    server.Port),
                                          new JProperty("tls",                     true),
                                          new JProperty("identity",                identity),
                                          new JProperty("certificateFingerprint",  new String('a', 64))
                                      ));

            Assert.That(success, Is.True, error);

            await Assert.MultipleAsync(async () => {
                Assert.That(async () => await meter.Backends.Read(40000, 2),
                            Throws.TypeOf<ModbusException>().With.Property("Code").EqualTo(ModbusExceptionCode.GatewayPathUnavailable));
                Assert.That(meter.Backends.Upstream?.State,                        Is.EqualTo("untrusted"));
                Assert.That(meter.UpstreamJSON()["state"]!.Value<String>("error"), Does.Contain(new String('a', 64)));
            });

        }

        #endregion

        #region The page's door

        /// <summary>
        /// Saved from the page, the meter stands in front of another meter at
        /// once; saved with a blank host, it measures with its simulation again
        /// - and the file says so both times.
        /// </summary>
        [Test]
        public async Task ThePageSetsTheMeterBehindAndTakesItAwayAgain()
        {

            await using var server = await PlainServer.Serving(new SunSpecBackendFactory(behind!));
            await using var meter  = await Gateway(null);

            Assert.That(meter.Backends.Upstream, Is.Null, "a meter told nothing stands in front of something");

            var (success, error, _) = await meter.UpdateUpstream(new JObject(new JProperty("host", "127.0.0.1"), new JProperty("port", server.Port)));
            Assert.That(success, Is.True, error);

            var throughIt = await (await SunSpecChain.Walk(meter.Backends.Read)).Common(meter.Backends.Read);

            (success, error, _) = await meter.UpdateUpstream(new JObject(new JProperty("host", "")));
            Assert.That(success, Is.True, error);

            var itself = await (await SunSpecChain.Walk(meter.Backends.Read)).Common(meter.Backends.Read);

            Assert.Multiple(() => {
                Assert.That(throughIt?.SerialNumber,  Is.EqualTo("meter-behind-01"));
                Assert.That(itself?.SerialNumber,     Is.EqualTo("meter-in-front"));
                Assert.That(meter.Backends.Upstream,  Is.Null);
                Assert.That(JObject.Parse(File.ReadAllText(Path.Combine(directory!, "configuration.json")))[UpstreamConfiguration.SectionName]?.Type,
                            Is.EqualTo(JTokenType.Null), "the file still says it stands in front of a meter");
                Assert.That(meter.Log.Recent(200, Tag: "upstream").Select(entry => entry.Message),
                            Has.Some.Contains("measures with its own simulation now"));
            });

        }

        /// <summary>
        /// What is no meter to stand in front of is refused, and says why.
        /// </summary>
        [Test]
        public void WhatIsNoMeterToStandInFrontOfIsRefusedWithWhy()
        {

            String RefusalOf(params JProperty[] Properties)
            {
                Assert.That(UpstreamConfiguration.TryParse(new JObject(Properties), "upstream", out _, out var error), Is.False, "it was taken");
                return error!;
            }

            Assert.Multiple(() => {

                Assert.That(UpstreamConfiguration.TryParse(new JObject(new JProperty("host", "10.0.0.7")), "upstream", out var plain, out _), Is.True);
                Assert.That(plain,  Is.EqualTo(new UpstreamConfiguration("10.0.0.7", 502, 1, false)), "Modbus/TCP is on 502 by default");

                Assert.That(UpstreamConfiguration.TryParse(new JObject(new JProperty("host", "10.0.0.7"), new JProperty("tls", true)), "upstream", out var tls, out _), Is.True);
                Assert.That(tls!.Port,  Is.EqualTo(802), "Modbus/TLS is on 802 by default");

                Assert.That(RefusalOf(new JProperty("host", "http://meter/")),                                     Does.Contain("no host"));
                Assert.That(RefusalOf(new JProperty("host", "meter"), new JProperty("port", 0)),                   Does.Contain("'upstream.port'"));
                Assert.That(RefusalOf(new JProperty("host", "meter"), new JProperty("tls", "yes")),                Does.Contain("'upstream.tls'"));
                Assert.That(RefusalOf(new JProperty("host", "meter"), new JProperty("identity", "aaaabbbbccccdddd")),
                            Does.Contain("only Modbus/TLS has"));
                Assert.That(RefusalOf(new JProperty("host", "meter"), new JProperty("certificateFingerprint", new String('b', 64))),
                            Does.Contain("only Modbus/TLS has"));

            });

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// A meter in front, its configuration file saying what it stands in
        /// front of - or nothing.
        /// </summary>
        private async Task<ModbusTLSEnergyMeter> Gateway(JObject? Upstream)
        {

            var configuration = Path.Combine(directory!, "configuration.json");

            var json = new JObject(new JProperty("nts", new JObject(new JProperty("enabled", false))));

            if (Upstream is not null)
                json[UpstreamConfiguration.SectionName] = Upstream;

            File.WriteAllText(configuration, json.ToString());

            var (serverPfx, serverPfxPassword) = ServerIdentity();

            return await TestPorts.StartedOnFreshPorts(() => new ModbusTLSEnergyMeter(
                       SerialNumber:       "meter-in-front",
                       ServerPfxPath:      serverPfx,
                       ServerPfxPassword:  serverPfxPassword,
                       ClientCACertPath:   Path.Combine(pki, "issuing-clients-ca.crt"),
                       ListenAddress:      NetIPAddress.Loopback,
                       ListenPort:         TestPorts.Free(),
                       HTTPHostname:       IPv4Address.Localhost,
                       HTTPPort:           IPPort.Parse(TestPorts.Free()),
                       DataPath:           Path.Combine(directory!, "data"),
                       ConfigFile:         new WWCPConfigFile(configuration),
                       LogToConsole:       false
                   ));

        }

        /// <summary>
        /// The PKI's server certificate, with its key and its chain, under a
        /// password of this test's own.
        /// </summary>
        private (String Path, String Password) ServerIdentity()
        {

            using var leaf = X509Certificate2.CreateFromPemFile(System.IO.Path.Combine(pki, "server.crt"), System.IO.Path.Combine(pki, "server.key"));

            var chain = new X509Certificate2Collection();
            chain.ImportFromPemFile(System.IO.Path.Combine(pki, "server.chain.crt"));

            var bag = new X509Certificate2Collection { leaf };

            foreach (var certificate in chain)
                if (certificate.Thumbprint != leaf.Thumbprint)
                    bag.Add(certificate);

            var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
            var path     = System.IO.Path.Combine(directory!, "meter.pfx");

            File.WriteAllBytes(path, bag.Export(X509ContentType.Pkcs12, password)!);

            return (path, password);

        }

        /// <summary>
        /// A client certificate of the PKI, imported into the meter's store as
        /// a TLS identity - and its id there.
        /// </summary>
        private String ImportIdentity(ModbusTLSEnergyMeter Meter, String Role)
        {

            using var leaf  = X509Certificate2.CreateFromPemFile(Path.Combine(pki, $"client-{Role}.crt"), Path.Combine(pki, $"client-{Role}.key"));

            var chain = new X509Certificate2Collection();
            chain.ImportFromPemFile(Path.Combine(pki, $"client-{Role}.chain.crt"));

            var bag = new X509Certificate2Collection { leaf };

            foreach (var certificate in chain)
                if (certificate.Thumbprint != leaf.Thumbprint)
                    bag.Add(certificate);

            Assert.That(Meter.Certificates.Import(bag.Export(X509ContentType.Pkcs12)!, CertificateKind.TLSIdentity, null, $"upstream {Role}", out var entry, out var error),
                        Is.True, error);

            return entry!.Id;

        }

        /// <summary>
        /// The root of the PKI, as a TLS root for the meter behind.
        /// </summary>
        private void ImportRoot(ModbusTLSEnergyMeter Meter)

            => Assert.That(Meter.Certificates.Import(File.ReadAllBytes(Path.Combine(pki, "ca.crt")), CertificateKind.TLSRoot, null, "the root of the meter behind",
                                                     [ UpstreamConfiguration.Usage ], out _, out var error),
                           Is.True, error);

        private static VerificationResult Verify(String Document, String PublicKey)
        {
            var scanned = new OCMFDocumentScanner().Scan([ Document ]);
            return new OCMFSignatureValidator(I18NDictionary.Default()).Validate(scanned.Documents[0], PublicKey, "hex");
        }


        /// <summary>
        /// A meter behind over plain Modbus/TCP: a listener on a port of its
        /// own, answering every frame with what its backend answers.
        /// </summary>
        private sealed class PlainServer : IAsyncDisposable
        {

            private readonly TcpListener              listener;
            private readonly CancellationTokenSource  stopping = new ();
            private readonly Task                     serving;

            public Int32 Port { get; }

            private PlainServer(TcpListener Listener, IModbusBackendFactory Backend)
            {
                listener = Listener;
                Port     = ((IPEndPoint) Listener.LocalEndpoint).Port;
                serving  = Serve(Backend);
            }

            public static Task<PlainServer> Serving(IModbusBackendFactory Backend)
            {
                var listener = new TcpListener(NetIPAddress.Loopback, 0);
                listener.Start();
                return Task.FromResult(new PlainServer(listener, Backend));
            }

            private async Task Serve(IModbusBackendFactory Backend)
            {
                while (!stopping.IsCancellationRequested)
                {
                    TcpClient client;
                    try { client = await listener.AcceptTcpClientAsync(stopping.Token); }
                    catch { return; }
                    _ = Task.Run(async () => {
                        using (client)
                        {
                            var stream  = client.GetStream();
                            var backend = await Backend.CreateAsync(0, null, stopping.Token);
                            try
                            {
                                while (!stopping.IsCancellationRequested)
                                {
                                    var request = await ModbusFrame.ReadAsync(stream, stopping.Token);
                                    var answer  = await backend.ProcessRequestAsync(request.UnitId, request.Pdu, stopping.Token);
                                    await stream.WriteAsync(new ModbusFrame(request.TransactionId, request.UnitId, answer).ToBytes(), stopping.Token);
                                }
                            }
                            catch { }
                        }
                    });
                }
            }

            public async ValueTask DisposeAsync()
            {
                stopping.Cancel();
                listener.Stop();
                try { await serving; } catch { }
            }

        }


        /// <summary>
        /// A meter behind over Modbus/TLS: Hermod's frontend with the PKI's
        /// server certificate, believing the PKI's clients.
        /// </summary>
        private sealed class TLSServer : IAsyncDisposable
        {

            private readonly ModbusTlsFrontend        frontend;
            private readonly CancellationTokenSource  stopping;
            private readonly Task                     running;

            public Int32 Port { get; }

            private TLSServer(ModbusTlsFrontend Frontend, CancellationTokenSource Stopping, Task Running, Int32 Port)
            {
                frontend   = Frontend;
                stopping   = Stopping;
                running    = Running;
                this.Port  = Port;
            }

            public static async Task<TLSServer> Serving(String PKI, IModbusBackendFactory Backend, ISunSpecDevice Device)
            {

                var server   = ServerCertificateChain.Load(Path.Combine(PKI, "server.chain.crt"), Path.Combine(PKI, "server.key"));
                var root     = X509CertificateLoader.LoadCertificateFromFile(Path.Combine(PKI, "ca.crt"));

                var frontend = new ModbusTlsFrontend(
                                   new ModbusTlsFrontendOptions(
                                       NetIPAddress.Loopback, 0,
                                       ServerPfxPath:              null,
                                       ServerPfxPassword:          null,
                                       CaCertPath:                 null,
                                       HandshakeTimeout:           TimeSpan.FromSeconds(5),
                                       IdleTimeout:                TimeSpan.FromMinutes(1),
                                       WriteTimeout:               TimeSpan.FromSeconds(5),
                                       ServerCertificateSelector:  _ => server,
                                       ClientTrustAnchors:         () => [ root ]
                                   ),
                                   Backend,
                                   new AuthorizationPolicy(Device)
                               );

                var stopping = new CancellationTokenSource();
                var running  = Task.Run(() => frontend.RunAsync(stopping.Token));
                var bound    = await frontend.BoundEndPoint;

                return new TLSServer(frontend, stopping, running, bound.Port);

            }

            public async ValueTask DisposeAsync()
            {
                stopping.Cancel();
                try { await running; } catch { }
                frontend.Dispose();
                stopping.Dispose();
            }

        }


        /// <summary>
        /// A Modbus/TLS client of the meter in front, with the client
        /// certificate of a role.
        /// </summary>
        private sealed class TLSClient : IDisposable
        {

            private readonly TcpClient  tcp;
            private readonly SslStream  tls;
            private UInt16              transaction;

            private TLSClient(TcpClient TCP, SslStream TLS)
            {
                tcp = TCP;
                tls = TLS;
            }

            public static async Task<TLSClient> Open(Int32 Port, String PKI, String Role)
            {

                using var pem   = X509Certificate2.CreateFromPemFile(Path.Combine(PKI, $"client-{Role}.crt"), Path.Combine(PKI, $"client-{Role}.key"));

                // A key read from PEM is ephemeral, and Windows' TLS will not
                // sign a handshake with one.
                var leaf  = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet);

                var chain = new X509Certificate2Collection();
                chain.ImportFromPemFile(Path.Combine(PKI, $"client-{Role}.chain.crt"));

                var tcp   = new TcpClient();
                await tcp.ConnectAsync(NetIPAddress.Loopback, Port);

                var tls   = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);

                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                          TargetHost                      = "localhost",
                          EnabledSslProtocols             = SslProtocols.Tls12 | SslProtocols.Tls13,
                          ClientCertificateContext        = SslStreamCertificateContext.Create(leaf, chain, offline: true),
                          CertificateRevocationCheckMode  = X509RevocationMode.NoCheck
                      });

                return new TLSClient(tcp, tls);

            }

            private async Task<Byte[]> Ask(Byte[] PDU)
            {
                await tls.WriteAsync(new ModbusFrame(++transaction, 1, PDU).ToBytes());
                return (await ModbusFrame.ReadAsync(tls, CancellationToken.None)).Pdu;
            }

            public async Task<UInt16[]> Read(UInt16 First, UInt16 Count)
            {
                var answer = await Ask(ModbusPDU.BuildReadHoldingRegisters(First, Count));
                if (ModbusPDU.TryGetException(answer) is ModbusExceptionCode code)
                    throw new ModbusException(code);
                return ModbusPDU.DecodeReadResponse(answer);
            }

            public async Task<ModbusExceptionCode?> TryRead(UInt16 First, UInt16 Count)
                => ModbusPDU.TryGetException(await Ask(ModbusPDU.BuildReadHoldingRegisters(First, Count)));

            public async Task<ModbusExceptionCode?> Write(UInt16 First, UInt16[] Values)
                => ModbusPDU.TryGetException(await Ask(ModbusPDU.BuildWriteMultipleRegisters(First, Values)));

            public void Dispose()
            {
                tls.Dispose();
                tcp.Dispose();
            }

        }

        #endregion

    }

}
