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

using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

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
    /// A meter in front of one meter over Modbus/TLS, and then in front of
    /// another at the same name: the second is shown this meter's certificate
    /// as the first was, and not a TLS session resumed from the first, which
    /// carries none.
    /// </summary>
    /// <remarks>
    /// Two meters behind in one process with one certificate, as two meters of
    /// one installer's PKI behind one name are: on Linux a session for a name
    /// is offered to every server of that name whose tickets can read it, and a
    /// resumed handshake shows no client certificate - the meter behind sees a
    /// peer without a role and hangs up. Windows does not resume like this, so
    /// this is red only where it was wrong.
    /// </remarks>
    [TestFixture]
    public class UpstreamSessionResumptionTests
    {

        #region Data

        private String  pki        = default!;
        private String? directory;

        #endregion

        #region OneTimeSetUp / SetUp / TearDown

        [OneTimeSetUp]
        public async Task MakeTheKeyInfrastructure()
        {
            pki = Path.Combine(Path.GetTempPath(), $"meter-resumption-pki-{Guid.NewGuid().ToString("N")[..12]}");
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
        }

        [TearDown]
        public void TearDown()
        {
            if (directory is not null && Directory.Exists(directory))
            {
                try { Directory.Delete(directory, recursive: true); }
                catch { /* a file still held is not what is under test */ }
            }
        }

        #endregion


        [Test]
        public async Task TheSecondMeterBehindAtTheSameNameIsShownTheCertificateAndNotAResumedSession()
        {

            using var first  = new SunSpecMeterDevice("meter-behind-01", SunSpecMeterMode.ImportOnly, runSimulation: false);
            using var second = new SunSpecMeterDevice("meter-behind-02", SunSpecMeterMode.ImportOnly, runSimulation: false);

            await using var serverOfFirst  = await TLSServer.Serving(pki, first);
            await using var serverOfSecond = await TLSServer.Serving(pki, second);
            await using var meter          = await Gateway();

            var identity = ImportIdentity(meter, SunSpecRoles.ReadOnly);
            ImportRoot(meter);

            async Task<String?> SerialBehind(Int32 Port)
            {

                var (success, error, _) = await meter.UpdateUpstream(new JObject(
                                              new JProperty("host",      "localhost"),
                                              new JProperty("port",      Port),
                                              new JProperty("tls",       true),
                                              new JProperty("identity",  identity)
                                          ));

                Assert.That(success, Is.True, error);

                try
                {
                    return (await (await SunSpecChain.Walk(meter.Backends.Read)).Common(meter.Backends.Read))?.SerialNumber;
                }
                catch (Exception e)
                {
                    return $"{e.GetType().Name}: {e.Message} - {meter.Backends.Upstream?.StatusJSON()}";
                }

            }

            await Assert.MultipleAsync(async () => {
                Assert.That(await SerialBehind(serverOfFirst.Port),   Is.EqualTo("meter-behind-01"));
                Assert.That(await SerialBehind(serverOfSecond.Port),  Is.EqualTo("meter-behind-02"), "the second meter behind was not read");
            });

        }


        #region (private) Helpers

        private async Task<ModbusTLSEnergyMeter> Gateway()
        {

            var configuration = Path.Combine(directory!, "configuration.json");

            File.WriteAllText(configuration,
                              new JObject(
                                  new JProperty("nts", new JObject(
                                      new JProperty("groups", new JObject(
                                          new JProperty("legal", new JObject(
                                              new JProperty("enabled", false)
                                          ))
                                      ))
                                  ))
                              ).ToString());

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

            using var leaf = X509Certificate2.CreateFromPemFile(Path.Combine(pki, "server.crt"), Path.Combine(pki, "server.key"));

            var chain = new X509Certificate2Collection();
            chain.ImportFromPemFile(Path.Combine(pki, "server.chain.crt"));

            var bag = new X509Certificate2Collection { leaf };

            foreach (var certificate in chain)
                if (certificate.Thumbprint != leaf.Thumbprint)
                    bag.Add(certificate);

            var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
            var path     = Path.Combine(directory!, "meter.pfx");

            File.WriteAllBytes(path, bag.Export(X509ContentType.Pkcs12, password)!);

            return (path, password);

        }

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

        private void ImportRoot(ModbusTLSEnergyMeter Meter)

            => Assert.That(Meter.Certificates.Import(File.ReadAllBytes(Path.Combine(pki, "ca.crt")), CertificateKind.TLSRoot, null, "the root of the meters behind",
                                                     [ UpstreamConfiguration.Usage ], out _, out var error),
                           Is.True, error);


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

            public static async Task<TLSServer> Serving(String PKI, SunSpecMeterDevice Device)
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
                                   new SunSpecBackendFactory(Device),
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

        #endregion

    }

}
