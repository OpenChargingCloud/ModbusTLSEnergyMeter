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
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;
using cloud.charging.open.EnergyMeters.ModbusTLS.Logging;

using HermodModbusTCPClient = org.GraphDefined.Vanaheimr.Hermod.Modbus.ModbusTCPClient;
using NetIPAddress          = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What ends up in the event log when somebody talks Modbus to this meter.
    /// </summary>
    /// <remarks>
    /// Both outcomes, and the refused one above all: a meter that records only
    /// what it permitted cannot afterwards answer who was turned away, how
    /// often, or with which certificate - and that is the question an audit
    /// log is opened for.
    /// </remarks>
    public class EventLogTests
    {

        #region Data

        private ModbusTLSEnergyMeter?  meter;
        private String?                workingDirectory;
        private String?                pkiDirectory;
        private Int32                  modbusPort;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            workingDirectory = Path.Combine(
                                   Path.GetTempPath(),
                                   "ModbusTLSEnergyMeterTests",
                                   Guid.NewGuid().ToString("N")
                               );

            Directory.CreateDirectory(workingDirectory);

            pkiDirectory = Path.Combine(workingDirectory, "pki");

            await new ModbusPKI().BuildPKI(pkiDirectory);

            modbusPort = FreeTCPPort();

            meter = new ModbusTLSEnergyMeter(
                        SerialNumber:       "meter-log-001",
                        ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                        ServerPfxPassword:  "demo",
                        ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                        ListenAddress:      NetIPAddress.Loopback,
                        ListenPort:         modbusPort,
                        HTTPHostname:       IPv4Address.Localhost,
                        HTTPPort:           IPPort.Parse(FreeTCPPort()),
                        DataPath:           Path.Combine(workingDirectory, "data"),
                        ConfigFile:         new MeterConfigFile(Path.Combine(workingDirectory, "configuration.json")),
                        LogToConsole:       false
                    );

            await meter.StartAsync();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (meter is not null)
                await meter.DisposeAsync();

            meter = null;

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file the meter still holds is not what is under test */ }
            }

        }

        #endregion


        #region AnAllowedRead_IsInTheLog()

        /// <summary>
        /// A read that the policy permits leaves an entry saying what was asked
        /// and by which role.
        /// </summary>
        [Test]
        public async Task AnAllowedRead_IsInTheLog()
        {

            await ReadAsAsync(SunSpecRoles.ReadOnly);

            var entry = Requests().LastOrDefault();

            Assert.That(entry, Is.Not.Null, "the read was not written down at all");

            Assert.Multiple(() => {

                Assert.That(entry!.Tags,                             Does.Contain("modbus").And.Contain("request"));
                Assert.That(entry!.Tags,                             Does.Not.Contain("denied"));
                Assert.That(entry!.Level,                            Is.EqualTo(LogLevel.Info));

                Assert.That(entry!.Data?["role"]?.ToString(),        Is.EqualTo(SunSpecRoles.ReadOnly));
                Assert.That(entry!.Data?["allowed"]?.ToObject<Boolean>(), Is.True);
                Assert.That(entry!.Data?["functionCode"]?.ToString(), Is.EqualTo("0x03"));
                Assert.That(entry!.Data?["address"]?.ToObject<Int32>(),  Is.EqualTo(SunSpecMeterMap.BaseAddress));
                Assert.That(entry!.Data?["exceptionCode"]?.Type,      Is.EqualTo(Newtonsoft.Json.Linq.JTokenType.Null));

            });

        }

        #endregion

        #region ARefusedRead_IsInTheLogToo()

        /// <summary>
        /// A certificate carrying no SunSpec role is refused - and the refusal,
        /// its reason and the Modbus exception that went back are all written
        /// down.
        /// </summary>
        [Test]
        public async Task ARefusedRead_IsInTheLogToo()
        {

            // The read itself fails: the meter answers with a Modbus exception,
            // which this client cannot parse into a register block. That is the
            // refusal arriving, and what the log says about it is the point.
            try   { await ReadAsAsync("NO-ROLE"); }
            catch { }

            var entry = Requests().LastOrDefault();

            Assert.That(entry, Is.Not.Null, "the refusal was not written down at all");

            Assert.Multiple(() => {

                Assert.That(entry!.Tags,                               Does.Contain("denied"));
                Assert.That(entry!.Level,                              Is.EqualTo(LogLevel.Warning));

                Assert.That(entry!.Data?["allowed"]?.ToObject<Boolean>(), Is.False);
                Assert.That(entry!.Data?["role"]?.Type,                Is.EqualTo(Newtonsoft.Json.Linq.JTokenType.Null));
                Assert.That(entry!.Data?["denyReason"]?.ToString(),    Does.Contain("no role"));
                Assert.That(entry!.Data?["exceptionCode"]?.ToString(), Is.EqualTo(ModbusExceptionCode.IllegalFunction.ToString()));
                Assert.That(entry!.Data?["peer"]?.ToString(),          Is.Not.Empty);

            });

        }

        #endregion

        #region TheLogCanBeFilteredDownToTheRefusals()

        /// <summary>
        /// "Show me everything that was refused" is one query, not a search
        /// through everything that was not.
        /// </summary>
        [Test]
        public async Task TheLogCanBeFilteredDownToTheRefusals()
        {

            await ReadAsAsync(SunSpecRoles.ReadOnly);
            try   { await ReadAsAsync("NO-ROLE"); }
            catch { }

            var denied = meter!.Log.Recent(100, Tag: "denied").ToArray();

            Assert.Multiple(() => {
                Assert.That(denied,                             Has.Length.EqualTo(1));
                Assert.That(denied[0].Data?["allowed"]?.ToObject<Boolean>(),  Is.False);
            });

        }

        #endregion


        #region TheLogSurvivesARestart()

        /// <summary>
        /// What was written down before a restart is still there afterwards,
        /// and the numbering carries on rather than beginning again.
        /// </summary>
        /// <remarks>
        /// The numbering is half the test. A browser follows this log by asking
        /// for everything after the last number it saw; a meter that began
        /// again at 1 would hand it entries it would then decide it had already
        /// seen, and two different events would share a number in the file.
        /// </remarks>
        [Test]
        public async Task TheLogSurvivesARestart()
        {

            await ReadAsAsync(SunSpecRoles.ReadOnly);

            var before       = Requests().Last();
            var lastIdBefore = meter!.Log.LastId;

            Assert.That(meter!.Log.Store, Is.Not.Null, "the log was not being written to disk at all");

            // Stopped rather than abandoned: the file has to be closed before
            // another meter reads it back.
            await meter!.DisposeAsync();
            meter = null;

            var restarted = new ModbusTLSEnergyMeter(
                                SerialNumber:       "meter-log-001",
                                ServerPfxPath:      Path.Combine(pkiDirectory!, "server.pfx"),
                                ServerPfxPassword:  "demo",
                                ClientCACertPath:   Path.Combine(pkiDirectory!, "issuing-clients-ca.crt"),
                                ListenAddress:      NetIPAddress.Loopback,
                                ListenPort:         FreeTCPPort(),
                                HTTPHostname:       IPv4Address.Localhost,
                                HTTPPort:           IPPort.Parse(FreeTCPPort()),
                                DataPath:           Path.Combine(workingDirectory!, "data"),
                                ConfigFile:         new MeterConfigFile(Path.Combine(workingDirectory!, "configuration.json")),
                                LogToConsole:       false
                            );

            meter = restarted;

            var after = restarted.Log.Recent(200, Tag: "request").LastOrDefault();

            Assert.Multiple(() => {

                Assert.That(after,                                  Is.Not.Null, "the request was gone after the restart");
                Assert.That(after!.Id,                              Is.EqualTo(before.Id));
                Assert.That(after!.Message,                         Is.EqualTo(before.Message));
                Assert.That(after!.Tags,                            Is.EquivalentTo(before.Tags));
                Assert.That(after!.Data?["role"]?.ToString(),       Is.EqualTo(SunSpecRoles.ReadOnly),
                            "the data attached to the entry did not survive");

                Assert.That(restarted.Log.LastId,                   Is.GreaterThanOrEqualTo(lastIdBefore),
                            "the numbering began again instead of carrying on");

            });

        }

        #endregion

        #region AMeterAskedToKeepNoDays_WritesNothingToDisk()

        /// <summary>
        /// Asking for no days at all keeps the log in memory, and leaves the
        /// disk alone.
        /// </summary>
        [Test]
        public async Task AMeterAskedToKeepNoDays_WritesNothingToDisk()
        {

            await using var quiet = new ModbusTLSEnergyMeter(
                                  SerialNumber:       "meter-log-002",
                                  ServerPfxPath:      Path.Combine(pkiDirectory!, "server.pfx"),
                                  ServerPfxPassword:  "demo",
                                  ClientCACertPath:   Path.Combine(pkiDirectory!, "issuing-clients-ca.crt"),
                                  ListenAddress:      NetIPAddress.Loopback,
                                  ListenPort:         FreeTCPPort(),
                                  HTTPHostname:       IPv4Address.Localhost,
                                  HTTPPort:           IPPort.Parse(FreeTCPPort()),
                                  DataPath:           Path.Combine(workingDirectory!, "quiet"),
                                  ConfigFile:         new MeterConfigFile(Path.Combine(workingDirectory!, "quiet.json")),
                                  LogKeepDays:        0,
                                  LogToConsole:       false
                              );

            Assert.Multiple(() => {
                Assert.That(quiet.Log.Store,  Is.Null);
                Assert.That(quiet.Log.Count,  Is.GreaterThan(0), "and still keeps a log in memory");
                Assert.That(Directory.Exists(Path.Combine(workingDirectory!, "quiet", "logs")), Is.False);
            });

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// Every entry this meter wrote about a Modbus request.
        /// </summary>
        private IEnumerable<LogEntry> Requests()

            => meter!.Log.Recent(200, Tag: "request").
                          OrderBy(entry => entry.Id);

        /// <summary>
        /// Read the whole register block with the client certificate of the
        /// given role.
        /// </summary>
        private async Task ReadAsAsync(String Role)
        {

            var certificates = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                                   Path.Combine(pkiDirectory!, $"client-{Role}.pfx"),
                                   "demo",
                                   X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
                               ).
                               OfType<X509Certificate2>().
                               ToArray();

            var leaf         = certificates.Single(certificate =>  certificate.HasPrivateKey &&
                                                                  !IsCertificateAuthority(certificate));

            var issuingCA    = certificates.Single(certificate =>  IsCertificateAuthority(certificate) &&
                                                                   certificate.Subject.Contains("Issuing Clients CA", StringComparison.Ordinal));

            using var client = new HermodModbusTCPClient(
                                   IPv4Address.Localhost,
                                   IPPort.Parse(modbusPort),
                                   UnitAddress:                 1,
                                   StartingAddressOffset:       1,
                                   RemoteCertificateValidator:  (a, b, c, d, e) => TLSValidationResult.Success(),
                                   ClientCert:                  leaf,
                                   ClientCertificateChain:      [ leaf, issuingCA ],
                                   TLSProtocol:                 SslProtocols.Tls12 | SslProtocols.Tls13,
                                   PreferIPv4:                  true,
                                   RequestTimeout:              TimeSpan.FromSeconds(10),
                                   MaxNumberOfRetries:          1
                               );

            var connected = await client.ReconnectAsync();

            Assert.That(connected.IsSuccess, Is.True, $"'{Role}' could not connect");

            try
            {
                await client.ReadHoldingRegisters(
                          SunSpecMeterMap.BaseAddress,
                          SunSpecMeterMap.RegisterCount
                      );
            }
            finally
            {
                await client.Close();
            }

        }

        private static Boolean IsCertificateAuthority(X509Certificate2 Certificate)

            => Certificate.Extensions.
                   OfType<X509BasicConstraintsExtension>().
                   Any(extension => extension.CertificateAuthority);

        private static Int32 FreeTCPPort()
        {

            var listener = new TcpListener(NetIPAddress.Loopback, 0);

            listener.Start();
            var port = ((System.Net.IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return port;

        }

        #endregion

    }

}
