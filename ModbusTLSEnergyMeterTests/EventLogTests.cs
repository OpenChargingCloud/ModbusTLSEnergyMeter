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

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;

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
                        ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory, "configuration.json")),
                        LogToConsole:       false
                    );

            await meter.Start();

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
                Assert.That(entry!.Metrological,                     Is.False,
                            "a read that was allowed is evidence of nothing, and stays out of the log book");

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
                Assert.That(entry!.Metrological,                       Is.True,
                            "a refusal is evidence, and belongs in the log book");

                Assert.That(entry!.Data?["allowed"]?.ToObject<Boolean>(), Is.False);
                Assert.That(entry!.Data?["role"]?.Type,                Is.EqualTo(Newtonsoft.Json.Linq.JTokenType.Null));
                Assert.That(entry!.Data?["denyReason"]?.ToString(),    Does.Contain("no role"));
                Assert.That(entry!.Data?["exceptionCode"]?.ToString(), Is.EqualTo(ModbusExceptionCode.IllegalFunction.ToString()));
                Assert.That(entry!.Data?["peer"]?.ToString(),          Is.Not.Empty);

            });

        }

        #endregion

        #region AnAllowedWrite_IsInTheLogBook()

        /// <summary>
        /// A write that the policy permits changes what the meter is, and so is
        /// written into the log book - signed, chained and read back - and not
        /// only into the log files beside it.
        /// </summary>
        [Test]
        public async Task AnAllowedWrite_IsInTheLogBook()
        {

            var answer = await WriteAsAsync(SunSpecRoles.SuperAdministrator,
                                            SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterMeterMode),
                                            (UInt16) SunSpecMeterMode.ImportOnly);

            Assert.That(answer[7], Is.EqualTo(0x06), $"the meter refused the write: {Convert.ToHexString(answer)}");

            // Looked for until it is there: whether the entry is written before
            // the answer leaves or after is the frontend's business.
            LogEntry? entry = null;

            for (var attempt = 0; attempt < 50 && entry is null; attempt++)
            {

                entry = Requests().LastOrDefault(request => request.Data?["functionCode"]?.ToString() == "0x06");

                if (entry is null)
                    await Task.Delay(100);

            }

            Assert.That(entry, Is.Not.Null, "the write was not written down at all");

            Assert.Multiple(() => {

                Assert.That(entry!.Data?["allowed"]?.ToObject<Boolean>(),  Is.True);
                Assert.That(entry!.Data?["functionCode"]?.ToString(),      Is.EqualTo("0x06"));
                Assert.That(entry!.Data?["exceptionCode"]?.Type,           Is.EqualTo(Newtonsoft.Json.Linq.JTokenType.Null),
                            "the write did not reach the register it was meant for");

                Assert.That(entry!.Metrological,                           Is.True,
                            "a write is evidence, and belongs in the log book");

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


        #region TheLogBookSurvivesARestart()

        /// <summary>
        /// What went into the log book before a restart is still there
        /// afterwards, and the numbering carries on rather than beginning
        /// again - while what went only into the log files is in those files,
        /// and is not read back.
        /// </summary>
        /// <remarks>
        /// A refusal, because that is what the log book is for: the entries
        /// that are evidence are signed, chained and read back at the start.
        /// The rest is in the day's log file, written for reading.
        ///
        /// The numbering is half the test. A browser follows this log by asking
        /// for everything after the last number it saw; a meter that began
        /// again at 1 would hand it entries it would then decide it had already
        /// seen, and two different events would share a number in the file.
        /// </remarks>
        [Test]
        public async Task TheLogBookSurvivesARestart()
        {

            await ReadAsAsync(SunSpecRoles.ReadOnly);

            var allowed      = Requests().Last();

            try   { await ReadAsAsync("NO-ROLE"); }
            catch { }

            var before       = Requests().Last();
            var lastIdBefore = meter!.Log.LastId;

            Assert.That(meter!.MetrologicalLog,  Is.Not.Null, "the log book was not being written to disk at all");
            Assert.That(before.Metrological,     Is.True,     "the refusal did not go into the log book");

            // Stopped rather than abandoned: the file has to be closed before
            // another meter reads it back.
            await meter!.DisposeAsync();
            meter = null;

            // And the day's log file read now, while nothing holds it open:
            // the meter started next writes to it again.
            var logFiles = String.Concat(Directory.GetFiles(Path.Combine(workingDirectory!, "data", ModbusTLSEnergyMeter.LogDirectoryName), "meter-*.log").
                                                   Select(File.ReadAllText));

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
                                ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory!, "configuration.json")),
                                LogToConsole:       false
                            );

            meter = restarted;

            var after = restarted.Log.Recent(200, Tag: "request").LastOrDefault();

            Assert.Multiple(() => {

                Assert.That(after,                                  Is.Not.Null, "the refusal was gone after the restart");
                Assert.That(after!.Id,                              Is.EqualTo(before.Id));
                Assert.That(after!.Message,                         Is.EqualTo(before.Message));
                Assert.That(after!.Tags,                            Is.EquivalentTo(before.Tags));
                Assert.That(after!.Data?["denyReason"]?.ToString(), Is.EqualTo(before.Data?["denyReason"]?.ToString()),
                            "the data attached to the entry did not survive");

                Assert.That(restarted.Log.LastId,                   Is.GreaterThanOrEqualTo(lastIdBefore),
                            "the numbering began again instead of carrying on");

                Assert.That(restarted.Log.Recent(200, Tag: "request").Select(entry => entry.Id),
                            Does.Not.Contain(allowed.Id),
                            "the allowed read was read back as if it were evidence");

                Assert.That(logFiles,
                            Does.Contain(allowed.Message),
                            "the allowed read is not in the log file either");

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
                                  ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory!, "quiet.json")),
                                  LogKeepDays:        0,
                                  LogToConsole:       false
                              );

            Assert.Multiple(() => {
                Assert.That(quiet.MetrologicalLog,  Is.Null, "no log book");
                Assert.That(quiet.LogPath,          Is.Null, "and no log files");
                Assert.That(quiet.Log.Count,        Is.GreaterThan(0), "and still keeps a log in memory");
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

            using var client = await ConnectAsAsync(Role);

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

        /// <summary>
        /// Write one register with the client certificate of the given role,
        /// and return the frame the meter answered with.
        /// </summary>
        private async Task<Byte[]> WriteAsAsync(String  Role,
                                                UInt16  Address,
                                                UInt16  Value)
        {

            using var client = await ConnectAsAsync(Role);

            try
            {
                return await client.WriteSingleRegister(Address, [ (Byte) (Value >> 8), (Byte) Value ]);
            }
            finally
            {
                await client.Close();
            }

        }

        /// <summary>
        /// The client certificate of the given role, and the CA that issued it.
        /// </summary>
        private (X509Certificate2 Leaf, X509Certificate2 IssuingCA) ClientCertificatesOf(String Role)
        {

            var certificates = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                                   Path.Combine(pkiDirectory!, $"client-{Role}.pfx"),
                                   "demo",
                                   X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
                               ).
                               OfType<X509Certificate2>().
                               ToArray();

            return (certificates.Single(certificate =>  certificate.HasPrivateKey &&
                                                       !IsCertificateAuthority(certificate)),

                    certificates.Single(certificate =>  IsCertificateAuthority(certificate) &&
                                                        certificate.Subject.Contains("Issuing Clients CA", StringComparison.Ordinal)));

        }

        /// <summary>
        /// A Modbus/TLS client of this meter, connected with the client
        /// certificate of the given role.
        /// </summary>
        private async Task<HermodModbusTCPClient> ConnectAsAsync(String Role)
        {

            var (leaf, issuingCA) = ClientCertificatesOf(Role);

            var client       = new HermodModbusTCPClient(
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

            return client;

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
