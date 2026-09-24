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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.DNS;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What the "dns" section may say about the name servers - and what it may
    /// not, said as a sentence about the file rather than as an exception.
    /// </summary>
    /// <remarks>
    /// The README showed a name server as "udp://192.168.1.1:53", which is how
    /// a log names one and not a form this section has ever taken - here, or
    /// in the vehicle and the charging station whose sections this one shares.
    /// A meter given it stopped at its start with an ArgumentException out of
    /// Hermod's IPAddress.TryParse, naming neither the file nor the key. The
    /// README now shows what is read, and what is not read is refused.
    /// </remarks>
    public class DNSConfigurationTests
    {

        #region Data

        private String directory = "";

        private String ConfigurationPath
            => Path.Combine(directory, MeterConfigFile.DefaultFileName);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "dns-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch (Exception)
            {
                // A temporary directory that outlives one test run is not worth
                // failing the run over.
            }

        }

        #endregion


        #region TheREADMEsExampleIsOneNameServerOverUDP()

        /// <summary>
        /// The section as the README writes it: an address, which is a name
        /// server asked over UDP on port 53.
        /// </summary>
        [Test]
        public void TheREADMEsExampleIsOneNameServerOverUDP()
        {

            var section = JObject.Parse("""{ "enabled": true, "servers": [ "192.168.1.1" ] }""");

            Assert.That(DNSConfiguration.TryParse(section, out var read, out var error),  Is.True,  error);

            var server = read!.Servers!.Single();

            Assert.Multiple(() =>
            {
                Assert.That(read.Enabled,                  Is.True);
                Assert.That(server.IPAddress?.ToString(),  Is.EqualTo("192.168.1.1"));
                Assert.That(server.Port.ToUInt16(),        Is.EqualTo(53));
                Assert.That(server.Transport,              Is.EqualTo(DNSTransport.UDP));
            });

        }

        #endregion

        #region TheLongFormIsWhatThePageWritesBack()

        /// <summary>
        /// The object the README shows for a server with more to say about it
        /// is read, and written back as it was - which is what makes it the
        /// form the DNS page saves the list in.
        /// </summary>
        [Test]
        public void TheLongFormIsWhatThePageWritesBack()
        {

            var entry = JObject.Parse("""{ "address": "192.168.1.1", "port": 53, "transport": "UDP", "queryTimeoutSeconds": 2 }""");

            Assert.That(DNSConfiguration.TryParseServer(entry, out var server, out var error),  Is.True,  error);

            var written = DNSConfiguration.ServerJSON(server!);

            Assert.Multiple(() =>
            {
                Assert.That(written.Value<String>("address"),              Is.EqualTo("192.168.1.1"));
                Assert.That(written.Value<Int32> ("port"),                 Is.EqualTo(53));
                Assert.That(written.Value<String>("transport"),            Is.EqualTo("UDP"));
                Assert.That(written.Value<Double>("queryTimeoutSeconds"),  Is.EqualTo(2));
            });

        }

        #endregion

        #region AFormTheFileDoesNotTakeIsRefusedWithASentence(Entry)

        /// <summary>
        /// How a log names a name server, and an address with its port: not
        /// forms the section takes, so refused - with the entry named, and not
        /// with an exception out of the parser, which is what all three were.
        /// </summary>
        [TestCase("udp://192.168.1.1:53")]
        [TestCase("udp://[2a01:4f8:0:1::add:1010]:53")]
        [TestCase("192.168.1.1:53")]
        public void AFormTheFileDoesNotTakeIsRefusedWithASentence(String Entry)
        {

            var                section  = new JObject(new JProperty("servers", new JArray(Entry)));
            var                parsed   = true;
            DNSConfiguration?  read     = null;
            String?            error    = null;

            Assert.That(() => parsed = DNSConfiguration.TryParse(section, out read, out error),  Throws.Nothing);

            Assert.Multiple(() =>
            {
                Assert.That(parsed,  Is.False);
                Assert.That(read,    Is.Null);
                Assert.That(error,   Does.Contain("'dns.servers'").And.Contain(Entry));
            });

        }

        #endregion

        #region AMeterWhoseFileSaysSoStopsWithASentence()

        /// <summary>
        /// And at a start: the meter stops over the file the way it stops over
        /// any file it cannot read, saying what is wrong and where - rather than
        /// with an ArgumentException, which is how it stopped before.
        /// </summary>
        /// <remarks>
        /// Constructed and never started, and without a certificate: the file
        /// is read before the certificate is, so this is where it stops. No
        /// days of log on disk either, so that nothing is left behind.
        /// </remarks>
        [Test]
        public void AMeterWhoseFileSaysSoStopsWithASentence()
        {

            File.WriteAllText(ConfigurationPath, """{ "dns": { "servers": [ "udp://192.168.1.1:53" ] } }""");

            var problem = Assert.Throws<InvalidOperationException>(() => new ModbusTLSEnergyMeter(
                                                                             SerialNumber:       "meter-dns-001",
                                                                             ServerPfxPath:      Path.Combine(directory, "server.pfx"),
                                                                             ServerPfxPassword:  "demo",
                                                                             ClientCACertPath:   Path.Combine(directory, "issuing-clients-ca.crt"),
                                                                             DataPath:           Path.Combine(directory, "data"),
                                                                             ConfigFile:         new MeterConfigFile(ConfigurationPath),
                                                                             LogKeepDays:        0,
                                                                             LogToConsole:       false
                                                                         ));

            Assert.That(problem?.Message,  Does.Contain("udp://192.168.1.1:53").And.Contain(ConfigurationPath));

        }

        #endregion

    }

}
