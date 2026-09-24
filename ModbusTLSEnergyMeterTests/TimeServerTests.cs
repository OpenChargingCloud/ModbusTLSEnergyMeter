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

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// Asking one time server everything there is to ask.
    /// </summary>
    /// <remarks>
    /// Nothing here reaches a time server: what is measured is which question
    /// the meter decides to put, on which ports, and what it says when it
    /// decides it cannot put one at all. Where a question would go out, name
    /// resolution is switched off, so that the first step is written and
    /// everything after it fails at once.
    ///
    /// The charging station's tests of its test, which it took from the
    /// vehicle, in one place. The meters are constructed and never started,
    /// as in the tests of the nts section, and one PKI serves them all.
    /// </remarks>
    [TestFixture]
    public class TimeServerTests
    {

        #region Data

        private String  fixtureDirectory  = "";
        private String  pkiDirectory      = "";
        private String  directory         = "";

        private String ConfigurationPath
            => Path.Combine(directory, MeterConfigFile.DefaultFileName);

        #endregion

        #region OneTimeSetup / Setup / TearDown / OneTimeTearDown

        [OneTimeSetUp]
        public async Task OneTimeSetup()
        {

            fixtureDirectory  = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "time-server-" + Guid.NewGuid().ToString("N")[..12]);
            pkiDirectory      = Path.Combine(fixtureDirectory, "pki");

            await new ModbusPKI().BuildPKI(pkiDirectory);

        }

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(fixtureDirectory, Guid.NewGuid().ToString("N")[..12]);

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
                // A temporary directory that outlives one test is not worth
                // failing the run over.
            }

        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {

            try
            {
                if (Directory.Exists(fixtureDirectory))
                    Directory.Delete(fixtureDirectory, recursive: true);
            }
            catch (Exception)
            { }

        }

        #endregion


        #region (helper) Meter(Configuration = null)

        /// <summary>
        /// A meter as it stands after reading this configuration file, or after
        /// reading none.
        /// </summary>
        private ModbusTLSEnergyMeter Meter(String? Configuration = null)
        {

            if (Configuration is not null)
                File.WriteAllText(ConfigurationPath, Configuration);

            return new ModbusTLSEnergyMeter(
                       SerialNumber:       "meter-time-server-001",
                       ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                       ServerPfxPassword:  "demo",
                       ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                       DataPath:           Path.Combine(directory, "data"),
                       ConfigFile:         new MeterConfigFile(ConfigurationPath),
                       LogKeepDays:        0,
                       LogToConsole:       false
                   );

        }

        #endregion

        #region (helper) Steps(Result)

        private static String[] Steps(JObject Result)

            => [.. (Result["steps"] as JArray ?? []).Select(step => step.Value<String>("text") ?? "")];

        #endregion


        #region SomethingThatIsNeitherIsRefused()

        /// <summary>
        /// Not a name and not an address: said, and nothing asked.
        /// </summary>
        [Test]
        public async Task SomethingThatIsNeitherIsRefused()
        {

            await using var meter = Meter();

            var before  = meter.Log.LastId;
            var result  = await meter.TestTimeServerAsync("not a host at all");

            Assert.Multiple(() => {
                Assert.That(result.Value<Boolean>("ok"),  Is.False);
                Assert.That(Steps(result),                Is.EqualTo(new[] { "'not a host at all' is neither a name nor an address that can be asked." }));
                Assert.That(meter.Log.Recent(50, before, "test"),  Is.Empty, "nothing was asked, so there is nothing to log");
            });

        }

        #endregion

        #region NothingIsAskedWhileTimeSynchronisationIsOff()

        /// <summary>
        /// Switched off means switched off, for the test as much as for the
        /// meter's own checks.
        /// </summary>
        /// <remarks>
        /// A test that quietly asked anyway would be a meter sending traffic
        /// somebody switched off - and the page would be showing an answer from
        /// a server this meter is not using.
        /// </remarks>
        [Test]
        public async Task NothingIsAskedWhileTimeSynchronisationIsOff()
        {

            await using var meter = Meter("""{ "nts": { "enabled": false } }""");

            var before  = meter.Log.LastId;
            var result  = await meter.TestTimeServerAsync("ptbtime2.ptb.de");

            Assert.Multiple(() => {
                Assert.That(result.Value<Boolean>("ok"),  Is.False);
                Assert.That(Steps(result),                Is.EqualTo(new[] { "Time synchronisation is switched off on this meter, so nothing was asked." }));
                Assert.That(meter.Log.Recent(50, before, "test"),  Is.Empty);
            });

        }

        #endregion

        #region AnAddressIsAskedWithTheCookiesOfTheSingleClientsExchange()

        /// <summary>
        /// An address is a server to be asked, not something to refuse - and it
        /// is asked with the cookies of a key exchange with a name.
        /// </summary>
        /// <remarks>
        /// A key exchange very commonly names addresses rather than host names -
        /// nts.netnod.se names "2a01:3f7:2:44::9" and nothing else. An address
        /// cannot have a key exchange of its own, because the TLS certificate is
        /// issued for a name; the exchange therefore stays with the single
        /// client's host, and the time request is directed at the address.
        ///
        /// The charging station's test of this switched time synchronisation
        /// off, and then the test stopped before it looked at the address at
        /// all: it would have passed with addresses refused. Here it is on, and
        /// name resolution is off, so that the first step - which says what is
        /// going to be asked - is written, and the key exchange after it fails
        /// without anything going out. Where the request would go is Norn's
        /// decision and is tested there.
        /// </remarks>
        [Test]
        public async Task AnAddressIsAskedWithTheCookiesOfTheSingleClientsExchange()
        {

            await using var meter = Meter("""{ "dns": { "enabled": false }, "nts": { "timeoutSeconds": 1 } }""");

            var result = await meter.TestTimeServerAsync("[2a01:3f7:2:44::9]");

            Assert.Multiple(() => {
                Assert.That(result.Value<String>("host"),  Is.EqualTo("2a01:3f7:2:44::9"));
                Assert.That(result.Value<Boolean>("ok"),   Is.False, "nothing could be resolved, so nothing answered");
                Assert.That(Steps(result)[0],              Is.EqualTo($"Asking 2a01:3f7:2:44::9 for the time, with cookies from a key exchange with " +
                                                                      $"{meter.NTSClient.Hostname.Trimmed} - an address cannot have a key exchange of its " +
                                                                       "own, because the TLS certificate is issued for a name."));
            });

        }

        #endregion

        #region AServerOfTheGroupIsTestedOnItsOwnPorts()

        /// <summary>
        /// The detailed test asks a server of the group on the ports that server
        /// is configured with, and not on those of the single client.
        /// </summary>
        /// <remarks>
        /// A server with a port of its own would otherwise be asked on the usual
        /// one and reported as not answering. The first step names the ports
        /// before anything is asked, and the rest fails at once.
        /// </remarks>
        [Test]
        public async Task AServerOfTheGroupIsTestedOnItsOwnPorts()
        {

            await using var meter = Meter("""
                                          { "dns": { "enabled": false },
                                            "nts": { "servers": [ "a.example",
                                                                  { "hostname": "b.example", "ntsKEPort": 4461, "ntpPort": 1234 } ],
                                                     "timeoutSeconds": 1 } }
                                          """);

            var result = await meter.TestTimeServerAsync("b.example");

            Assert.That(Steps(result)[0],
                        Is.EqualTo("Asking b.example: key exchange on port 4461, time on port 1234, 1 second(s) allowed."));

        }

        #endregion

        #region TheTestWritesTheNameAsItIsRead()

        /// <summary>
        /// The detailed test names the server the way everything else this
        /// meter prints does: without the root's dot.
        /// </summary>
        /// <remarks>
        /// "Asking ptbtime2.ptb.de.: key exchange on port 4460" - the name is
        /// exact with the dot, and in the middle of a sentence it reads like a
        /// typing mistake. The steps and the log lines use the name as it is
        /// read, typed with the dot or without; the name the result carries as
        /// data is left as it is.
        /// </remarks>
        [Test]
        public async Task TheTestWritesTheNameAsItIsRead()
        {

            await using var meter = Meter("""
                                          { "dns": { "enabled": false },
                                            "nts": { "servers": [ "a.example", "b.example" ], "timeoutSeconds": 1 } }
                                          """);

            var before  = meter.Log.LastId;
            var result  = await meter.TestTimeServerAsync("b.example.");
            var said    = meter.Log.Recent(50, before, "test").Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {
                Assert.That(Steps(result)[0],               Does.StartWith("Asking b.example:"));
                Assert.That(said,                           Has.Some.EqualTo("NTS test: asking b.example ..."),  String.Join(" | ", said));
                Assert.That(result.Value<String>("host"),   Is.EqualTo("b.example."),  "the data keeps the name exactly");
            });

        }

        #endregion

    }

}
