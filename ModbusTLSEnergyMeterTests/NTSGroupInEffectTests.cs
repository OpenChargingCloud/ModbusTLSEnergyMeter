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
    /// What a meter makes of an "nts" section: the section put into effect on
    /// top of the group of time servers it already has.
    /// </summary>
    /// <remarks>
    /// Beside the tests of the section on its own, because the rule that
    /// matters here - what a section does not mention is left as it is - can
    /// only be seen against something that is already there.
    ///
    /// The meters are constructed and never started. The constructor is what
    /// applies the file, and starting would open two ports, make up an account
    /// and set the clock check going for nothing. One PKI serves them all: the
    /// certificates are only read.
    /// </remarks>
    public class NTSGroupInEffectTests
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

            fixtureDirectory  = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "nts-group-" + Guid.NewGuid().ToString("N")[..12]);
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
        /// <remarks>
        /// No days of log on disk: the entries are still kept in memory, which
        /// is where the tests read them, and nothing is left behind.
        /// </remarks>
        private ModbusTLSEnergyMeter Meter(String? Configuration = null)
        {

            if (Configuration is not null)
                File.WriteAllText(ConfigurationPath, Configuration);

            return new ModbusTLSEnergyMeter(
                       SerialNumber:       "meter-nts-001",
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

        #region (helper) SaidSince(Meter, Before)

        private static String[] SaidSince(ModbusTLSEnergyMeter  Meter,
                                          UInt64                Before)

            => [.. Meter.Log.Recent(100, Before).Select(entry => entry.Message)];

        #endregion


        #region AQuorumOnItsOwnHoldsTheServersInEffectToIt()

        /// <summary>
        /// "minServers" without a list is about the servers the meter has.
        /// </summary>
        /// <remarks>
        /// It used to count only beside a list or a hostname: the file was read
        /// and the default four went on being held to two.
        /// </remarks>
        [Test]
        public async Task AQuorumOnItsOwnHoldsTheServersInEffectToIt()
        {

            await using var meter = Meter("""{ "nts": { "minServers": 3 } }""");

            Assert.Multiple(() =>
            {
                Assert.That(meter.TimeSources.Sources.Count(),  Is.EqualTo(4),  "the servers were not mentioned, so they are the default four");
                Assert.That(meter.TimeSources.MinServers,       Is.EqualTo(3),  "the quorum was read and changed nothing");
            });

        }

        #endregion

        #region ADeviationOnItsOwnAppliesToTheServersInEffect()

        [Test]
        public async Task ADeviationOnItsOwnAppliesToTheServersInEffect()
        {

            await using var meter = Meter("""{ "nts": { "maxDeviationSeconds": 0.5 } }""");

            Assert.Multiple(() =>
            {
                Assert.That(meter.TimeSources.Sources.Count(),  Is.EqualTo(4));
                Assert.That(meter.TimeSources.MinServers,       Is.EqualTo(2));
                Assert.That(meter.TimeSources.MaxDeviation,     Is.EqualTo(TimeSpan.FromSeconds(0.5)),  "the deviation was read and changed nothing");
            });

        }

        #endregion

        #region AQuorumTheServersInEffectCannotReachStopsTheStart()

        /// <summary>
        /// Five of four is refused while the file is read, as five of a list of
        /// four always was.
        /// </summary>
        [Test]
        public void AQuorumTheServersInEffectCannotReachStopsTheStart()
        {

            var problem = Assert.Throws<InvalidOperationException>(() => Meter("""{ "nts": { "minServers": 5 } }"""));

            Assert.That(problem?.Message,  Does.Contain("minServers").And.Contain(ConfigurationPath));

        }

        #endregion

        #region AQuorumOnItsOwnIsRefusedBeforeItIsWrittenDown()

        /// <summary>
        /// And the same from the page: refused, and the file left as it was, so
        /// that the next start does not stop over what was refused.
        /// </summary>
        [Test]
        public async Task AQuorumOnItsOwnIsRefusedBeforeItIsWrittenDown()
        {

            await using var meter = Meter();

            Assert.Multiple(() =>
            {

                Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "minServers": 5 }"""), out var error),  Is.False);
                Assert.That(error,                                                                                 Does.Contain("minServers"));

                Assert.That(!File.Exists(ConfigurationPath) || !File.ReadAllText(ConfigurationPath).Contains("minServers"),
                            Is.True,
                            "a refused quorum was written down all the same");

                Assert.That(meter.TimeSources.MinServers,  Is.EqualTo(2));

            });

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "minServers": 3 }"""), out var unexpected),  Is.True,  unexpected);
            Assert.That(meter.TimeSources.MinServers,                                                                  Is.EqualTo(3));

        }

        #endregion

        #region AListAfterALoneHostnameIsHeldToTheQuorumAgain()

        /// <summary>
        /// The quorum a group of one has to settle for is not carried over to
        /// the four that come after it.
        /// </summary>
        /// <remarks>
        /// Read from the file at the next start, the same section holds the four
        /// to two. A running meter that held them to one would be a different
        /// meter from the one that file describes.
        /// </remarks>
        [Test]
        public async Task AListAfterALoneHostnameIsHeldToTheQuorumAgain()
        {

            await using var meter = Meter();

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "hostname": "ptbtime1.ptb.de" }"""), out var error),  Is.True,  error);
            Assert.That(meter.TimeSources.MinServers,                                                                          Is.EqualTo(1),  "one server cannot be held to two");

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""
                            {
                                "servers": [ "ptbtime1.ptb.de", "ptbtime2.ptb.de",
                                             "ptbtime3.ptb.de", "ptbtime4.ptb.de" ]
                            }
                            """), out error),  Is.True,  error);

            Assert.That(meter.TimeSources.MinServers,  Is.EqualTo(2),  "the group of one's quorum was carried over to four");

        }

        #endregion

        #region ALoneHostnameReplacesTheListHereAndInTheFile()

        /// <summary>
        /// A save naming a lone hostname and no list makes the group that one
        /// server - now, and at the next start.
        /// </summary>
        /// <remarks>
        /// The file kept its list beside the hostname, and the next start made
        /// the list again: the meter ran with one server until it was restarted
        /// and with three after it, nobody having changed anything in between.
        /// The NTS page's form sent exactly such a save.
        /// </remarks>
        [Test]
        public async Task ALoneHostnameReplacesTheListHereAndInTheFile()
        {

            await using (var meter = Meter("""{ "nts": { "servers": [ "a.example", "b.example", "c.example" ] } }"""))
            {

                Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "hostname": "d.example" }"""), out var error),  Is.True,  error);

                Assert.That(meter.TimeSources.Sources.Select(source => source.Hostname.Trimmed),  Is.EqualTo(new[] { "d.example" }));

            }

            await using var restarted = Meter();

            Assert.That(restarted.TimeSources.Sources.Select(source => source.Hostname.Trimmed),  Is.EqualTo(new[] { "d.example" }),
                        "the next start made the list again");

        }

        #endregion

        #region ASaveOfPartOfTheSectionLeavesTheRestInEffect()

        /// <summary>
        /// A save sends part of the section, and the rest of what the file said
        /// stays in effect.
        /// </summary>
        /// <remarks>
        /// It used to be replaced by what was sent: saving the time server's
        /// settings took the legal time authority away, and saving the legal
        /// time's settings put the interval back to fifteen minutes - both
        /// until the next start read the file again.
        /// </remarks>
        [Test]
        public async Task ASaveOfPartOfTheSectionLeavesTheRestInEffect()
        {

            await using var meter = Meter("""{ "nts": { "checkEverySeconds": 600, "legalTimeAuthority": "PTB" } }""");

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "enabled": true }"""), out var error),  Is.True,  error);

            Assert.Multiple(() =>
            {
                Assert.That(meter.TimeCheckEvery,      Is.EqualTo(TimeSpan.FromSeconds(600)),  "the interval went back to its default");
                Assert.That(meter.LegalTimeAuthority,  Is.EqualTo("PTB"),                      "the authority was forgotten");
            });

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "legalTimeToleranceSeconds": 0.5 }"""), out error),  Is.True,  error);

            Assert.Multiple(() =>
            {
                Assert.That(meter.TimeCheckEvery,      Is.EqualTo(TimeSpan.FromSeconds(600)),  "the interval went back to its default");
                Assert.That(meter.LegalTimeAuthority,  Is.EqualTo("PTB"),                      "the authority was forgotten");
                Assert.That(meter.LegalTimeTolerance,  Is.EqualTo(TimeSpan.FromSeconds(0.5)));
            });

        }

        #endregion

        #region AnAuthorityTakenAwayStaysAway()

        /// <summary>
        /// The legal time's authority is taken away by sending it as null -
        /// which is what the page does with an empty field - and it stays away,
        /// here and in the file.
        /// </summary>
        /// <remarks>
        /// A null in a section otherwise means "the file does not say", and the
        /// file kept what it said: the authority was gone until the next start,
        /// and back after it, with nobody having put it back.
        /// </remarks>
        [Test]
        public async Task AnAuthorityTakenAwayStaysAway()
        {

            await using (var meter = Meter("""{ "nts": { "checkEverySeconds": 600, "legalTimeAuthority": "PTB" } }"""))
            {

                var before = meter.Log.LastId;

                Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "legalTimeAuthority": null }"""), out var error),  Is.True,  error);

                Assert.Multiple(() =>
                {
                    Assert.That(meter.LegalTimeAuthority,  Is.Null,                                "still vouched for");
                    Assert.That(meter.TimeCheckEvery,      Is.EqualTo(TimeSpan.FromSeconds(600)),  "the rest went with it");
                    Assert.That(SaidSince(meter, before),  Has.Some.Contains("no legal time authority"),
                                "a change to who stands behind the time is not written down");
                });

            }

            Assert.That(File.ReadAllText(ConfigurationPath),  Does.Not.Contain("legalTimeAuthority"),
                        "the file still names the authority, and the next start brings it back");

            await using var restarted = Meter();

            Assert.That(restarted.LegalTimeAuthority,  Is.Null,  "the authority came back at the next start");

        }

        #endregion

        #region AListShorterThanTheQuorumIsRefusedAndNotWritten()

        /// <summary>
        /// A server deleted or switched off below the quorum the file holds is
        /// refused, and the file is left as it was.
        /// </summary>
        /// <remarks>
        /// Each half was fine on its own - the quorum in the file, the list that
        /// was sent - and merged they made a section the next start refuses. A
        /// save that is accepted and then stops the meter is the one thing
        /// worse than a save that is refused.
        /// </remarks>
        [Test]
        public async Task AListShorterThanTheQuorumIsRefusedAndNotWritten()
        {

            await using var meter = Meter("""
                                        { "nts": { "servers": [ "a.example", "b.example", "c.example" ], "minServers": 3 } }
                                        """);

            var before = File.ReadAllText(ConfigurationPath);

            Assert.Multiple(() =>
            {

                Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out var deleted),
                            Is.False,
                            "a server was deleted below the quorum");

                Assert.That(deleted,  Does.Contain("minServers"));

                Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""
                                { "servers": [ "a.example", "b.example", { "hostname": "c.example", "enabled": false } ] }
                                """), out _),
                            Is.False,
                            "a server was switched off below the quorum");

                Assert.That(File.ReadAllText(ConfigurationPath),  Is.EqualTo(before),  "a refused save was written down");
                Assert.That(meter.TimeSources.Sources.Count(),     Is.EqualTo(3));

            });

        }

        #endregion

        #region EveryServerIsListedWithItsPorts()

        /// <summary>
        /// The list the page edits and sends back whole has every server in it,
        /// the switched-off ones included, with the ports each is asked on.
        /// </summary>
        /// <remarks>
        /// The NTS answer did not list the group at all. It described the single
        /// client - one host, its ports - which is why the page could only edit
        /// one server, and saving it made the group that one server.
        /// </remarks>
        [Test]
        public async Task EveryServerIsListedWithItsPorts()
        {

            await using var meter = Meter("""
                                        { "nts": { "servers": [ "a.example",
                                                                { "hostname": "b.example", "ntsKEPort": 4461, "enabled": false } ] } }
                                        """);

            var shown   = meter.NTSConfigurationJSON();
            var listed  = shown["timeSources"] as JArray;

            Assert.Multiple(() =>
            {

                Assert.That(listed,                                 Has.Count.EqualTo(2),  "the switched-off server is missing");
                Assert.That(listed?[1]?.Value<String>("hostname"),  Is.EqualTo("b.example."));
                Assert.That(listed?[1]?.Value<Boolean>("enabled"),  Is.False);
                Assert.That(listed?[1]?.Value<Int32>("ntsKEPort"),  Is.EqualTo(4461));
                Assert.That(listed?[0]?.Value<Int32>("ntpPort"),    Is.EqualTo(123));

                // There and empty until a key exchange has shown a chain.
                Assert.That(listed?[0]?["rootCA"]?.Type,            Is.EqualTo(JTokenType.Null));
                Assert.That(listed?[0]?["aeadAlgorithm"]?.Type,     Is.EqualTo(JTokenType.Null));

                Assert.That(shown.ContainsKey("hostname"),          Is.False,  "the single client is described as the time server again");

            });

        }

        #endregion

        #region TheQuorumWantedAndTheQuorumHeldAreBothShown()

        /// <summary>
        /// A lone hostname holds the group to one, and the page shows both that
        /// and the two that is wanted, which the next list is held to.
        /// </summary>
        [Test]
        public async Task TheQuorumWantedAndTheQuorumHeldAreBothShown()
        {

            await using var meter = Meter("""{ "nts": { "hostname": "a.example" } }""");

            var shown = meter.NTSConfigurationJSON();

            Assert.Multiple(() =>
            {
                Assert.That(shown["settings"]?.Value<Int32>("minServers"),  Is.EqualTo(2),  "the quorum wanted");
                Assert.That(shown["group"]?.   Value<Int32>("minServers"),  Is.EqualTo(1),  "the quorum one server can be held to");
            });

        }

        #endregion

        #region AChangeToOneServerIsWrittenDown()

        /// <summary>
        /// A server given another priority or a port of its own is a change to
        /// the group, and the log hears of it.
        /// </summary>
        /// <remarks>
        /// The log compared the names of the servers switched on, in the order
        /// they are asked. A priority that put a server into a band of its own
        /// at the end, and a port of its own, left those just as they were -
        /// and so the group changed without a line saying so.
        /// </remarks>
        [Test]
        public async Task AChangeToOneServerIsWrittenDown()
        {

            await using var meter = Meter("""{ "nts": { "servers": [ "a.example", "b.example" ] } }""");

            var before = meter.Log.LastId;

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""
                            { "servers": [ "a.example", { "hostname": "b.example", "priority": 5, "ntsKEPort": 4461 } ] }
                            """), out var error),
                        Is.True,
                        error);

            var said = SaidSince(meter, before);

            Assert.That(said,  Has.Some.Contains("time servers = a.example, b.example (priority 5, NTS-KE port 4461)"),
                        String.Join(" | ", said));

        }

        #endregion

        #region ADeviationStaysWhenTheServersChange()

        /// <summary>
        /// What a section does not mention is left as it is - the deviation
        /// too, when the servers are replaced.
        /// </summary>
        [Test]
        public async Task ADeviationStaysWhenTheServersChange()
        {

            await using var meter = Meter("""{ "nts": { "maxDeviationSeconds": 0.5 } }""");

            Assert.That(meter.TryUpdateNTSConfiguration(JObject.Parse("""{ "servers": [ "a.example", "b.example" ] }"""), out var error),  Is.True,  error);

            Assert.That(meter.TimeSources.MaxDeviation,  Is.EqualTo(TimeSpan.FromSeconds(0.5)));

        }

        #endregion

        #region TheClockIsCheckedAgainstTheGroup()

        /// <summary>
        /// Against whom the clock is checked, as its JSON says it: the group,
        /// its servers switched on in the order they are asked, and how many of
        /// them have to answer.
        /// </summary>
        /// <remarks>
        /// The names without the root's dot: the NTS page draws this list, and
        /// drew "ptbtime1.ptb.de., ptbtime2.ptb.de., ..." - where everything
        /// else this meter prints for somebody to read leaves the dot out.
        /// </remarks>
        [Test]
        public async Task TheClockIsCheckedAgainstTheGroup()
        {

            await using var meter = Meter("""
                                        { "nts": { "servers": [ { "hostname": "b.example", "priority": 5 },
                                                                "a.example",
                                                                { "hostname": "c.example", "enabled": false } ] } }
                                        """);

            var clock = meter.ClockJSON();

            Assert.Multiple(() =>
            {

                Assert.That(clock.Value<String>("group"),        Is.EqualTo("legal"));

                Assert.That(clock["servers"]!.Values<String>(),  Is.EqualTo(new[] { "a.example", "b.example" }),
                            "switched on, in the order their bands are asked, and without the root's dot");

                Assert.That(clock.Value<Int32>("minServers"),    Is.EqualTo(2));

                Assert.That(clock.ContainsKey("server"),         Is.False,  "a single server is named beside the group");

                // There and empty while nothing has been synchronised, so that
                // the page says "never" rather than leaving the line out.
                Assert.That(clock["lastSync"]?.      Type,       Is.EqualTo(JTokenType.Null));
                Assert.That(clock["lastSyncResult"]?.Type,       Is.EqualTo(JTokenType.Null));

            });

        }

        #endregion

        #region AClockThatIsNotCheckedNamesNobody()

        /// <summary>
        /// Switched off, the clock is checked against nobody, and says so -
        /// rather than naming servers that are not asked.
        /// </summary>
        [Test]
        public async Task AClockThatIsNotCheckedNamesNobody()
        {

            await using var meter = Meter("""{ "nts": { "enabled": false } }""");

            var clock = meter.ClockJSON();

            Assert.Multiple(() =>
            {
                Assert.That(clock.Value<Boolean>("ntsEnabled"),  Is.False);
                Assert.That(clock["group"]?.     Type,           Is.EqualTo(JTokenType.Null));
                Assert.That(clock["servers"]?.   Type,           Is.EqualTo(JTokenType.Null));
                Assert.That(clock["minServers"]?.Type,           Is.EqualTo(JTokenType.Null));
            });

        }

        #endregion

    }

}
