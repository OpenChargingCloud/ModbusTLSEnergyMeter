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

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What this meter stands at has to outlive the process that runs it.
    /// </summary>
    /// <remarks>
    /// A real meter's energy register survives losing power - that is most of
    /// what makes it a meter rather than a sensor - and this one is a
    /// simulation, so it survives only because something writes it down. The
    /// failure being guarded against is not an exception: a meter that came
    /// back at zero would start again quietly and plausibly, and only a
    /// charging session that spanned the restart would notice, by ending up
    /// having used a negative amount of energy.
    ///
    /// The exact numbers are asserted through what the meter said rather than
    /// through its registers, because it goes on measuring the moment it is
    /// started: a register read a few milliseconds later is allowed to have
    /// moved on, and a test demanding otherwise would be demanding that the
    /// meter stop measuring. What the log says was read back cannot move.
    /// </remarks>
    public class MeterStateTests
    {

        #region Data

        private String?  workingDirectory;
        private String?  pkiDirectory;

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

        }

        [TearDown]
        public void TearDown()
        {

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file the meter still holds is not what is under test */ }
            }

        }

        #endregion

        #region (private) DataPath, StatePath, NewMeter()

        private String DataPath
            => Path.Combine(workingDirectory!, "data");

        /// <summary>
        /// Where the counters that have to outlive the process are kept - named
        /// here rather than asked of the meter, so that moving the file without
        /// meaning to breaks a test.
        /// </summary>
        private String StatePath
            => Path.Combine(DataPath, "meter-state.json");

        /// <summary>
        /// Another meter on the same data, which is what a restart is.
        /// </summary>
        private ModbusTLSEnergyMeter NewMeter()

            => new (SerialNumber:       "meter-state-001",
                    ServerPfxPath:      Path.Combine(pkiDirectory!, "server.pfx"),
                    ServerPfxPassword:  "demo",
                    ClientCACertPath:   Path.Combine(pkiDirectory!, "issuing-clients-ca.crt"),
                    ListenAddress:      NetIPAddress.Loopback,
                    ListenPort:         FreeTCPPort(),
                    HTTPHostname:       IPv4Address.Localhost,
                    HTTPPort:           IPPort.Parse(FreeTCPPort()),
                    DataPath:           DataPath,
                    ConfigFile:         new MeterConfigFile(Path.Combine(workingDirectory!, "configuration.json")),
                    LogToConsole:       false);

        #endregion


        #region TheEnergyCounters_ComeBackWhereTheyWereLeft()

        /// <summary>
        /// The whole point of writing them down.
        /// </summary>
        [Test]
        public async Task TheEnergyCounters_ComeBackWhereTheyWereLeft()
        {

            const UInt32  imported = 123_456;
            const UInt32  exported =   7_890;

            Int16         scaleFactor;
            UInt32        writtenDown;

            await using (var before = NewMeter())
            {

                await before.StartAsync();

                scaleFactor = before.Device.EnergyCounters.ScaleFactor;

                // A meter that has been running for a while rather than one
                // just switched on: a counter at zero comes back from a restart
                // looking right whether or not anything was read.
                Assert.That(before.Device.RestoreEnergyCounters(imported, exported, scaleFactor),
                            Is.True, "the test could not put the meter at a reading to start from");

                writtenDown = before.Device.EnergyCounters.ImportedWh;

            }
            // ... and an orderly stop writes them down on the way out.

            Assert.That(File.Exists(StatePath), Is.True,
                        "an orderly stop left no counters behind at all");

            var onDisk = JObject.Parse(File.ReadAllText(StatePath));

            await using var after = NewMeter();
            await after.StartAsync();

            var back = after.Device.EnergyCounters;

            Assert.Multiple(() => {

                Assert.That(onDisk["importedWh"]?. Value<UInt32>(), Is.GreaterThanOrEqualTo(imported),
                            "what was written down is below where the meter was put");

                Assert.That(onDisk["scaleFactor"]?.Value<Int16>(),  Is.EqualTo(scaleFactor),
                            "a counter written down without its scale factor is a number nobody can read back");

                // Never below where it was left. Above is allowed and expected:
                // this meter measures, and it has been running since it came up.
                Assert.That(back.ImportedWh,   Is.GreaterThanOrEqualTo(writtenDown),
                            "the meter came back below where it was left");

                Assert.That(back.ScaleFactor,  Is.EqualTo(scaleFactor));

                // And at exactly the numbers in the file, which is what the log
                // says and what the register is allowed to have moved past.
                Assert.That(Said(after, "meter"),
                            Does.Contain(imported.ToString() + " imported").And.
                                 Contains(exported.ToString() + " exported"),
                            "the meter did not say it had read the counters back");

            });

        }

        #endregion

        #region CountersUnderAnotherScaleFactor_AreRefused()

        /// <summary>
        /// The same number under a different scale factor is a different amount
        /// of energy, and taking it quietly would move a meter reading by a
        /// factor of ten.
        /// </summary>
        /// <remarks>
        /// Left at zero on purpose, and said out loud. Starting at zero is
        /// wrong and obvious; starting ten times too high is wrong and
        /// plausible, and it is the one a bill would be written from.
        /// </remarks>
        [Test]
        public async Task CountersUnderAnotherScaleFactor_AreRefused()
        {

            const UInt32 tenTimesTooMuch = 500_000;

            Int16 scaleFactor;

            await using (var before = NewMeter())
            {
                await before.StartAsync();
                scaleFactor = before.Device.EnergyCounters.ScaleFactor;
            }

            WriteState(tenTimesTooMuch, 0, (Int16) (scaleFactor + 1));

            await using var after = NewMeter();
            await after.StartAsync();

            Assert.Multiple(() => {

                Assert.That(after.Device.EnergyCounters.ImportedWh, Is.Not.EqualTo(tenTimesTooMuch),
                            "the meter took a reading that means ten times the energy it was written down as");

                Assert.That(after.Device.EnergyCounters.ScaleFactor, Is.EqualTo(scaleFactor),
                            "and it kept its own scale factor");

                Assert.That(Said(after, "meter"), Does.Contain("scale factor"),
                            "it was refused without saying so, which leaves a meter silently at zero");

            });

        }

        #endregion

        #region AnUnreadableStateFile_StartsTheMeterAnyway()

        /// <summary>
        /// A meter that refused to start because of an unreadable file would be
        /// worse than one that starts at zero and says so.
        /// </summary>
        [Test]
        public async Task AnUnreadableStateFile_StartsTheMeterAnyway()
        {

            Directory.CreateDirectory(DataPath);
            File.WriteAllText(StatePath, "{ this is not what a meter wrote ");

            await using var meter = NewMeter();

            Assert.DoesNotThrowAsync(async () => await meter.StartAsync(),
                                     "an unreadable file stopped the meter from starting");

            Assert.That(Said(meter, "meter"), Does.Contain("start at zero"),
                        "the meter started at zero without saying why");

        }

        #endregion

        #region AMeterThatNeverRanBefore_SaysNothingAboutCounters()

        /// <summary>
        /// The first start of all is not a failure to restore anything, and
        /// should not read like one.
        /// </summary>
        [Test]
        public async Task AMeterThatNeverRanBefore_SaysNothingAboutCounters()
        {

            await using var meter = NewMeter();
            await meter.StartAsync();

            var said = Said(meter, "meter");

            Assert.Multiple(() => {
                Assert.That(said, Does.Not.Contain("came back where they were left"));
                Assert.That(said, Does.Not.Contain("could not be read back"));
            });

        }

        #endregion


        #region (private) Said(Meter, Tag), WriteState(...), FreeTCPPort()

        /// <summary>
        /// Everything the meter said under this tag, as one string to look in.
        /// </summary>
        private static String Said(ModbusTLSEnergyMeter Meter, String Tag)

            => String.Join(" | ", Meter.Log.Recent(500, Tag: Tag).Select(entry => entry.Message));

        /// <summary>
        /// A state file as a previous run would have left it.
        /// </summary>
        private void WriteState(UInt32 ImportedWh,
                                UInt32 ExportedWh,
                                Int16  ScaleFactor)
        {

            Directory.CreateDirectory(DataPath);

            File.WriteAllText(
                StatePath,
                new JObject(
                    new JProperty("importedWh",   ImportedWh),
                    new JProperty("exportedWh",   ExportedWh),
                    new JProperty("scaleFactor",  ScaleFactor),
                    new JProperty("savedAt",      DateTime.UtcNow.ToString("o"))
                ).ToString()
            );

        }

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
