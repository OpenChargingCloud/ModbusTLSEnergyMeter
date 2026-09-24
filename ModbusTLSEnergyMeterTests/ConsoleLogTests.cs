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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// Who gets to write on the console once somebody is typing on it.
    /// </summary>
    /// <remarks>
    /// The command line of the program owns the line being typed, and the
    /// meter's log has to ask it for the screen rather than write over that
    /// line. What is measured here is the meter's half of that: every entry
    /// the console would have shown is handed over, whole, and nothing that
    /// the console would not have shown is.
    ///
    /// The meters are constructed and never started, as in the tests of the
    /// nts section: nothing asked of them here needs a port, and a meter that
    /// is not started has no timer that could log in the middle of a count.
    /// Not in parallel, because the console is one for the whole process.
    /// </remarks>
    [NonParallelizable]
    public class ConsoleLogTests
    {

        #region Data

        private String  fixtureDirectory  = "";
        private String  pkiDirectory      = "";
        private String  directory         = "";

        #endregion

        #region OneTimeSetup / Setup / TearDown / OneTimeTearDown

        [OneTimeSetUp]
        public async Task OneTimeSetup()
        {

            fixtureDirectory  = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "console-log-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helper) Meter(LogToConsole)

        /// <summary>
        /// A meter whose log does or does not reach the console, with no days
        /// of it on disk and no configuration file.
        /// </summary>
        private ModbusTLSEnergyMeter Meter(Boolean LogToConsole)

            => new (
                   SerialNumber:       "meter-console-001",
                   ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                   ServerPfxPassword:  "demo",
                   ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                   DataPath:           Path.Combine(directory, "data"),
                   ConfigFile:         new MeterConfigFile(Path.Combine(directory, MeterConfigFile.DefaultFileName)),
                   LogKeepDays:        0,
                   LogToConsole:       LogToConsole
               );

        #endregion


        #region EveryEntryTheConsoleWouldShowIsHandedOver()

        /// <summary>
        /// Handed over rather than written, and only what the console shows.
        /// </summary>
        /// <remarks>
        /// What is handed over is run here, with the console's output caught,
        /// because being asked is only half of it: what the command line is
        /// given has to write the entry, and write all of it.
        /// </remarks>
        [Test]
        public async Task EveryEntryTheConsoleWouldShowIsHandedOver()
        {

            await using var meter = Meter(LogToConsole: true);

            var handed = new List<Action>();

            meter.ShareConsoleWith(handed.Add);

            meter.Log.Info ("Somebody is typing, and this has to wait its turn.", "test");
            meter.Log.Debug("Below what the console shows, so nobody is asked.",  "test");

            var output   = new StringWriter();
            var previous = Console.Out;

            Console.SetOut(output);

            try
            {
                foreach (var write in handed)
                    write();
            }
            finally
            {
                Console.SetOut(previous);
            }

            Assert.Multiple(() => {

                Assert.That(handed, Has.Count.EqualTo(1),
                            "Either an entry went past whoever holds the console, or a debug entry was put on it.");

                // The message rather than the whole line, whose shape depends
                // on whether this runner's output counts as a terminal: in
                // colour the level and the tags are written without brackets.
                Assert.That(output.ToString(), Does.Contain("Somebody is typing, and this has to wait its turn."));

            });

        }

        #endregion

        #region WithoutAConsoleThereIsNothingToShare()

        /// <summary>
        /// A meter whose log does not reach the console has nothing to hand
        /// over, and asking it to is not an error.
        /// </summary>
        [Test]
        public async Task WithoutAConsoleThereIsNothingToShare()
        {

            await using var meter = Meter(LogToConsole: false);

            var handed = 0;

            meter.ShareConsoleWith(write => handed++);

            meter.Log.Warning("Nobody is watching the console of this one.", "test");

            Assert.That(handed, Is.Zero);

        }

        #endregion

    }

}
