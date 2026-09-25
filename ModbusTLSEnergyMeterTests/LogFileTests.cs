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

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// How long the log files of a meter are kept - and that the log book
    /// beside them is kept whole, however old it is.
    /// </summary>
    /// <remarks>
    /// The meters are constructed and never started: the files are thinned out
    /// on request here, on a clock of the test's own, so that nothing depends
    /// on what day it is or on when a timer fires.
    /// </remarks>
    public class LogFileTests
    {

        #region Data

        private String  fixtureDirectory  = "";
        private String  pkiDirectory      = "";
        private String  directory         = "";

        /// <summary>
        /// A clock that says one time, whenever it is asked.
        /// </summary>
        private sealed class FixedClock(DateTimeOffset Now) : TimeProvider
        {
            public override DateTimeOffset GetUtcNow()
                => Now;
        }

        #endregion

        #region OneTimeSetup / Setup / TearDown / OneTimeTearDown

        [OneTimeSetUp]
        public async Task OneTimeSetup()
        {

            fixtureDirectory  = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "log-files-" + Guid.NewGuid().ToString("N")[..12]);
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


        #region (helper) Meter(LogKeepDays, Now)

        private ModbusTLSEnergyMeter Meter(Int32           LogKeepDays,
                                           DateTimeOffset  Now)

            => new (
                   SerialNumber:       "meter-log-files-001",
                   ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                   ServerPfxPassword:  "demo",
                   ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                   DataPath:           Path.Combine(directory, "data"),
                   ConfigFile:         new WWCPConfigFile(Path.Combine(directory, WWCPConfigFile.DefaultFileName)),
                   LogKeepDays:        LogKeepDays,
                   LogToConsole:       false,
                   TimeProvider:       new FixedClock(Now)
               );

        #endregion


        #region TheLogFilesOlderThanTheDaysKept_AreDeleted_AndNothingElse()

        /// <summary>
        /// Seven days kept: the log file of eight days ago goes, the one of
        /// seven days ago stays - and the log book, a file that is not a day's
        /// and a file that is not the meter's all stay, whatever their dates.
        /// </summary>
        [Test]
        public async Task TheLogFilesOlderThanTheDaysKept_AreDeleted_AndNothingElse()
        {

            var now    = DateTimeOffset.UtcNow;
            var today  = DateOnly.FromDateTime(now.UtcDateTime);

            await using var meter = Meter(LogKeepDays: 7, Now: now);

            var logs   = meter.LogPath!;

            Directory.CreateDirectory(logs);

            String Day(Int32 DaysAgo, String Extension)
                => Path.Combine(logs, $"meter-{today.AddDays(-DaysAgo):yyyy-MM-dd}{Extension}");

            // Not today's: that one is the meter's own, and open.
            var expired  = new[] { Day(30, ".log"),
                                   Day( 8, ".log") };

            var kept     = new[] { Day( 7, ".log"),
                                   Day( 1, ".log"),
                                   Day(30, ".jsonl"),
                                   Path.Combine(logs, "meter-notes.log"),
                                   Path.Combine(logs, "notes-2020-01-01.log") };

            foreach (var file in expired.Concat(kept))
                File.WriteAllText(file, "a line" + Environment.NewLine);

            var deleted = meter.PruneTheLogFiles();

            Assert.Multiple(() => {

                Assert.That(deleted, Is.EqualTo(expired.Length));

                foreach (var file in expired)
                    Assert.That(File.Exists(file), Is.False, $"'{Path.GetFileName(file)}' is older than seven days, and was kept");

                foreach (var file in kept)
                    Assert.That(File.Exists(file), Is.True,  $"'{Path.GetFileName(file)}' was deleted");

            });

        }

        #endregion

        #region TheLogBook_CarriesOnTheChainOfTheSignedLogBeforeIt()

        /// <summary>
        /// The log book is written where the meter's signed log was written
        /// before the meter was a node, and goes on from the line that log
        /// ended at: one chain, and one check for all of it.
        /// </summary>
        [Test]
        public async Task TheLogBook_CarriesOnTheChainOfTheSignedLogBeforeIt()
        {

            var logs = Path.Combine(directory, "data", ModbusTLSEnergyMeter.LogDirectoryName);

            // What a meter from before left behind: its signed log, one line
            // long, in files called as they always were.
            String headBefore;

            using (var before = new SignedLog(logs, "meter"))
            {
                before.Append(new LogEntry(1, DateTimeOffset.UtcNow, LogLevel.Notice, [ "meter" ], "Written before the meter was a node."));
                headBefore = before.Head;
            }

            await using var meter = Meter(LogKeepDays: 7, Now: DateTimeOffset.UtcNow);

            meter.Log.Metrological(LogLevel.Notice, "Written by the meter as a node.", "meter");

            var result = meter.MetrologicalLog!.Verify();

            Assert.Multiple(() => {
                Assert.That(meter.MetrologicalLog.Path,  Is.EqualTo(Path.GetFullPath(logs)),  "the log book is written somewhere else");
                Assert.That(result.IsIntact,             Is.True,                             result.FirstProblem);
                Assert.That(result.Entries,              Is.GreaterThanOrEqualTo(2));
                Assert.That(result.Head,                 Is.Not.EqualTo(headBefore),          "nothing was added to it");
            });

        }

        #endregion

        #region AMeterThatWritesNoLogFiles_DeletesNone()

        /// <summary>
        /// No days kept means no log files written - and none deleted either,
        /// from a directory that only happens to be where they would be.
        /// </summary>
        [Test]
        public async Task AMeterThatWritesNoLogFiles_DeletesNone()
        {

            await using var meter = Meter(LogKeepDays: 0, Now: DateTimeOffset.UtcNow);

            var logs = Path.Combine(directory, "data", ModbusTLSEnergyMeter.LogDirectoryName);
            var old  = Path.Combine(logs, "meter-2020-01-01.log");

            Directory.CreateDirectory(logs);
            File.WriteAllText(old, "a line" + Environment.NewLine);

            Assert.Multiple(() => {
                Assert.That(meter.LogPath,             Is.Null);
                Assert.That(meter.PruneTheLogFiles(),  Is.Zero);
                Assert.That(File.Exists(old),          Is.True, "a meter that writes no log files deleted one");
            });

        }

        #endregion

    }

}
