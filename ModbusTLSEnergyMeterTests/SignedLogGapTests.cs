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

using cloud.charging.open.EnergyMeters.ModbusTLS.Logging;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What the signed log does while its file cannot be written.
    /// </summary>
    /// <remarks>
    /// It used to set a LastError nobody read after the start, try every entry
    /// again in silence, and carry on the chain from the last line that made
    /// it once writing worked again - so that the entries in between were
    /// simply not there, and --verify-log called the log intact. Now the first
    /// failure is said once on stderr, and the first line that makes it is
    /// preceded by a signed line of the chain saying how many are missing,
    /// since when, and which numbers they had.
    ///
    /// The file is read back rather than the store asked what it believes it
    /// wrote, and the failure is made the way the vehicle's and the charging
    /// station's tests make it: a directory standing where the day's file
    /// should be. Not in parallel, because stderr is one for the whole process.
    /// </remarks>
    [NonParallelizable]
    public class SignedLogGapTests
    {

        #region Data

        private String        directory  = "";
        private TextWriter?   stderr;
        private StringWriter  said       = new();

        /// <summary>
        /// Two seconds before midnight, UTC: the next entries belong to a day
        /// whose file does not exist yet, which is where a failure can be made.
        /// </summary>
        private static readonly DateTimeOffset  lateOnTheDay  = new (2026, 9, 24, 23, 59, 58, TimeSpan.Zero);

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", "gap-" + Guid.NewGuid().ToString("N")[..12]);

            Directory.CreateDirectory(directory);

            stderr = Console.Error;
            said   = new StringWriter();

            Console.SetError(said);

        }

        [TearDown]
        public void TearDown()
        {

            if (stderr is not null)
                Console.SetError(stderr);

            try
            {
                if (Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch
            { }

        }

        #endregion


        #region (helpers) Entry(Id), DayFile(Day), Block(Day), Unblock(Day), Lines(Day), SaidLines()

        /// <summary>
        /// Entry number Id, a second after the one before it.
        /// </summary>
        private static LogEntry Entry(UInt64 Id)

            => new (Id,
                    lateOnTheDay.AddSeconds(Id),
                    LogLevel.Info,
                    [ "meter", "test" ],
                    $"entry {Id}");

        private String DayFile(Int32 Day)
            => Path.Combine(directory, $"meter-2026-09-{Day:00}.jsonl");

        /// <summary>
        /// What a broken disk looks like from here, made on purpose: something
        /// the day's file cannot be opened as.
        /// </summary>
        private void Block(Int32 Day)
            => Directory.CreateDirectory(DayFile(Day));

        private void Unblock(Int32 Day)
            => Directory.Delete(DayFile(Day));

        /// <summary>
        /// The day's file as it is on disk, read while the store still holds it
        /// open - sharing write, as the store's own reader does.
        /// </summary>
        private JObject[] Lines(Int32 Day)
        {

            using var stream = new FileStream(DayFile(Day), FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream);

            return [.. reader.ReadToEnd().Split('\n').Select(line => line.Trim()).Where(line => line.Length > 0).Select(JObject.Parse)];

        }

        private String[] SaidLines()
            => [.. said.ToString().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)];

        #endregion


        #region AFileThatCannotBeWrittenIsSaidOnceAndItsGapWrittenDown()

        /// <summary>
        /// Three entries while the day's file is blocked: said once, and the
        /// first entry that makes it afterwards is preceded by the gap.
        /// </summary>
        [Test]
        public void AFileThatCannotBeWrittenIsSaidOnceAndItsGapWrittenDown()
        {

            using var store = new LogStore(directory);

            store.Append(Entry(1));

            Block(25);

            store.Append(Entry(2));
            store.Append(Entry(3));
            store.Append(Entry(4));

            var whileBlocked = SaidLines();

            Unblock(25);

            store.Append(Entry(5));

            var today = Lines(25);
            var gap   = today[0];

            Assert.Multiple(() =>
            {

                Assert.That(whileBlocked,                   Has.Length.EqualTo(1),  "not said once: " + String.Join(" | ", whileBlocked));
                Assert.That(whileBlocked.FirstOrDefault(),  Does.Contain("could not be written").And.Contain(directory));

                Assert.That(today,                          Has.Length.EqualTo(2),  "the gap and the entry that made it");

                Assert.That(gap.Value<String>("message"),   Does.StartWith("3 entries since 2026-09-25T00:00:00.000Z could not be written here"));
                Assert.That(gap.Value<String>("message"),   Does.Contain("numbers 2 to 4"));
                Assert.That(gap.Value<String>("level"),     Is.EqualTo("warning"));
                Assert.That(gap.Value<UInt64>("id"),        Is.EqualTo(4),          "numbered as the last of the entries it stands for");

                Assert.That(today[1].Value<String>("message"),  Is.EqualTo("entry 5"));

                Assert.That(SaidLines().Skip(1).FirstOrDefault(),  Does.Contain("being written again").And.Contain("3 entries"));

            });

            // And the chain walks through it: the gap is a line of the log
            // like any other, signed and pointing back at the last line that
            // made it before the failure.
            var verified = store.Verify();

            Assert.Multiple(() =>
            {
                Assert.That(verified.IsIntact,  Is.True,              verified.FirstProblem);
                Assert.That(verified.Entries,   Is.EqualTo(3));
                Assert.That(verified.Head,      Is.EqualTo(store.Head));
            });

        }

        #endregion

        #region ASecondFailureIsSaidAgainAndCountedAfresh()

        /// <summary>
        /// Once writing works again, the next failure is a new one: said again,
        /// and its own gap counted from zero.
        /// </summary>
        [Test]
        public void ASecondFailureIsSaidAgainAndCountedAfresh()
        {

            using var store = new LogStore(directory);

            store.Append(Entry(1));

            Block(25);
            store.Append(Entry(2));
            Unblock(25);

            store.Append(Entry(3));

            // A day later, the same again.
            Block(26);
            store.Append(new LogEntry(4, lateOnTheDay.AddDays(1).AddSeconds(4), LogLevel.Info, [ "meter", "test" ], "entry 4"));
            store.Append(new LogEntry(5, lateOnTheDay.AddDays(1).AddSeconds(5), LogLevel.Info, [ "meter", "test" ], "entry 5"));
            Unblock(26);

            store.Append(new LogEntry(6, lateOnTheDay.AddDays(1).AddSeconds(6), LogLevel.Info, [ "meter", "test" ], "entry 6"));

            var said = SaidLines();

            Assert.Multiple(() =>
            {

                Assert.That(said.Count(line => line.Contains("could not be written")),  Is.EqualTo(2),  String.Join(" | ", said));
                Assert.That(said.Count(line => line.Contains("being written again")),   Is.EqualTo(2),  String.Join(" | ", said));

                Assert.That(Lines(25)[0].Value<String>("message"),  Does.StartWith("1 entry since").And.Contain("number 2"));
                Assert.That(Lines(26)[0].Value<String>("message"),  Does.StartWith("2 entries since").And.Contain("numbers 4 to 5"));

                Assert.That(store.Verify().IsIntact,  Is.True,  store.Verify().FirstProblem);

            });

        }

        #endregion

    }

}
