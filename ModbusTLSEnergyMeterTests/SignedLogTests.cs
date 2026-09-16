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

using cloud.charging.open.EnergyMeters.ModbusTLS.Logging;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What the signed log notices about somebody who edits it afterwards.
    /// </summary>
    /// <remarks>
    /// Written against the store directly rather than through a meter: what is
    /// under test is the chain and the signatures, and a meter logging away in
    /// the background would make every one of these tests race with it.
    /// </remarks>
    public class SignedLogTests
    {

        #region Data

        private String?  directory;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(
                            Path.GetTempPath(),
                            "ModbusTLSEnergyMeterTests",
                            Guid.NewGuid().ToString("N")
                        );

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {

            if (directory is not null && Directory.Exists(directory))
            {
                try   { Directory.Delete(directory, recursive: true); }
                catch { }
            }

        }

        #endregion


        #region AnUntouchedLog_Verifies()

        /// <summary>
        /// A log nobody has been at checks out, line by line.
        /// </summary>
        [Test]
        public void AnUntouchedLog_Verifies()
        {

            var head = WriteSomeEntries(6);

            using var store  = new LogStore(directory!);
            var       result = store.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.True, result.FirstProblem);
                Assert.That(result.Entries,       Is.EqualTo(6));
                Assert.That(result.Head,          Is.EqualTo(head), "the walk ended somewhere else than the writing did");
                Assert.That(result.FirstProblem,  Is.Null);
            });

        }

        #endregion

        #region AnEditedLine_IsFound()

        /// <summary>
        /// Changing what a line says breaks its own hash.
        /// </summary>
        [Test]
        public void AnEditedLine_IsFound()
        {

            WriteSomeEntries(6);

            Rewrite(lines => {
                lines[3] = lines[3].Replace("entry 4", "entry 4 (nothing happened)");
                return lines;
            });

            using var store  = new LogStore(directory!);
            var       result = store.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.False);
                Assert.That(result.FirstProblem,  Does.Contain("does not match its own hash"));
            });

        }

        #endregion

        #region ARemovedLine_IsFound()

        /// <summary>
        /// Taking a line out entirely breaks the line that followed it - which
        /// is the whole reason for the chain, because a removed line leaves
        /// nothing of its own behind to check.
        /// </summary>
        [Test]
        public void ARemovedLine_IsFound()
        {

            WriteSomeEntries(6);

            Rewrite(lines => { lines.RemoveAt(3); return lines; });

            using var store  = new LogStore(directory!);
            var       result = store.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.False);
                Assert.That(result.FirstProblem,  Does.Contain("does not follow the line before it"));
            });

        }

        #endregion

        #region AReorderedLog_IsFound()

        /// <summary>
        /// So does moving two of them around each other.
        /// </summary>
        [Test]
        public void AReorderedLog_IsFound()
        {

            WriteSomeEntries(6);

            Rewrite(lines => {
                (lines[2], lines[3]) = (lines[3], lines[2]);
                return lines;
            });

            using var store  = new LogStore(directory!);
            var       result = store.Verify();

            Assert.Multiple(() => {
                Assert.That(result.IsIntact,      Is.False);
                Assert.That(result.FirstProblem,  Does.Contain("does not follow the line before it"));
            });

        }

        #endregion

        #region ALineFromAnotherMeter_IsFound()

        /// <summary>
        /// A line signed by a different key does not pass, even when it is
        /// perfectly well formed.
        /// </summary>
        [Test]
        public void ALineFromAnotherMeter_IsFound()
        {

            WriteSomeEntries(3);

            // Another meter's log, with its own key, and one of its lines
            // pasted into this one.
            var elsewhere = Path.Combine(directory!, "elsewhere");
            Directory.CreateDirectory(elsewhere);

            using (var other = new LogStore(elsewhere))
                other.Append(new LogEntry(99, DateTimeOffset.UtcNow, LogLevel.Info, ["meter"], "a line from somewhere else"));

            var theirs = File.ReadAllLines(Directory.GetFiles(Path.Combine(elsewhere), "meter-*.jsonl")[0])[0];

            Rewrite(lines => { lines[1] = theirs; return lines; });

            using var store  = new LogStore(directory!);
            var       result = store.Verify();

            Assert.That(result.IsIntact, Is.False);

        }

        #endregion

        #region ATruncatedLog_StillVerifies_WhichIsWhatTheHeadIsFor()

        /// <summary>
        /// Cutting the end off a log leaves something that checks out
        /// perfectly - and this is the limit of what signing a file can do.
        /// </summary>
        /// <remarks>
        /// Every line that is left is genuine, follows the one before it, and
        /// is properly signed. Nothing inside the file says how long it was
        /// meant to be, and nothing can: the last line of any log looks exactly
        /// like the last line of a log.
        ///
        /// What catches it is the head, compared against a copy of it kept
        /// somewhere this meter cannot reach. That is why the head is on the
        /// store, in the answer of the verify resource and on the console -
        /// it is the one value worth writing down elsewhere.
        ///
        /// A test for a hole rather than for a feature, so that nobody later
        /// reads the green tests and concludes that the log cannot be cut.
        /// </remarks>
        [Test]
        public void ATruncatedLog_StillVerifies_WhichIsWhatTheHeadIsFor()
        {

            var head = WriteSomeEntries(6);

            Rewrite(lines => [.. lines.Take(3)]);

            using var store  = new LogStore(directory!);
            var       result = store.Verify();

            Assert.Multiple(() => {

                Assert.That(result.IsIntact,  Is.True,
                            "the remaining lines are genuine, and the file cannot know it was cut");

                Assert.That(result.Entries,   Is.EqualTo(3));

                Assert.That(result.Head,      Is.Not.EqualTo(head),
                            "but it no longer ends where it ended - which is what the head is compared for");

            });

        }

        #endregion

        #region TheChainCarriesOnAcrossARestart()

        /// <summary>
        /// A store opened again on the same directory continues the chain
        /// rather than beginning a new one.
        /// </summary>
        [Test]
        public void TheChainCarriesOnAcrossARestart()
        {

            WriteSomeEntries(3);

            using (var second = new LogStore(directory!))
            {

                second.Load(100);

                second.Append(new LogEntry(4, DateTimeOffset.UtcNow, LogLevel.Info, ["meter"], "entry 4 after a restart"));

                var verified = second.Verify();

                Assert.That(verified.IsIntact, Is.True,
                            $"the first line after the restart did not follow the last one before it: {verified.FirstProblem}");

            }

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// Write a few entries and hand back the head they ended at.
        /// </summary>
        private String WriteSomeEntries(Int32 Count)
        {

            using var store = new LogStore(directory!);

            for (var i = 1; i <= Count; i++)
                store.Append(
                    new LogEntry(
                        (UInt64) i,
                        DateTimeOffset.UtcNow,
                        LogLevel.Info,
                        ["meter", "test"],
                        $"entry {i}"
                    )
                );

            return store.Head;

        }

        /// <summary>
        /// Somebody with write access to the directory, having a go at it.
        /// </summary>
        private void Rewrite(Func<List<String>, List<String>> Change)
        {

            var file  = Directory.GetFiles(Path.Combine(directory!, ""), "meter-*.jsonl")[0];
            var lines = Change([.. File.ReadAllLines(file)]);

            File.WriteAllLines(file, lines);

        }

        #endregion

    }

}
