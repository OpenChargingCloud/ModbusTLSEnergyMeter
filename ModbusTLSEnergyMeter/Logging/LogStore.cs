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

using System.Globalization;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Logging
{

    /// <summary>
    /// The event log on disk: one JSON object per line, one file per day, each
    /// line pointing back at the one before it and signed.
    /// </summary>
    /// <remarks>
    /// A meter is asked what happened long after it happened - which Modbus
    /// peer was turned away last Tuesday, when the clock last agreed with the
    /// time server - and a log that lives only in memory cannot answer any of
    /// that after a restart, a crash or a power cut.
    ///
    /// One line of JSON per entry, because that is the format that survives
    /// being read by something other than this program: grep finds a line, jq
    /// takes it apart, and a file that was truncated mid-write loses its last
    /// line and nothing else. One file per day, because that is how somebody
    /// asks for a log ("the day it stopped working") and how old ones are
    /// thrown away without reading them.
    ///
    /// Each line carries the hash of the line before it and a signature of its
    /// own, so that a line cannot be changed, removed or moved without every
    /// line after it saying so. What that is worth, and what it is not worth,
    /// is written down on <see cref="LogSigner"/>.
    ///
    /// A file that cannot be written does not take the meter down, and does not
    /// bury the console under one complaint per entry either. It is said once
    /// on stderr, every following entry is tried again, and the first one that
    /// makes it is preceded by a line saying how many are missing, since when
    /// and which numbers they had - a line of the chain like any other, signed
    /// and pointing back at the last one written before the failure. Without it
    /// the chain simply went on from there, and a log with a hole in it was
    /// called intact.
    /// </remarks>
    public sealed class LogStore : IDisposable
    {

        #region Data

        /// <summary>
        /// The directory the files go in, below the meter's data path.
        /// </summary>
        public const  String  DefaultDirectoryName  = "logs";

        /// <summary>
        /// How many days of them are kept.
        /// </summary>
        public const  Int32   DefaultKeepDays       = 30;

        /// <summary>
        /// How much of a day's file is read back at a start, at most.
        /// </summary>
        /// <remarks>
        /// A busy day can leave a file of any size, and a meter that read all
        /// of it to show the last 2000 lines would take longer to start the
        /// busier it had been. The tail is all anybody wants; the rest of the
        /// file is still there for whoever asks the file itself.
        /// </remarks>
        public const  Int64   MaxTailBytes          = 8L * 1024 * 1024;

        /// <summary>
        /// What the fields the chain is made of are called on the wire.
        /// </summary>
        public const  String  PrevProperty          = "prev";
        public const  String  KeyProperty           = "key";
        public const  String  HashProperty          = "hash";
        public const  String  SignatureProperty     = "sig";

        private readonly Lock     padlock  = new();

        private FileStream?       file;
        private DateOnly          fileDay;
        private Boolean           disposed;

        /// <summary>
        /// Since when entries have not made it into a file, how many, and the
        /// number of the first of them, while writing fails; null and zero
        /// while it works.
        /// </summary>
        private DateTimeOffset?   failingSince;
        private UInt64            missed;
        private UInt64            firstMissed;

        #endregion

        #region Properties

        /// <summary>
        /// Where the files are.
        /// </summary>
        public String     Path       { get; }

        /// <summary>
        /// How many days are kept before a file is deleted.
        /// </summary>
        public Int32      KeepDays   { get; }

        /// <summary>
        /// The key every line is signed with.
        /// </summary>
        public LogSigner  Signer     { get; }

        /// <summary>
        /// The hash of the newest line: the head of the chain.
        /// </summary>
        /// <remarks>
        /// This is the one value worth taking somewhere else. Everything in the
        /// directory can be rewritten by whoever can write the directory, this
        /// value included - but a copy of it kept where they cannot reach says
        /// what the log ended with, and a log that no longer leads to it has
        /// been rewritten no matter how well it signs itself.
        /// </remarks>
        public String     Head       { get; private set; } = "";

        /// <summary>
        /// What went wrong the last time writing failed, or null.
        /// </summary>
        /// <remarks>
        /// Kept rather than thrown: a meter whose disk is full must go on
        /// measuring and go on answering Modbus. It says so once, here and on
        /// stderr, and does not die of it; the log itself says what it missed
        /// once it can be written again.
        /// </remarks>
        public String?    LastError  { get; private set; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Open a log store in the given directory, creating it - and the
        /// signing key - if needed.
        /// </summary>
        /// <param name="Path">Where the files go.</param>
        /// <param name="KeepDays">How many days of them are kept.</param>
        public LogStore(String  Path,
                        Int32?  KeepDays   = null)
        {

            this.Path      = System.IO.Path.GetFullPath(Path);
            this.KeepDays  = KeepDays ?? DefaultKeepDays;

            Directory.CreateDirectory(this.Path);

            this.Signer    = new LogSigner(this.Path);

        }

        #endregion


        #region Load(Limit)

        /// <summary>
        /// The newest entries that were written before this start, oldest of
        /// them first, and the highest number any of them carries.
        /// </summary>
        /// <remarks>
        /// The number matters as much as the entries: a browser follows this
        /// log by asking for everything after the last number it saw, so a
        /// meter that began again at 1 after a restart would hand it entries it
        /// would then decide it had already seen.
        ///
        /// The head of the chain is picked up here too, from the last line of
        /// the newest file, so that the first line written after a restart
        /// points back at the last one written before it. A restart is not a
        /// break in the chain.
        ///
        /// A line that cannot be read is skipped rather than fatal. A file
        /// truncated by a power cut ends in half a line, and that is the one
        /// moment the log is most worth having.
        /// </remarks>
        /// <param name="Limit">How many entries to read back, at most.</param>
        public (IReadOnlyList<LogEntry> Entries, UInt64 LastId) Load(Int32 Limit)
        {

            var collected = new List<LogEntry>();
            var lastId    = 0UL;

            try
            {

                var files = Files().ToArray();

                // The head first, and from the newest file only: it is the last
                // line of the whole log, wherever the reading below stops.
                foreach (var file in files.Reverse())
                {

                    var lines = TailLines(file);

                    for (var i = lines.Count - 1; i >= 0; i--)
                        if (TryReadLine(lines[i], out _, out _, out var hash) && hash.Length > 0)
                        {
                            Head = hash;
                            break;
                        }

                    if (Head.Length > 0)
                        break;

                }

                // Newest file first, and stop as soon as enough has been read:
                // a meter that has been running for a month should not read a
                // month of logs to show the last screenful.
                foreach (var file in files.Reverse())
                {

                    var lines = TailLines(file);

                    for (var i = lines.Count - 1; i >= 0 && collected.Count < Limit; i--)
                        if (TryReadLine(lines[i], out var entry, out _, out _))
                            collected.Add(entry);

                    if (collected.Count >= Limit)
                        break;

                }

            }
            catch (Exception e)
            {
                LastError = $"The log could not be read back: {e.Message}";
            }

            // Collected newest-first above; a log is replayed oldest-first.
            collected.Reverse();

            foreach (var entry in collected)
                if (entry.Id > lastId)
                    lastId = entry.Id;

            return (collected, lastId);

        }

        #endregion

        #region Append(Entry)

        /// <summary>
        /// Write one entry: chained onto the one before it, signed, and rolled
        /// over to a new file when the day turns.
        /// </summary>
        public void Append(LogEntry Entry)
        {

            lock (padlock)
            {

                if (disposed)
                    return;

                try
                {

                    var day = DateOnly.FromDateTime(Entry.Timestamp.UtcDateTime);

                    if (file is null || day != fileDay)
                    {

                        Close();

                        // Unbuffered, so that a line is on its way to the disk
                        // the moment it is written - the entries worth having
                        // afterwards are the ones written just before whatever
                        // went wrong - and so that nothing is left in a buffer
                        // to be written later, behind the chain's back, by the
                        // Dispose of a file that failed.
                        file    = new FileStream(
                                      System.IO.Path.Combine(this.Path, FileNameOf(day)),
                                      FileMode.Append,
                                      FileAccess.Write,
                                      FileShare.Read,
                                      bufferSize: 0
                                  );

                        fileDay = day;

                        Prune();

                    }

                    // The gap first, where it happened: a line of the chain like
                    // any other, signed and pointing back at the last line that
                    // made it, and numbered as the last of the entries it stands
                    // for - so that the numbers still only go up, somebody
                    // reading from the top meets it exactly where the entries
                    // stop making sense, and --verify-log walks through it.
                    if (failingSince is DateTimeOffset since)
                    {

                        var last = Entry.Id > 0 ? Entry.Id - 1 : 0;

                        WriteLine(new LogEntry(
                                      last,
                                      Entry.Timestamp,
                                      LogLevel.Warning,
                                      [ "meter", "log" ],
                                      $"{missed} entr{(missed == 1 ? "y" : "ies")} since {Stamp(since)} could not be written here " +
                                      (missed == 1 ? $"(number {firstMissed})." : $"(numbers {firstMissed} to {last}).")
                                  ));

                        Console.Error.WriteLine($"The log in '{this.Path}' is being written again; " +
                                                $"{missed} entr{(missed == 1 ? "y is" : "ies are")} missing from it, and it says so.");

                        failingSince  = null;
                        missed        = 0;
                        LastError     = null;

                    }

                    WriteLine(Entry);

                }
                catch (Exception e)
                {

                    // Once, and on stderr rather than through the log - going
                    // through the log would come back here and fail again. A
                    // disk that is full would otherwise fill the console with
                    // the news that the log cannot be written.
                    if (failingSince is null)
                    {

                        LastError     = $"The log could not be written to '{this.Path}': {e.Message}";
                        failingSince  = Entry.Timestamp;
                        firstMissed   = Entry.Id;

                        Console.Error.WriteLine($"{LastError} Every following entry is tried again, and the log will say what it missed.");

                    }

                    missed++;

                    Close();

                }

            }

        }

        #endregion

        #region (private) WriteLine(Entry)

        /// <summary>
        /// One entry as one line of the chain: pointing back at the line before
        /// it, hashed, signed, and on its way to the disk - or not written at
        /// all.
        /// </summary>
        private void WriteLine(LogEntry Entry)
        {

            var json = Entry.ToJSON();

            json.Add(PrevProperty, Head);
            json.Add(KeyProperty,  Signer.KeyId);

            // The bytes that are hashed and signed are the bytes that are
            // written, less the two fields carrying the hash and the signature
            // themselves - spliced in as text rather than added to the object,
            // so that checking a line never depends on a JSON library
            // serialising it the same way twice.
            var payload     = json.ToString(Formatting.None);
            var payloadUTF  = Encoding.UTF8.GetBytes(payload);

            var hash        = LogSigner.HashOf(payloadUTF);
            var signature   = Signer.Sign(payloadUTF);

            var line        = Encoding.UTF8.GetBytes(
                                  $"{payload[..^1]},\"{HashProperty}\":\"{hash}\",\"{SignatureProperty}\":\"{signature}\"}}" +
                                  Environment.NewLine
                              );

            var before      = file!.Length;

            try
            {
                file.Write(line);
            }
            catch
            {

                // And not half of it. A disk that fills up in the middle of a
                // line leaves part of it behind, and half a line is one the
                // chain cannot walk through: the log would be broken at the
                // very moment it was most worth having, and stay broken after
                // the gap was written down. Taken back while the handle still
                // allows it; what cannot be taken back is what a power cut
                // leaves as well.
                try   { file.SetLength(before); }
                catch { }

                throw;

            }

            Head = hash;

        }

        #endregion

        #region (private) Close()

        /// <summary>
        /// Let go of the open file, whatever state it is in.
        /// </summary>
        /// <remarks>
        /// A handle that failed may throw again on its way out; what it would
        /// have written is lost already, and a second error about it is not
        /// worth an exception in the middle of a meter's logging.
        /// </remarks>
        private void Close()
        {

            try   { file?.Dispose(); }
            catch { }

            file = null;

        }

        #endregion

        #region (private static) Stamp(Timestamp)

        /// <summary>
        /// A moment as a gap line names it: in full, in UTC, and in the same
        /// punctuation on every machine.
        /// </summary>
        private static String Stamp(DateTimeOffset Timestamp)

            => Timestamp.UtcDateTime.ToString("yyyy'-'MM'-'dd'T'HH':'mm':'ss'.'fff'Z'", CultureInfo.InvariantCulture);

        #endregion

        #region Verify(PublicKeyPem = null)

        /// <summary>
        /// Walk every file and say whether the log still leads to where it
        /// says it does.
        /// </summary>
        /// <remarks>
        /// Three questions per line, and they catch different things: the hash
        /// catches a line that was edited, the chain catches a line that was
        /// removed, moved or inserted, and the signature catches a line written
        /// by something that did not have this meter's key.
        ///
        /// It stops at the first line it cannot account for and says which.
        /// A log that is broken in the middle is not half-good: everything
        /// after the break is worth exactly as much as the break is.
        /// </remarks>
        /// <param name="PublicKeyPem">The key to check against, or null for this meter's own.</param>
        public LogVerification Verify(String? PublicKeyPem = null)
        {

            var files    = new List<LogFileVerification>();
            var previous = "";
            var lastId   = 0UL;
            var total    = 0;

            foreach (var file in Files())
            {

                var name     = System.IO.Path.GetFileName(file);
                var counted  = 0;
                String? problem = null;

                try
                {

                    // Every line, and not only the tail: this is the one place
                    // that has to read the whole file, because a line quietly
                    // removed from the middle is exactly what it is looking for.
                    //
                    // Sharing write, because the usual moment to ask this is of
                    // a meter that is running - and it is holding today's file
                    // open. File.ReadLines() would refuse it.
                    foreach (var line in AllLines(file))
                    {

                        if (line.Length == 0)
                            continue;

                        counted++;

                        if (!TrySplit(line, out var payload, out var hash, out var signature))
                        {
                            problem = $"line {counted} is not a signed log line";
                            break;
                        }

                        var payloadUTF = Encoding.UTF8.GetBytes(payload);

                        if (LogSigner.HashOf(payloadUTF) != hash)
                        {
                            problem = $"line {counted} does not match its own hash - it was changed after it was written";
                            break;
                        }

                        var json = JObject.Parse(payload);
                        var prev = json[PrevProperty]?.ToString() ?? "";
                        var id   = json["id"]?.ToObject<UInt64>() ?? 0;

                        if (prev != previous)
                        {
                            problem = previous.Length == 0
                                          ? $"line {counted} points back at a line that is not here"
                                          : $"line {counted} does not follow the line before it - something was removed, inserted or moved";
                            break;
                        }

                        if (id <= lastId && lastId > 0)
                        {
                            problem = $"line {counted} is numbered {id}, which does not come after {lastId}";
                            break;
                        }

                        var ok = PublicKeyPem is null
                                     ? Signer.Verify(payloadUTF, signature)
                                     : LogSigner.Verify(payloadUTF, signature, PublicKeyPem);

                        if (!ok)
                        {
                            problem = $"line {counted} is not signed by this key";
                            break;
                        }

                        previous  = hash;
                        lastId    = id;
                        total++;

                    }

                }
                catch (Exception e)
                {
                    problem = $"the file could not be read: {e.Message}";
                }

                files.Add(new LogFileVerification(name, counted, problem is null, problem));

                if (problem is not null)
                    break;

            }

            return new LogVerification(
                       files.All(file => file.IsIntact),
                       total,
                       previous,
                       Signer.KeyId,
                       files
                   );

        }

        #endregion

        #region Dispose()

        public void Dispose()
        {

            lock (padlock)
            {

                if (disposed)
                    return;

                disposed = true;

                Close();

                Signer.Dispose();

            }

        }

        #endregion


        #region (private) Files()

        /// <summary>
        /// Every log file, oldest first.
        /// </summary>
        private IEnumerable<String> Files()

            => Directory.Exists(this.Path)
                   ? Directory.EnumerateFiles(this.Path, "meter-*.jsonl").OrderBy(file => file, StringComparer.Ordinal)
                   : [];

        #endregion

        #region (private) Prune()

        /// <summary>
        /// Throw away what is older than <see cref="KeepDays"/>.
        /// </summary>
        /// <remarks>
        /// By the date in the name rather than by the age of the file, so that
        /// a directory copied from one machine to another keeps meaning what it
        /// said. Done when the day turns, which is also the only moment it can
        /// change anything.
        ///
        /// This does break the chain, and deliberately: the oldest file that is
        /// left begins with a line pointing at something that is gone. A check
        /// of the whole log says so, which is the honest answer - those days
        /// were thrown away on purpose.
        /// </remarks>
        private void Prune()
        {

            if (KeepDays < 1)
                return;

            var oldest = DateOnly.FromDateTime(DateTime.UtcNow).AddDays(-KeepDays);

            foreach (var file in Files())
            {

                var name = System.IO.Path.GetFileNameWithoutExtension(file);

                if (name.Length == "meter-yyyy-MM-dd".Length &&
                    DateOnly.TryParse(name["meter-".Length..], out var day) &&
                    day < oldest)
                {
                    try   { File.Delete(file); }
                    catch { /* a file somebody else holds open is not worth failing a write over */ }
                }

            }

        }

        #endregion

        #region (private static) FileNameOf(Day) / TailLines(Path)

        private static String FileNameOf(DateOnly Day)

            => $"meter-{Day:yyyy-MM-dd}.jsonl";


        /// <summary>
        /// Every line of a file, without minding that somebody is writing to it.
        /// </summary>
        private static IEnumerable<String> AllLines(String Path)
        {

            using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream, new UTF8Encoding(false));

            while (reader.ReadLine() is String line)
                yield return line;

        }


        /// <summary>
        /// The last <see cref="MaxTailBytes"/> of a file, as whole lines.
        /// </summary>
        private static List<String> TailLines(String Path)
        {

            var lines = new List<String>();

            using var stream = new FileStream(Path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);

            var skipFirst = false;

            if (stream.Length > MaxTailBytes)
            {
                stream.Seek(-MaxTailBytes, SeekOrigin.End);

                // The seek almost certainly landed inside a line, and half a
                // line is not an entry.
                skipFirst = true;
            }

            using var reader = new StreamReader(stream, new UTF8Encoding(false));

            if (skipFirst)
                reader.ReadLine();

            while (reader.ReadLine() is String line)
                if (line.Length > 0)
                    lines.Add(line);

            return lines;

        }

        #endregion

        #region (private static) TrySplit(Line, out Payload, out Hash, out Signature)

        /// <summary>
        /// One written line back into the three things it was made of.
        /// </summary>
        /// <remarks>
        /// By cutting the text at the two fields that were spliced onto it,
        /// rather than by parsing and re-serialising: the bytes that were
        /// signed are the bytes that were written, and nothing about checking
        /// them may depend on a JSON library writing the same object the same
        /// way twice.
        /// </remarks>
        private static Boolean TrySplit(String      Line,
                                        out String  Payload,
                                        out String  Hash,
                                        out String  Signature)
        {

            Payload = Hash = Signature = "";

            var marker = $",\"{HashProperty}\":\"";
            var cut    = Line.LastIndexOf(marker, StringComparison.Ordinal);

            if (cut < 0 || !Line.EndsWith('}'))
                return false;

            Payload = String.Concat(Line.AsSpan(0, cut), "}");

            try
            {

                var tail = JObject.Parse(String.Concat("{", Line.AsSpan(cut + 1)));

                Hash       = tail[HashProperty]?.     ToString() ?? "";
                Signature  = tail[SignatureProperty]?.ToString() ?? "";

                return Hash.Length > 0 && Signature.Length > 0;

            }
            catch
            {
                return false;
            }

        }

        #endregion

        #region (private static) TryReadLine(Line, out Entry, out Prev, out Hash)

        /// <summary>
        /// One line as the entry it carries, without asking whether it is
        /// signed correctly - that is <see cref="Verify"/>'s question.
        /// </summary>
        private static Boolean TryReadLine(String       Line,
                                           out LogEntry Entry,
                                           out String   Prev,
                                           out String   Hash)
        {

            Entry = default!;
            Prev  = Hash = "";

            try
            {

                // Old lines from before the chain, and lines written by hand,
                // are still entries - they simply carry no hash to follow.
                if (TrySplit(Line, out var payload, out var hash, out _))
                    Hash = hash;
                else
                    payload = Line;

                var json = JObject.Parse(payload);

                var id        = json["id"]?.       ToObject<UInt64>();
                var timestamp = json["timestamp"]?.ToObject<DateTimeOffset>();
                var message   = json["message"]?.  ToString();
                var level     = json["level"]?.    ToString();

                Prev = json[PrevProperty]?.ToString() ?? "";

                if (id is null || timestamp is null || message is null ||
                    !Enum.TryParse<LogLevel>(level, true, out var parsedLevel))
                    return false;

                Entry = new LogEntry(
                            id.Value,
                            timestamp.Value,
                            parsedLevel,
                            [.. json["tags"]?.Values<String>().Where(tag => tag is not null).Select(tag => tag!) ?? []],
                            message,
                            json["data"] as JObject
                        );

                return true;

            }
            catch
            {
                return false;
            }

        }

        #endregion

    }


    /// <summary>
    /// What a walk through the whole log found.
    /// </summary>
    /// <param name="IsIntact">Whether every line accounted for itself.</param>
    /// <param name="Entries">How many lines were checked.</param>
    /// <param name="Head">The hash the log ends at - the value worth keeping elsewhere.</param>
    /// <param name="KeyId">Which key it was checked against.</param>
    /// <param name="Files">One result per file, oldest first.</param>
    public sealed record LogVerification(Boolean                          IsIntact,
                                         Int32                            Entries,
                                         String                           Head,
                                         String                           KeyId,
                                         IReadOnlyList<LogFileVerification>  Files)
    {

        /// <summary>
        /// The first thing that was wrong, or null when nothing was.
        /// </summary>
        public String? FirstProblem
            => Files.FirstOrDefault(file => !file.IsIntact)?.Problem;

    }


    /// <summary>
    /// What that walk found in one file.
    /// </summary>
    /// <param name="Name">The file.</param>
    /// <param name="Entries">How many lines were read from it.</param>
    /// <param name="IsIntact">Whether all of them accounted for themselves.</param>
    /// <param name="Problem">The first one that did not, or null.</param>
    public sealed record LogFileVerification(String   Name,
                                             Int32    Entries,
                                             Boolean  IsIntact,
                                             String?  Problem);

}
