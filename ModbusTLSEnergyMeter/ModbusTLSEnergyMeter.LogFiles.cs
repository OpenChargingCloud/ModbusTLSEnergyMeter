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

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// How long the ordinary log files of a meter are kept.
    /// </summary>
    /// <remarks>
    /// The node keeps every day's log file, which suits a simulator somebody
    /// empties now and then and not a meter left running for a year. So the
    /// meter thins them out after <see cref="LogKeepDays"/> days, as its
    /// signed log was thinned out before it was a node. What it never thins
    /// out is the log book, the node's metrological log, beside them: it is
    /// evidence, and evidence that threw itself away would be asked why by the
    /// first person who needed it.
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// How often the old log files are looked for.
        /// </summary>
        public static readonly TimeSpan PruneLogFilesEvery = TimeSpan.FromHours(6);

        #endregion


        #region (private) StartPruningTheLogFiles()

        private void StartPruningTheLogFiles()
        {

            logFileTimer?.Dispose();
            logFileTimer = null;

            if (LogPath is null || LogKeepDays < 1)
                return;

            logFileTimer = TimeProvider.CreateTimer(
                               _ => PruneTheLogFiles(),
                               null,
                               TimeSpan.Zero,
                               PruneLogFilesEvery
                           );

        }

        #endregion

        #region (internal) PruneTheLogFiles()

        /// <summary>
        /// Delete the ordinary log files older than <see cref="LogKeepDays"/>
        /// days, by the date in their names, and nothing else.
        /// </summary>
        /// <remarks>
        /// By the date in the name rather than by the age of the file, so that a
        /// directory copied from one machine to another keeps meaning what it
        /// said. Only "meter-yyyy-MM-dd.log": the log book's files end in
        /// ".jsonl", and whatever else somebody put there is theirs.
        /// </remarks>
        /// <returns>How many files were deleted.</returns>
        internal Int32 PruneTheLogFiles()
        {

            if (LogPath is null || LogKeepDays < 1 || !Directory.Exists(LogPath))
                return 0;

            var oldest   = DateOnly.FromDateTime(TimeProvider.GetUtcNow().UtcDateTime).AddDays(-LogKeepDays);
            var prefix   = $"{Kind.LogFilePrefix}-";
            var deleted  = 0;

            foreach (var file in Directory.EnumerateFiles(LogPath, $"{prefix}*.log"))
            {

                var name = Path.GetFileNameWithoutExtension(file);

                if (name.Length == prefix.Length + "yyyy-MM-dd".Length &&
                    DateOnly.TryParseExact(name[prefix.Length..], "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var day) &&
                    day < oldest)
                {
                    try
                    {
                        File.Delete(file);
                        deleted++;
                    }
                    catch
                    {
                        // A file somebody else holds open is not worth failing
                        // over; it is tried again in six hours.
                    }
                }

            }

            if (deleted > 0)
                Log.Info($"{deleted} log file(s) older than {LogKeepDays} day(s) were deleted from '{LogPath}'; the log book beside them is kept whole.",
                         "meter", "log");

            return deleted;

        }

        #endregion

    }

}
