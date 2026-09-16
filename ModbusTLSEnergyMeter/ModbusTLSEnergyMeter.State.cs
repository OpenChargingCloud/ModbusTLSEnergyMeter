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

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// How often the energy counters are written down.
        /// </summary>
        /// <remarks>
        /// A crash loses at most this much of what was measured since the last
        /// save, and it is lost downwards - the counters come back where they
        /// were written, never ahead of it. That is the right side to be wrong
        /// on: a meter that came back slightly high would be one billing for
        /// energy nobody used.
        /// </remarks>
        public static readonly TimeSpan SaveCountersEvery = TimeSpan.FromSeconds(10);

        #endregion

        #region (private) StatePath

        /// <summary>
        /// Where the counters that have to outlive this process are kept.
        /// </summary>
        private String StatePath

            => Path.Combine(DataPath, "meter-state.json");

        #endregion

        #region (private) RestoreTheEnergyCounters()

        /// <summary>
        /// Put the energy counters back where the last run left them.
        /// </summary>
        /// <remarks>
        /// A real meter's energy register is monotonic and survives losing
        /// power; most of what makes it a meter rather than a sensor is that it
        /// does. This simulation held its counters in memory, so every restart
        /// put them back to zero - which is invisible until something spans a
        /// restart, and then produces a charging session that used a negative
        /// amount of energy.
        ///
        /// Called before the device starts measuring, and never afterwards: a
        /// counter that jumps is the one thing a meter must not do.
        /// </remarks>
        private void RestoreTheEnergyCounters()
        {

            try
            {

                if (!File.Exists(StatePath))
                    return;

                var json         = MeterJSON.ReadFile(StatePath);

                var imported     = json["importedWh"]?. Value<UInt32>();
                var exported     = json["exportedWh"]?. Value<UInt32>();
                var scaleFactor  = json["scaleFactor"]?.Value<Int16>();

                if (imported is null || exported is null || scaleFactor is null)
                    return;

                if (Device.RestoreEnergyCounters(imported.Value, exported.Value, scaleFactor.Value))
                    Log.Info(
                        $"The energy counters came back where they were left: " +
                        $"{imported} imported, {exported} exported (scale factor {scaleFactor}).",
                        "meter"
                    );

                else
                    Log.Warning(
                        $"The energy counters were written down under scale factor {scaleFactor} and this meter " +
                        $"runs with {Device.EnergyCounters.ScaleFactor}, so they were left at zero rather than " +
                         "read as a different amount of energy.",
                        "meter"
                    );

            }
            catch (Exception e)
            {
                // A meter that refused to start because of an unreadable file
                // would be worse than one that starts at zero and says so.
                Log.Warning($"The energy counters could not be read back, so they start at zero: {e.Message}", "meter");
            }

        }

        #endregion

        #region (private) SaveTheEnergyCounters()

        /// <summary>
        /// Write the energy counters down.
        /// </summary>
        /// <remarks>
        /// On a timer, on an orderly stop, and at both ends of a charging
        /// session. The last of those is the one that earns its place: a
        /// session's start reading is written into the session file, and if the
        /// counter behind it were not written down at the same moment, a crash
        /// in between would leave a session starting at a reading the meter no
        /// longer stands at.
        /// </remarks>
        internal void SaveTheEnergyCounters()
        {

            try
            {

                var (imported, exported, scaleFactor) = Device.EnergyCounters;

                var json = new JObject(
                               new JProperty("importedWh",   imported),
                               new JProperty("exportedWh",   exported),
                               new JProperty("scaleFactor",  scaleFactor),
                               new JProperty("savedAt",      TimeProvider.GetUtcNow().UtcDateTime.ToString("o"))
                           );

                // Written beside and moved into place, so that a process dying
                // mid-write leaves the previous counters rather than half of
                // the new ones.
                var temporary = StatePath + ".new";

                File.WriteAllText(temporary, json.ToString());
                File.Move(temporary, StatePath, overwrite: true);

            }
            catch (Exception e)
            {
                Log.Warning($"The energy counters could not be written down: {e.Message}", "meter");
            }

        }

        #endregion

        #region (private) ResumeTheChargingSession()

        /// <summary>
        /// Say what happened to the charging session that was running when this
        /// meter last stopped.
        /// </summary>
        /// <remarks>
        /// Nothing to resume, strictly: the session store read it back when it
        /// was opened, and the session has been running the whole time as far as
        /// anybody charging is concerned. What this does is say so, and check
        /// the two things that could have gone wrong while the process was away
        /// - the key it has to be signed with could have been removed, and the
        /// energy counters could have come back below where it started.
        /// </remarks>
        private void ResumeTheChargingSession()
        {

            if (sessions.Current is not Signing.ChargingSession session)
                return;

            Log.Notice(
                $"The charging session '{session.Id}' was running when this meter last stopped and still is: " +
                $"started {session.StartedAt.UtcDateTime:yyyy-MM-dd HH:mm:ss}Z at {session.StartValue} kWh.",
                "sessions"
            );

            if (signingKeys.Get(session.KeyId) is null)
                Log.Warning(
                    $"The key '{session.KeyId}' that session has to be signed with is gone, so it cannot be " +
                     "stopped into a document. Whoever is charging is still being measured; the session is not.",
                    "sessions", "signing"
                );

            var (imported, _, scaleFactor) = Device.EnergyCounters;
            var standingAt                 = (Decimal) (imported * Math.Pow(10, scaleFactor)) / 1000m;

            if (standingAt < session.StartValue)
                Log.Warning(
                    $"That session started at {session.StartValue} kWh and this meter now stands at {standingAt} kWh. " +
                     "Stopping it would have to report less energy than none, so it will be refused until the " +
                     "counter passes where it began.",
                    "sessions", "meter"
                );

        }

        #endregion

        #region (private) StartSavingTheEnergyCounters()

        private void StartSavingTheEnergyCounters()
        {

            stateTimer?.Dispose();

            stateTimer = TimeProvider.CreateTimer(
                             _ => SaveTheEnergyCounters(),
                             null,
                             SaveCountersEvery,
                             SaveCountersEvery
                         );

        }

        #endregion

    }

}
