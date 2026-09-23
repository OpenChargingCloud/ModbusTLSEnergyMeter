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

using System.Diagnostics;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// What time this meter thinks it is, and what that is worth.
    /// </summary>
    /// <remarks>
    /// An energy meter whose readings are worth anything has to be able to say
    /// when it read them, and "when" is only as good as the clock behind it. So
    /// the clock is checked against a time source that authenticates itself,
    /// and what that check found is kept where a reader can see it - including
    /// the case where the last check is too old to mean anything any more.
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region Properties

        /// <summary>
        /// How often this meter checks its clock against its time server.
        /// </summary>
        public TimeSpan  TimeCheckEvery
            => ntsSettings?.CheckEvery ?? NTSConfiguration.DefaultCheckEvery;

        /// <summary>
        /// Who the operator says stands behind that server's time, e.g. "PTB".
        /// </summary>
        public String?   LegalTimeAuthority
            => ntsSettings?.LegalTimeAuthority;

        /// <summary>
        /// How far this meter's own clock may be from it and still count.
        /// </summary>
        public TimeSpan  LegalTimeTolerance
            => ntsSettings?.LegalTimeTolerance ?? NTSConfiguration.DefaultLegalTolerance;

        /// <summary>
        /// How old the last check may be and still count.
        /// </summary>
        public TimeSpan  LegalTimeMaxAge
            => ntsSettings?.LegalTimeMaxAge ?? NTSConfiguration.DefaultLegalMaxAge;

        #endregion


        #region (private) StartCheckingTheClock()

        /// <summary>
        /// Begin checking this meter's clock against its time server.
        /// </summary>
        /// <remarks>
        /// Through the meter's own <see cref="TimeProvider"/> rather than a
        /// bare timer, so that a test which moves the clock moves this too.
        ///
        /// The first check is one minute in rather than at once: everything
        /// else is still coming up, the network may not be there yet, and a
        /// meter that says "unverified" for a minute after a start is telling
        /// the truth.
        /// </remarks>
        private void StartCheckingTheClock()
        {

            timeCheckTimer?.Dispose();
            timeCheckTimer = null;

            if (!NTSEnabled)
            {
                Log.Info("The clock of this meter is not being checked: NTS is switched off.", "nts", "clock");
                return;
            }

            timeCheckTimer = TimeProvider.CreateTimer(
                                 _ => _ = CheckTheClockAsync(),
                                 null,
                                 TimeSpan.FromMinutes(1),
                                 TimeCheckEvery
                             );

            // Named rather than counted, because this is written once at a
            // start and somebody reading it is checking that the file took
            // effect. "4 time servers" would not tell them which four.
            var asking = timeSources.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()).ToArray();

            Log.Info(
                $"The clock of this meter will be checked against {String.Join(", ", asking)} every {TimeCheckEvery.TotalMinutes:F0} minute(s)" +
                (asking.Length > 1 ? $", at least {timeSources.MinServers} of which must answer" : "") +
                (LegalTimeAuthority is not null ? $", which the operator says is {LegalTimeAuthority}." : "."),
                "nts", "clock"
            );

        }

        #endregion

        #region (private) CheckTheClockAsync()

        /// <summary>
        /// One check, quietly.
        /// </summary>
        /// <remarks>
        /// A failed check is a warning and not an exception: a time server that
        /// cannot be reached for ten minutes is a thing that happens, and
        /// <see cref="ClockJSON"/> already says the time is unverified when the
        /// last check is stale.
        /// </remarks>
        private async Task CheckTheClockAsync()
        {

            try
            {

                var result = await SyncTimeAsync();

                if (result.Value<Boolean>("ok") != true)
                    Log.Warning(
                        $"The clock of this meter could not be checked: {result.Value<String>("error") ?? "no answer"}.",
                        "nts", "clock"
                    );

            }
            catch (Exception e)
            {
                Log.Warning($"The clock of this meter could not be checked: {e.Message}", "nts", "clock");
            }

        }

        #endregion

        #region SyncTimeAsync(CancellationToken = default)

        /// <summary>
        /// Ask this meter's group of time servers what the time is.
        /// </summary>
        /// <remarks>
        /// The group and not a single client, because a clock that a signed
        /// reading is stamped from should not be believed on the word of one
        /// server. What comes back is the group's verdict: the offset the
        /// servers that answered and authenticated agree on, how many there
        /// were, and how far apart they were, with a line for each server -
        /// because a log book records what was asked and what each one said,
        /// not only the conclusion.
        ///
        /// The clock of this meter is still not set from the answer, and that
        /// is deliberate and unchanged: every reading this meter hands out is
        /// stamped from that clock, and stepping it by surprise is a different
        /// thing from finding out that it is off.
        /// </remarks>
        public async Task<JObject> SyncTimeAsync(CancellationToken CancellationToken = default)
        {

            if (!NTSEnabled)
                return Failed("NTS is switched off on this energy meter.");

            var group      = timeSources;
            var asked      = group.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()).ToArray();
            var stopwatch  = Stopwatch.StartNew();

            Log.Info($"NTS: asking the {asked.Length} time server(s) of group '{group.Name}' ...", "nts", "clock");

            try
            {

                var verdict = await group.Measure(timeEngine, dnsClient, CancellationToken);

                stopwatch.Stop();

                #region What the group concluded, and what each server said

                var servers = new JArray(
                                  verdict.Results.Select(result => new JObject(
                                      new JProperty("hostname",       result.ServerHostname.ToString()),
                                      new JProperty("ok",             TimeSyncVerdict.CanBeTrusted(result)),
                                      new JProperty("offset_ms",      result.NTP?.Offset.TotalMilliseconds),
                                      new JProperty("roundTrip_ms",   result.NTP?.RoundTripDelay.TotalMilliseconds),
                                      new JProperty("authenticated",  result.NTP?.NTSAuthenticationValid),
                                      new JProperty("keyExchange",    result.NTSKEFromCache ? "reused" : "new"),
                                      new JProperty("error",          result.ErrorMessage?.ToString())
                                  ))
                              );

                var groupJSON = new JObject(
                                    new JProperty("name",               group.Name),
                                    new JProperty("answered",           verdict.Answered),
                                    new JProperty("required",           verdict.Required),
                                    new JProperty("offset_ms",          verdict.Offset?.TotalMilliseconds),
                                    new JProperty("spread_ms",          verdict.Spread?.TotalMilliseconds),
                                    new JProperty("deviationExceeded",  verdict.DeviationExceeded)
                                );

                #endregion

                if (!verdict.IsUsable)
                {

                    Log.Error($"NTS: group '{group.Name}' produced no time after {stopwatch.ElapsedMilliseconds} ms: {verdict}.", "nts", "clock");

                    return Failed(
                               verdict.Outcome == TimeSyncOutcome.NothingAnswered
                                   ? "No time server answered."
                                   : $"Only {verdict.Answered} of {verdict.Required} time server(s) answered.",
                               new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                               new JProperty("group",       groupJSON),
                               new JProperty("servers",     servers)
                           );

                }

                // What the asking was actually for: the difference between what
                // this meter believes and what servers that know were saying at
                // the same moment.
                lastTimeCheck          = TimeProvider.GetUtcNow();
                lastTimeCheckOffset    = verdict.Offset;
                lastTimeCheckAsked     = asked.Length;
                lastTimeCheckAnswered  = verdict.Answered;

                // A name only where naming one is the truth. Four servers
                // answering is not "checked against ptbtime1", and picking one
                // of them to print would be the nicer-looking lie.
                lastTimeCheckServer    = asked.Length == 1
                                             ? asked[0]
                                             : null;

                // Written down rather than acted on: the disagreement belongs
                // in the log, and the time is still a time.
                if (verdict.DeviationExceeded)
                    Log.Warning(
                        $"NTS: the time servers of group '{group.Name}' disagree by " +
                        $"{verdict.Spread!.Value.TotalMilliseconds:F1} ms, which reaches the agreed deviation of " +
                        $"{group.MaxDeviation.TotalSeconds:F0} s.",
                        "nts", "clock"
                    );

                var answer = new JObject(
                                 new JProperty("ok",          true),
                                 new JProperty("server",      $"{group.Name}: {String.Join(", ", asked)}"),
                                 new JProperty("at",          TimeProvider.GetUtcNow().ToString("o")),
                                 new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                                 new JProperty("offset_ms",   verdict.Offset?.TotalMilliseconds),
                                 new JProperty("group",       groupJSON),
                                 new JProperty("servers",     servers)
                             );

                Log.Log(
                    Logging.LogLevel.Notice,
                    $"NTS: group '{group.Name}' answered in {stopwatch.ElapsedMilliseconds} ms - {verdict}.",
                    answer,
                    "nts", "clock"
                );

                return answer;

            }
            catch (Exception e)
            {
                stopwatch.Stop();
                Log.Error($"NTS: asking group '{group.Name}' failed after {stopwatch.ElapsedMilliseconds} ms: {e.Message}", "nts", "clock");
                return Failed(e.Message);
            }

        }

        #endregion

        #region ClockJSON()

        /// <summary>
        /// What time it is here, and what that is worth.
        /// </summary>
        /// <remarks>
        /// "Legal" is not a claim this meter can make on its own: it holds only
        /// while a check against a time source the operator vouches for is both
        /// recent enough and close enough. Either of those failing makes the
        /// time ordinary again, and this says which.
        /// </remarks>
        /// <summary>
        /// Whether this meter's clock has ever been set from a time server.
        /// </summary>
        /// <remarks>
        /// What a signed reading needs to know, and less than
        /// <see cref="ClockJSON"/>'s "isLegalTime": a document says how far its
        /// timestamp can be trusted with one letter, and the honest letter is
        /// "S" only when something outside this meter has confirmed the time at
        /// least once. Claiming a synchronised clock it does not have would be
        /// lying about the one field of a reading that cannot be checked
        /// afterwards.
        /// </remarks>
        public Boolean ClockIsSynchronised

            => lastTimeCheck.HasValue;

                public JObject ClockJSON()
        {

            var now       = TimeProvider.GetUtcNow();
            var asking    = timeSources.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()).ToArray();
            var age       = lastTimeCheck.HasValue ? now - lastTimeCheck.Value : (TimeSpan?) null;

            var isRecent  = age.HasValue && age.Value <= LegalTimeMaxAge;
            var isClose   = lastTimeCheckOffset.HasValue &&
                            lastTimeCheckOffset.Value.Duration() <= LegalTimeTolerance;

            return new JObject(

                       new JProperty("now",                 now.ToString("o")),
                       new JProperty("ntsEnabled",          NTSEnabled),
                       // A name where naming one is the truth, and null where it
                       // is not: four servers are not "the server". The list
                       // beside it is what a page should draw.
                       new JProperty("server",              asking.Length == 1 ? asking[0] : null),
                       new JProperty("servers",             new JArray(asking)),
                       new JProperty("minServers",          timeSources.MinServers),
                       new JProperty("checkEvery_s",        TimeCheckEvery.TotalSeconds),

                       new JProperty("lastCheck",           lastTimeCheck?.ToString("o")),
                       new JProperty("lastCheckServer",     lastTimeCheckServer),
                       new JProperty("lastCheckAsked",      lastTimeCheckAsked),
                       new JProperty("lastCheckAnswered",   lastTimeCheckAnswered),
                       new JProperty("lastCheckAge_s",      age?.TotalSeconds),
                       new JProperty("lastCheckOffset_ms",  lastTimeCheckOffset?.TotalMilliseconds),

                       new JProperty("legalAuthority",      LegalTimeAuthority),
                       new JProperty("legalTolerance_ms",   LegalTimeTolerance.TotalMilliseconds),
                       new JProperty("legalMaxAge_s",       LegalTimeMaxAge.TotalSeconds),

                       // Only the operator naming an authority makes the
                       // question meaningful at all; without one this is an
                       // ordinary clock that happens to be checked.
                       new JProperty("isLegalTime",         LegalTimeAuthority is not null && isRecent && isClose),
                       new JProperty("why",                 LegalTimeAuthority is null ? "no time authority is configured"
                                                                : !lastTimeCheck.HasValue ? "the clock has not been checked yet"
                                                                : !isRecent               ? "the last check is too old"
                                                                : !isClose                ? "the clock is further off than the tolerance allows"
                                                                :                           "checked, recent and within tolerance")

                   );

        }

        #endregion

        #region (private static) Failed(Error, ...)

        private static JObject Failed(String                 Error,
                                      params JProperty[]  Details)
        {

            var json = new JObject(
                           new JProperty("ok",     false),
                           new JProperty("error",  Error)
                       );

            foreach (var detail in Details)
                json.Add(detail);

            return json;

        }

        #endregion

    }

}
