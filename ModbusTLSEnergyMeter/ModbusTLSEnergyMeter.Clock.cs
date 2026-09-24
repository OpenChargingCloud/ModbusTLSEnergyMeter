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
using System.Globalization;

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
            var asking = CheckedAgainst();

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

            // Remembered whichever way it goes, and before it is answered:
            // what the page shows as the last synchronisation must be this one
            // from the moment its answer exists.
            JObject Remember(JObject Result)
            {
                lastTimeSync = Result;
                return Result;
            }

            var group      = timeSources;
            var asked      = group.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()).ToArray();
            var stopwatch  = Stopwatch.StartNew();

            var asking     = asked.Select(hostname => hostname.TrimEnd('.')).ToArray();

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

                    return Remember(Failed(
                               verdict.Outcome == TimeSyncOutcome.NothingAnswered
                                   ? "No time server answered."
                                   : $"Only {verdict.Answered} of {verdict.Required} time server(s) answered.",
                               new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                               new JProperty("group",       groupJSON),
                               new JProperty("servers",     servers)
                           ));

                }

                // What the asking was actually for: the difference between what
                // this meter believes and what servers that know were saying at
                // the same moment.
                lastTimeCheck          = TimeProvider.GetUtcNow();
                lastTimeCheckOffset    = verdict.Offset;
                // The servers actually asked, which is fewer than those switched
                // on when the first band was enough: "2 of 3 answered" read as a
                // server that failed, where the third had not been asked at all.
                lastTimeCheckAsked     = verdict.Results.Count;
                lastTimeCheckAnswered  = verdict.Answered;

                // A name only where naming one is the truth. Four servers
                // answering is not "checked against ptbtime1", and picking one
                // of them to print would be the nicer-looking lie.
                lastTimeCheckServer    = asking.Length == 1
                                             ? asking[0]
                                             : null;

                // Written down rather than acted on: the disagreement belongs
                // in the log, and the time is still a time.
                if (verdict.DeviationExceeded)
                    Log.Warning(DisagreementLine(group, verdict), "nts", "clock");

                var answer = new JObject(
                                 new JProperty("ok",          true),
                                 new JProperty("server",      $"{group.Name}: {String.Join(", ", asking)}"),
                                 new JProperty("at",          TimeProvider.GetUtcNow().ToString("o")),
                                 new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                                 new JProperty("offset_ms",   verdict.Offset?.TotalMilliseconds),
                                 new JProperty("group",       groupJSON),
                                 new JProperty("servers",     servers)
                             );

                Log.Log(
                    Logging.LogLevel.Notice,
                    AnsweredLine(group, stopwatch.ElapsedMilliseconds, verdict),
                    answer,
                    "nts", "clock"
                );

                return Remember(answer);

            }
            catch (Exception e)
            {
                stopwatch.Stop();
                Log.Error($"NTS: asking group '{group.Name}' failed after {stopwatch.ElapsedMilliseconds} ms: {e.Message}", "nts", "clock");
                return Remember(Failed(e.Message));
            }

        }

        #endregion

        #region ClockIsSynchronised

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

        #endregion

        #region (private) CheckedAgainst()

        /// <summary>
        /// The time servers the clock check asks: those switched on, in the
        /// order their bands are asked in.
        /// </summary>
        /// <remarks>
        /// Trimmed, because both places this goes are read by somebody: a
        /// sentence in the log, and the clock's JSON for the NTS page. The root
        /// dot belongs on a name going back into a file - see how the
        /// configuration is written - and not in the middle of prose, where it
        /// reads as a typing mistake.
        /// </remarks>
        private String[] CheckedAgainst()

            => [.. timeSources.Bands().SelectMany(band => band).Select(source => source.Hostname.Trimmed)];

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
        public JObject ClockJSON()
        {

            var now       = TimeProvider.GetUtcNow();
            var age       = lastTimeCheck.HasValue ? now - lastTimeCheck.Value : (TimeSpan?) null;

            var isRecent  = age.HasValue && age.Value <= LegalTimeMaxAge;
            var isClose   = lastTimeCheckOffset.HasValue &&
                            lastTimeCheckOffset.Value.Duration() <= LegalTimeTolerance;

            return new JObject(

                       new JProperty("now",                 now.ToString("o")),
                       new JProperty("ntsEnabled",          NTSEnabled),

                       // Against whom: the group the check asks, as the line at
                       // the start names it - and nobody while NTS is switched
                       // off, rather than servers that are not asked. There
                       // used to be a "server" beside it, naming one of them
                       // where there was only one, which the list says as well.
                       new JProperty("group",               NTSEnabled ? timeSources.Name : null),
                       new JProperty("servers",             NTSEnabled ? new JArray(CheckedAgainst()) : null),
                       new JProperty("minServers",          NTSEnabled ? timeSources.MinServers : null),
                       new JProperty("checkEvery_s",        TimeCheckEvery.TotalSeconds),

                       new JProperty("lastCheck",           lastTimeCheck?.ToString("o")),
                       new JProperty("lastCheckServer",     lastTimeCheckServer),
                       new JProperty("lastCheckAsked",      lastTimeCheckAsked),
                       new JProperty("lastCheckAnswered",   lastTimeCheckAnswered),
                       new JProperty("lastCheckAge_s",      age?.TotalSeconds),
                       new JProperty("lastCheckOffset_ms",  lastTimeCheckOffset?.TotalMilliseconds),

                       // The last synchronisation, whichever way it went, beside
                       // the last one that found a time: the moment alone reads
                       // as a success, and one that found no server has a
                       // moment just as much.
                       new JProperty("lastSync",            lastTimeSync?.Value<String>("at")),
                       new JProperty("lastSyncResult",      LastSyncSaid(lastTimeSync)),

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

        #region (internal static) AnsweredLine    (Group, Milliseconds, Verdict)

        /// <summary>
        /// What the log says when the group had a time.
        /// </summary>
        internal static String AnsweredLine(TimeSourceGroup  Group,
                                            Int64            Milliseconds,
                                            TimeSyncVerdict  Verdict)

            => $"NTS: group '{Group.Name}' answered in {Milliseconds} ms - {Verdict}.";

        #endregion

        #region (internal static) DisagreementLine(Group, Verdict)

        /// <summary>
        /// What the log says when the servers that answered are further apart
        /// than the group's agreed deviation.
        /// </summary>
        /// <remarks>
        /// Invariant, like the verdict it is logged beside: the sentence is
        /// English and goes into a record, whose numbers should not change
        /// their punctuation with the machine that wrote them. And the agreed
        /// deviation with as many places as it has - it may be set as low as a
        /// millisecond, and a whole-second format wrote that as "0 s".
        /// </remarks>
        internal static String DisagreementLine(TimeSourceGroup  Group,
                                                TimeSyncVerdict  Verdict)

            => String.Format(CultureInfo.InvariantCulture,
                             "NTS: the time servers of group '{0}' disagree by {1:F1} ms, " +
                             "which reaches the agreed deviation of {2:0.###} s.",
                             Group.Name,
                             Verdict.Spread!.Value.TotalMilliseconds,
                             Group.MaxDeviation.TotalSeconds);

        #endregion

        #region (private static) LastSyncSaid(Sync)

        /// <summary>
        /// How the last synchronisation went, in a few words: that it
        /// succeeded and how far off the clock was, or why it did not.
        /// </summary>
        /// <param name="Sync">The last synchronisation, or null while there has been none.</param>
        private static String? LastSyncSaid(JObject? Sync)
        {

            if (Sync is null)
                return null;

            if (Sync.Value<Boolean>("ok"))
                return Sync.Value<Double?>("offset_ms") is Double offset
                           ? String.Format(CultureInfo.InvariantCulture,
                                           "succeeded, the clock is {0:+0.0;-0.0;0.0} ms off", offset)
                           : "succeeded";

            return $"failed: {Sync.Value<String>("error") ?? "no reason was given"}";

        }

        #endregion

        #region (private) Failed(Error, ...)

        private JObject Failed(String                 Error,
                               params JProperty[]     Details)
        {

            // With the moment, like an answer that found a time: this is what
            // the page shows as the last synchronisation, and a failure needs
            // to say when it happened just as much.
            var json = new JObject(
                           new JProperty("ok",     false),
                           new JProperty("at",     TimeProvider.GetUtcNow().ToString("o")),
                           new JProperty("error",  Error)
                       );

            foreach (var detail in Details)
                json.Add(detail);

            return json;

        }

        #endregion

    }

}
