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

            Log.Info(
                $"The clock of this meter will be checked against {ntsClient.Hostname} every {TimeCheckEvery.TotalMinutes:F0} minute(s)" +
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
        /// Ask the time server what time it is: the key exchange first, then
        /// one authenticated NTP request.
        /// </summary>
        /// <remarks>
        /// The clock of this meter is not set from the answer, and that is
        /// deliberate: this says whether the time source can be reached and
        /// what it thinks of the local clock. Stepping the clock of a running
        /// meter is a different thing - every reading it hands out is stamped
        /// from here - and not something a check does by surprise.
        /// </remarks>
        public async Task<JObject> SyncTimeAsync(CancellationToken CancellationToken = default)
        {

            if (!NTSEnabled)
                return Failed("NTS is switched off on this energy meter.");

            var client     = ntsClient;
            var stopwatch  = Stopwatch.StartNew();

            try
            {

                #region NTS-KE

                var keyExchange = await client.GetNTSKERecords(CancellationToken: CancellationToken);

                if (!keyExchange.Success || keyExchange.Response is null)
                    return Failed($"The key exchange failed: {keyExchange.ErrorMessage}",
                                  new JProperty("step",           "ntske"),
                                  new JProperty("errorCategory",  keyExchange.ErrorCategory.ToString()));

                var response = keyExchange.Response;

                foreach (var warning in response.WarningMessages)
                    Log.Warning($"NTS: the key exchange with {client.Hostname} warned: {warning}", "nts", "ntske");

                // The cookies are what the NTP request below spends, so they go
                // into the pool before it is sent and not after.
                client.SeedCookies(response);

                #endregion

                #region NTP over NTS

                var query = await client.QueryTime(CancellationToken: CancellationToken);

                stopwatch.Stop();

                if (!query.Success || query.Response is null)
                    return Failed($"The NTP request failed: {query.ErrorMessage}",
                                  new JProperty("step",           "ntp"),
                                  new JProperty("errorCategory",  query.ErrorCategory.ToString()));

                #endregion

                // What the exchange was actually for: the difference between
                // what this meter believes and what a server that knows was
                // saying at the same moment.
                var offset = query.Response.ClockOffset;

                lastTimeCheck        = TimeProvider.GetUtcNow();
                lastTimeCheckOffset  = offset;
                lastTimeCheckServer  = client.Hostname.ToString();

                var answer = new JObject(
                                 new JProperty("ok",          true),
                                 new JProperty("server",      client.Hostname.ToString()),
                                 new JProperty("at",          TimeProvider.GetUtcNow().ToString("o")),
                                 new JProperty("runtime_ms",  stopwatch.ElapsedMilliseconds),
                                 new JProperty("offset_ms",   offset?.TotalMilliseconds)
                             );

                Log.Log(
                    Logging.LogLevel.Notice,
                    $"NTS: {client.Hostname} answered in {stopwatch.ElapsedMilliseconds} ms" +
                    (offset.HasValue ? $", this meter's clock is {offset.Value.TotalMilliseconds:+0.0;-0.0;0} ms off." : "."),
                    answer,
                    "nts", "clock"
                );

                return answer;

            }
            catch (Exception e)
            {
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
            var age       = lastTimeCheck.HasValue ? now - lastTimeCheck.Value : (TimeSpan?) null;

            var isRecent  = age.HasValue && age.Value <= LegalTimeMaxAge;
            var isClose   = lastTimeCheckOffset.HasValue &&
                            lastTimeCheckOffset.Value.Duration() <= LegalTimeTolerance;

            return new JObject(

                       new JProperty("now",                 now.ToString("o")),
                       new JProperty("ntsEnabled",          NTSEnabled),
                       new JProperty("server",              ntsClient.Hostname.ToString()),
                       new JProperty("checkEvery_s",        TimeCheckEvery.TotalSeconds),

                       new JProperty("lastCheck",           lastTimeCheck?.ToString("o")),
                       new JProperty("lastCheckServer",     lastTimeCheckServer),
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
