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

using System.Diagnostics.CodeAnalysis;
using System.Globalization;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Norn.NTS;
using org.GraphDefined.Vanaheimr.Norn.TimeSync;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// What this meter resolves names with, and what it reads the time from -
    /// both changeable while it runs, because an address is a thing that
    /// changes around a device that stays where it is.
    /// </summary>
    public partial class ModbusTLSEnergyMeter
    {

        #region DNS

        #region DNSConfigurationJSON()

        /// <summary>
        /// How this meter resolves names, as it stands.
        /// </summary>
        public JObject DNSConfigurationJSON()

            => new DNSConfiguration(
                   Enabled:           DNSEnabled,
                   Servers:           configuredDNSServers,
                   QueryTimeout:      dnsClient.QueryTimeout,
                   RecursionDesired:  dnsClient.RecursionDesired,
                   UseCache:          dnsClient.UseCache,
                   DnssecOK:          dnsClient.DnssecOK,
                   FollowCNAMEs:      dnsClient.FollowCNAMEs,
                   MaxCNAMEFollows:   dnsClient.MaxCNAMEFollows,
                   MaxRetries:        dnsClient.MaxRetries
               ).ToJSON();

        #endregion

        #region TryUpdateDNSConfiguration(JSON, out Error)

        /// <summary>
        /// Change how this meter resolves names, and write that down.
        /// </summary>
        /// <remarks>
        /// The file is written first and the change made second: a setting that
        /// took effect but was not saved comes back at the next start as
        /// something else, and nobody would know which of the two this meter is
        /// actually running as.
        /// </remarks>
        public Boolean TryUpdateDNSConfiguration(JObject                           JSON,
                                                 [NotNullWhen(false)] out String?  Error)
        {

            if (!DNSConfiguration.TryParse(JSON, out var configuration, out Error))
                return false;

            if (!ConfigFile.TryMergeSection(DNSConfiguration.SectionName, JSON, out Error))
                return false;

            ApplyDNSConfiguration(configuration);

            return true;

        }

        #endregion

        #region (private) ApplyDNSConfiguration(Configuration)

        /// <summary>
        /// Put a DNS section into effect. What it does not mention is left as
        /// it is.
        /// </summary>
        private void ApplyDNSConfiguration(DNSConfiguration Configuration)
        {

            var changed = new List<String>();

            if (Configuration.Servers is not null &&
                !configuredDNSServers.SequenceEqual(Configuration.Servers))
            {
                configuredDNSServers = Configuration.Servers;
                changed.Add($"servers = {String.Join(", ", configuredDNSServers)}");
            }

            if (Configuration.Enabled.HasValue && DNSEnabled != Configuration.Enabled.Value)
            {
                DNSEnabled = Configuration.Enabled.Value;
                changed.Add(DNSEnabled ? "switched on" : "switched off");
            }

            // Always, not only when one of the two above changed: the client
            // must end up holding exactly the servers this meter means it to
            // hold, and working that out from which halves changed is how the
            // two drift apart.
            dnsClient.SetDNSServers(DNSEnabled ? configuredDNSServers : []);

            if (Configuration.QueryTimeout.HasValue && dnsClient.QueryTimeout != Configuration.QueryTimeout.Value)
            {
                dnsClient.QueryTimeout = Configuration.QueryTimeout.Value;
                changed.Add($"query timeout = {dnsClient.QueryTimeout}");
            }

            if (Configuration.RecursionDesired.HasValue && dnsClient.RecursionDesired != Configuration.RecursionDesired)
            {
                dnsClient.RecursionDesired = Configuration.RecursionDesired;
                changed.Add($"recursion desired = {Configuration.RecursionDesired}");
            }

            if (Configuration.UseCache.HasValue && dnsClient.UseCache != Configuration.UseCache.Value)
            {
                dnsClient.UseCache = Configuration.UseCache.Value;
                changed.Add($"use cache = {dnsClient.UseCache}");
            }

            if (Configuration.DnssecOK.HasValue && dnsClient.DnssecOK != Configuration.DnssecOK.Value)
            {
                dnsClient.DnssecOK = Configuration.DnssecOK.Value;
                changed.Add($"DNSSEC OK = {dnsClient.DnssecOK}");
            }

            if (Configuration.FollowCNAMEs.HasValue && dnsClient.FollowCNAMEs != Configuration.FollowCNAMEs.Value)
            {
                dnsClient.FollowCNAMEs = Configuration.FollowCNAMEs.Value;
                changed.Add($"follow CNAMEs = {dnsClient.FollowCNAMEs}");
            }

            if (Configuration.MaxCNAMEFollows.HasValue && dnsClient.MaxCNAMEFollows != Configuration.MaxCNAMEFollows.Value)
            {
                dnsClient.MaxCNAMEFollows = Configuration.MaxCNAMEFollows.Value;
                changed.Add($"max CNAME follows = {dnsClient.MaxCNAMEFollows}");
            }

            if (Configuration.MaxRetries.HasValue && dnsClient.MaxRetries != Configuration.MaxRetries.Value)
            {
                dnsClient.MaxRetries = Configuration.MaxRetries.Value;
                changed.Add($"max retries = {dnsClient.MaxRetries}");
            }

            if (changed.Count > 0)
                Log.Notice($"DNS configuration changed: {String.Join(", ", changed)}.", "dns", "config");

        }

        #endregion

        #endregion

        #region NTS

        #region NTSConfigurationJSON()

        /// <summary>
        /// Where this meter reads the time: the group of time servers, the rules
        /// it is held to, and what legal time rests on.
        /// </summary>
        /// <remarks>
        /// The group, and nothing about the single client beside it. This
        /// answer used to be that client's host and ports - one server, which
        /// was the one the page's form edited - while the clock has been checked
        /// against the whole group since there were groups; and saving that
        /// form told this meter a lone host name, which made the group that one
        /// server.
        /// </remarks>
        public JObject NTSConfigurationJSON()

            => new (

                   new JProperty("enabled",      NTSEnabled),

                   // What may be changed, as it is in effect. The quorum is the
                   // one this meter was told; the group's own, below, can be
                   // lower when it has fewer servers switched on.
                   new JProperty("settings",     new JObject(
                       new JProperty("timeoutSeconds",             ntsClient.Timeout?.TotalSeconds),
                       new JProperty("checkEverySeconds",          TimeCheckEvery.TotalSeconds),
                       new JProperty("minServers",                 ntsQuorum),
                       new JProperty("maxDeviationSeconds",        timeSources.MaxDeviation.TotalSeconds),
                       new JProperty("legalTimeAuthority",         LegalTimeAuthority),
                       new JProperty("legalTimeToleranceSeconds",  LegalTimeTolerance.TotalSeconds),
                       new JProperty("legalTimeMaxAgeSeconds",     LegalTimeMaxAge.TotalSeconds)
                   )),

                   // Every server, in the order configured, the switched-off
                   // ones included: this is the list the page edits and sends
                   // back whole, and a server missing from it because it was
                   // switched off would be deleted by the next save of anything
                   // else. With the key exchange each one holds from the
                   // group's own asking, which is what a check spends.
                   new JProperty("timeSources",  new JArray(
                       timeSources.Sources.Select(source => {

                           var held = timeEngine.KeyExchanges.TryGetValue(source.Hostname, out var state) ? state : null;

                           return new JObject(
                                      new JProperty("hostname",      source.Hostname.ToString()),
                                      new JProperty("priority",      source.Priority),
                                      new JProperty("ntsKEPort",     source.NTSKEPort.ToUInt16()),
                                      new JProperty("ntpPort",       source.NTPPort.  ToUInt16()),
                                      new JProperty("enabled",       source.Enabled),
                                      new JProperty("cookies",       held?.RemainingCookies),
                                      new JProperty("lastExchange",  held?.LastRefreshed.ToString("o"))
                                  );

                       })
                   )),

                   new JProperty("group",        new JObject(
                       new JProperty("name",                 timeSources.Name),
                       new JProperty("minServers",           timeSources.MinServers),
                       new JProperty("maxDeviationSeconds",  timeSources.MaxDeviation.TotalSeconds)
                   )),

                   new JProperty("limits",       new JObject(
                       new JProperty("maxTimeout",          NTSConfiguration.MaxTimeoutSeconds),
                       new JProperty("minCheckEvery",       NTSConfiguration.MinCheckEverySeconds),
                       new JProperty("maxCheckEvery",       NTSConfiguration.MaxCheckEverySeconds),
                       new JProperty("minDeviation",        NTSConfiguration.MinDeviationSeconds),
                       new JProperty("maxDeviation",        NTSConfiguration.MaxDeviationSeconds),
                       new JProperty("minTolerance",        NTSConfiguration.MinToleranceSeconds),
                       new JProperty("maxTolerance",        NTSConfiguration.MaxToleranceSeconds),
                       new JProperty("minMaxAge",           NTSConfiguration.MinMaxAgeSeconds),
                       new JProperty("maxMaxAge",           NTSConfiguration.MaxMaxAgeSeconds),
                       new JProperty("maxAuthorityLength",  NTSConfiguration.MaxAuthorityLength),
                       new JProperty("defaultNTSKEPort",    NTSClient.DefaultNTSKE_Port.ToUInt16()),
                       new JProperty("defaultNTPPort",      NTSClient.DefaultNTP_Port.  ToUInt16())
                   )),

                   new JProperty("file",         ConfigFile.Path)

               );

        #endregion

        #region TryUpdateNTSConfiguration(JSON, out Error)

        /// <summary>
        /// Change where this meter reads the time, and write that down.
        /// </summary>
        /// <remarks>
        /// What is sent is part of the section, laid over what is in effect -
        /// the switch sends "enabled" and nothing else. What is written into the
        /// file is what was read of it rather than the text that was sent, so
        /// that a key this meter does not know is not kept as if it meant
        /// something.
        /// </remarks>
        public Boolean TryUpdateNTSConfiguration(JObject                           JSON,
                                                 [NotNullWhen(false)] out String?  Error)
        {

            if (!NTSConfiguration.TryParse(JSON, out var configuration, out Error))
                return false;

            lock (ntsLock)
            {

                // Before the file, so that what is refused is not written down
                // either - and inside the lock, because the servers a quorum on
                // its own is checked against are the ones in effect.
                if (!TryCheckNTSQuorum(configuration, out Error))
                    return false;

                // And the file as the next start will read it. Each half can
                // be fine and the two together not: the quorum the file holds
                // and a list saved now that is shorter than it would be a
                // section the next start refuses, and a meter that does not
                // start because of a save that was accepted.
                if (!ConfigFile.TryPreviewSection(NTSConfiguration.SectionName, configuration.ToJSON(), configuration.RemovedKeys, out var merged, out Error))
                    return false;

                if (!NTSConfiguration.TryParse(merged, out _, out var mergedError))
                {
                    Error = $"{mergedError} Nothing was changed.";
                    return false;
                }

                if (!ConfigFile.TryMergeSection(NTSConfiguration.SectionName, configuration.ToJSON(), configuration.RemovedKeys, out Error))
                    return false;

                ApplyNTSConfiguration(configuration);

                return true;

            }

        }

        #endregion

        #region (private) ApplyNTSConfiguration(Configuration)

        /// <summary>
        /// Put an NTS section into effect. What it does not mention is left as
        /// it is.
        /// </summary>
        private void ApplyNTSConfiguration(NTSConfiguration Configuration)
        {

            // Kept whole: what this method does with the client is only half of
            // it, and the other half - how often to check, and what the
            // operator claims about the server - is read from elsewhere and
            // much later. See ModbusTLSEnergyMeter.Clock.cs.
            //
            // Laid over what was kept rather than put in its place. A save sends
            // part of the section, and replaced by that part the rest went back
            // to its defaults until the next start read the file again: saving
            // the time server's settings took the legal time authority away,
            // and saving the legal time's settings put the interval back to
            // fifteen minutes.
            var wasCheckingEvery  = TimeCheckEvery;
            var wasEnabled        = NTSEnabled;
            var wasAuthority      = LegalTimeAuthority;

            ntsSettings = ntsSettings?.OverriddenBy(Configuration) ?? Configuration;

            var changed  = new List<String>();

            #region The group of time servers

            var wasServers    = Described(timeSources);
            var wasQuorum     = timeSources.MinServers;
            var wasDeviation  = timeSources.MaxDeviation;

            if (Configuration.MinServers.HasValue)
                ntsQuorum = Configuration.MinServers.Value;

            // The servers only when the section says something about them. That
            // is this method's rule everywhere else, and it earns its place here
            // now that the servers have a default worth keeping: a section
            // mentioning nothing but "enabled" would otherwise quietly reduce
            // four servers to one.
            //
            // Rebuilt from the section rather than patched when it does: it is a
            // list, and working out which entry changed in order to report it
            // would say less than naming the servers, which is what happens
            // below.
            var sources       = Configuration.Servers  is not null ||
                                Configuration.Hostname is not null
                                    ? Configuration.ToGroup(Configuration.Hostname ?? ntsClient.Hostname).Sources
                                    : timeSources.Sources;

            // The quorum and the deviation by the same rule, and on their own as
            // well. They used to count only beside a list or a hostname, so a
            // section saying nothing but "minServers": 3 was read and changed
            // nothing; and a list without a quorum was held to one, whatever
            // had been agreed before.
            timeSources       = new TimeSourceGroup(
                                    timeSources.Name,
                                    sources,
                                    NTSConfiguration.QuorumFor(ntsQuorum, sources),
                                    Configuration.MaxDeviation ?? timeSources.MaxDeviation
                                );

            var nowServers    = Described(timeSources);

            if (wasServers != nowServers)
                changed.Add($"time servers = {nowServers}");

            if (wasQuorum != timeSources.MinServers)
                changed.Add($"quorum = {timeSources.MinServers}");

            if (wasDeviation != timeSources.MaxDeviation)
                changed.Add($"agreed deviation = {timeSources.MaxDeviation.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)} s");

            #endregion


            var hostname = Configuration.Hostname  ?? ntsClient.Hostname;
            var ntsKE    = Configuration.NTSKEPort ?? ntsClient.NTSKE_Port;
            var ntp      = Configuration.NTPPort   ?? ntsClient.NTP_Port;

            if (hostname != ntsClient.Hostname ||
                ntsKE    != ntsClient.NTSKE_Port ||
                ntp      != ntsClient.NTP_Port)
            {

                ntsClient = new NTSClient(
                                hostname,
                                NTSKE_Port:    ntsKE,
                                NTP_Port:      ntp,
                                Timeout:       Configuration.Timeout ?? ntsClient.Timeout,
                                DNSClient:     dnsClient,
                                TimeProvider:  TimeProvider
                            );

                // The old client's cookies went with it, so what the last check
                // found belongs to a server this meter no longer asks.
                lastTimeCheck        = null;
                lastTimeCheckOffset  = null;
                lastTimeCheckServer  = null;

                changed.Add($"server = {hostname.Trimmed}:{ntsKE} (NTS-KE), :{ntp} (NTP)");

            }

            else if (Configuration.Timeout.HasValue && ntsClient.Timeout != Configuration.Timeout.Value)
            {
                ntsClient.Timeout = Configuration.Timeout.Value;
                changed.Add($"timeout = {Configuration.Timeout.Value}");
            }

            if (Configuration.Enabled.HasValue && NTSEnabled != Configuration.Enabled.Value)
            {
                NTSEnabled = Configuration.Enabled.Value;
                changed.Add(NTSEnabled ? "switched on" : "switched off");
            }

            if (TimeCheckEvery != wasCheckingEvery)
                changed.Add($"clock checked every {TimeCheckEvery.TotalSeconds.ToString("0.###", CultureInfo.InvariantCulture)} s");

            // Who stands behind the time is what "legal time" rests on, so a
            // change to it is written down like a change of the servers.
            if (LegalTimeAuthority != wasAuthority)
                changed.Add(LegalTimeAuthority is null
                                ? "no legal time authority"
                                : $"legal time authority = {LegalTimeAuthority}");

            if (changed.Count > 0)
                Log.Notice($"NTS configuration changed: {String.Join(", ", changed)}.", "nts", "config");

            // The clock is checked on a timer set when the meter started, so
            // whether and how often it is checked has to be put into that timer
            // here - otherwise the page says "in effect" about something that
            // waits for the next start. Before the start there is no timer yet,
            // and the start sets one from what this left behind; setting one
            // here would leave a meter that was never started checking its
            // clock, with nothing to stop it.
            if (started &&
               (TimeCheckEvery != wasCheckingEvery || NTSEnabled != wasEnabled))
            {
                StartCheckingTheClock();
            }

        }

        #endregion

        #region (private static) Described(Group)

        /// <summary>
        /// A group of time servers as a log line names it: every server in the
        /// order configured, with whatever about it is not the usual.
        /// </summary>
        /// <remarks>
        /// All of them, and all of that, because this is also what a change is
        /// found by. It used to be the names of the servers switched on, in the
        /// order they are asked: a server given another priority or a port of
        /// its own was a change the log never heard of, and one switched off
        /// simply went missing from the line.
        /// </remarks>
        private static String Described(TimeSourceGroup Group)

            => String.Join(", ", Group.Sources.Select(source => {

                   var unusual = new List<String>();

                   if (source.Priority  != 0)                            unusual.Add($"priority {source.Priority}");
                   if (source.NTSKEPort != NTSClient.DefaultNTSKE_Port)  unusual.Add($"NTS-KE port {source.NTSKEPort}");
                   if (source.NTPPort   != NTSClient.DefaultNTP_Port)    unusual.Add($"NTP port {source.NTPPort}");
                   if (!source.Enabled)                                  unusual.Add("switched off");

                   return unusual.Count == 0
                              ? source.Hostname.Trimmed
                              : $"{source.Hostname.Trimmed} ({String.Join(", ", unusual)})";

               }));

        #endregion

        #region (private) TryCheckNTSQuorum(Configuration, out Error)

        /// <summary>
        /// Whether a quorum named on its own can be met by the servers this
        /// meter asks.
        /// </summary>
        /// <remarks>
        /// A section naming its servers as well had its quorum checked against
        /// them when it was read. One naming only the quorum is about the
        /// servers in effect, which the section cannot know and this meter
        /// does.
        /// </remarks>
        private Boolean TryCheckNTSQuorum(NTSConfiguration                  Configuration,
                                          [NotNullWhen(false)] out String?  Error)
        {

            Error = null;

            if (Configuration.MinServers is Byte quorum &&
                Configuration.Servers    is null        &&
                Configuration.Hostname   is null)
            {

                var asked = timeSources.Sources.Count(source => source.Enabled);

                if (quorum > asked)
                {
                    Error = $"'nts.minServers' is {quorum}, which is more servers than the {asked} this meter asks.";
                    return false;
                }

            }

            return true;

        }

        #endregion

        #endregion

    }

}
