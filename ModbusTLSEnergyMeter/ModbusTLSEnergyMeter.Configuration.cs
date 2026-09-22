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

using Microsoft.Extensions.Logging;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Norn.NTS;

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
        public Boolean TryUpdateDNSConfiguration(JObject      JSON,
                                                 out String?  Error)
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
        /// Where this meter reads the time, as it stands.
        /// </summary>
        public JObject NTSConfigurationJSON()

            => new NTSConfiguration(
                   Enabled:         NTSEnabled,
                   Hostname:        ntsClient.Hostname,
                   NTSKEPort:       ntsClient.NTSKE_Port,
                   NTPPort:         ntsClient.NTP_Port,
                   Timeout:         ntsClient.Timeout,
                   CheckEvery:          ntsSettings?.CheckEvery,
                   LegalTimeAuthority:  ntsSettings?.LegalTimeAuthority,
                   LegalTimeTolerance:  ntsSettings?.LegalTimeTolerance,
                   LegalTimeMaxAge:     ntsSettings?.LegalTimeMaxAge
               ).ToJSON();

        #endregion

        #region TryUpdateNTSConfiguration(JSON, out Error)

        /// <summary>
        /// Change where this meter reads the time, and write that down.
        /// </summary>
        public Boolean TryUpdateNTSConfiguration(JObject      JSON,
                                                 out String?  Error)
        {

            if (!NTSConfiguration.TryParse(JSON, out var configuration, out Error))
                return false;

            if (!ConfigFile.TryMergeSection(NTSConfiguration.SectionName, JSON, out Error))
                return false;

            ApplyNTSConfiguration(configuration);

            // The clock is checked on a timer that was built from the old
            // settings, so it is rebuilt here rather than left to notice.
            StartCheckingTheClock();

            return true;

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
            ntsSettings = Configuration;

            var changed  = new List<String>();

            #region The group of time servers

            // Rebuilt from the section rather than patched: it is a list, and
            // working out which entry changed in order to report it would say
            // less than naming the servers, which is what happens below.
            // Only when the section says something about them. That is this
            // method's rule everywhere else, and it earns its place here now
            // that the servers have a default worth keeping: a section
            // mentioning nothing but "enabled" would otherwise quietly reduce
            // four servers to one.
            if (Configuration.Servers is not null ||
                Configuration.Hostname is not null)
            {

                var wasAsking  = String.Join(", ", timeSources.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()));

                timeSources    = Configuration.ToGroup(Configuration.Hostname ?? ntsClient.Hostname);

                var nowAsking  = String.Join(", ", timeSources.Bands().SelectMany(band => band).Select(source => source.Hostname.ToString()));

                if (wasAsking != nowAsking)
                    changed.Add($"time servers = {nowAsking}");

            }

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

                changed.Add($"server = {hostname}:{ntsKE} (NTS-KE), :{ntp} (NTP)");

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

            if (changed.Count > 0)
                Log.Notice($"NTS configuration changed: {String.Join(", ", changed)}.", "nts", "config");

        }

        #endregion

        #endregion

    }

}
