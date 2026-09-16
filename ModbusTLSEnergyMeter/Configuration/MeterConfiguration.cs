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

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Configuration
{

    /// <summary>
    /// Everything this energy meter can be told in writing: one document
    /// with one section per thing that can be configured.
    /// </summary>
    /// <remarks>
    /// One file rather than one per subject, because these settings are read
    /// together, changed together and backed up together - and because the
    /// question "what is this controller configured as" should have one answer
    /// that fits on a screen instead of a directory to go through.
    ///
    /// Every section is optional and so is every field inside it. A section
    /// that is absent is not a section set to nothing: it means the file has no
    /// opinion, and whatever the controller was handed at construction stands.
    /// A controller handed nothing either falls back to the system default. So
    /// the order is: system default, then what the constructor was given, then
    /// what this file says - each one only where it actually speaks.
    /// </remarks>
    /// <param name="DNS">How this energy meter resolves names.</param>
    /// <param name="NTS">Where this energy meter reads the time.</param>
    public sealed record MeterConfiguration(DNSConfiguration?  DNS   = null,
                                            NTSConfiguration?  NTS   = null)
    {

        #region Properties

        /// <summary>
        /// Whether this document says anything at all.
        /// </summary>
        public Boolean IsEmpty
            => DNS is null && NTS is null;

        #endregion


        #region (static) TryParse(JSON, out Configuration, out Error)

        /// <summary>
        /// The whole document, or the one sentence that says what is wrong with it.
        /// </summary>
        /// <remarks>
        /// A section of the wrong kind is an error rather than a section
        /// skipped: <c>"dns": null</c> is a file that has nothing to say about
        /// DNS, but <c>"dns": "google"</c> is a file whose author believed they
        /// had configured something.
        ///
        /// Sections this energy meter does not know are passed over without
        /// a word. A file written by a newer controller should still start an
        /// older one, and the file keeps them - see
        /// <see cref="MeterConfigFile.TryReplaceSection"/>.
        /// </remarks>
        public static Boolean TryParse(JObject                                          JSON,
                                       [NotNullWhen(true)]  out MeterConfiguration? Configuration,
                                       [NotNullWhen(false)] out String?                  Error)
        {

            Configuration  = null;
            Error          = null;

            #region DNS

            DNSConfiguration? dns = null;

            if (JSON[DNSConfiguration.SectionName] is JToken dnsToken && dnsToken.Type != JTokenType.Null)
            {

                if (dnsToken is not JObject dnsJSON)
                {
                    Error = $"'{DNSConfiguration.SectionName}' must be a JSON object.";
                    return false;
                }

                if (!DNSConfiguration.TryParse(dnsJSON, out dns, out Error))
                    return false;

            }

            #endregion

            #region NTS

            NTSConfiguration? nts = null;

            if (JSON[NTSConfiguration.SectionName] is JToken ntsToken && ntsToken.Type != JTokenType.Null)
            {

                if (ntsToken is not JObject ntsJSON)
                {
                    Error = $"'{NTSConfiguration.SectionName}' must be a JSON object.";
                    return false;
                }

                if (!NTSConfiguration.TryParse(ntsJSON, out nts, out Error))
                    return false;

            }

            #endregion

            Configuration = new MeterConfiguration(dns, nts);
            return true;

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The document as it is written to the file.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject();

            if (DNS  is not null)
                json.Add(DNSConfiguration. SectionName,  DNS. ToJSON());

            if (NTS  is not null)
                json.Add(NTSConfiguration. SectionName,  NTS. ToJSON());

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => IsEmpty
                   ? "nothing configured"
                   : String.Join(", ",
                         new[] {
                             DNS  is not null ? "DNS"  : null,
                             NTS  is not null ? "NTS"  : null
                         }.Where(section => section is not null));

        #endregion

    }

}
