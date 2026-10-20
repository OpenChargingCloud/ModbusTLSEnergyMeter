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

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// What a charging session is begun with, besides the reading: who charges,
    /// where, on which terms, and what whoever began it calls it.
    /// </summary>
    /// <remarks>
    /// All but the last go into the signed document: OCMF "IT" and "ID", "CT"
    /// and "CI", and "TT". The session id does not - OCMF has no field for it,
    /// and a field of this meter's own inside what is signed would be read by
    /// no verifier there is. It is handed back beside the document instead, so
    /// that whoever began a session can tell its document from another's.
    /// </remarks>
    /// <param name="IdentificationType">How whoever charges was identified, OCMF "IT": "ISO14443" for a card, "EMAID" for a contract, "LOCAL" or "CENTRAL" for an account.</param>
    /// <param name="Identification">Whom they were identified as, OCMF "ID".</param>
    /// <param name="ChargePointIdType">What the charge point is identified by, OCMF "CT": "EVSEID" or "CBIDC".</param>
    /// <param name="ChargePointId">The charge point, OCMF "CI".</param>
    /// <param name="TariffText">The tariff, OCMF "TT" - in the Bonn form "001;EUR;...", or free text.</param>
    /// <param name="StationSessionId">What whoever began the session calls it.</param>
    public sealed record SessionParameters(String?  IdentificationType  = null,
                                           String?  Identification      = null,
                                           String?  ChargePointIdType   = null,
                                           String?  ChargePointId       = null,
                                           String?  TariffText          = null,
                                           String?  StationSessionId    = null)
    {

        #region Data

        /// <summary>
        /// Nothing: a session nobody was identified for, at no charge point, on
        /// no tariff.
        /// </summary>
        public static readonly SessionParameters  Nothing = new ();

        /// <summary>
        /// How OCMF says somebody was identified, "IT".
        /// </summary>
        public static readonly IReadOnlySet<String>  IdentificationTypes = new HashSet<String> {
            "NONE", "DENIED", "UNDEFINED",
            "ISO14443", "ISO15693", "EMAID", "EVCCID", "EVCOID", "ISO7812", "CARD_TXN_NR",
            "CENTRAL", "CENTRAL_1", "CENTRAL_2", "LOCAL", "LOCAL_1", "LOCAL_2",
            "PHONE_NUMBER", "KEY_CODE"
        };

        /// <summary>
        /// How OCMF says a charge point is identified, "CT".
        /// </summary>
        public static readonly IReadOnlySet<String>  ChargePointIdTypes = new HashSet<String> {
            "EVSEID", "CBIDC"
        };

        #endregion


        #region (static) TryParse(JSON, out Parameters, out Error)

        /// <summary>
        /// What a JSON request begins a session with.
        /// </summary>
        public static Boolean TryParse(JObject                                     JSON,
                                       [NotNullWhen(true)]  out SessionParameters?  Parameters,
                                       [NotNullWhen(false)] out String?            Error)
        {

            Parameters  = null;
            Error       = null;

            var texts   = new Dictionary<String, String?>();

            foreach (var property in new[] { "identificationType", "identification", "chargePointIdType", "chargePointId", "tariffText", "stationSessionId" })
            {

                var token = JSON[property];

                if (token is null || token.Type == JTokenType.Null)
                    texts[property] = null;

                else if (token.Type == JTokenType.String)
                    texts[property] = token.Value<String>();

                else
                {
                    Error = $"'{property}' is a text, not {token.Type.ToString().ToLowerInvariant()}.";
                    return false;
                }

            }

            var parameters = new SessionParameters(
                                 texts["identificationType"],
                                 texts["identification"],
                                 texts["chargePointIdType"],
                                 texts["chargePointId"],
                                 texts["tariffText"],
                                 texts["stationSessionId"]
                             ).Trimmed();

            if (!parameters.IsValid(out Error))
                return false;

            Parameters = parameters;
            return true;

        }

        #endregion

        #region Trimmed()

        /// <summary>
        /// The same, with every text trimmed and an empty one taken for none.
        /// </summary>
        public SessionParameters Trimmed()

            => new (
                   NoneIfEmpty(IdentificationType)?.ToUpperInvariant(),
                   NoneIfEmpty(Identification),
                   NoneIfEmpty(ChargePointIdType)?.ToUpperInvariant(),
                   NoneIfEmpty(ChargePointId),
                   NoneIfEmpty(TariffText),
                   NoneIfEmpty(StationSessionId)
               );

        #endregion

        #region IsValid(out Error)

        /// <summary>
        /// Whether a session may be begun with these, and why not.
        /// </summary>
        public Boolean IsValid([NotNullWhen(false)] out String? Error)
        {

            if (IdentificationType is not null && !IdentificationTypes.Contains(IdentificationType))
            {
                Error = $"'{IdentificationType}' is no identification type OCMF knows. It knows {String.Join(", ", IdentificationTypes)}.";
                return false;
            }

            if (IdentificationType is not null && Identification is null &&
                IdentificationType is not "NONE" and not "DENIED" and not "UNDEFINED")
            {
                Error = $"The identification type is {IdentificationType}, but nobody is identified by it.";
                return false;
            }

            if (ChargePointIdType is not null && !ChargePointIdTypes.Contains(ChargePointIdType))
            {
                Error = $"'{ChargePointIdType}' is no way OCMF identifies a charge point. It knows {String.Join(", ", ChargePointIdTypes)}.";
                return false;
            }

            if (ChargePointId is not null && ChargePointIdType is null)
            {
                Error = $"The charge point is '{ChargePointId}', but nothing says whether that is an EVSE id (EVSEID) or a charge box and connector (CBIDC).";
                return false;
            }

            if (ChargePointIdType is not null && ChargePointId is null)
            {
                Error = $"The charge point is identified by {ChargePointIdType}, but there is no charge point.";
                return false;
            }

            foreach (var (name, text) in new[] { ("identification", Identification), ("charge point", ChargePointId), ("tariff text", TariffText), ("session id", StationSessionId) })
                if (text is not null && text.Any(Char.IsControl))
                {
                    Error = $"The {name} has a control character in it.";
                    return false;
                }

            Error = null;
            return true;

        }

        #endregion

        #region (private static) NoneIfEmpty(Text)

        private static String? NoneIfEmpty(String? Text)

            => String.IsNullOrWhiteSpace(Text) ? null : Text.Trim();

        #endregion

    }

}
