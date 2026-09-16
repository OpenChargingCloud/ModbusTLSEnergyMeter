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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// Reading the JSON files this meter keeps on disk.
    /// </summary>
    /// <remarks>
    /// One thing, and it exists because of one bug. Newtonsoft looks at every
    /// string while it parses and silently turns the ones that look like a
    /// timestamp into a <c>DateTime</c> - in local time. What comes back out of
    /// such a token has lost its fraction of a second and, depending on which
    /// way the conversion went, is wrong by the machine's offset from UTC.
    ///
    /// That is invisible in a field nothing computes with, and it moved a
    /// charging session two hours into the past the first time one was read
    /// back after a restart. Every timestamp this meter writes down is ISO 8601
    /// in UTC and is meant to be read as exactly that, so the parser is told to
    /// leave strings alone and <see cref="Moment"/> does the conversion where it
    /// can be seen.
    /// </remarks>
    public static class MeterJSON
    {

        #region Parse(Text) / ReadFile(Path)

        /// <summary>
        /// Parse JSON without letting the parser reinterpret anything that
        /// looks like a date.
        /// </summary>
        public static JObject Parse(String Text)
        {

            using var reader = new JsonTextReader(new StringReader(Text)) {
                                   DateParseHandling = DateParseHandling.None
                               };

            return JObject.Load(reader);

        }

        /// <summary>
        /// Read one of this meter's JSON files.
        /// </summary>
        public static JObject ReadFile(String Path)

            => Parse(File.ReadAllText(Path));

        #endregion

        #region Moment(Token)

        /// <summary>
        /// A timestamp out of JSON, read from its text as written.
        /// </summary>
        /// <returns>
        /// The moment, or <see cref="DateTimeOffset.MinValue"/> when the token
        /// says nothing that can be read as one.
        /// </returns>
        public static DateTimeOffset Moment(JToken? Token)

            => Token is not null &&
               DateTimeOffset.TryParse(Token.ToString(),
                                       CultureInfo.InvariantCulture,
                                       DateTimeStyles.RoundtripKind,
                                       out var moment)
                   ? moment
                   : DateTimeOffset.MinValue;

        /// <summary>
        /// The same, saying whether it worked rather than answering with a
        /// moment in the year one.
        /// </summary>
        public static Boolean TryReadMoment(JToken? Token, out DateTimeOffset Moment)

            => DateTimeOffset.TryParse(Token?.ToString(),
                                       CultureInfo.InvariantCulture,
                                       DateTimeStyles.RoundtripKind,
                                       out Moment);

        #endregion

    }

}
