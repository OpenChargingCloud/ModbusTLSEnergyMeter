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

using cloud.charging.open.protocols.WWCP.Node.Configuration;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// The meter this one stands in front of: where it is reached, over plain
    /// Modbus/TCP or over Modbus/TLS, and - over TLS - whom this meter is to
    /// it, and whom it is believed to be.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Without one, this meter measures with its own simulation. With one, it
    /// measures with that meter: every request a client asks is passed on to
    /// it, and what this meter adds - the session model, which signs charging
    /// sessions - sits behind that meter's models.
    /// </para>
    /// <para>
    /// Over TLS, whom this meter is to it is a TLS identity of its certificate
    /// store whose certificate carries a SunSpec role, by its id; whom it is
    /// believed to be is said as a time server's is, with WWCP_Node's
    /// <see cref="ServerPins"/>, beside what every server is held to: a
    /// certificate issued for its host that chains to a root of the machine or
    /// a TLS root of the store for "upstream".
    /// </para>
    /// </remarks>
    /// <param name="Host">Its name or its address.</param>
    /// <param name="Port">Its port.</param>
    /// <param name="Unit">Its Modbus unit address.</param>
    /// <param name="TLS">Whether it speaks Modbus/TLS rather than plain Modbus/TCP.</param>
    /// <param name="Identity">Over TLS, the id of the TLS identity it is shown; null for none.</param>
    /// <param name="Pins">Over TLS, what its certificate is held to beyond what every server's is; null for nothing.</param>
    public sealed record UpstreamConfiguration(String       Host,
                                               UInt16       Port,
                                               Byte         Unit,
                                               Boolean      TLS,
                                               String?      Identity  = null,
                                               ServerPins?  Pins      = null)
    {

        #region Data

        /// <summary>The section of the configuration file.</summary>
        public const String  SectionName     = "upstream";

        /// <summary>What a TLS root or a server certificate of the store may be for: the meter in front of which this one stands.</summary>
        public const String  Usage           = "upstream";

        /// <summary>Modbus/TCP's port.</summary>
        public const UInt16  DefaultTCPPort  = 502;

        /// <summary>Modbus/TLS's port, mbaps.</summary>
        public const UInt16  DefaultTLSPort  = 802;

        public const Byte    DefaultUnit     = 1;

        public const Int32   MaxHostLength      = 253;
        public const Int32   MaxIdentityLength  = 64;

        #endregion

        #region Properties

        /// <summary>
        /// How the node's judgements name it: "10.0.0.7:802".
        /// </summary>
        public String Server
            => $"{(Host.Contains(':') ? $"[{Host}]" : Host)}:{Port}";

        #endregion


        #region (static) TryParse(JSON, Path, out Upstream, out Error)

        /// <summary>
        /// The section, or a page's change to it - <c>{ "host": "10.0.0.7",
        /// "port": 802, "unit": 1, "tls": true, "identity": "…",
        /// "trustOnFirstUse": "certificate" }</c>.
        /// </summary>
        /// <param name="JSON">The section.</param>
        /// <param name="Path">Where it is, for the sentence of a refusal.</param>
        /// <param name="Upstream">The meter in front of which this one stands; null where the section has no host, which is none.</param>
        /// <param name="Error">Why it was refused.</param>
        public static Boolean TryParse(JObject                           JSON,
                                       String                            Path,
                                       out UpstreamConfiguration?        Upstream,
                                       [NotNullWhen(false)] out String?  Error)
        {

            Upstream = null;
            Error    = null;

            if (JSON["host"] is JToken given && given.Type is not JTokenType.String and not JTokenType.Null)
            {
                Error = $"'{Path}.host' must be the name or the address the meter in front of which this one stands is reached at.";
                return false;
            }

            var host = JSON.Value<String>("host")?.Trim();

            if (String.IsNullOrEmpty(host))
                return true;

            if (host.Length > MaxHostLength || host.Any(Char.IsWhiteSpace) || host.Contains('/'))
            {
                Error = $"'{Path}.host' is '{host}', which is no host a meter can be reached at; give its name or its address, without a port or a path.";
                return false;
            }

            if (host.StartsWith('[') && host.EndsWith(']'))
                host = host[1..^1];

            var tls = false;

            if (JSON["tls"] is JToken tlsToken && tlsToken.Type != JTokenType.Null)
            {
                if (tlsToken.Type != JTokenType.Boolean)
                {
                    Error = $"'{Path}.tls' must be true, for Modbus/TLS, or false, for plain Modbus/TCP.";
                    return false;
                }
                tls = tlsToken.Value<Boolean>();
            }

            var port = tls ? DefaultTLSPort : DefaultTCPPort;

            if (JSON["port"] is JToken portToken && portToken.Type != JTokenType.Null)
            {
                if (portToken.Type != JTokenType.Integer || portToken.Value<Int64>() is < 1 or > 65535)
                {
                    Error = $"'{Path}.port' must be a whole number between 1 and 65535.";
                    return false;
                }
                port = (UInt16) portToken.Value<Int64>();
            }

            var unit = DefaultUnit;

            if (JSON["unit"] is JToken unitToken && unitToken.Type != JTokenType.Null)
            {
                if (unitToken.Type != JTokenType.Integer || unitToken.Value<Int64>() is < 0 or > 255)
                {
                    Error = $"'{Path}.unit' must be a Modbus unit address, a whole number between 0 and 255.";
                    return false;
                }
                unit = (Byte) unitToken.Value<Int64>();
            }

            String? identity = null;

            if (JSON["identity"] is JToken identityToken && identityToken.Type != JTokenType.Null)
            {

                var text = identityToken.Type == JTokenType.String ? identityToken.Value<String>()!.Trim() : null;

                if (text is null || text.Length > MaxIdentityLength || text.Any(Char.IsWhiteSpace))
                {
                    Error = $"'{Path}.identity' must be the id of a TLS identity of the certificate store.";
                    return false;
                }

                identity = text.Length == 0 ? null : text.ToLowerInvariant();

            }

            if (!ServerPins.TryParse(JSON, Path, out var pins, out Error))
                return false;

            if (!tls && (identity is not null || pins is { SaysAnything: true }))
            {
                Error = $"'{Path}' says whom the meter at {host} is shown or held to, which only Modbus/TLS has: say \"tls\": true, or leave them out.";
                return false;
            }

            Upstream = new UpstreamConfiguration(host, port, unit, tls, identity, pins);
            return true;

        }

        #endregion

        #region SameAs(Other)

        /// <summary>
        /// Whether a meter reached this way is reached as the other way reaches
        /// it - where, how, shown which identity and held to what.
        /// </summary>
        public Boolean SameAs(UpstreamConfiguration? Other)

            => Other is not null                                                      &&
               Host == Other.Host && Port == Other.Port && Unit == Other.Unit && TLS == Other.TLS &&
               String.Equals(Identity, Other.Identity, StringComparison.OrdinalIgnoreCase) &&
               (Pins ?? ServerPins.None).SameAs(Other.Pins);

        #endregion

        #region ToJSON()

        /// <summary>
        /// The section as the file keeps it.
        /// </summary>
        public JObject ToJSON()
        {

            var json = new JObject(
                           new JProperty("host",  Host),
                           new JProperty("port",  Port),
                           new JProperty("unit",  Unit),
                           new JProperty("tls",   TLS)
                       );

            if (Identity is not null)
                json["identity"] = Identity;

            Pins?.WriteInto(json);

            return json;

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"{(TLS ? "Modbus/TLS" : "Modbus/TCP")} {Server}, unit {Unit}" +
               (Identity  is not null    ? $", shown {Identity}"   : "") +
               (Pins?.Text is String held ? $", held to {held}"     : "");

        #endregion

    }

}
