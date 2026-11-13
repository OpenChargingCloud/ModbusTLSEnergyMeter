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

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// A Modbus/TLS connection to this meter that is open now: which one, from
    /// where, who the certificate its client showed says it is and the SunSpec
    /// role in it, since when, and what it has asked so far.
    /// </summary>
    /// <remarks>
    /// Known from the moment its TLS handshake held - a connection that showed
    /// no certificate this meter believes never becomes one - until it is
    /// closed: the Modbus/TLS frontend says both.
    /// </remarks>
    /// <param name="Opened">What the Modbus/TLS frontend said of it when its handshake held.</param>
    public sealed class ModbusConnection(ModbusConnectionInfo Opened)
    {

        #region Data

        private Int64  requests;
        private Int64  refused;
        private Int64  lastRequestTicks;

        #endregion

        #region Properties

        /// <summary>The number the Modbus/TLS frontend gave it, as the log has it.</summary>
        public Int64            Id                 { get; } = Opened.ConnectionId;

        /// <summary>Where it comes from.</summary>
        public String?          Peer               { get; } = Opened.Peer;

        /// <summary>The SunSpec role in the client's certificate; null for a certificate without one.</summary>
        public String?          Role               { get; } = Opened.Role;

        /// <summary>The subject of the client's certificate.</summary>
        public String           ClientSubject      { get; } = Opened.ClientSubject;

        /// <summary>The SHA-256 fingerprint of the client's certificate, in upper-case hexadecimal.</summary>
        public String           ClientFingerprint  { get; } = Opened.ClientFingerprint;

        /// <summary>The TLS version its handshake agreed on, as it is written: "TLS 1.3".</summary>
        public String           Protocol           { get; } = Opened.Protocol switch {
                                                                  System.Security.Authentication.SslProtocols.Tls13  => "TLS 1.3",
                                                                  System.Security.Authentication.SslProtocols.Tls12  => "TLS 1.2",
                                                                  _                                                  => Opened.Protocol.ToString()
                                                              };

        /// <summary>When its TLS handshake held.</summary>
        public DateTimeOffset   Since              { get; } = Opened.Since;

        /// <summary>How many requests it has made, the refused ones among them.</summary>
        public Int64            Requests
            => Interlocked.Read(ref requests);

        /// <summary>How many of its requests the policy refused.</summary>
        public Int64            Refused
            => Interlocked.Read(ref refused);

        /// <summary>When it last asked something; null while it has not.</summary>
        public DateTimeOffset?  LastRequest
            => Interlocked.Read(ref lastRequestTicks) is var ticks and not 0
                   ? new DateTimeOffset(ticks, TimeSpan.Zero)
                   : null;

        #endregion


        #region (internal) Asked(Allowed, When)

        /// <summary>
        /// It made a request.
        /// </summary>
        /// <param name="Allowed">Whether the policy allowed the request.</param>
        /// <param name="When">When.</param>
        internal void Asked(Boolean         Allowed,
                            DateTimeOffset  When)
        {

            Interlocked.Increment(ref requests);

            if (!Allowed)
                Interlocked.Increment(ref refused);

            Interlocked.Exchange(ref lastRequestTicks, When.UtcTicks);

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// As GET /api/v1/meter/connections says it.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("id",                 Id),
                   new JProperty("peer",               Peer),
                   new JProperty("role",               Role),
                   new JProperty("clientSubject",      ClientSubject),
                   new JProperty("clientFingerprint",  ClientFingerprint),
                   new JProperty("protocol",           Protocol),
                   new JProperty("since",              Since.ToString("o")),
                   new JProperty("requests",           Requests),
                   new JProperty("refused",            Refused),
                   new JProperty("lastRequest",        LastRequest?.ToString("o"))
               );

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"Modbus/TLS connection {Id} ({Role ?? "no role"}) from {Peer ?? "somewhere"}";

        #endregion

    }

}
