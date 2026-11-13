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

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// A Modbus/TLS connection to this meter that is open now: which one, the
    /// SunSpec role in the certificate its client showed, since when, and what
    /// it has asked so far.
    /// </summary>
    /// <remarks>
    /// Known from the moment its TLS handshake held - a connection that showed
    /// no certificate this meter believes never becomes one - until it is
    /// closed. Where it comes from is known with its first request: the
    /// Modbus/TLS frontend says the peer with every request and not before.
    /// </remarks>
    /// <param name="Id">The number the Modbus/TLS frontend gave it, as the log has it.</param>
    /// <param name="Role">The SunSpec role in the client's certificate; null for a certificate without one.</param>
    /// <param name="Since">When its TLS handshake held.</param>
    public sealed class ModbusConnection(Int64           Id,
                                         String?         Role,
                                         DateTimeOffset  Since)
    {

        #region Data

        private          Int64    requests;
        private          Int64    refused;
        private          Int64    lastRequestTicks;
        private volatile String?  peer;

        #endregion

        #region Properties

        /// <summary>The number the Modbus/TLS frontend gave it, as the log has it.</summary>
        public Int64            Id        { get; } = Id;

        /// <summary>The SunSpec role in the client's certificate; null for a certificate without one.</summary>
        public String?          Role      { get; } = Role;

        /// <summary>When its TLS handshake held.</summary>
        public DateTimeOffset   Since     { get; } = Since;

        /// <summary>Where it comes from; null until it has asked something.</summary>
        public String?          Peer
            => peer;

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


        #region (internal) Asked(Peer, Allowed, When)

        /// <summary>
        /// It made a request.
        /// </summary>
        /// <param name="Peer">Where it comes from.</param>
        /// <param name="Allowed">Whether the policy allowed the request.</param>
        /// <param name="When">When.</param>
        internal void Asked(String?         Peer,
                            Boolean         Allowed,
                            DateTimeOffset  When)
        {

            if (Peer is not null)
                peer = Peer;

            Interlocked.Increment(ref requests);

            if (!Allowed)
                Interlocked.Increment(ref refused);

            Interlocked.Exchange(ref lastRequestTicks, When.UtcTicks);

        }

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"Modbus/TLS connection {Id} ({Role ?? "no role"}){(Peer is not null ? $" from {Peer}" : "")}";

        #endregion

    }

}
