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

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// The two listeners of a meter, as the node's certificate store names
    /// them, and what of them the node's ListenerCertificate does not say.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two listeners: the Modbus/TLS port says "I am this device" to a
    /// charging station, and the web interface says "I am this administrative
    /// web server" to a browser. Nothing issues a certificate both of those
    /// would accept, which is why an identity is told which listener it is
    /// for. One never told is for both.
    /// </para>
    /// <para>
    /// Which identity a listener shows is the node's to choose - see
    /// WWCPNode.ListenerCertificates: the newest one valid now, or what was
    /// issued for the listener's current server key, chosen again at every
    /// handshake, so that a certificate put in before the old one runs out
    /// takes over by itself.
    /// </para>
    /// </remarks>
    public static class MeterListeners
    {

        /// <summary>
        /// The Modbus/TLS listener: what a charging station connecting to this
        /// meter is shown.
        /// </summary>
        public const String  Modbus  = "modbus";

        /// <summary>
        /// The web interface: what a browser is shown.
        /// </summary>
        public const String  Web     = "web";

        /// <summary>
        /// The WebSocket port of Modbus, which a charging station or a local
        /// controller reads this meter over: what it shows them, from a device
        /// PKI as for Modbus/TLS.
        /// </summary>
        public const String  WebSocket  = "websocket";

        /// <summary>
        /// Every listener of this meter, as the node's store names them.
        /// </summary>
        public static readonly IReadOnlyList<String>  All  = [ Modbus, Web, WebSocket ];


        #region NextFor(Store, Listener, Now)

        /// <summary>
        /// The identity that takes over next on the given listener: switched
        /// on, for it, and not valid yet - the earliest of them.
        /// </summary>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Listener">The listener, "modbus" or "web".</param>
        /// <param name="Now">Now, by the node's clock.</param>
        public static CertificateEntry? NextFor(CertificateStore  Store,
                                                CertificateUsage  Listener,
                                                DateTimeOffset    Now)

            => Store.ByKind(CertificateKind.TLSServerIdentity).
                     Where  (entry => entry.IsActive && entry.IsNotYetValidAt(Now) && entry.IsFor(Listener)).
                     OrderBy(entry => entry.NotBefore).
                     FirstOrDefault();

        #endregion

    }

}
