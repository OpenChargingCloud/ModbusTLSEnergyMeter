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

using System.Security.Cryptography.X509Certificates;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// Which CAs a Modbus/TLS client certificate may chain to: the client
    /// roots of the node's certificate store that are switched on and valid.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Usually not a root at all but the CA below one that issues the clients
    /// and nothing else - the root above it signs the devices as well, and
    /// would let any of them in. The Modbus/TLS listener judges a client
    /// against the CA that issued it, so that is what is kept here.
    /// </para>
    /// <para>
    /// Asked at every handshake, and read from the store's files only when
    /// what is switched on has changed since the last one.
    /// </para>
    /// </remarks>
    public sealed class ClientRoots
    {

        #region Data

        private readonly Lock                                  cacheLock  = new();
        private          String?                               cachedKey;
        private          IReadOnlyCollection<X509Certificate2>  cached     = [];

        #endregion

        #region Properties

        /// <summary>
        /// The node's certificate store the client roots are kept in.
        /// </summary>
        public CertificateStore  Store  { get; }

        /// <summary>
        /// The client roots that are switched on and valid now.
        /// </summary>
        public IReadOnlyList<CertificateEntry> Usable

            => Store.UsableByKind(CertificateKind.ClientRoot);

        /// <summary>
        /// Every client root, switched on or not.
        /// </summary>
        public IReadOnlyList<CertificateEntry> All

            => Store.ByKind(CertificateKind.ClientRoot);

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The client roots of the given store.
        /// </summary>
        public ClientRoots(CertificateStore Store)
        {
            this.Store = Store;
        }

        #endregion


        #region Anchors()

        /// <summary>
        /// The CAs a client certificate may chain to at this moment.
        /// </summary>
        public IReadOnlyCollection<X509Certificate2> Anchors()
        {

            var usable  = Usable;
            var key     = String.Join(",", usable.Select(entry => entry.Thumbprint));

            lock (cacheLock)
                if (key == cachedKey)
                    return cached;

            var anchors = new List<X509Certificate2>();

            foreach (var entry in usable)
                if (Store.TryLoad(entry, out var certificate, out _))
                    anchors.Add(certificate);

            lock (cacheLock)
            {
                cachedKey  = key;
                cached     = anchors;
            }

            return anchors;

        }

        #endregion

    }

}
