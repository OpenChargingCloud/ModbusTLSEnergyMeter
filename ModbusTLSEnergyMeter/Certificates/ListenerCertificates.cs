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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// A certificate a listener shows: the entry of the node's store it comes
    /// from, the certificate with its private key, and the chain it is sent
    /// with.
    /// </summary>
    /// <param name="Entry">The entry of the node's certificate store.</param>
    /// <param name="Certificate">The certificate, with the private key the TLS stack will take.</param>
    /// <param name="Chain">The certificate and the intermediates that go with it.</param>
    public sealed record ShownCertificate(CertificateEntry        Entry,
                                          X509Certificate2        Certificate,
                                          ServerCertificateChain  Chain);


    /// <summary>
    /// What one listener of this meter shows: the TLS identities of the
    /// node's certificate store that are for it, and the rule for which of
    /// them it shows now.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Two listeners, and so two of these over the one store: the Modbus/TLS
    /// port says "I am this device" to a charging station, and the web
    /// interface says "I am this administrative web server" to a browser.
    /// Nothing issues a certificate both of those would accept, which is why
    /// an identity is told which listener it is for - see
    /// <see cref="Modbus"/> and <see cref="Web"/>. One never told is for both.
    /// </para>
    /// <para>
    /// Of the identities for a listener that are valid now and switched on,
    /// the one whose validity began last is shown - so that a certificate put
    /// in before the old one runs out takes over on the day it becomes valid,
    /// without anybody being there. Asked at every handshake, which is what
    /// lets a certificate be replaced under a running meter.
    /// </para>
    /// </remarks>
    public sealed class ListenerCertificates
    {

        #region Data

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
        /// Every listener of this meter, as the node's store names them.
        /// </summary>
        public static readonly IReadOnlyList<String>  All  = [ Modbus, Web ];

        private readonly Lock                                   cacheLock  = new();
        private readonly Dictionary<String, ShownCertificate?>  loaded     = [];
        private          String?                                shownId;

        #endregion

        #region Properties

        /// <summary>
        /// The listener: "modbus" or "web".
        /// </summary>
        public String            Listener  { get; }

        /// <summary>
        /// The node's certificate store the identities are kept in.
        /// </summary>
        public CertificateStore  Store     { get; }

        /// <summary>
        /// The identities this listener could show now - switched on, valid, and
        /// for it - the one it shows first.
        /// </summary>
        public IReadOnlyList<CertificateEntry> Candidates

            => [.. Store.UsableFor(CertificateKind.TLSIdentity, Listener).
                         OrderByDescending(entry => entry.NotBefore).
                         ThenByDescending (entry => entry.NotAfter).
                         ThenByDescending (entry => entry.Id, StringComparer.Ordinal)];

        /// <summary>
        /// What this listener shows now, or null when there is nothing it could:
        /// the newest valid identity for it that this machine can present.
        /// </summary>
        public ShownCertificate? Current
        {
            get
            {

                foreach (var entry in Candidates)
                    if (Load(entry) is ShownCertificate shown)
                        return shown;

                return null;

            }
        }

        /// <summary>
        /// The identity that takes over next: switched on, for this listener, and
        /// not valid yet - the earliest of them.
        /// </summary>
        public CertificateEntry? Next

            => Store.ByKind(CertificateKind.TLSIdentity).
                     Where  (entry => entry.IsActive && entry.IsNotYetValid && entry.IsFor(Listener)).
                     OrderBy(entry => entry.NotBefore).
                     FirstOrDefault();

        #endregion

        #region Events

        /// <summary>
        /// This listener shows another certificate than before - or none any
        /// more, when the argument is null.
        /// </summary>
        public event Action<ShownCertificate?>? OnCurrentChanged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The identities of the given store for the given listener.
        /// </summary>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Listener">The listener: <see cref="Modbus"/> or <see cref="Web"/>.</param>
        public ListenerCertificates(CertificateStore  Store,
                                    String            Listener)
        {

            this.Store     = Store;
            this.Listener  = Listener;

            // What is shown at the start is where changes are counted from, and
            // not a change of its own.
            this.shownId   = Current?.Entry.Id;

        }

        #endregion


        #region ChainFor(ServerName)

        /// <summary>
        /// The certificate and intermediates to show a client that asked for
        /// the given server name - or null when there is none.
        /// </summary>
        /// <remarks>
        /// The server name is not what decides: a meter is one device, and
        /// whoever reaches it by whichever name is talking to that device.
        /// </remarks>
        public ServerCertificateChain? ChainFor(String? ServerName)

            => Current?.Chain;

        #endregion

        #region CheckRollover()

        /// <summary>
        /// Say so when this listener shows another certificate than it did
        /// when last asked - because one became valid, ran out, was switched off,
        /// removed or put in.
        /// </summary>
        public void CheckRollover()
        {

            var now = Current;

            String? before;

            lock (cacheLock)
            {
                before   = shownId;
                shownId  = now?.Entry.Id;
            }

            if (!String.Equals(before, now?.Entry.Id, StringComparison.Ordinal))
                OnCurrentChanged?.Invoke(now);

        }

        #endregion

        #region (static) AlgorithmIdOf(Certificate)

        /// <summary>
        /// The name Hermod gives the kind of key of this certificate -
        /// "ecdsa-p256", "rsa-3072" - or null for one it has no name for.
        /// </summary>
        public static String? AlgorithmIdOf(X509Certificate2 Certificate)
        {

            using var ecdsa = Certificate.GetECDsaPublicKey();

            if (ecdsa is not null)
                return ecdsa.KeySize switch {
                           256  => "ecdsa-p256",
                           384  => "ecdsa-p384",
                           521  => "ecdsa-p521",
                           _    => null
                       };

            using var rsa = Certificate.GetRSAPublicKey();

            return rsa is not null && KeyAlgorithm.Find($"rsa-{rsa.KeySize}") is KeyAlgorithm algorithm
                       ? algorithm.Id
                       : null;

        }

        #endregion


        #region (private) Load(Entry)

        /// <summary>
        /// The identity of an entry as a listener hands it to the TLS stack, or
        /// null when this machine cannot present it - read once per certificate.
        /// </summary>
        /// <remarks>
        /// Read from the store's file here rather than through the store, and
        /// with the key in the user's key set: a key read into an ephemeral key
        /// set is one SChannel refuses to present, and the listener would find
        /// that out at the first handshake.
        /// </remarks>
        private ShownCertificate? Load(CertificateEntry Entry)
        {

            lock (cacheLock)
                if (loaded.TryGetValue(Entry.Thumbprint, out var known))
                    return known is null
                               ? null
                               : known with { Entry = Entry };

            ShownCertificate? shown = null;

            try
            {

                var collection  = X509CertificateLoader.LoadPkcs12Collection(
                                      File.ReadAllBytes(Store.FullPath(Entry)),
                                      (String?) null,
                                      X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
                                  );

                var leaf        = collection.FirstOrDefault(certificate => certificate.HasPrivateKey);

                // Whether the platform's TLS stack can hold it up to somebody,
                // found out by doing it once per kind of key - which depends on
                // the operating system and the year, and not on a list here.
                if (leaf is not null &&
                    KeyAlgorithm.CanBePresented(AlgorithmIdOf(leaf) ?? leaf.PublicKey.Oid.Value ?? "unknown", leaf))
                {
                    shown = new ShownCertificate(
                                Entry,
                                leaf,
                                new ServerCertificateChain(
                                    leaf,
                                    collection.Where(certificate => !ReferenceEquals(certificate, leaf))
                                )
                            );
                }

            }
            catch (Exception)
            {
                // Not presentable: kept in the store, and never shown.
            }

            lock (cacheLock)
                loaded[Entry.Thumbprint] = shown;

            return shown;

        }

        #endregion

    }

}
