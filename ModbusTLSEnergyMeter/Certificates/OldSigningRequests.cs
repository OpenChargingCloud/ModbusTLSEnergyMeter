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
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

using NodeSigningRequest = cloud.charging.open.protocols.WWCP.Node.Certificates.SigningRequest;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// The signing requests this meter kept itself, before the node's
    /// certificate store made keys: one directory each below "requests",
    /// with the key, the request and what was asked for - moved into the
    /// node's store once, at a start.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The node keeps a key that waits as three files directly in
    /// "requests" (&lt;id&gt;.key.pem, .csr.pem, .json), so the two never
    /// met: it reads files there, the meter read directories.
    /// </para>
    /// <para>
    /// A request whose certificate is in the store still is that identity,
    /// which holds the key; there is nothing left to wait for. One that was
    /// never answered - or whose answers were all taken out of the store
    /// since - waits in the node's store from now on, as a TLS server
    /// identity for the listener it was asked for, with its note as its
    /// label and its names as what it is reachable as. What was moved is
    /// not deleted but put below "moved/requests", as the old stores' was;
    /// what could not be moved stays where it is and is named in the log,
    /// at every start, until somebody takes it away.
    /// </para>
    /// <para>
    /// The meter kept an answered request so that the same key could be
    /// certified again by sending the same request. The node's store does
    /// that without one: a certificate that comes back for the key of an
    /// identity it holds is put together with that key - and the request,
    /// as it was sent, is kept below "moved" for whoever wants to send it
    /// again.
    /// </para>
    /// </remarks>
    public static class OldSigningRequests
    {

        #region Data

        /// <summary>
        /// The directory below the certificate store the meter kept its
        /// requests in - the node's own, which it keeps files in.
        /// </summary>
        public const String DirectoryName = CertificateStore.RequestsDirectoryName;

        /// <summary>
        /// The spellings the meter's own store used before Hermod had a list of
        /// key types, and what they are called now - read, never written.
        /// </summary>
        private static readonly Dictionary<String, String> renamedKeyTypes = new () {
            { "ec256",    "ecdsa-p256" },
            { "ec384",    "ecdsa-p384" },
            { "ec521",    "ecdsa-p521" },
            { "rsa2048",  "rsa-2048"   },
            { "rsa3072",  "rsa-3072"   },
            { "rsa4096",  "rsa-4096"   },
            { "mldsa44",  "ml-dsa-44"  },
            { "mldsa65",  "ml-dsa-65"  },
            { "mldsa87",  "ml-dsa-87"  }
        };

        #endregion


        #region MoveInto(Store, Log, Now)

        /// <summary>
        /// Move the requests the meter kept itself into the node's store, and
        /// say what was moved and what could not be.
        /// </summary>
        /// <param name="Store">The node's certificate store; the old requests are in its directory.</param>
        /// <param name="Log">Where to say what was moved.</param>
        /// <param name="Now">What time it is.</param>
        public static void MoveInto(CertificateStore  Store,
                                    EventLog          Log,
                                    DateTimeOffset    Now)
        {

            var old = Path.Combine(Store.Directory, DirectoryName);

            if (!Directory.Exists(old))
                return;

            foreach (var directory in Directory.EnumerateDirectories(old).Order(StringComparer.Ordinal).ToArray())
            {

                // What is left of a request thrown away whose directory could
                // not be deleted afterwards is nobody's request.
                if (DirectoryRemoval.IsSetAside(directory))
                    continue;

                var id = Path.GetFileName(directory);

                try
                {

                    var metaFile     = Path.Combine(directory, "meta.json");
                    var keyFile      = Path.Combine(directory, "key.pem");
                    var requestFile  = Path.Combine(directory, "request.pem");

                    if (!File.Exists(metaFile) || !File.Exists(keyFile) || !File.Exists(requestFile))
                        continue;

                    var meta      = ReadJSON(File.ReadAllText(metaFile));
                    var listener  = meta["listener"]?.Value<String>() ?? MeterListeners.Modbus;
                    var note      = meta["note"]?.    Value<String>();
                    var answers   = (meta["answeredBy"]?.Values<String>().OfType<String>() ?? []).
                                        Select(answer => Store.Get(answer)).
                                        OfType<CertificateEntry>().
                                        ToArray();

                    if (answers.Length > 0)
                    {

                        OldCertificateStores.Keep(directory, Path.Combine(Store.Directory, OldCertificateStores.MovedDirectoryName, DirectoryName, id));

                        Log.Notice($"The {listener} signing request '{note ?? id}' was answered by '{answers[0].Label}' ({answers[0].Id}), which holds its key: " +
                                   $"it is kept below '{OldCertificateStores.MovedDirectoryName}' now, for a renewal of the same key.",
                                   "certificates", listener);

                        continue;

                    }

                    if (!TryAdopt(Store,
                                  listener,
                                  meta,
                                  File.ReadAllText(keyFile),
                                  File.ReadAllText(requestFile),
                                  Now,
                                  out var error))
                    {
                        Log.Warning($"The {listener} signing request '{note ?? id}' could not be moved into the certificate store, " +
                                    $"and stays in '{directory}': {error}",
                                    "certificates", listener);
                        continue;
                    }

                    OldCertificateStores.Keep(directory, Path.Combine(Store.Directory, OldCertificateStores.MovedDirectoryName, DirectoryName, id));

                    Log.Notice($"The {listener} signing request '{note ?? id}' waits in the certificate store now for its certificate.",
                               "certificates", listener);

                }
                catch (Exception e)
                {
                    Log.Warning($"The signing request in '{directory}' could not be moved into the certificate store: {e.Message}",
                                "certificates");
                }

            }

        }

        #endregion

        #region (internal static) TryAdopt(Store, Listener, Meta, KeyPEM, RequestPEM, Now, out Error)

        /// <summary>
        /// A key the meter made, with the request it was made with, waiting in
        /// the node's store for its certificate: a TLS server identity of the
        /// listener it was asked for.
        /// </summary>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Listener">Which listener the certificate is for: "modbus" or "web".</param>
        /// <param name="Meta">What was asked for, as the meter wrote it down.</param>
        /// <param name="KeyPEM">The private key, as PKCS#8.</param>
        /// <param name="RequestPEM">The signing request.</param>
        /// <param name="Now">What time it is, when the request does not say when it was made.</param>
        /// <param name="Error">Why it was not taken over.</param>
        internal static Boolean TryAdopt(CertificateStore                  Store,
                                         String                            Listener,
                                         JObject                           Meta,
                                         String                            KeyPEM,
                                         String                            RequestPEM,
                                         DateTimeOffset                    Now,
                                         [NotNullWhen(false)] out String?  Error)
        {

            // The node's store takes a key over as it is given, and finds out
            // whether it can be read, and whether it is the key of the request,
            // only when a certificate comes for it - from a CA, weeks later.
            // So asked here, while the key is still where it was and somebody
            // can be told.
            try
            {

                var ours     = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(PKIFactory.PublicKeyOf(PrivateKeyOf(KeyPEM))).GetDerEncoded();
                var request  = new Pkcs10CertificationRequest(new PemReader(new StringReader(RequestPEM)).ReadPemObject().Content);

                if (!request.GetCertificationRequestInfo().SubjectPublicKeyInfo.GetDerEncoded().SequenceEqual(ours))
                {
                    Error = "Its key is not the key of its signing request.";
                    return false;
                }

            }
            catch (Exception e)
            {
                Error = $"Its key or its signing request could not be read: {e.Message}";
                return false;
            }

            var kind      = CertificateKind.TLSServerIdentity;
            var template  = CSRTemplate.DefaultFor(kind)!;
            var keyType   = Meta["keyType"]?.Value<String>();
            var subject   = Meta["subject"]?.Value<String>() ?? "";
            var created   = TryParseTimestamp(Meta["createdAt"], out var createdAt) ? createdAt : Now;

            // What the request asked for, as far as the meter wrote it down:
            // the names a peer dials it by. Its key usages were not written
            // down, and are read from the request where the node shows it.
            var asked     = new NodeSigningRequest("", kind, "", "", created, subject, RequestPEM) {
                                Template           = template.Id,
                                ExtendedKeyUsages  = [ template.Purpose ],
                                ReachableAs        = [ .. Meta["dnsNames"]?.   Values<String>().OfType<String>() ?? [],
                                                       .. Meta["ipAddresses"]?.Values<String>().OfType<String>() ?? [] ]
                            };

            return Store.TryAdoptRequest(kind,
                                         KeyPEM,
                                         RequestPEM,
                                         AlgorithmOf(keyType)?.Id ?? keyType ?? "unknown",
                                         created,
                                         [ Listener ],
                                         Meta["note"]?.Value<String>(),
                                         asked,
                                         out _,
                                         out Error,
                                         out _);

        }

        #endregion


        #region (static) AlgorithmOf(KeyType)

        /// <summary>
        /// The algorithm a key type names, under its name now or the one the
        /// meter's own store used to write.
        /// </summary>
        public static KeyAlgorithm? AlgorithmOf(String? KeyType)

            => KeyAlgorithm.Find(KeyType) ??
               (KeyType is not null && renamedKeyTypes.TryGetValue(KeyType, out var renamed)
                    ? KeyAlgorithm.Find(renamed)
                    : null);

        #endregion

        #region (internal static) ReadJSON(Text) / TryParseTimestamp(Token, out Timestamp)

        /// <summary>
        /// A JSON file as it was written: with its timestamps as the text they
        /// were written as, rather than turned into dates the way the reader
        /// guesses them.
        /// </summary>
        internal static JObject ReadJSON(String Text)

            => JsonConvert.DeserializeObject<JObject>(Text, new JsonSerializerSettings { DateParseHandling = DateParseHandling.None })
                   ?? throw new JsonException("That file holds no JSON object.");

        /// <summary>
        /// A timestamp written as ISO 8601, whatever the culture of the machine
        /// reading it - "09/27/2026" is no date in a German one.
        /// </summary>
        internal static Boolean TryParseTimestamp(JToken?             Token,
                                                  out DateTimeOffset  Timestamp)
        {

            Timestamp = default;

            return Token switch {
                       JValue { Type: JTokenType.Date } date
                           => (Timestamp = date.Value is DateTimeOffset offset
                                               ? offset
                                               : new DateTimeOffset(DateTime.SpecifyKind(date.Value<DateTime>(), DateTimeKind.Utc))) != default,
                       JValue value
                           => DateTimeOffset.TryParse(value.Value<String>(),
                                                      CultureInfo.InvariantCulture,
                                                      DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                                                      out Timestamp),
                       _   => false
                   };

        }

        #endregion

        #region (internal static) TryCredential(PEM, KeyPEM, Now, out PKCS12, out Error, RefuseExpired = true)

        /// <summary>
        /// The certificate of a key, and the intermediates that came with it, as
        /// the PKCS#12 the store takes - or why it is not one.
        /// </summary>
        /// <param name="PEM">The certificate, and the intermediates above it, in any order.</param>
        /// <param name="KeyPEM">The private key, as PKCS#8.</param>
        /// <param name="Now">What time it is, which an expired certificate is refused against.</param>
        /// <param name="PKCS12">The certificate with its key, and the intermediates.</param>
        /// <param name="Error">Why there is none.</param>
        /// <param name="RefuseExpired">Whether a certificate that has run out is refused - which a new answer is, and one kept from before is not.</param>
        internal static Boolean TryCredential(String                           PEM,
                                              String                           KeyPEM,
                                              DateTimeOffset                   Now,
                                              [NotNullWhen(true)]  out Byte[]?  PKCS12,
                                              [NotNullWhen(false)] out String?  Error,
                                              Boolean                          RefuseExpired = true)
        {

            PKCS12 = null;

            var uploaded = new X509Certificate2Collection();

            try
            {
                uploaded.ImportFromPem(PEM);
            }
            catch (Exception e)
            {
                Error = $"That is not a PEM encoded certificate: {e.Message}";
                return false;
            }

            if (uploaded.Count == 0)
            {
                Error = "There was no certificate in that.";
                return false;
            }

            AsymmetricKeyParameter key;
            Byte[]                 ours;

            try
            {
                key   = PrivateKeyOf(KeyPEM);
                ours  = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(PKIFactory.PublicKeyOf(key)).GetDerEncoded();
            }
            catch (Exception e)
            {
                Error = $"The key of that request could not be read: {e.Message}";
                return false;
            }

            // Which of the certificates is ours: the one our key belongs to -
            // the public key is in both, and two SubjectPublicKeyInfos being
            // equal is the proof. Anything else is an intermediate on the way up.
            var leaf = uploaded.FirstOrDefault(candidate => candidate.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(ours));

            if (leaf is null)
            {
                Error = "That certificate was not made for the key of this request. Check that the right file was uploaded, or ask for a new request.";
                return false;
            }

            if (RefuseExpired && Now > leaf.NotAfter)
            {
                Error = $"That certificate ran out on {leaf.NotAfter:yyyy-MM-dd}.";
                return false;
            }

            try
            {

                using var withKey    = PKIFactory.WithPrivateKey(leaf, key);

                var credential       = new X509Certificate2Collection { withKey };

                foreach (var certificate in uploaded)
                    if (!ReferenceEquals(certificate, leaf))
                        credential.Add(certificate);

                PKCS12 = credential.Export(X509ContentType.Pkcs12)
                             ?? throw new CryptographicException("The certificate and its key could not be put together.");

            }
            catch (Exception e)
            {
                Error = $"This machine cannot keep that certificate with its key: {e.Message}";
                return false;
            }

            Error = null;
            return true;

        }

        #endregion

        #region (private static) PrivateKeyOf(KeyPEM)

        private static AsymmetricKeyParameter PrivateKeyOf(String KeyPEM)

            => PrivateKeyFactory.CreateKey(
                   new PemReader(new StringReader(KeyPEM)).ReadPemObject().Content
               );

        #endregion

    }

}
