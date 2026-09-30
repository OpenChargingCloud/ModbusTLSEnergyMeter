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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// A key made in this meter and the certificate signing request for it,
    /// waiting for a CA to answer - or answered already, and kept so that the
    /// same key can be certified again.
    /// </summary>
    /// <param name="Id">The request, and the name of its directory.</param>
    /// <param name="Listener">Which listener the certificate is for: "modbus" or "web".</param>
    /// <param name="CreatedAt">When the key was made.</param>
    /// <param name="Subject">The subject asked for.</param>
    /// <param name="DNSNames">The names asked for.</param>
    /// <param name="IPAddresses">The addresses asked for.</param>
    /// <param name="KeyType">The kind of key, as Hermod names it: "ecdsa-p256".</param>
    /// <param name="Note">A line to remember what this is for.</param>
    /// <param name="AnsweredBy">The entries of the certificate store its answers were put in as.</param>
    public sealed record SigningRequest(String                 Id,
                                        String                 Listener,
                                        DateTimeOffset         CreatedAt,
                                        String                 Subject,
                                        IReadOnlyList<String>  DNSNames,
                                        IReadOnlyList<String>  IPAddresses,
                                        String                 KeyType,
                                        String?                Note,
                                        IReadOnlyList<String>  AnsweredBy)
    {

        #region ToJSON(Store = null)

        /// <summary>
        /// This request as a page reads it - with the answers that are still in
        /// the given store, when one is given.
        /// </summary>
        public JObject ToJSON(CertificateStore? Store = null)
        {

            var answers = AnsweredBy.Where(id => Store is null || Store.Get(id) is not null).ToList();

            return new JObject(
                       new JProperty("id",           Id),
                       new JProperty("listener",     Listener),
                       new JProperty("createdAt",    CreatedAt.UtcDateTime),
                       new JProperty("subject",      Subject),
                       new JProperty("dnsNames",     new JArray(DNSNames)),
                       new JProperty("ipAddresses",  new JArray(IPAddresses)),
                       new JProperty("keyType",      KeyType),
                       new JProperty("note",         Note),
                       new JProperty("answeredBy",   new JArray(answers)),
                       new JProperty("state",        answers.Count > 0
                                                         ? "answered"
                                                         : "awaiting a certificate")
                   );

        }

        #endregion

        #region (internal) MetadataJSON() / (internal static) TryParse(JSON, out Request)

        internal JObject MetadataJSON()

            => new (
                   new JProperty("id",           Id),
                   new JProperty("listener",     Listener),
                   new JProperty("createdAt",    CreatedAt.ToString("o")),
                   new JProperty("subject",      Subject),
                   new JProperty("dnsNames",     new JArray(DNSNames)),
                   new JProperty("ipAddresses",  new JArray(IPAddresses)),
                   new JProperty("keyType",      KeyType),
                   new JProperty("note",         Note),
                   new JProperty("answeredBy",   new JArray(AnsweredBy))
               );

        internal static Boolean TryParse(JObject                                  JSON,
                                         [NotNullWhen(true)] out SigningRequest?  Request)
        {

            Request = null;

            var id        = JSON["id"]?.      Value<String>();
            var listener  = JSON["listener"]?.Value<String>();
            var subject   = JSON["subject"]?. Value<String>();
            var keyType   = JSON["keyType"]?. Value<String>();

            if (id is null || listener is null || subject is null || keyType is null ||
                !TryParseTimestamp(JSON["createdAt"], out var createdAt))
            {
                return false;
            }

            Request = new SigningRequest(
                          id,
                          listener,
                          createdAt,
                          subject,
                          [.. JSON["dnsNames"]?.   Values<String>().OfType<String>() ?? []],
                          [.. JSON["ipAddresses"]?.Values<String>().OfType<String>() ?? []],
                          keyType,
                          JSON["note"]?.Value<String>(),
                          [.. JSON["answeredBy"]?. Values<String>().OfType<String>() ?? []]
                      );

            return true;

        }

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

    }


    /// <summary>
    /// The certificate signing requests of this meter: a key made here, a
    /// request for a CA to sign, and - when the certificate comes back - an
    /// identity in the node's certificate store for the listener it was asked
    /// for.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The node's store keeps certificates, and a request is not one yet: it
    /// is a key waiting for its certificate. So requests live beside the store,
    /// in "requests", one directory each with the key, the request and what
    /// was asked for - and stay there once answered, so that a certificate
    /// that runs out can be renewed for the same key by sending the same
    /// request again.
    /// </para>
    /// <para>
    /// The private key is made here and never leaves this meter. It is kept
    /// unencrypted, as the store keeps the keys of its identities - readable
    /// only by the account the meter runs as, where the platform says so.
    /// </para>
    /// </remarks>
    public sealed class SigningRequests
    {

        #region Data

        /// <summary>
        /// The directory below the certificate store the requests live in.
        /// </summary>
        public const String DirectoryName = "requests";

        /// <summary>
        /// What this meter asks for when nobody says.
        /// </summary>
        public const String DefaultKeyType = KeyAlgorithm.DefaultId;

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

        private readonly Lock  requestLock = new();

        #endregion

        #region Properties

        /// <summary>
        /// The directory the requests live in.
        /// </summary>
        public String        Path          { get; }

        /// <summary>
        /// Where the time a request was made is read.
        /// </summary>
        public TimeProvider  TimeProvider  { get; }

        /// <summary>
        /// What happens once a request's directory is set aside, before it is
        /// deleted - for the tests, which make that fail.
        /// </summary>
        internal Action<String>? BeforeDeleting { get; set; }

        /// <summary>
        /// Every request, newest first.
        /// </summary>
        public IReadOnlyList<SigningRequest> All
        {
            get
            {

                lock (requestLock)
                {

                    if (!Directory.Exists(Path))
                        return [];

                    var requests = new List<SigningRequest>();

                    // Not what is left of a request thrown away whose directory
                    // could not be deleted afterwards.
                    foreach (var directory in Directory.EnumerateDirectories(Path))
                        if (!DirectoryRemoval.IsSetAside(directory) &&
                            Read(directory) is SigningRequest request)
                            requests.Add(request);

                    return [.. requests.OrderByDescending(request => request.CreatedAt).
                                        ThenByDescending (request => request.Id, StringComparer.Ordinal)];

                }

            }
        }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// The requests in the given directory, which is made when the first
        /// request is.
        /// </summary>
        public SigningRequests(String         Path,
                               TimeProvider?  TimeProvider = null)
        {
            this.Path          = System.IO.Path.GetFullPath(Path);
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;
        }

        #endregion


        #region (static) KeyTypes / AlgorithmOf(KeyType)

        /// <summary>
        /// The kinds of key a certificate can be asked for here: the ones the
        /// certificate store can keep with their certificate and a TLS stack can
        /// present - RSA and the NIST curves.
        /// </summary>
        /// <remarks>
        /// Hermod could make more - Edwards curves, lattices - and a CA could
        /// sign them. But a certificate for such a key cannot be held together
        /// with its key by this platform, so it could neither be kept in the
        /// store nor shown on a listener, and asking for one would only lead to
        /// a certificate that goes nowhere.
        /// </remarks>
        public static IReadOnlyList<KeyAlgorithm> KeyTypes

            => [.. KeyAlgorithm.All.Where(algorithm => algorithm.Id.StartsWith("ecdsa-", StringComparison.Ordinal) ||
                                                       algorithm.Id.StartsWith("rsa-",   StringComparison.Ordinal))];

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


        #region Get(Id) / RequestPEM(Id)

        /// <summary>
        /// The request of the given id, or null.
        /// </summary>
        public SigningRequest? Get(String? Id)
        {

            if (!IsId(Id))
                return null;

            lock (requestLock)
                return Read(System.IO.Path.Combine(Path, Id!));

        }

        /// <summary>
        /// The signing request of the given id, as the PEM file a CA is sent - or
        /// null.
        /// </summary>
        public String? RequestPEM(String? Id)
        {

            if (!IsId(Id))
                return null;

            var file = System.IO.Path.Combine(Path, Id!, "request.pem");

            lock (requestLock)
                return File.Exists(file)
                           ? File.ReadAllText(file)
                           : null;

        }

        #endregion

        #region TryCreate(Listener, Subject, DNSNames, IPAddresses, KeyType, Note, out Request, out Error)

        /// <summary>
        /// Make a key and a certificate signing request for it.
        /// </summary>
        /// <param name="Listener">Which listener the certificate is for: "modbus" or "web".</param>
        /// <param name="Subject">The subject to ask for, e.g. "CN=meter7.lan, O=Acme".</param>
        /// <param name="DNSNames">The names a peer will dial.</param>
        /// <param name="IPAddresses">The addresses a peer will dial.</param>
        /// <param name="KeyType">One of <see cref="KeyTypes"/>; <see cref="DefaultKeyType"/> when null.</param>
        /// <param name="Note">A line to remember what this is for.</param>
        /// <param name="Request">The request.</param>
        /// <param name="Error">Why there is none.</param>
        public Boolean TryCreate(String                                   Listener,
                                 String                                   Subject,
                                 IEnumerable<String>?                     DNSNames,
                                 IEnumerable<String>?                     IPAddresses,
                                 String?                                  KeyType,
                                 String?                                  Note,
                                 [NotNullWhen(true)]  out SigningRequest?  Request,
                                 [NotNullWhen(false)] out String?          Error)
        {

            Request = null;

            if (!ListenerCertificates.All.Contains(Listener))
            {
                Error = $"'{Listener}' is not a listener of this meter. Its listeners are: {String.Join(", ", ListenerCertificates.All)}.";
                return false;
            }

            var algorithm = AlgorithmOf(KeyType?.Trim().ToLowerInvariant() ?? DefaultKeyType);

            if (algorithm is null || !KeyTypes.Contains(algorithm))
            {
                Error = $"'{KeyType}' is not a kind of key a certificate can be asked for here. " +
                        $"One of: {String.Join(", ", KeyTypes.Select(keyType => keyType.Id))}.";
                return false;
            }

            X509Name subject;

            try
            {
                subject = new X509Name(Subject);
            }
            catch (Exception e)
            {
                Error = $"'{Subject}' is not a subject a certificate can be asked for: {e.Message}";
                return false;
            }

            var now          = TimeProvider.GetUtcNow();
            var id           = NewId(now);
            var dnsNames     = DNSNames?.   Select(name    => name.Trim()).Where(name    => name.   Length > 0).Distinct().ToList() ?? [];
            var ipAddresses  = IPAddresses?.Select(address => address.Trim()).Where(address => address.Length > 0).Distinct().ToList() ?? [];

            try
            {

                var pair        = algorithm.Generate();
                var request     = PKIFactory.GenerateCertificateSigningRequest(pair, subject, algorithm, [.. dnsNames, .. ipAddresses]);

                Request         = new SigningRequest(id, Listener, now, Subject, dnsNames, ipAddresses, algorithm.Id, Note, []);

                lock (requestLock)
                    Write(
                        Request,
                        PEM("PRIVATE KEY",         PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded()),
                        PEM("CERTIFICATE REQUEST", request.GetEncoded())
                    );

            }
            catch (Exception e)
            {
                Request = null;
                Error   = $"The key or the request could not be made: {e.Message}";
                return false;
            }

            Error = null;
            return true;

        }

        #endregion

        #region TryAnswer(Id, PEM, Store, out Entry, out Error)

        /// <summary>
        /// Put the certificate a CA signed for a request into the store, as an
        /// identity of the listener it was asked for.
        /// </summary>
        /// <remarks>
        /// Checked against the key that asked for it before anything is kept: a
        /// certificate this meter has no key for is not one it can show, and
        /// finding that out at the next handshake would mean finding it out as
        /// an outage. The intermediates that came with it travel with it.
        /// </remarks>
        /// <param name="Id">The request.</param>
        /// <param name="PEM">The certificate, and the intermediates above it.</param>
        /// <param name="Store">The node's certificate store.</param>
        /// <param name="Entry">The identity the certificate became.</param>
        /// <param name="Error">Why it did not.</param>
        public Boolean TryAnswer(String                                     Id,
                                 String                                     PEM,
                                 CertificateStore                           Store,
                                 [NotNullWhen(true)]  out CertificateEntry?  Entry,
                                 [NotNullWhen(false)] out String?            Error)
        {

            Entry = null;

            var request = Get(Id);

            if (request is null)
            {
                Error = "There is no signing request with that id.";
                return false;
            }

            var keyFile = System.IO.Path.Combine(Path, request.Id, "key.pem");

            if (!File.Exists(keyFile))
            {
                Error = "That request has no private key here any more, so nothing could be done with a certificate for it.";
                return false;
            }

            if (!TryCredential(PEM, File.ReadAllText(keyFile), TimeProvider.GetUtcNow(), out var pkcs12, out Error))
                return false;

            if (!Store.Import(pkcs12, CertificateKind.TLSIdentity, null, request.Note, [ request.Listener ], out Entry, out Error))
                return false;

            lock (requestLock)
                if (!request.AnsweredBy.Contains(Entry.Id))
                    WriteMetadata(request with { AnsweredBy = [ .. request.AnsweredBy, Entry.Id ] });

            return true;

        }

        #endregion

        #region TryRemove(Id, out Error)

        /// <summary>
        /// Throw a request away, and its key with it.
        /// </summary>
        /// <remarks>
        /// What was put into the store from it stays there: that is a
        /// certificate with its key, and the store's to remove.
        /// </remarks>
        public Boolean TryRemove(String                            Id,
                                 [NotNullWhen(false)] out String?  Error)

            => TryRemove(Id, out Error, out _);

        #endregion

        #region TryRemove(Id, out Error, out LeftBehind)

        /// <summary>
        /// Throw a request away, and its key with it - whole, or not at all.
        /// </summary>
        /// <remarks>
        /// Its directory is set aside in one step before it is deleted
        /// (<see cref="DirectoryRemoval"/>): a file somebody else holds open
        /// fails the removal and leaves the request as it was, where deleting
        /// file by file could leave a request in the list without its key, or
        /// its key on disk with nothing listing it. What could not be deleted
        /// once set aside is no longer read, and is said in LeftBehind.
        /// </remarks>
        /// <param name="Id">The request.</param>
        /// <param name="Error">Why it was not removed.</param>
        /// <param name="LeftBehind">Where what is left of its directory lies, when deleting it failed once it was set aside - the request is removed all the same.</param>
        public Boolean TryRemove(String                            Id,
                                 [NotNullWhen(false)] out String?  Error,
                                 out String?                       LeftBehind)
        {

            LeftBehind = null;

            if (Get(Id) is null)
            {
                Error = "There is no signing request with that id.";
                return false;
            }

            try
            {
                lock (requestLock)
                    LeftBehind = DirectoryRemoval.RemoveInOneStep(System.IO.Path.Combine(Path, Id), BeforeDeleting);
            }
            catch (Exception e)
            {
                Error = $"That request could not be removed: {e.Message}";
                return false;
            }

            Error = null;
            return true;

        }

        #endregion

        #region (internal) Adopt(Request, KeyPEM, RequestPEM)

        /// <summary>
        /// Keep a request that was made before there was this list - by the
        /// meter's own stores, which kept key and request beside the certificate.
        /// </summary>
        internal void Adopt(SigningRequest  Request,
                            String          KeyPEM,
                            String          RequestPEM)
        {

            lock (requestLock)
            {

                if (Read(System.IO.Path.Combine(Path, Request.Id)) is SigningRequest known)
                {
                    WriteMetadata(known with { AnsweredBy = [ .. known.AnsweredBy.Union(Request.AnsweredBy) ] });
                    return;
                }

                Write(Request, KeyPEM, RequestPEM);

            }

        }

        #endregion


        #region (internal static) TryCredential(PEM, KeyPEM, Now, out PKCS12, out Error)

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

        #region (private) Read(Directory) / Write(Request, KeyPEM, RequestPEM) / WriteMetadata(Request)

        private static SigningRequest? Read(String Directory)
        {

            var meta = System.IO.Path.Combine(Directory, "meta.json");

            try
            {
                return File.Exists(meta) &&
                       SigningRequest.TryParse(SigningRequest.ReadJSON(File.ReadAllText(meta)), out var request)
                           ? request
                           : null;
            }
            catch (Exception)
            {
                return null;
            }

        }

        private void Write(SigningRequest  Request,
                           String          KeyPEM,
                           String          RequestPEM)
        {

            var directory = System.IO.Path.Combine(Path, Request.Id);

            System.IO.Directory.CreateDirectory(directory);
            Protect(directory, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            var keyFile = System.IO.Path.Combine(directory, "key.pem");

            File.WriteAllText(keyFile, KeyPEM);
            Protect(keyFile, UnixFileMode.UserRead | UnixFileMode.UserWrite);

            File.WriteAllText(System.IO.Path.Combine(directory, "request.pem"), RequestPEM);

            WriteMetadata(Request);

        }

        private void WriteMetadata(SigningRequest Request)

            => File.WriteAllText(System.IO.Path.Combine(Path, Request.Id, "meta.json"), Request.MetadataJSON().ToString());

        #endregion

        #region (private static) helpers

        /// <summary>
        /// Whether the text is an id of a request, and not a path somebody tried.
        /// </summary>
        private static Boolean IsId(String? Id)

            => !String.IsNullOrWhiteSpace(Id) &&
               Id.All(character => Char.IsAsciiLetterOrDigit(character) || character == '-');

        private static String NewId(DateTimeOffset Now)

            => $"{Now.UtcDateTime:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}";

        private static AsymmetricKeyParameter PrivateKeyOf(String KeyPEM)

            => PrivateKeyFactory.CreateKey(
                   new PemReader(new StringReader(KeyPEM)).ReadPemObject().Content
               );

        private static String PEM(String  Label,
                                  Byte[]  DER)
        {

            var text   = new StringWriter();
            var writer = new PemWriter(text);

            writer.WriteObject(new PemObject(Label, DER));
            writer.Writer.Flush();

            return text.ToString();

        }

        private static void Protect(String        Path,
                                    UnixFileMode  Mode)
        {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                File.SetUnixFileMode(Path, Mode);
        }

        #endregion

    }

}
