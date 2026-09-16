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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;
using Org.BouncyCastle.X509;

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// The certificates one TLS listener of this meter can show, and the rule
    /// for which of them it shows at any moment: the newest one that is valid
    /// now.
    /// </summary>
    /// <remarks>
    /// There are two of these, and they are deliberately not one. The
    /// certificate a meter shows a charging station says "I am this device",
    /// is issued by a device PKI and is checked by a machine that has pinned
    /// that PKI. The certificate it shows a browser says "I am this
    /// administrative web server", comes from wherever the operator's web
    /// certificates come from, and is checked against a trust store this meter
    /// has no say in. One certificate for both would have to be accepted by
    /// both, and nothing issues such a thing.
    ///
    /// The private key is made here and never leaves: what goes out is a
    /// PKCS#10 request, and what comes back is a certificate, which is checked
    /// against the key that asked for it before it is kept.
    ///
    /// Rolling over is not an operation, it is a consequence. The listeners ask
    /// this store at every handshake which certificate to show, and the answer
    /// is whichever valid one has the latest notBefore - so a certificate
    /// uploaded today that becomes valid in two days is simply not the answer
    /// until then, and is the answer from the second it is.
    /// </remarks>
    public class CertificateStore
    {

        #region Data

        /// <summary>
        /// How long a self-signed certificate this store makes for itself is
        /// good for.
        /// </summary>
        public static readonly TimeSpan SelfSignedLifetime = TimeSpan.FromDays(825);

        private readonly Dictionary<String, CertificateEntry>  entries = [];
        private readonly Lock                                  cacheLock = new();

        private CertificateEntry?       current;
        private ServerCertificateChain?  currentChain;
        private DateTimeOffset           currentValidUntil = DateTimeOffset.MinValue;

        #endregion

        #region Key types

        /// <summary>
        /// The kinds of key a certificate can be asked for here.
        /// </summary>
        /// <remarks>
        /// Hermod's list, not one of this meter's own. Generating a key,
        /// writing it down, making a signing request and pairing the answer
        /// back with the key are the same problem for every device that has a
        /// certificate, and this store solved it a second time until Hermod
        /// solved it properly - including the two things that were guesswork
        /// here: whether a key may claim keyEncipherment, and whether the
        /// platform can present it at all.
        /// </remarks>
        public static IEnumerable<String> KeyTypes

            => KeyAlgorithm.All.Select(algorithm => algorithm.Id);

        /// <summary>
        /// What this meter asks for when nobody says.
        /// </summary>
        public const String DefaultKeyType = KeyAlgorithm.DefaultId;

        /// <summary>
        /// The spellings this store used before Hermod had a list, and what
        /// they are called now.
        /// </summary>
        /// <remarks>
        /// Read only, never written. A certificate already in a store was
        /// written down under the old name, and dropping it because the
        /// spelling changed would lose a certificate over a rename.
        /// </remarks>
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

        /// <summary>
        /// The algorithm a key type names, under its name now or the one this
        /// store used to write.
        /// </summary>
        public static KeyAlgorithm? AlgorithmOf(String? KeyType)

            => KeyAlgorithm.Find(KeyType) ??
               (KeyType is not null && renamedKeyTypes.TryGetValue(KeyType, out var renamed)
                    ? KeyAlgorithm.Find(renamed)
                    : null);

        /// <summary>
        /// Whether this machine can hold a certificate of this kind up to
        /// somebody during a TLS handshake.
        /// </summary>
        /// <remarks>
        /// Asked by doing it, once per algorithm, and not answered from a list
        /// written here. Whether an Ed25519 certificate can be presented
        /// depends on the operating system's TLS stack, on the runtime and on
        /// the year, and a table in this file would be wrong on somebody's
        /// machine from the day it was written. Hermod does the asking; this
        /// only needs a certificate to ask with.
        /// </remarks>
        public static Boolean ServedByTLS(String?           KeyType,
                                          X509Certificate2  Certificate)

               // Asked only of a certificate that has its key, and not because
               // the answer would otherwise be wrong - it would be no, and
               // rightly. It is that the answer is kept per algorithm: a no
               // about one keyless certificate would be remembered as a no
               // about the algorithm, for every certificate after it.
               //
               // A certificate that came out of this store without a private
               // key is one .NET could not hold the key for, which is its own
               // kind of "cannot be presented".
            => Certificate.HasPrivateKey &&
               AlgorithmOf(KeyType) is KeyAlgorithm algorithm &&
               KeyAlgorithm.CanBePresented(algorithm.Id, Certificate);

        #endregion

        #region Properties

        /// <summary>
        /// The directory this store keeps its entries in.
        /// </summary>
        public String          Path          { get; }

        /// <summary>
        /// What these certificates are for, in one word, for log lines and for
        /// the API: "modbus" or "web".
        /// </summary>
        public String          Purpose       { get; }

        /// <summary>
        /// Where this store reads the time.
        /// </summary>
        public TimeProvider    TimeProvider  { get; }

        /// <summary>
        /// What went wrong while reading the store, if anything did. A store
        /// that cannot be read is not a reason to refuse to start - the meter
        /// says so and carries on with what it could read.
        /// </summary>
        public String?         LastError     { get; private set; }

        /// <summary>
        /// Every entry, newest first.
        /// </summary>
        public IEnumerable<CertificateEntry> Entries
        {
            get
            {
                lock (cacheLock)
                    return [.. entries.Values.OrderByDescending(entry => entry.Id)];
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Raised when the certificate this store would hand out has changed:
        /// one was uploaded, one became valid, one expired, one was removed.
        /// </summary>
        public event Action<CertificateEntry?, CertificateEntry?>? OnCurrentChanged;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Open, or create, a certificate store.
        /// </summary>
        /// <param name="Path">The directory it lives in.</param>
        /// <param name="Purpose">What these certificates are for: "modbus" or "web".</param>
        /// <param name="TimeProvider">Where it reads the time.</param>
        public CertificateStore(String         Path,
                                String         Purpose,
                                TimeProvider?  TimeProvider   = null)
        {

            this.Path          = System.IO.Path.GetFullPath(Path);
            this.Purpose       = Purpose;
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;

            try
            {

                Directory.CreateDirectory(this.Path);
                Reload();

            }
            catch (Exception e)
            {
                LastError = $"The {Purpose} certificate store at '{this.Path}' could not be read: {e.Message}";
            }

        }

        #endregion


        #region Current / Next

        /// <summary>
        /// The entry this store would hand out now: of those valid at this
        /// moment, the one whose validity began last.
        /// </summary>
        /// <remarks>
        /// "Newest" is by notBefore and not by when it was uploaded, because
        /// what a certificate says about itself is the thing both ends of a
        /// TLS handshake can check. Ties - two certificates beginning in the
        /// same second - go to the one that lasts longer, and then to the one
        /// that came later.
        /// </remarks>
        public CertificateEntry? Current
        {
            get
            {

                var now = TimeProvider.GetUtcNow();

                lock (cacheLock)
                {

                    if (current is not null && now < currentValidUntil && current.IsValidAt(now))
                        return current;

                    return Recompute(now).After;

                }

            }
        }

        /// <summary>
        /// The entry that is going to take over, and when: the earliest one
        /// whose validity has not begun yet.
        /// </summary>
        public CertificateEntry? Next
        {
            get
            {

                var now = TimeProvider.GetUtcNow();

                lock (cacheLock)
                    return entries.Values.
                               Where  (entry => entry.Certificate is not null &&
                                                entry.Certificate.HasPrivateKey &&
                                                now < entry.Certificate.NotBefore &&
                                                now < entry.Certificate.NotAfter).
                               OrderBy(entry => entry.Certificate!.NotBefore).
                               FirstOrDefault();

            }
        }

        /// <summary>
        /// Look again at what should be shown, and say so if it changed.
        /// </summary>
        /// <remarks>
        /// Called on a timer by whoever owns this store. Without it a rollover
        /// would still happen - the listeners ask at every handshake - but
        /// nothing would be written down about it until the next peer
        /// connected, which on a quiet meter could be hours.
        /// </remarks>
        public void CheckRollover()
        {

            var now = TimeProvider.GetUtcNow();

            CertificateEntry? before;
            CertificateEntry? after;

            lock (cacheLock)
            {

                if (current is not null && now < currentValidUntil && current.IsValidAt(now))
                    return;

                (before, after) = Recompute(now);

            }

            if (!ReferenceEquals(before, after))
            {
                // A handler that throws is not a reason to refuse a
                // certificate that is otherwise in and usable: the same
                // principle as an audit log that cannot be written not being a
                // reason to stop answering a meter.
                try
                {
                    OnCurrentChanged?.Invoke(before, after);
                }
                catch (Exception e)
                {
                    LastError = $"Something listening for the {Purpose} certificate to change threw: {e}";
                }
            }

        }

        /// <summary>
        /// Work out the current entry again. Must be called under the lock.
        /// </summary>
        private (CertificateEntry? Before, CertificateEntry? After) Recompute(DateTimeOffset Now)
        {

            var before = current;

            current = entries.Values.
                          Where      (entry => entry.IsValidAt(Now)).
                          OrderByDescending(entry => entry.Certificate!.NotBefore).
                          ThenByDescending (entry => entry.Certificate!.NotAfter).
                          ThenByDescending (entry => entry.Id).
                          FirstOrDefault();

            // Built here rather than per handshake: what goes on the wire is
            // the certificate and the intermediates that came with it, and
            // ServerCertificateChain drops the leaf and a self-signed root
            // from that list by itself - a root sent along is bytes that
            // change nothing.
            currentChain = current?.Certificate is not null
                               ? new ServerCertificateChain(current.Certificate, current.Chain)
                               : null;

            // Only cache until the soonest moment the answer could change:
            // when this one runs out, or when a newer one begins.
            var nextChange = new List<DateTimeOffset>();

            if (current?.Certificate is not null)
                nextChange.Add(current.Certificate.NotAfter);

            foreach (var entry in entries.Values)
                if (entry.Certificate is not null && Now < entry.Certificate.NotBefore)
                    nextChange.Add(entry.Certificate.NotBefore);

            currentValidUntil = nextChange.Count > 0
                                    ? nextChange.Min()
                                    : Now.AddMinutes(1);

            return (before, current);

        }

        /// <summary>
        /// The certificate to show a peer, together with the intermediates
        /// that lead to it. What the TLS listeners are handed.
        /// </summary>
        /// <remarks>
        /// The intermediates matter: a client that does not already hold them
        /// cannot build a path from this certificate to its trust anchor, and
        /// what it reports is a handshake failure with nothing in it about
        /// why. A peer that pinned the issuing CA - the whole mbaps
        /// arrangement - would not have needed them, and a browser almost
        /// always does.
        ///
        /// The server name a client sent is not used to pick: this meter is one
        /// device with one identity per listener, and answering different names
        /// with different certificates is a thing for a host that serves more
        /// than one.
        /// </remarks>
        public ServerCertificateChain? ChainFor(String? ServerName)
        {

            // Through Current, so that the validity window is re-checked and
            // the chain below is rebuilt whenever the answer changes.
            var now = TimeProvider.GetUtcNow();

            lock (cacheLock)
            {

                if (current is null || !current.IsValidAt(now) || now >= currentValidUntil)
                    Recompute(now);

                return currentChain;

            }

        }

        /// <summary>
        /// The certificate this store would hand out now, without its chain.
        /// </summary>
        public X509Certificate2? SelectFor(String? ServerName)
            => Current?.Certificate;

        #endregion


        #region CreateRequest(...)

        /// <summary>
        /// Make a key and write a certificate signing request for it.
        /// </summary>
        /// <param name="Subject">The subject to ask for, e.g. "CN=meter7.lan, O=Acme".</param>
        /// <param name="DNSNames">The names a peer will dial.</param>
        /// <param name="IPAddresses">The addresses a peer will dial.</param>
        /// <param name="KeyType">One of <see cref="KeyTypes"/>, e.g. "ecdsa-p256", "ed448" or "ml-dsa-65".</param>
        /// <param name="Note">A line to remember what this is for.</param>
        public CertificateEntry CreateRequest(String                 Subject,
                                              IEnumerable<String>?   DNSNames      = null,
                                              IEnumerable<String>?   IPAddresses   = null,
                                              String                 KeyType       = DefaultKeyType,
                                              String?                Note          = null)
        {

            var now          = TimeProvider.GetUtcNow();
            var id           = NewId(now);
            var dnsNames     = DNSNames?.   Where(name => name.   Trim().Length > 0).Select(name => name.Trim()).Distinct().ToList() ?? [];
            var ipAddresses  = IPAddresses?.Where(address => address.Trim().Length > 0).Select(address => address.Trim()).Distinct().ToList() ?? [];

            var algorithm    = AlgorithmOf(KeyType)
                                   ?? throw new ArgumentException(
                                          $"'{KeyType}' is not a key type this meter can ask for. " +
                                          $"One of: {String.Join(", ", KeyTypes)}.",
                                          nameof(KeyType));

            // Written down under the name it is called now, whatever spelling
            // the caller used.
            var entry        = new CertificateEntry(id, now, Subject, dnsNames, ipAddresses, algorithm.Id, Note);

            var directory    = System.IO.Path.Combine(Path, id);
            Directory.CreateDirectory(directory);

            // One path for every kind of key. There used to be three - .NET for
            // RSA, .NET for the curves, Bouncy Castle for the rest - and a
            // store that generates one way and reads back another is a store
            // with two sets of bugs in it.
            var pair       = algorithm.Generate();

            var request    = PKIFactory.GenerateCertificateSigningRequest(
                                 pair,
                                 new X509Name(Subject),
                                 algorithm,
                                 [.. dnsNames, .. ipAddresses]
                             );

            var requestPEM = PEM("CERTIFICATE REQUEST", request.GetEncoded());
            var keyPEM     = PEM("PRIVATE KEY",         PrivateKeyInfoFactory.CreatePrivateKeyInfo(pair.Private).GetEncoded());

            WritePrivateFile(System.IO.Path.Combine(directory, "key.pem"), keyPEM);
            File.WriteAllText(System.IO.Path.Combine(directory, "request.pem"), requestPEM);

            entry.RequestPEM = requestPEM;

            File.WriteAllText(System.IO.Path.Combine(directory, "meta.json"), entry.MetadataJSON().ToString());

            lock (cacheLock)
            {
                entries[id] = entry;
                currentValidUntil = DateTimeOffset.MinValue;
            }

            return entry;

        }

        #endregion

        #region CreateSelfSigned(...)

        /// <summary>
        /// Make a key and sign a certificate for it here, so that a listener
        /// has something to show before anybody has been to a CA.
        /// </summary>
        /// <remarks>
        /// What this is for: the web interface, on a meter that has just been
        /// started for the first time. A browser will say it does not know who
        /// signed it, and it is right - but a page nobody can reach is not a
        /// better answer, and the certificate a CA signs later simply becomes
        /// the newer one and takes over.
        /// </remarks>
        public CertificateEntry CreateSelfSigned(String                Subject,
                                                 IEnumerable<String>?  DNSNames      = null,
                                                 IEnumerable<String>?  IPAddresses   = null,
                                                 String?               Note          = null)
        {

            var entry      = CreateRequest(Subject, DNSNames, IPAddresses, DefaultKeyType, Note);
            var directory  = System.IO.Path.Combine(Path, entry.Id);
            var now        = TimeProvider.GetUtcNow();

            using var key  = ECDsa.Create();
            key.ImportFromPem(File.ReadAllText(System.IO.Path.Combine(directory, "key.pem")));

            var request    = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256);

            var alternativeNames = new SubjectAlternativeNameBuilder();
            var any              = false;

            foreach (var name in entry.DNSNames)
            {
                alternativeNames.AddDnsName(name);
                any = true;
            }

            foreach (var address in entry.IPAddresses)
                if (NetIPAddress.TryParse(address, out var parsed))
                {
                    alternativeNames.AddIpAddress(parsed);
                    any = true;
                }

            if (any)
                request.CertificateExtensions.Add(alternativeNames.Build());

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([new Oid("1.3.6.1.5.5.7.3.1", "serverAuth")], false));

            // A few minutes back, because a meter and whoever looks at it do
            // not always agree about the time to the second.
            using var certificate = request.CreateSelfSigned(now.AddMinutes(-5), now.Add(SelfSignedLifetime));

            var pem = new System.Text.StringBuilder();
            pem.AppendLine(PemEncoding.WriteString("CERTIFICATE", certificate.RawData));

            if (!TryImportCertificate(entry.Id, pem.ToString(), out var error))
                throw new InvalidOperationException($"The self-signed {Purpose} certificate could not be kept: {error}");

            return entries[entry.Id];

        }

        #endregion

        #region Adopt(Certificate, Note = null)

        /// <summary>
        /// Take a certificate that already has its key - the one this meter was
        /// started with - into the store, so that there is one place that
        /// decides what is shown.
        /// </summary>
        public CertificateEntry? Adopt(X509Certificate2  Certificate,
                                       String?           Note   = null)
        {

            if (!Certificate.HasPrivateKey)
                return null;

            // Already here, by thumbprint: adopting the same file at every
            // start would fill the store with copies of one certificate.
            lock (cacheLock)
            {
                var known = entries.Values.FirstOrDefault(entry => entry.Certificate?.Thumbprint == Certificate.Thumbprint);
                if (known is not null)
                    return known;
            }

            var now        = TimeProvider.GetUtcNow();
            var id         = NewId(now);
            var directory  = System.IO.Path.Combine(Path, id);

            Directory.CreateDirectory(directory);

            var entry = new CertificateEntry(
                            id,
                            now,
                            Certificate.Subject,
                            [.. DNSNamesOf(Certificate)],
                            [.. IPAddressesOf(Certificate)],
                            KeyTypeOf(Certificate),
                            Note
                        );

            // As a PKCS#12 rather than as key and certificate side by side:
            // what was adopted came as one thing and is kept as one.
            WritePrivateFile(
                System.IO.Path.Combine(directory, "certificate.pfx"),
                Convert.ToBase64String(Certificate.Export(X509ContentType.Pkcs12))
            );

            File.WriteAllText(System.IO.Path.Combine(directory, "meta.json"), entry.MetadataJSON().ToString());

            entry.Certificate = Usable(Certificate);
            entry.Chain       = [entry.Certificate];

            lock (cacheLock)
            {
                entries[id]       = entry;
                currentValidUntil = DateTimeOffset.MinValue;
            }

            return entry;

        }

        #endregion

        #region TryImportCertificate(Id, PEM, out Error)

        /// <summary>
        /// Put a signed certificate back where its request came from.
        /// </summary>
        /// <remarks>
        /// Checked against the key that asked for it before anything is
        /// written: a certificate this meter has no key for is not a
        /// certificate this meter can use, and finding that out at the next
        /// handshake instead of here would mean finding it out as an outage.
        /// </remarks>
        public Boolean TryImportCertificate(String       Id,
                                            String       PEM,
                                            out String?  Error)
        {

            Error = null;

            CertificateEntry? entry;

            lock (cacheLock)
                if (!entries.TryGetValue(Id, out entry))
                {
                    Error = "There is no request with that id.";
                    return false;
                }

            var directory = System.IO.Path.Combine(Path, Id);
            var keyFile   = System.IO.Path.Combine(directory, "key.pem");

            if (!File.Exists(keyFile))
            {
                Error = "That entry has no private key here, so nothing could be done with a certificate for it.";
                return false;
            }

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

            // Which of the certificates is ours: the one our key belongs to.
            // Anything else in the file is an intermediate on the way up.
            X509Certificate2? leaf     = null;
            X509Certificate2? withKey  = null;

            var keyPEM = File.ReadAllText(keyFile);

            foreach (var candidate in uploaded)
            {

                if (TryPairWithKey(candidate, entry.KeyType, keyPEM, out withKey))
                {
                    leaf = candidate;
                    break;
                }

            }

            if (leaf is null || withKey is null)
            {
                Error = "That certificate was not made for the key of this request. Check that the right file was uploaded, or ask for a new request.";
                return false;
            }

            var now = TimeProvider.GetUtcNow();

            if (now > leaf.NotAfter)
            {
                Error = $"That certificate ran out on {leaf.NotAfter:yyyy-MM-dd}.";
                return false;
            }

            try
            {

                File.WriteAllText(System.IO.Path.Combine(directory, "certificate.pem"), PEM);

                // The key has to go through a PKCS#12 round trip to be usable
                // by SslStream on every platform; CopyWithPrivateKey alone
                // gives a certificate whose key the TLS stack will not take.
                var usable = Usable(withKey);

                lock (cacheLock)
                {
                    entry.Certificate  = usable;
                    entry.Chain        = [usable, .. uploaded.Cast<X509Certificate2>().Where(certificate => certificate.Thumbprint != leaf.Thumbprint)];
                    currentValidUntil  = DateTimeOffset.MinValue;
                }

            }
            catch (Exception e)
            {
                Error = $"The certificate could not be kept: {e.Message}";
                return false;
            }
            finally
            {
                withKey.Dispose();
            }

            CheckRollover();

            return true;

        }

        #endregion

        #region TryRemove(Id, out Error)

        /// <summary>
        /// Throw an entry away, key and all.
        /// </summary>
        /// <remarks>
        /// The one being shown at this moment cannot be removed while it is the
        /// only one that could be: a listener with nothing to show refuses
        /// every handshake, and doing that to oneself through a web page is not
        /// a mistake worth making possible.
        /// </remarks>
        public Boolean TryRemove(String       Id,
                                 out String?  Error)
        {

            Error = null;

            lock (cacheLock)
            {

                if (!entries.TryGetValue(Id, out var entry))
                {
                    Error = "There is no entry with that id.";
                    return false;
                }

                var now = TimeProvider.GetUtcNow();

                if (entry.IsValidAt(now) &&
                    !entries.Values.Any(other => other.Id != Id && other.IsValidAt(now)))
                {
                    Error = "That is the only certificate this listener could show. Put another one in first.";
                    return false;
                }

                try
                {
                    Directory.Delete(System.IO.Path.Combine(Path, Id), true);
                }
                catch (Exception e)
                {
                    Error = $"The entry could not be removed: {e.Message}";
                    return false;
                }

                entry.Certificate?.Dispose();
                entries.Remove(Id);
                currentValidUntil = DateTimeOffset.MinValue;

            }

            CheckRollover();

            return true;

        }

        #endregion

        #region (private) Reload()

        /// <summary>
        /// Read what is on disk. Every entry that can be read is kept, and one
        /// that cannot is said about rather than throwing the rest away.
        /// </summary>
        private void Reload()
        {

            foreach (var directory in Directory.GetDirectories(Path))
            {

                var id       = System.IO.Path.GetFileName(directory);
                var metaFile = System.IO.Path.Combine(directory, "meta.json");

                if (!File.Exists(metaFile))
                    continue;

                try
                {

                    if (!CertificateEntry.TryParseMetadata(MeterJSON.ReadFile(metaFile), out var entry) ||
                        entry is null)
                        continue;

                    var pfxFile  = System.IO.Path.Combine(directory, "certificate.pfx");
                    var certFile = System.IO.Path.Combine(directory, "certificate.pem");
                    var keyFile  = System.IO.Path.Combine(directory, "key.pem");
                    var csrFile  = System.IO.Path.Combine(directory, "request.pem");

                    if (File.Exists(csrFile))
                        entry.RequestPEM = File.ReadAllText(csrFile);

                    if (File.Exists(pfxFile))
                    {
                        using var adopted = X509CertificateLoader.LoadPkcs12(
                                                Convert.FromBase64String(File.ReadAllText(pfxFile)),
                                                (String?) null,
                                                X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
                                            );
                        entry.Certificate = Usable(adopted);
                        entry.Chain       = [entry.Certificate];
                    }

                    else if (File.Exists(certFile) && File.Exists(keyFile))
                    {

                        var uploaded = new X509Certificate2Collection();
                        uploaded.ImportFromPem(File.ReadAllText(certFile));

                        var keyPEM = File.ReadAllText(keyFile);

                        foreach (var candidate in uploaded)
                        {
                            if (TryPairWithKey(candidate, entry.KeyType, keyPEM, out var paired))
                            {
                                entry.Certificate = paired;
                                entry.Chain       = [entry.Certificate, .. uploaded.Cast<X509Certificate2>().Where(certificate => certificate.Thumbprint != candidate.Thumbprint)];
                                break;
                            }
                        }

                    }

                    entries[entry.Id] = entry;

                }
                catch (Exception e)
                {
                    LastError = $"The {Purpose} certificate '{id}' could not be read: {e.Message}";
                }

            }

        }

        #endregion

        #region (private static) TryPairWithKey(Candidate, KeyType, KeyPEM, out Paired)

        /// <summary>
        /// Whether this certificate is the one our key asked for, and the form
        /// of it this store keeps.
        /// </summary>
        /// <remarks>
        /// Two ways of asking the same question, because .NET only knows one of
        /// them. For RSA and ECDSA the private key is attached to the
        /// certificate, which both proves the match and produces the thing a
        /// listener is handed.
        ///
        /// For an Edwards curve or a lattice there is nothing to attach it to:
        /// .NET has no CopyWithPrivateKey for those and its TLS stack could not
        /// use the result. So the match is made where it really lives - the
        /// public key is in the certificate and in our key, and two
        /// SubjectPublicKeyInfos being equal is the same proof - and what comes
        /// back is the bare certificate. Without a private key on it,
        /// <see cref="CertificateEntry.IsValidAt"/> is false and no listener is
        /// ever handed it, which is exactly right: it could not show it.
        /// </remarks>
        private static Boolean TryPairWithKey(X509Certificate2                          Candidate,
                                              String                                    KeyType,
                                              String                                    KeyPEM,
                                              [NotNullWhen(true)] out X509Certificate2?  Paired)
        {

            Paired = null;

            try
            {

                // Whether this certificate is the one our key asked for. The
                // public key is in both, and two SubjectPublicKeyInfos being
                // equal is the proof - which works for every kind of key,
                // unlike attaching the private one and seeing whether .NET
                // complains.
                var ours       = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                                     PKIFactory.PublicKeyOf(PrivateKeyOf(KeyPEM))
                                 ).GetDerEncoded();

                if (!Candidate.PublicKey.ExportSubjectPublicKeyInfo().SequenceEqual(ours))
                    return false;

            }
            catch
            {
                // Not this one - an intermediate, or a certificate for a
                // different key altogether.
                return false;
            }

            // It is ours. Whether the key can also be attached to it is a
            // second question with a different answer per algorithm: .NET holds
            // an RSA or an ECDSA private key and refuses an Ed448 one outright.
            // A failure here is not a reason to reject the certificate - it was
            // already shown to be the right one - it only means no listener
            // will be able to show it.
            try
            {
                Paired = PKIFactory.WithPrivateKey(Candidate, PrivateKeyOf(KeyPEM));
            }
            catch
            {
                Paired = Candidate;
            }

            return true;

        }

        #endregion

        #region (private static) helpers

        /// <summary>
        /// A certificate whose private key the TLS stack will actually use.
        /// </summary>
        /// <remarks>
        /// CopyWithPrivateKey gives a certificate whose key lives nowhere the
        /// platform's TLS implementation can reach it. Exporting to PKCS#12 and
        /// reading it back is the round trip that fixes that, and is what the
        /// rest of this project already does with the PFX files it loads.
        /// </remarks>
        private static X509Certificate2 Usable(X509Certificate2 Certificate)

            => X509CertificateLoader.LoadPkcs12(
                   Certificate.Export(X509ContentType.Pkcs12),
                   (String?) null,
                   X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
               );

        /// <summary>
        /// Whether a key type names an RSA key.
        /// </summary>
        /// <remarks>
        /// By family and not by the exact name: this used to compare against
        /// "rsa3072", which was true while that was the only RSA size on offer
        /// and silently made every other one an elliptic curve key the moment a
        /// second size existed.
        /// </remarks>
        private static Boolean IsRSA(String? KeyType)

            => KeyType?.StartsWith("rsa", StringComparison.OrdinalIgnoreCase) == true;

        private static ECDsa ECDsaFrom(String PEM)
        {
            var key = ECDsa.Create();
            key.ImportFromPem(PEM);
            return key;
        }

        private static RSA RSAFrom(String PEM)
        {
            var key = RSA.Create();
            key.ImportFromPem(PEM);
            return key;
        }

        /// <summary>
        /// What kind of key a certificate carries, as far as this matters here.
        /// </summary>
        /// <remarks>
        /// Only for a certificate adopted from outside, which this meter did
        /// not make a request for and therefore has no key type written down
        /// for. Everything it asked for itself says so in its own metadata.
        /// </remarks>
        private static String KeyTypeOf(X509Certificate2 Certificate)
        {

            if (Certificate.GetECDsaPublicKey() is ECDsa ecdsa)
            {
                using (ecdsa)
                    return ecdsa.KeySize switch {
                               384  => "ecdsa-p384",
                               521  => "ecdsa-p521",
                               _    => "ecdsa-p256"
                           };
            }

            if (Certificate.GetRSAPublicKey() is RSA rsa)
            {
                using (rsa)
                    return rsa.KeySize switch {
                               2048  => "rsa-2048",
                               4096  => "rsa-4096",
                               _     => "rsa-3072"
                           };
            }

            return "unknown";

        }

        private static IEnumerable<String> DNSNamesOf(X509Certificate2 Certificate)

            => Certificate.Extensions.
                   OfType<X509SubjectAlternativeNameExtension>().
                   SelectMany(extension => extension.EnumerateDnsNames());

        private static IEnumerable<String> IPAddressesOf(X509Certificate2 Certificate)

            => Certificate.Extensions.
                   OfType<X509SubjectAlternativeNameExtension>().
                   SelectMany(extension => extension.EnumerateIPAddresses()).
                   Select(address => address.ToString());

        /// <summary>
        /// A private key out of the PEM this store wrote.
        /// </summary>
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

        private String NewId(DateTimeOffset Now)

            => $"{Now:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}";

        /// <summary>
        /// Write something only this process's user may read.
        /// </summary>
        private static void WritePrivateFile(String Path, String Content)
        {

            File.WriteAllText(Path, Content);

            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                File.SetUnixFileMode(Path, UnixFileMode.UserRead | UnixFileMode.UserWrite);

        }

        #endregion

        #region ToJSON()

        /// <summary>
        /// The whole store, as a page needs it.
        /// </summary>
        public JObject ToJSON()
        {

            var now      = TimeProvider.GetUtcNow();
            var current  = Current;
            var next     = Next;

            return new JObject(

                       new JProperty("purpose",   Purpose),
                       new JProperty("path",      Path),
                       new JProperty("lastError", LastError),
                       new JProperty("currentId", current?.Id),
                       new JProperty("nextId",    next?.Id),

                       next?.Certificate is not null
                           ? new JProperty("nextAt", next.Certificate.NotBefore.ToUniversalTime().ToString("o"))
                           : new JProperty("nextAt", JValue.CreateNull()),

                       new JProperty("entries",   new JArray(Entries.Select(entry => entry.ToJSON(now))))

                   );

        }

        #endregion

    }

}
