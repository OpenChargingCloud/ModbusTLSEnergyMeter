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

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The certificate store: asking for a certificate, putting one back, and
    /// the one rule that makes a rollover happen by itself - of the ones valid
    /// now, the one whose validity began last.
    /// </summary>
    /// <remarks>
    /// A clock that can be moved, because the whole point of the thing is what
    /// it does at a moment that has not arrived yet, and waiting two days for a
    /// test is not a test.
    /// </remarks>
    [TestFixture]
    public class CertificateStoreTests
    {

        #region Data

        private String  storePath = "";

        /// <summary>
        /// A clock a test can move.
        /// </summary>
        private sealed class MovableClock(DateTimeOffset Now) : TimeProvider
        {

            private DateTimeOffset now = Now;

            public override DateTimeOffset GetUtcNow()
                => now;

            public void MoveTo(DateTimeOffset When)
                => now = When;

        }

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void SetUp()
        {
            storePath = Path.Combine(Path.GetTempPath(), "meter-certificate-tests", Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(storePath);
        }

        [TearDown]
        public void TearDown()
        {
            try { Directory.Delete(storePath, true); } catch { }
        }

        #endregion

        #region (helpers)

        /// <summary>
        /// A throwaway CA, standing in for whoever signs certificates here.
        /// </summary>
        private static (ECDsa Key, X509Certificate2 Certificate) NewCA(String Name = "CN=Test CA")
        {

            var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request  = new CertificateRequest(Name, key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            return (key, request.CreateSelfSigned(DateTimeOffset.UtcNow.AddYears(-1), DateTimeOffset.UtcNow.AddYears(10)));

        }

        /// <summary>
        /// Sign a PKCS#10 request the way a CA would, for a chosen stretch of
        /// time - which is what lets a test put tomorrow's certificate in
        /// today.
        /// </summary>
        private static String Sign(String            RequestPEM,
                                   ECDsa             CAKey,
                                   X509Certificate2  CACertificate,
                                   DateTimeOffset    NotBefore,
                                   DateTimeOffset    NotAfter)
        {

            var request     = CertificateRequest.LoadSigningRequestPem(
                                  RequestPEM,
                                  HashAlgorithmName.SHA256,
                                  CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions
                              );

            var certificate = request.Create(
                                  CACertificate.SubjectName,
                                  X509SignatureGenerator.CreateForECDsa(CAKey),
                                  NotBefore,
                                  NotAfter,
                                  RandomNumberGenerator.GetBytes(16)
                              );

            return PemEncoding.WriteString("CERTIFICATE", certificate.RawData);

        }

        /// <summary>
        /// A CA signed by another CA, so that a certificate signed by it needs
        /// an intermediate to be reachable from the root.
        /// </summary>
        private static (ECDsa Key, X509Certificate2 Certificate) NewIntermediate(ECDsa             RootKey,
                                                                                 X509Certificate2  RootCertificate,
                                                                                 String            Name = "CN=Test Issuing CA")
        {

            var key      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var request  = new CertificateRequest(Name, key, HashAlgorithmName.SHA256);

            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, true, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));

            return (key, request.Create(
                             RootCertificate.SubjectName,
                             X509SignatureGenerator.CreateForECDsa(RootKey),
                             DateTimeOffset.UtcNow.AddYears(-1),
                             DateTimeOffset.UtcNow.AddYears(5),
                             RandomNumberGenerator.GetBytes(16)
                         ));

        }

        private static CertificateStore NewStore(TimeProvider Clock, String Path)
            => new (Path, "modbus", Clock);

        #endregion



        #region EveryKeyType_MakesAUsableRequest(KeyType, Bits)

        /// <summary>
        /// Every key type on offer makes a signing request a CA would accept,
        /// over a key of the size it promised.
        /// </summary>
        /// <remarks>
        /// The size is checked and not only the fact that something came out:
        /// a table that silently fell back to P-256 for every name it did not
        /// recognise would pass a test that only asked whether a request
        /// appeared, and would hand somebody a 256 bit key when they asked for
        /// 521.
        /// </remarks>
        [TestCase("ec256",    256)]
        [TestCase("ec384",    384)]
        [TestCase("ec521",    521)]
        [TestCase("rsa2048",  2048)]
        [TestCase("rsa3072",  3072)]
        [TestCase("rsa4096",  4096)]
        public void EveryKeyType_MakesAUsableRequest(String KeyType, Int32 Bits)
        {

            var store = NewStore(TimeProvider.System, storePath);
            var entry = store.CreateRequest("CN=meter.example", ["meter.example"], null, KeyType);

            Assert.That(entry.RequestPEM, Is.Not.Null);
            Assert.That(entry.KeyType,    Is.EqualTo(KeyType));

            var request = CertificateRequest.LoadSigningRequestPem(
                              entry.RequestPEM!,
                              HashAlgorithmName.SHA256,
                              CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions
                          );

            Assert.Multiple(() => {

                Assert.That(request.SubjectName.Name, Does.Contain("meter.example"));

                Assert.That(KeyType.StartsWith("rsa")
                                ? request.PublicKey.GetRSAPublicKey()!.KeySize
                                : request.PublicKey.GetECDsaPublicKey()!.KeySize,
                            Is.EqualTo(Bits),
                            $"'{KeyType}' should ask for a {Bits} bit key");

                // The names a peer will dial have to be in the request, or the
                // certificate that comes back is for a host nobody connects to.
                Assert.That(request.CertificateExtensions.
                                OfType<X509SubjectAlternativeNameExtension>().
                                SelectMany(extension => extension.EnumerateDnsNames()),
                            Does.Contain("meter.example"));

            });

        }

        #endregion

        #region EveryBouncyCastleKeyType_MakesARequestThatVerifies(KeyType)

        /// <summary>
        /// The key types .NET will not build a request for: an Edwards curve,
        /// and the three lattice parameter sets.
        /// </summary>
        /// <remarks>
        /// The request has to verify against its own key, which is the one
        /// property a CA will check first and the one a wrong signature
        /// algorithm name breaks - an ML-DSA key of one parameter set signed
        /// with the name of another produces nothing at all, and pairing them
        /// by hand is exactly the mistake a table is meant to prevent.
        /// </remarks>
        [TestCase("ed25519")]
        [TestCase("ed448")]
        [TestCase("mldsa44")]
        [TestCase("mldsa65")]
        [TestCase("mldsa87")]
        public void EveryBouncyCastleKeyType_MakesARequestThatVerifies(String KeyType)
        {

            var store = NewStore(TimeProvider.System, storePath);
            var entry = store.CreateRequest("CN=meter.example", ["meter.example"], null, KeyType);

            Assert.That(entry.RequestPEM, Is.Not.Null);
            Assert.That(entry.KeyType,    Is.EqualTo(KeyType));

            var request = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(
                              Convert.FromBase64String(
                                  String.Concat(entry.RequestPEM!.Split('\n').
                                                    Where(line => !line.StartsWith("-----")).
                                                    Select(line => line.Trim()))
                              )
                          );

            Assert.Multiple(() => {

                Assert.That(request.Verify(), Is.True, "a request must verify against the key that made it");

                Assert.That(request.GetCertificationRequestInfo().Subject.ToString(),
                            Does.Contain("meter.example"));

                // And this meter says plainly that no listener of its own will
                // ever show the certificate that comes back.
                Assert.That(entry.ServedByTLS,                Is.False);
                Assert.That(CertificateStore.ServedByTLS(KeyType), Is.False);

            });

        }

        #endregion

        #region TheKeyTypesSayWhichOnesAListenerCanShow()

        /// <summary>
        /// Two families on one list, and which is which is not guesswork.
        /// </summary>
        [Test]
        public void TheKeyTypesSayWhichOnesAListenerCanShow()
        {

            Assert.Multiple(() => {

                Assert.That(CertificateStore.KeyTypes,
                            Is.SupersetOf(new[] { "ec256", "ec521", "rsa4096", "ed448", "mldsa87" }));

                foreach (var keyType in CertificateStore.TLSKeyTypes)
                    Assert.That(CertificateStore.ServedByTLS(keyType), Is.True, keyType);

                foreach (var keyType in new[] { "ed25519", "ed448", "mldsa44", "mldsa65", "mldsa87" })
                    Assert.That(CertificateStore.ServedByTLS(keyType), Is.False, keyType);

            });

        }

        #endregion


        #region ACertificateOnSuchAKey_ComesBackIn_AndIsNeverShown(KeyType)

        /// <summary>
        /// The whole round trip for a key .NET cannot attach to a certificate:
        /// a request goes out, a signed certificate comes back, the store takes
        /// it - and no listener is ever handed it.
        /// </summary>
        /// <remarks>
        /// The last part is the one that matters. A certificate this meter
        /// accepted and then quietly showed to nobody would be a mystery; a
        /// certificate it accepted and then tried to show would be a handshake
        /// failure at the worst possible moment. It is kept, it says what it is,
        /// and it stays out of the way.
        /// </remarks>
        [TestCase("ed448")]
        [TestCase("mldsa65")]
        public void ACertificateOnSuchAKey_ComesBackIn_AndIsNeverShown(String KeyType)
        {

            var clock = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store = NewStore(clock, storePath);

            var entry = store.CreateRequest("CN=meter.example", ["meter.example"], null, KeyType);

            var signed = SignWithATestCA(entry.RequestPEM!, clock.GetUtcNow());

            Assert.That(store.TryImportCertificate(entry.Id, signed, out var error), Is.True,
                        $"the signed certificate should be accepted: {error}");

            var stored = store.Entries.First(candidate => candidate.Id == entry.Id);

            Assert.Multiple(() => {

                Assert.That(stored.Certificate,                   Is.Not.Null);
                Assert.That(stored.Certificate!.Subject,          Does.Contain("meter.example"));

                // Kept, and honest about itself.
                Assert.That(stored.ServedByTLS,                   Is.False);
                Assert.That(stored.StateAt(clock.GetUtcNow()),    Is.EqualTo("not for a listener"));

                // And never the answer to "what should this listener show?",
                // however valid it is right now.
                Assert.That(stored.IsValidAt(clock.GetUtcNow()),  Is.False);
                Assert.That(store.Current,                        Is.Null);
                Assert.That(store.ChainFor(null),                 Is.Null);

            });

        }

        #endregion

        #region ACertificateForSomebodyElsesKey_IsRefused()

        /// <summary>
        /// The match is made on the public key for these, and it has to be a
        /// real check rather than a shrug.
        /// </summary>
        [Test]
        public void ACertificateForSomebodyElsesKey_IsRefused()
        {

            var clock = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store = NewStore(clock, storePath);

            var ours    = store.CreateRequest("CN=ours.example",   null, null, "ed448");
            var theirs  = store.CreateRequest("CN=theirs.example", null, null, "ed448");

            // A certificate made for the second request, offered to the first.
            var signed  = SignWithATestCA(theirs.RequestPEM!, clock.GetUtcNow());

            Assert.Multiple(() => {
                Assert.That(store.TryImportCertificate(ours.Id, signed, out var error), Is.False);
                Assert.That(error, Does.Contain("not made for the key of this request"));
            });

        }

        #endregion

        #region (private) SignWithATestCA(RequestPEM, Now)

        /// <summary>
        /// Stand in for the certificate authority: take the public key and the
        /// subject out of a request and issue a certificate for them.
        /// </summary>
        /// <remarks>
        /// Signed with an ordinary P-256 CA key, because what the CA signs with
        /// has nothing to do with what the subject's key is - which is the whole
        /// reason a certificate over an Edwards curve or a lattice can exist at
        /// all without every CA in the world changing.
        /// </remarks>
        private static String SignWithATestCA(String          RequestPEM,
                                              DateTimeOffset  Now)
        {

            var request = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(
                              Convert.FromBase64String(
                                  String.Concat(RequestPEM.Split('\n').
                                                    Where(line => !line.StartsWith("-----")).
                                                    Select(line => line.Trim()))
                              )
                          );

            var info      = request.GetCertificationRequestInfo();

            var curve     = Org.BouncyCastle.Asn1.X9.ECNamedCurveTable.GetByName("secp256r1")!;

            var caKeys    = new Org.BouncyCastle.Crypto.Generators.ECKeyPairGenerator();
            caKeys.Init(new Org.BouncyCastle.Crypto.Parameters.ECKeyGenerationParameters(
                            new Org.BouncyCastle.Crypto.Parameters.ECDomainParameters(curve),
                            new Org.BouncyCastle.Security.SecureRandom()));

            var ca        = caKeys.GenerateKeyPair();

            var generator = new Org.BouncyCastle.X509.X509V3CertificateGenerator();

            generator.SetSerialNumber(Org.BouncyCastle.Math.BigInteger.ValueOf(Now.ToUnixTimeSeconds()));
            generator.SetIssuerDN (new Org.BouncyCastle.Asn1.X509.X509Name("CN=A test CA"));
            generator.SetSubjectDN(info.Subject);
            generator.SetNotBefore(Now.UtcDateTime.AddDays(-1));
            generator.SetNotAfter (Now.UtcDateTime.AddDays(90));
            generator.SetPublicKey(request.GetPublicKey());

            var certificate = generator.Generate(
                                  new Org.BouncyCastle.Crypto.Operators.Asn1SignatureFactory(
                                      "SHA256withECDSA", ca.Private, new Org.BouncyCastle.Security.SecureRandom())
                              );

            return "-----BEGIN CERTIFICATE-----\n" +
                   Convert.ToBase64String(certificate.GetEncoded(), Base64FormattingOptions.InsertLineBreaks) +
                   "\n-----END CERTIFICATE-----\n";

        }

        #endregion

        #region AnUnknownKeyType_IsRefused()

        /// <summary>
        /// A key type this meter does not know is refused rather than quietly
        /// becoming the default one.
        /// </summary>
        [Test]
        public void AnUnknownKeyType_IsRefused()
        {

            var store = NewStore(TimeProvider.System, storePath);

            var problem = Assert.Throws<ArgumentException>(
                              () => store.CreateRequest("CN=meter.example", null, null, "falcon1024")
                          );

            Assert.That(problem!.Message, Does.Contain("ec521"), "and says what it does know");

        }

        #endregion

        #region ARequestKeepsItsKeyAndGivesOutOnlyTheRequest()

        [Test]
        public void ARequestKeepsItsKeyAndGivesOutOnlyTheRequest()
        {

            var clock = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store = NewStore(clock, storePath);

            var entry = store.CreateRequest("CN=meter7.lan", ["meter7.lan", "meter7"], ["192.168.7.20"], "ec256", "for the bench");

            Assert.Multiple(() => {

                Assert.That(entry.RequestPEM,   Does.StartWith("-----BEGIN CERTIFICATE REQUEST-----"));
                Assert.That(entry.HasCertificate, Is.False);
                Assert.That(entry.StateAt(clock.GetUtcNow()), Is.EqualTo("awaiting a certificate"));

                // Nothing to show yet: a request is not an identity.
                Assert.That(store.Current, Is.Null);

                // The key is on disk here and in no answer this store gives.
                Assert.That(File.Exists(Path.Combine(storePath, entry.Id, "key.pem")), Is.True);

            });

            // And what was asked for is in the request, so that a CA reading it
            // sees the names rather than having to be told them separately.
            var parsed = CertificateRequest.LoadSigningRequestPem(
                             entry.RequestPEM!,
                             HashAlgorithmName.SHA256,
                             CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions
                         );

            var names = parsed.CertificateExtensions.
                            OfType<X509SubjectAlternativeNameExtension>().
                            SelectMany(extension => extension.EnumerateDnsNames()).
                            ToArray();

            Assert.That(names, Is.EquivalentTo(new[] { "meter7.lan", "meter7" }));

        }

        #endregion

        #region ASignedCertificateComesBackAndIsShown()

        [Test]
        public void ASignedCertificateComesBackAndIsShown()
        {

            var clock          = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store          = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            var entry = store.CreateRequest("CN=meter7.lan", ["meter7.lan"]);

            var pem   = Sign(entry.RequestPEM!, caKey, caCert,
                             clock.GetUtcNow().AddDays(-1),
                             clock.GetUtcNow().AddDays(90));

            Assert.That(store.TryImportCertificate(entry.Id, pem, out var error), Is.True, error);

            Assert.Multiple(() => {

                Assert.That(store.Current?.Id,                        Is.EqualTo(entry.Id));
                Assert.That(store.Current?.Certificate?.Subject,      Is.EqualTo("CN=meter7.lan"));

                // With its key, or a TLS listener could not use it - which is
                // the failure that would otherwise only show up at a handshake.
                Assert.That(store.Current?.Certificate?.HasPrivateKey, Is.True);

                Assert.That(store.SelectFor(null),                    Is.Not.Null);
                Assert.That(store.Next,                               Is.Null);

            });

        }

        #endregion

        #region ACertificateForAnotherKeyIsRefused()

        /// <summary>
        /// The check that keeps a mistake from becoming an outage: a
        /// certificate this meter has no key for is no use to it, and finding
        /// that out at the next handshake would be finding it out the hard way.
        /// </summary>
        [Test]
        public void ACertificateForAnotherKeyIsRefused()
        {

            var clock           = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store           = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            var mine            = store.CreateRequest("CN=mine.lan");
            var somebodyElses   = store.CreateRequest("CN=theirs.lan");

            var theirCertificate = Sign(somebodyElses.RequestPEM!, caKey, caCert,
                                        clock.GetUtcNow().AddDays(-1),
                                        clock.GetUtcNow().AddDays(90));

            Assert.Multiple(() => {
                Assert.That(store.TryImportCertificate(mine.Id, theirCertificate, out var error), Is.False);
                Assert.That(error, Does.Contain("not made for the key"));
                Assert.That(store.Current, Is.Null);
            });

        }

        #endregion

        #region AnExpiredCertificateIsRefused()

        [Test]
        public void AnExpiredCertificateIsRefused()
        {

            var clock           = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store           = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            var entry = store.CreateRequest("CN=meter7.lan");

            var pem   = Sign(entry.RequestPEM!, caKey, caCert,
                             clock.GetUtcNow().AddDays(-400),
                             clock.GetUtcNow().AddDays(-35));

            Assert.Multiple(() => {
                Assert.That(store.TryImportCertificate(entry.Id, pem, out var error), Is.False);
                Assert.That(error, Does.Contain("ran out"));
            });

        }

        #endregion

        #region ACertificateThatIsNotValidYetTakesOverWhenItIs()

        /// <summary>
        /// The whole point: put tomorrow's certificate in today, and have
        /// nothing to do tomorrow.
        /// </summary>
        [Test]
        public void ACertificateThatIsNotValidYetTakesOverWhenItIs()
        {

            var monday          = DateTimeOffset.Parse("2026-09-14T10:00:00Z");
            var clock           = new MovableClock(monday);
            var store           = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            var changes         = new List<(String? From, String? To)>();
            store.OnCurrentChanged += (before, after) => changes.Add((before?.Id, after?.Id));

            // What it is showing today.
            var today = store.CreateRequest("CN=today");
            Assert.That(store.TryImportCertificate(today.Id, Sign(today.RequestPEM!, caKey, caCert, monday.AddDays(-30), monday.AddDays(10)), out var problem), Is.True, problem);
            Assert.That(store.Current?.Id, Is.EqualTo(today.Id));

            // And what somebody puts in on Monday for Wednesday.
            var wednesday = store.CreateRequest("CN=wednesday");
            Assert.That(store.TryImportCertificate(wednesday.Id, Sign(wednesday.RequestPEM!, caKey, caCert, monday.AddDays(2), monday.AddDays(400)), out problem), Is.True, problem);

            Assert.Multiple(() => {

                // Uploading it changes nothing about what is shown now ...
                Assert.That(store.Current?.Id, Is.EqualTo(today.Id), "the newer certificate is not valid yet");

                // ... but the store says it is coming, and when.
                Assert.That(store.Next?.Id,    Is.EqualTo(wednesday.Id));
                Assert.That(store.Next?.Certificate?.NotBefore, Is.EqualTo(monday.AddDays(2).LocalDateTime).Within(TimeSpan.FromSeconds(1)));

            });

            // Tuesday: still the old one.
            clock.MoveTo(monday.AddDays(1));
            store.CheckRollover();
            Assert.That(store.Current?.Id, Is.EqualTo(today.Id));

            // Wednesday, a minute after it began.
            clock.MoveTo(monday.AddDays(2).AddMinutes(1));
            store.CheckRollover();

            Assert.Multiple(() => {

                Assert.That(store.Current?.Id, Is.EqualTo(wednesday.Id), "the newer certificate takes over by itself");
                Assert.That(store.Next,        Is.Null);

                // And it was written down, which is what CheckRollover is for:
                // without it the swap would still happen, silently, at the next
                // handshake.
                Assert.That(changes,           Does.Contain((today.Id, wednesday.Id)));

            });

        }

        #endregion

        #region AnExpiredCertificateStopsBeingShown()

        [Test]
        public void AnExpiredCertificateStopsBeingShown()
        {

            var now             = DateTimeOffset.Parse("2026-09-16T10:00:00Z");
            var clock           = new MovableClock(now);
            var store           = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            var entry = store.CreateRequest("CN=short-lived");
            Assert.That(store.TryImportCertificate(entry.Id, Sign(entry.RequestPEM!, caKey, caCert, now.AddDays(-1), now.AddHours(2)), out var problem), Is.True, problem);
            Assert.That(store.Current?.Id, Is.EqualTo(entry.Id));

            clock.MoveTo(now.AddHours(3));
            store.CheckRollover();

            Assert.Multiple(() => {
                Assert.That(store.Current, Is.Null, "an expired certificate is not shown to anybody");
                Assert.That(store.Entries.First().StateAt(clock.GetUtcNow()), Is.EqualTo("expired"));
            });

        }

        #endregion

        #region TheLastCertificateCannotBeThrownAway()

        [Test]
        public void TheLastCertificateCannotBeThrownAway()
        {

            var now             = DateTimeOffset.Parse("2026-09-16T10:00:00Z");
            var clock           = new MovableClock(now);
            var store           = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            var only = store.CreateRequest("CN=only");
            Assert.That(store.TryImportCertificate(only.Id, Sign(only.RequestPEM!, caKey, caCert, now.AddDays(-1), now.AddDays(90)), out var problem), Is.True, problem);

            Assert.Multiple(() => {
                Assert.That(store.TryRemove(only.Id, out var error), Is.False);
                Assert.That(error, Does.Contain("only certificate"));
                Assert.That(store.Current?.Id, Is.EqualTo(only.Id));
            });

            // With a second one in, the first may go.
            var second = store.CreateRequest("CN=second");
            Assert.That(store.TryImportCertificate(second.Id, Sign(second.RequestPEM!, caKey, caCert, now.AddDays(-1), now.AddDays(90)), out problem), Is.True, problem);

            Assert.Multiple(() => {
                Assert.That(store.TryRemove(only.Id, out var error), Is.True, error);
                Assert.That(store.Entries.Count(), Is.EqualTo(1));
            });

        }

        #endregion

        #region AStoreIsReadBackAfterARestart()

        [Test]
        public void AStoreIsReadBackAfterARestart()
        {

            var now             = DateTimeOffset.Parse("2026-09-16T10:00:00Z");
            var clock           = new MovableClock(now);
            var (caKey, caCert) = NewCA();

            String id;

            {
                var store = NewStore(clock, storePath);
                var entry = store.CreateRequest("CN=meter7.lan", ["meter7.lan"], ["192.168.7.20"], "ec256", "the first one");
                Assert.That(store.TryImportCertificate(entry.Id, Sign(entry.RequestPEM!, caKey, caCert, now.AddDays(-1), now.AddDays(90)), out var problem), Is.True, problem);
                id = entry.Id;
            }

            // A new store over the same directory: a meter that was restarted.
            var reopened = NewStore(clock, storePath);

            Assert.Multiple(() => {

                Assert.That(reopened.LastError,                          Is.Null);
                Assert.That(reopened.Current?.Id,                        Is.EqualTo(id));
                Assert.That(reopened.Current?.Certificate?.HasPrivateKey, Is.True, "the key has to survive a restart, or the meter comes back mute");
                Assert.That(reopened.Current?.Note,                      Is.EqualTo("the first one"));
                Assert.That(reopened.Current?.DNSNames,                  Is.EquivalentTo(new[] { "meter7.lan" }));

            });

        }

        #endregion

        #region AnAdoptedCertificateIsNotAdoptedTwice()

        [Test]
        public void AnAdoptedCertificateIsNotAdoptedTwice()
        {

            var clock = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store = NewStore(clock, storePath);

            using var key         = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var       request     = new CertificateRequest("CN=started-with", key, HashAlgorithmName.SHA256);
            using var certificate = request.CreateSelfSigned(clock.GetUtcNow().AddDays(-1), clock.GetUtcNow().AddDays(365));

            var first  = store.Adopt(certificate, "what it was started with");
            var second = store.Adopt(certificate, "what it was started with");

            Assert.Multiple(() => {
                Assert.That(first,             Is.Not.Null);
                Assert.That(second?.Id,        Is.EqualTo(first?.Id), "every restart adopts the same file; the store must not fill up with copies");
                Assert.That(store.Entries.Count(), Is.EqualTo(1));
                Assert.That(store.Current?.Id, Is.EqualTo(first?.Id));
            });

        }

        #endregion

        #region TheIntermediatesAreKeptAndHandedOut()

        /// <summary>
        /// What goes on the wire is the certificate and the intermediates that
        /// lead to it. Without them a client that does not already hold them
        /// cannot build a path to its trust anchor, and all it can report is a
        /// handshake failure with nothing in it about why.
        /// </summary>
        [Test]
        public void TheIntermediatesAreKeptAndHandedOut()
        {

            var now                       = DateTimeOffset.Parse("2026-09-16T10:00:00Z");
            var clock                     = new MovableClock(now);
            var store                     = NewStore(clock, storePath);
            var (rootKey, rootCert)       = NewCA("CN=Test Root CA");
            var (issuingKey, issuingCert) = NewIntermediate(rootKey, rootCert);

            var entry = store.CreateRequest("CN=meter7.lan", ["meter7.lan"]);

            // What a CA hands back: the certificate, and the intermediate that
            // signed it, in one file.
            var leafPEM = Sign(entry.RequestPEM!, issuingKey, issuingCert, now.AddDays(-1), now.AddDays(90));
            var bundle  = leafPEM + "\u000A" + PemEncoding.WriteString("CERTIFICATE", issuingCert.RawData);

            Assert.That(store.TryImportCertificate(entry.Id, bundle, out var error), Is.True, error);

            var chain = store.ChainFor(null);

            Assert.Multiple(() => {

                Assert.That(chain,                                  Is.Not.Null);
                Assert.That(chain!.Certificate.Subject,             Is.EqualTo("CN=meter7.lan"));
                Assert.That(chain.HasIntermediates,                 Is.True, "the intermediate came with the certificate and has to go back out with it");
                Assert.That(chain.Intermediates,                    Has.Count.EqualTo(1));
                Assert.That(chain.Intermediates[0].Subject,         Is.EqualTo("CN=Test Issuing CA"));

                // The leaf is not repeated among the intermediates, and a root
                // is not sent at all: bytes on the wire that change nothing.
                Assert.That(chain.Intermediates.Cast<X509Certificate2>().Select(certificate => certificate.Thumbprint),
                            Does.Not.Contain(chain.Certificate.Thumbprint));

            });

            // And a store whose certificate came without intermediates says so,
            // rather than pretending to have some.
            var plain      = store.CreateRequest("CN=plain.lan");
            Assert.That(store.TryImportCertificate(plain.Id, Sign(plain.RequestPEM!, issuingKey, issuingCert, now, now.AddDays(90)), out error), Is.True, error);

            var plainChain = store.ChainFor(null);

            Assert.Multiple(() => {
                Assert.That(plainChain!.Certificate.Subject, Is.EqualTo("CN=plain.lan"));
                Assert.That(plainChain.HasIntermediates,     Is.False);

                // Two different chains must not share a cached TLS context.
                Assert.That(plainChain.CacheKey,             Is.Not.EqualTo(chain!.CacheKey));
            });

        }

        #endregion

        #region TheIntermediatesSurviveARestart()

        [Test]
        public void TheIntermediatesSurviveARestart()
        {

            var now                       = DateTimeOffset.Parse("2026-09-16T10:00:00Z");
            var clock                     = new MovableClock(now);
            var (rootKey, rootCert)       = NewCA("CN=Test Root CA");
            var (issuingKey, issuingCert) = NewIntermediate(rootKey, rootCert);

            {
                var store = NewStore(clock, storePath);
                var entry = store.CreateRequest("CN=meter7.lan");
                var bundle = Sign(entry.RequestPEM!, issuingKey, issuingCert, now.AddDays(-1), now.AddDays(90)) +
                             "\u000A" + PemEncoding.WriteString("CERTIFICATE", issuingCert.RawData);
                Assert.That(store.TryImportCertificate(entry.Id, bundle, out var error), Is.True, error);
            }

            var reopened = NewStore(clock, storePath);
            var chain    = reopened.ChainFor(null);

            Assert.Multiple(() => {
                Assert.That(reopened.LastError,      Is.Null);
                Assert.That(chain,                   Is.Not.Null);
                Assert.That(chain!.HasIntermediates, Is.True, "a restarted meter that forgot the intermediates would start failing handshakes it used to pass");
                Assert.That(chain.Intermediates[0].Subject, Is.EqualTo("CN=Test Issuing CA"));
            });

        }

        #endregion

        #region TheStoreCanBeRenderedAsJSON()

        /// <summary>
        /// Everything the API answers with goes through here, including the
        /// cases where a field is empty - which is where a JProperty with a
        /// literal null quietly binds to the params overload and throws.
        /// </summary>
        [Test]
        public void TheStoreCanBeRenderedAsJSON()
        {

            var now             = DateTimeOffset.Parse("2026-09-16T10:00:00Z");
            var clock           = new MovableClock(now);
            var store           = NewStore(clock, storePath);
            var (caKey, caCert) = NewCA();

            // A request with no certificate yet: every certificate field is
            // empty, and "nextAt" has nothing to say either.
            var waiting = store.CreateRequest("CN=waiting");

            var empty = store.ToJSON();

            Assert.Multiple(() => {
                Assert.That(empty["currentId"]?.Type, Is.EqualTo(JTokenType.Null));
                Assert.That(empty["nextAt"]?.Type,    Is.EqualTo(JTokenType.Null));
                Assert.That(empty["entries"]?[0]?["certificate"]?.Type, Is.EqualTo(JTokenType.Null));
                Assert.That(empty["entries"]?[0]?["state"]?.Value<String>(), Is.EqualTo("awaiting a certificate"));
            });

            // And with one in, the fields that were empty are filled.
            Assert.That(store.TryImportCertificate(waiting.Id, Sign(waiting.RequestPEM!, caKey, caCert, now.AddDays(-1), now.AddDays(90)), out var problem), Is.True, problem);

            var filled = store.ToJSON();

            Assert.Multiple(() => {
                Assert.That(filled["currentId"]?.Value<String>(),                        Is.EqualTo(waiting.Id));
                Assert.That(filled["entries"]?[0]?["certificate"]?["subject"]?.Value<String>(), Is.EqualTo("CN=waiting"));
                Assert.That(filled["entries"]?[0]?["state"]?.Value<String>(),            Is.EqualTo("valid"));
            });

        }

        #endregion

        #region ASelfSignedCertificateIsMadeAndUsable()

        [Test]
        public void ASelfSignedCertificateIsMadeAndUsable()
        {

            var clock = new MovableClock(DateTimeOffset.Parse("2026-09-16T10:00:00Z"));
            var store = new CertificateStore(storePath, "web", clock);

            var entry = store.CreateSelfSigned("CN=EnergyMeter01", ["localhost"], ["127.0.0.1"], "made at the first start");

            Assert.Multiple(() => {
                Assert.That(entry.HasCertificate,                 Is.True);
                Assert.That(entry.Certificate?.HasPrivateKey,     Is.True);
                Assert.That(store.Current?.Id,                    Is.EqualTo(entry.Id));
                Assert.That(entry.Certificate?.Subject,           Is.EqualTo("CN=EnergyMeter01"));
                Assert.That(entry.IsValidAt(clock.GetUtcNow()),   Is.True);
            });

        }

        #endregion

    }

}
