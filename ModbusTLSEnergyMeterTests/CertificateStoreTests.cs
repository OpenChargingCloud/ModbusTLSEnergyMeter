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
