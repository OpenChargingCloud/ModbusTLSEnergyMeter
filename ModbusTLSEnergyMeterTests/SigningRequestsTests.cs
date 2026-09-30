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

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The meter's certificate signing requests: a key made here, a request
    /// for a CA to sign, and the certificate that comes back - checked against
    /// that key before the node's store is given it.
    /// </summary>
    public class SigningRequestsTests
    {

        #region Data

        private String? directory;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(directory);

        }

        [TearDown]
        public void TearDown()
        {
            try
            {
                if (directory is not null && Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch
            {
                // A file somebody still holds is not what is under test.
            }
        }

        #endregion


        #region EveryKeyType_MakesARequestThatVerifies_AndIsShownWhereThisMachineCan()

        /// <summary>
        /// Every kind of key a certificate can be asked for here makes a
        /// request that verifies against that key, and the certificate a CA
        /// signs for it comes back in with its key - and is shown on the
        /// listener it was asked for exactly when this machine can present it.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Driven off the meter's list rather than a copy of it, so that a kind
        /// of key Hermod adds and the list takes in is covered here without
        /// anybody remembering to.
        /// </para>
        /// <para>
        /// Whether it is shown is not asserted either way. A certificate for a
        /// P-521 key is shown on Debian, and passed over on a Windows whose
        /// SChannel has that curve switched off, as it is by default - which
        /// the list does not know, and so offers it there all the same. What is
        /// asserted is that the listener's answer is the machine's: one this
        /// machine cannot present is never handed to the TLS stack, and one it
        /// can is not held back.
        /// </para>
        /// </remarks>
        [Test]
        public void EveryKeyType_MakesARequestThatVerifies_AndIsShownWhereThisMachineCan()
        {

            var requests         = NewRequests();
            var store            = NewStore();
            var modbus           = new ListenerCertificates(store, ListenerCertificates.Modbus);
            var (caKey, caCert)  = NewCA();
            var keyTypes         = SigningRequests.KeyTypes.Select(keyType => keyType.Id).ToList();
            var from             = DateTimeOffset.UtcNow.AddHours(-1);

            Assert.That(keyTypes, Does.Contain(SigningRequests.DefaultKeyType));

            foreach (var keyType in keyTypes)
            {

                Assert.That(requests.TryCreate(ListenerCertificates.Modbus, $"CN={keyType}.example", [ $"{keyType}.example" ], null, keyType, null, out var made, out var error),
                            Is.True, $"{keyType}: {error}");

                var request  = made!;
                var pem      = requests.RequestPEM(request.Id)!;
                var pkcs10   = new Org.BouncyCastle.Pkcs.Pkcs10CertificationRequest(DEROf(pem));

                Assert.Multiple(() => {
                    Assert.That(request.KeyType,                                         Is.EqualTo(keyType));
                    Assert.That(pkcs10.Verify(),                                         Is.True, $"a {keyType} request verifies against the key that made it");
                    Assert.That(pkcs10.GetCertificationRequestInfo().Subject.ToString(), Is.EqualTo($"CN={keyType}.example"));
                });

                // Each valid from a minute after the one before, so that the one
                // just answered is the newest, and the one the listener shows
                // when this machine can.
                from             = from.AddMinutes(1);

                Assert.That(requests.TryAnswer(request.Id, Sign(pem, caKey, caCert, from, from.AddDays(90)), store, out var entry, out error),
                            Is.True, $"{keyType}: {error}");

                var shown        = modbus.Current;

                // Found out by the listener, with a handshake, when it was asked.
                var presentable  = KeyAlgorithm.Find(keyType)?.KnownToBePresentable;

                TestContext.Out.WriteLine($"{keyType}: {(presentable == true ? "shown" : "passed over - this machine cannot present it")}");

                Assert.Multiple(() => {
                    Assert.That(entry?.HasPrivateKey,          Is.True,              $"a {keyType} certificate comes back in with its key");
                    Assert.That(presentable,                   Is.Not.Null,          $"the listener asked this machine whether it can present a {keyType} certificate");
                    Assert.That(shown?.Entry.Id == entry?.Id,  Is.EqualTo(presentable), $"a {keyType} certificate is shown exactly when this machine can present it");
                });

            }

        }

        #endregion

        #region TheOldKeyTypeSpellings_StillResolve()

        /// <summary>
        /// The meter's own store called these "ec256" and "mldsa65" before
        /// Hermod had a list, and its requests are adopted with the name they
        /// were written under. Losing a request over a rename would lose its key.
        /// </summary>
        [Test]
        public void TheOldKeyTypeSpellings_StillResolve()
        {

            Assert.Multiple(() => {

                Assert.That(SigningRequests.AlgorithmOf("ec256")?.Id,        Is.EqualTo("ecdsa-p256"));
                Assert.That(SigningRequests.AlgorithmOf("ec521")?.Id,        Is.EqualTo("ecdsa-p521"));
                Assert.That(SigningRequests.AlgorithmOf("rsa3072")?.Id,      Is.EqualTo("rsa-3072"));
                Assert.That(SigningRequests.AlgorithmOf("mldsa65")?.Id,      Is.EqualTo("ml-dsa-65"));

                // And the names used now, which is what everything writes.
                Assert.That(SigningRequests.AlgorithmOf("ecdsa-p384")?.Id,   Is.EqualTo("ecdsa-p384"));

                Assert.That(SigningRequests.AlgorithmOf("falcon-1024"),      Is.Null);

            });

            // Asked for under an old name, written down under the new one, so
            // that the requests do not go on accumulating both spellings.
            var requests = NewRequests();

            Assert.That(requests.TryCreate(ListenerCertificates.Web, "CN=meter.example", null, null, "ec256", null, out var request, out var error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(request?.KeyType,                    Is.EqualTo("ecdsa-p256"));
                Assert.That(requests.Get(request?.Id)?.KeyType,  Is.EqualTo("ecdsa-p256"), "and read back as it was written");
            });

        }

        #endregion

        #region WhatCannotBeAskedFor_IsRefused_AndNothingIsMade()

        /// <summary>
        /// A kind of key nobody knows, one Hermod makes but whose certificate
        /// could be neither kept with its key nor shown, a listener the meter
        /// does not have, and a subject that is none: each refused with a
        /// reason, and no key made for any of them. Asked without a kind of
        /// key, the default one.
        /// </summary>
        [Test]
        public void WhatCannotBeAskedFor_IsRefused_AndNothingIsMade()
        {

            var requests = NewRequests();

            Assert.Multiple(() => {

                Assert.That(requests.TryCreate(ListenerCertificates.Modbus, "CN=meter.example", null, null, "falcon-1024", null, out _, out var unknown),  Is.False);
                Assert.That(unknown,                                                                                                                         Does.Contain(SigningRequests.DefaultKeyType), "and it says which it does know");

                Assert.That(requests.TryCreate(ListenerCertificates.Modbus, "CN=meter.example", null, null, "ed25519",     null, out _, out var edwards),  Is.False, "an Edwards curve");
                Assert.That(edwards,                                                                                                                         Does.Contain("'ed25519'"));
                Assert.That(requests.TryCreate(ListenerCertificates.Modbus, "CN=meter.example", null, null, "mldsa65",     null, out _, out _),            Is.False, "a lattice, under its old spelling too");

                Assert.That(requests.TryCreate("dns",                       "CN=meter.example", null, null, null,          null, out _, out var listener), Is.False);
                Assert.That(listener,                                                                                                                        Does.Contain(ListenerCertificates.Modbus).And.Contain(ListenerCertificates.Web));

                Assert.That(requests.TryCreate(ListenerCertificates.Web,    "not a subject",    null, null, null,          null, out _, out _),            Is.False);

                Assert.That(requests.All,                                                                                                                    Is.Empty, "no key was made for any of them");

            });

            Assert.That(requests.TryCreate(ListenerCertificates.Web, "CN=meter.example", null, null, null, null, out var request, out var error), Is.True, error);
            Assert.That(request?.KeyType, Is.EqualTo(SigningRequests.DefaultKeyType));

        }

        #endregion

        #region ARequestKeepsItsKey_AndGivesOutOnlyTheRequest()

        /// <summary>
        /// The key is made here and stays here: what goes out is the request,
        /// which carries the names asked for, so that a CA reading it sees them
        /// rather than having to be told them separately.
        /// </summary>
        [Test]
        public void ARequestKeepsItsKey_AndGivesOutOnlyTheRequest()
        {

            var requests = NewRequests();

            Assert.That(requests.TryCreate(ListenerCertificates.Web, "CN=meter7.lan", [ "meter7.lan", "meter7" ], [ "192.168.7.20" ], null, "for the bench",
                                           out var made, out var error),
                        Is.True, error);

            var request  = made!;
            var pem      = requests.RequestPEM(request.Id);
            var keyFile  = Path.Combine(requests.Path, request.Id, "key.pem");

            Assert.Multiple(() => {

                Assert.That(pem,                                     Does.StartWith("-----BEGIN CERTIFICATE REQUEST-----"));
                Assert.That(pem,                                     Does.Not.Contain("PRIVATE KEY"));
                Assert.That(request.ToJSON().ToString(),             Does.Not.Contain("PRIVATE KEY"));
                Assert.That(request.ToJSON()["state"]?.ToString(),   Is.EqualTo("awaiting a certificate"));
                Assert.That(requests.Get(request.Id)?.Note,          Is.EqualTo("for the bench"));

                // The key is on disk here, and in nothing that is handed out.
                Assert.That(File.ReadAllText(keyFile),               Does.Contain("PRIVATE KEY"));

                if (!OperatingSystem.IsWindows())
                    Assert.That(File.GetUnixFileMode(keyFile),       Is.EqualTo(UnixFileMode.UserRead | UnixFileMode.UserWrite),
                                "readable by the account the meter runs as, and by nobody else");

            });

            var parsed   = CertificateRequest.LoadSigningRequestPem(pem!, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);
            var names    = parsed.CertificateExtensions.OfType<X509SubjectAlternativeNameExtension>().Single();

            Assert.Multiple(() => {
                Assert.That(parsed.SubjectName.Name,       Is.EqualTo("CN=meter7.lan"));
                Assert.That(names.EnumerateDnsNames(),     Is.EquivalentTo(new[] { "meter7.lan", "meter7" }));
                Assert.That(names.EnumerateIPAddresses(),  Is.EquivalentTo(new[] { NetIPAddress.Parse("192.168.7.20") }));
            });

        }

        #endregion

        #region ACertificateForAnotherKey_IsRefused()

        /// <summary>
        /// The check that keeps a mistake from becoming an outage: a
        /// certificate this meter has no key for is no use to it, and finding
        /// that out at the next handshake would be finding it out the hard way.
        /// Matched on the public key, and a real check: offered to the request
        /// it was made for, the same certificate is taken.
        /// </summary>
        [Test]
        public void ACertificateForAnotherKey_IsRefused()
        {

            var requests         = NewRequests();
            var store            = NewStore();
            var (caKey, caCert)  = NewCA();
            var now              = DateTimeOffset.UtcNow;

            Assert.That(requests.TryCreate(ListenerCertificates.Modbus, "CN=mine.lan",   null, null, null, null, out var madeMine,   out var error), Is.True, error);
            Assert.That(requests.TryCreate(ListenerCertificates.Modbus, "CN=theirs.lan", null, null, null, null, out var madeTheirs, out error),     Is.True, error);

            var mine             = madeMine!;
            var theirs           = madeTheirs!;

            // A certificate made for the second request, offered to the first.
            var theirCertificate = Sign(requests.RequestPEM(theirs.Id)!, caKey, caCert, now.AddDays(-1), now.AddDays(90));

            Assert.Multiple(() => {
                Assert.That(requests.TryAnswer(mine.Id, theirCertificate, store, out _, out var refused),   Is.False);
                Assert.That(refused,                                                                         Does.Contain("not made for the key of this request"));
                Assert.That(store.ByKind(CertificateKind.TLSIdentity),                                       Is.Empty, "nothing was put into the store");
                Assert.That(requests.Get(mine.Id)?.AnsweredBy,                                               Is.Empty);
            });

            Assert.That(requests.TryAnswer(theirs.Id, theirCertificate, store, out var taken, out error), Is.True, error);

            Assert.Multiple(() => {
                Assert.That(taken?.Usages,                          Is.EqualTo(new[] { ListenerCertificates.Modbus }));
                Assert.That(taken?.HasPrivateKey,                   Is.True);
                Assert.That(requests.Get(theirs.Id)?.AnsweredBy,    Is.EqualTo(new[] { taken?.Id }));
            });

        }

        #endregion

        #region AnExpiredCertificate_IsRefused()

        /// <summary>
        /// A certificate that has run out is refused as the answer to a request -
        /// and kept when it was kept already, by a meter from before, whose
        /// certificates are moved into the node's store and not judged on the
        /// way.
        /// </summary>
        [Test]
        public void AnExpiredCertificate_IsRefused()
        {

            var requests         = NewRequests();
            var store            = NewStore();
            var (caKey, caCert)  = NewCA();
            var now              = DateTimeOffset.UtcNow;

            Assert.That(requests.TryCreate(ListenerCertificates.Modbus, "CN=meter7.lan", null, null, null, null, out var made, out var error), Is.True, error);

            var request  = made!;
            var expired  = Sign(requests.RequestPEM(request.Id)!, caKey, caCert, now.AddDays(-400), now.AddDays(-35));

            Assert.Multiple(() => {
                Assert.That(requests.TryAnswer(request.Id, expired, store, out _, out var refused),  Is.False);
                Assert.That(refused,                                                                  Does.Contain("ran out"));
                Assert.That(store.ByKind(CertificateKind.TLSIdentity),                                Is.Empty);
                Assert.That(requests.Get(request.Id)?.AnsweredBy,                                     Is.Empty, "and the request still waits");
            });

            var key = File.ReadAllText(Path.Combine(requests.Path, request.Id, "key.pem"));

            Assert.That(SigningRequests.TryCredential(expired, key, now, out var pkcs12, out var kept, RefuseExpired: false), Is.True, kept);
            Assert.That(pkcs12, Is.Not.Empty);

        }

        #endregion


        #region ARequestIsRemovedWhole_OrNotAtAll()

        /// <summary>
        /// A request whose files somebody else holds open is not thrown away,
        /// and stays whole - listed, with its key; let go of, it goes, and
        /// nothing of it is left.
        /// </summary>
        /// <remarks>
        /// Deleted file by file, its key.pem went before its meta.json: the
        /// removal said it had failed, and the request was listed on with no
        /// key to take its certificate. Windows only: elsewhere an open file
        /// keeps nobody from renaming or deleting its directory.
        /// </remarks>
        [Test]
        [Platform("Win")]
        public void ARequestIsRemovedWhole_OrNotAtAll()
        {

            var requests = NewRequests();

            Assert.That(requests.TryCreate(ListenerCertificates.Web, "CN=meter7.lan", [ "meter7.lan" ], [], null, "held open",
                                           out var made, out var error),
                        Is.True, error);

            var request  = made!;
            var folder   = Path.Combine(requests.Path, request.Id);

            using (File.Open(Path.Combine(folder, "meta.json"), FileMode.Open, FileAccess.Read, FileShare.Read))
            {

                Assert.Multiple(() => {

                    Assert.That(requests.TryRemove(request.Id, out var refused),    Is.False, "a request whose files are held open cannot go");
                    Assert.That(refused,                                            Does.StartWith("That request could not be removed"));

                    Assert.That(requests.Get(request.Id),                           Is.Not.Null, "it is still listed");
                    Assert.That(File.Exists(Path.Combine(folder, "key.pem")),       Is.True, "with its key");
                    Assert.That(File.Exists(Path.Combine(folder, "request.pem")),   Is.True);

                });

            }

            // Let go of, it goes - all of it.
            Assert.Multiple(() => {
                Assert.That(requests.TryRemove(request.Id, out var failed, out var leftBehind),  Is.True, failed);
                Assert.That(leftBehind,                                                          Is.Null);
                Assert.That(Directory.GetDirectories(requests.Path),                             Is.Empty, "nothing of it is left");
                Assert.That(requests.All,                                                        Is.Empty);
            });

        }

        #endregion

        #region ARequestSetAside_IsNotReadAgain()

        /// <summary>
        /// A request whose directory is set aside and then cannot be deleted is
        /// thrown away all the same: neither this list nor the next one reads
        /// it any more, and the removal says where what is left of it lies.
        /// </summary>
        [Test]
        public void ARequestSetAside_IsNotReadAgain()
        {

            var requests = NewRequests();

            Assert.That(requests.TryCreate(ListenerCertificates.Web, "CN=meter7.lan", [ "meter7.lan" ], [], null, "cannot be deleted",
                                           out var made, out var error),
                        Is.True, error);

            var request = made!;

            requests.BeforeDeleting = aside => throw new IOException($"'{aside}' is held by somebody else.");

            Assert.That(requests.TryRemove(request.Id, out var failed, out var leftBehind), Is.True, failed);

            Assert.Multiple(() => {

                Assert.That(leftBehind,                                             Is.Not.Null);
                Assert.That(Path.GetFileName(leftBehind),                           Does.StartWith(request.Id + ".").And.EndWith(".removed"));
                Assert.That(File.Exists(Path.Combine(leftBehind!, "key.pem")),      Is.True, "left as it was, only renamed");

                Assert.That(requests.Get(request.Id),                               Is.Null, "no longer this list's");
                Assert.That(requests.All,                                           Is.Empty);
                Assert.That(NewRequests().All,                                      Is.Empty, "nor the next one's");

            });

        }

        #endregion

        #region (private) NewRequests() / NewStore() / NewCA(...) / Sign(...) / DEROf(PEM)

        private SigningRequests NewRequests()

            => new (Path.Combine(directory!, "certificates", SigningRequests.DirectoryName));

        /// <summary>
        /// A store as the meter's: the TLS kinds, and its two listeners.
        /// </summary>
        private CertificateStore NewStore()

            => new (Path.Combine(directory!, "certificates"),
                    new EventLog(),
                    CertificateKindExtensions.TLS,
                    Listeners: ListenerCertificates.All);

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
        /// Sign a request the way a CA would, for a chosen stretch of time.
        /// </summary>
        private static String Sign(String            RequestPEM,
                                   ECDsa             CAKey,
                                   X509Certificate2  CACertificate,
                                   DateTimeOffset    NotBefore,
                                   DateTimeOffset    NotAfter)
        {

            var request            = CertificateRequest.LoadSigningRequestPem(RequestPEM,
                                                                              HashAlgorithmName.SHA256,
                                                                              CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

            using var certificate  = request.Create(CACertificate.SubjectName,
                                                    X509SignatureGenerator.CreateForECDsa(CAKey),
                                                    NotBefore,
                                                    NotAfter,
                                                    [ 0x01, .. RandomNumberGenerator.GetBytes(15) ]);

            return certificate.ExportCertificatePem();

        }

        private static Byte[] DEROf(String PEM)
        {

            var fields = PemEncoding.Find(PEM);

            return Convert.FromBase64String(PEM[fields.Base64Data]);

        }

        #endregion

    }

}
