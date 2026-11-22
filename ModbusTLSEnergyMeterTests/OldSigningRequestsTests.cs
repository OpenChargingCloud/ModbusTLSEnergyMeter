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

using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The signing requests a meter kept itself, one directory each below
    /// "requests", before the node's certificate store made keys: what waits
    /// for its certificate waits in the node's store after the next start,
    /// what was answered is held by its identity, and the directories are
    /// below "moved".
    /// </summary>
    public class OldSigningRequestsTests
    {

        #region Data

        private String? directory;

        private String Certificates
            => Path.Combine(directory!, "data", "certificates");

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            directory = Path.Combine(Path.GetTempPath(), "ModbusTLSEnergyMeterTests", Guid.NewGuid().ToString("N"));

            Directory.CreateDirectory(directory);

            await new ModbusPKI().BuildPKI(Path.Combine(directory, "pki"));

        }

        [TearDown]
        public void TearDown()
        {

            if (directory is not null)
                TestAuthorities.RemoveInstalled(Path.Combine(directory, "pki"));

            try
            {
                if (directory is not null && Directory.Exists(directory))
                    Directory.Delete(directory, recursive: true);
            }
            catch
            {
                // A file a disposed meter still holds is not what is under test.
            }

        }

        #endregion


        #region TheOldKeyTypeSpellings_StillResolve()

        /// <summary>
        /// The meter's own store called these "ec256" and "mldsa65" before
        /// Hermod had a list, and its requests are taken over with the name
        /// they were written under. Losing a request over a rename would lose
        /// its key.
        /// </summary>
        [Test]
        public void TheOldKeyTypeSpellings_StillResolve()
        {

            Assert.Multiple(() => {

                Assert.That(OldSigningRequests.AlgorithmOf("ec256")?.Id,        Is.EqualTo("ecdsa-p256"));
                Assert.That(OldSigningRequests.AlgorithmOf("ec521")?.Id,        Is.EqualTo("ecdsa-p521"));
                Assert.That(OldSigningRequests.AlgorithmOf("rsa3072")?.Id,      Is.EqualTo("rsa-3072"));
                Assert.That(OldSigningRequests.AlgorithmOf("mldsa65")?.Id,      Is.EqualTo("ml-dsa-65"));

                // And the names used now, which is what everything writes.
                Assert.That(OldSigningRequests.AlgorithmOf("ecdsa-p384")?.Id,   Is.EqualTo("ecdsa-p384"));

                Assert.That(OldSigningRequests.AlgorithmOf("falcon-1024"),      Is.Null);

            });

        }

        #endregion

        #region AWaitingRequest_WaitsInTheNodesStore_AndItsCertificateIsShown()

        /// <summary>
        /// A key the meter made for its Modbus/TLS listener, whose certificate
        /// never came: after the next start it waits in the node's store, as a
        /// TLS server identity for that listener, under its note, reachable as
        /// the names it asked for, its kind of key under the name used now -
        /// and its directory is below "moved". Started again, it is not taken
        /// over twice. The certificate that comes back for it then is an
        /// identity of that listener, and the one it shows.
        /// </summary>
        [Test]
        public async Task AWaitingRequest_WaitsInTheNodesStore_AndItsCertificateIsShown()
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            OldRequest("20260105-000000-aaaaaa", MeterListeners.Modbus, key, "CN=meter7.lan", "ec256", "the next Modbus/TLS one",
                       DNSNames: [ "meter7.lan" ], IPAddresses: [ "192.0.2.7" ]);

            String requestId;

            await using (var meter = NewMeter())
            {

                var waiting = meter.Certificates.Requests.SingleOrDefault();

                Assert.Multiple(() => {

                    Assert.That(waiting?.Kind,                   Is.EqualTo(CertificateKind.TLSServerIdentity));
                    Assert.That(waiting?.Usages,                 Is.EqualTo(new CertificateUsage[] { MeterListeners.Modbus }));
                    Assert.That(waiting?.Label,                  Is.EqualTo("the next Modbus/TLS one"));
                    Assert.That(waiting?.Subject,                Is.EqualTo("CN=meter7.lan"));
                    Assert.That(waiting?.AlgorithmId,            Is.EqualTo("ecdsa-p256"), "the old spelling, under the name used now");
                    Assert.That(waiting?.Template,               Is.EqualTo(CSRTemplate.ServerId));
                    Assert.That(waiting?.ReachableAs,            Is.EqualTo(new[] { "meter7.lan", "192.0.2.7" }));

                    Assert.That(Directory.Exists(Path.Combine(Certificates, "requests", "20260105-000000-aaaaaa")),           Is.False);
                    Assert.That(Directory.Exists(Path.Combine(Certificates, "moved", "requests", "20260105-000000-aaaaaa")),  Is.True, "moved, not deleted");

                });

                requestId = waiting!.Id;

            }

            await using var again = NewMeter();

            Assert.That(again.Certificates.Requests.Select(request => request.Id), Is.EqualTo(new[] { requestId }), "taken over twice, or lost");

            // What a CA sends back for that key: a certificate whose validity
            // began after that of the one the meter was started with.
            using var certificate = new CertificateRequest("CN=meter7.lan", key, HashAlgorithmName.SHA256).
                                        CreateSelfSigned(DateTimeOffset.UtcNow.AddMinutes(-1), DateTimeOffset.UtcNow.AddDays(365));

            Assert.That(again.Certificates.TryAnswerRequest(certificate.ExportCertificatePem(), out var entry, out var answered, out _, out var error, out _),
                        Is.True, error);

            Assert.Multiple(() => {
                Assert.That(answered,                                   Is.EqualTo(requestId));
                Assert.That(entry?.Kind,                                Is.EqualTo(CertificateKind.TLSServerIdentity));
                Assert.That(entry?.Usages,                              Is.EqualTo(new CertificateUsage[] { MeterListeners.Modbus }));
                Assert.That(entry?.Label,                               Is.EqualTo("the next Modbus/TLS one"));
                Assert.That(again.Certificates.Requests,                Is.Empty, "the key waits for nothing any more");
                Assert.That(again.ModbusCertificates.Entry?.Id, Is.EqualTo(entry?.Id), "Modbus/TLS shows another one");
            });

        }

        #endregion

        #region AnAnsweredRequest_IsHeldByItsIdentity_AndOneWhoseAnswerIsGone_Waits()

        /// <summary>
        /// A request the meter kept after its certificate came, so that the
        /// same key could be certified again: that identity holds the key, so
        /// nothing waits for it - its directory is below "moved", with the
        /// request as it was sent. One whose certificate was taken out of the
        /// store since is a key nobody holds: it waits again.
        /// </summary>
        [Test]
        public async Task AnAnsweredRequest_IsHeldByItsIdentity_AndOneWhoseAnswerIsGone_Waits()
        {

            using var answeredKey  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var goneKey      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var answer       = new CertificateRequest("CN=answered.lan", answeredKey, HashAlgorithmName.SHA256).
                                         CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            var before = new CertificateStore(Certificates, new EventLog(), [ CertificateKind.TLSServerIdentity ], Listeners: MeterListeners.All);

            Assert.That(before.Import(answer.Export(X509ContentType.Pkcs12), CertificateKind.TLSServerIdentity, null,
                                      "the answered one", [ MeterListeners.Web ], out var identity, out var error), Is.True, error);

            OldRequest("20260106-000000-bbbbbb", MeterListeners.Web, answeredKey, "CN=answered.lan", "ecdsa-p256", "the answered one",
                       AnsweredBy: [ identity!.Id ]);

            OldRequest("20260107-000000-cccccc", MeterListeners.Web, goneKey,     "CN=gone.lan",     "ecdsa-p256", "its answer is gone",
                       DNSNames: [ "gone.lan" ], AnsweredBy: [ "20260101-000000-ffffff" ]);

            await using var meter = NewMeter();

            var requests = meter.Certificates.Requests;

            Assert.Multiple(() => {

                Assert.That(requests.Select(request => request.Label),  Is.EqualTo(new[] { "its answer is gone" }));
                Assert.That(meter.Certificates.Get(identity.Id)?.Kind,  Is.EqualTo(CertificateKind.TLSServerIdentity), "and the identity is as it was");

                Assert.That(File.Exists(Path.Combine(Certificates, "moved", "requests", "20260106-000000-bbbbbb", "request.pem")), Is.True,
                            "the request as it was sent, for a renewal of the same key");
                Assert.That(Directory.Exists(Path.Combine(Certificates, "moved", "requests", "20260107-000000-cccccc")),           Is.True);

            });

        }

        #endregion

        #region WhatCannotBeTakenOver_StaysWhereItIs()

        /// <summary>
        /// A request whose key cannot be read, or is not the key of the
        /// request, is not taken over - where a certificate would come for it
        /// weeks later and fit nothing -, and not moved away either: it stays
        /// where it was, for somebody to look at, and the meter starts all
        /// the same.
        /// </summary>
        [Test]
        public async Task WhatCannotBeTakenOver_StaysWhereItIs()
        {

            using var key = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var broken = OldRequest("20260108-000000-dddddd", MeterListeners.Modbus, key, "CN=broken.lan", "ecdsa-p256", "a broken one");

            File.WriteAllText(Path.Combine(broken, "key.pem"), "-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n");

            // And one whose key can be read, and is another request's.
            using var other = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var mixedUp = OldRequest("20260109-000000-eeeeee", MeterListeners.Web, key, "CN=mixed-up.lan", "ecdsa-p256", "a mixed-up one");

            File.WriteAllText(Path.Combine(mixedUp, "key.pem"), other.ExportPkcs8PrivateKeyPem());

            await using var meter = NewMeter();

            Assert.Multiple(() => {
                Assert.That(meter.Certificates.Requests,  Is.Empty);
                Assert.That(Directory.Exists(broken),     Is.True, "moved away, or deleted");
                Assert.That(Directory.Exists(mixedUp),    Is.True, "moved away, or deleted");
            });

        }

        #endregion


        #region (private) NewMeter() / OldRequest(...)

        /// <summary>
        /// A meter on the data directory of this test, started with the demo
        /// PKI's certificate and clients CA - not listening, which the store does
        /// not need.
        /// </summary>
        private ModbusTLSEnergyMeter NewMeter()

            => new (
                   SerialNumber:       "meter-test-003",
                   ServerPfxPath:      Path.Combine(directory!, "pki", "server.pfx"),
                   ServerPfxPassword:  "demo",
                   ClientCACertPath:   Path.Combine(directory!, "pki", "issuing-clients-ca.crt"),
                   ListenAddress:      NetIPAddress.Loopback,
                   ListenPort:         TestPorts.Free(),
                   HTTPHostname:       IPv4Address.Localhost,
                   HTTPPort:           TestPorts.Free(),
                   DataPath:           Path.Combine(directory!, "data"),
                   ConfigFile:         new WWCPConfigFile(Path.Combine(directory!, "configuration.json")),
                   LogToConsole:       false
               );

        /// <summary>
        /// A request as the meter wrote it while it kept them itself: a
        /// directory below "requests" with the key, the request and what was
        /// asked for.
        /// </summary>
        private String OldRequest(String                Id,
                                  String                Listener,
                                  ECDsa                 Key,
                                  String                Subject,
                                  String                KeyType,
                                  String                Note,
                                  IEnumerable<String>?  DNSNames     = null,
                                  IEnumerable<String>?  IPAddresses  = null,
                                  IEnumerable<String>?  AnsweredBy   = null)
        {

            var requestDirectory = Path.Combine(Certificates, "requests", Id);

            Directory.CreateDirectory(requestDirectory);

            File.WriteAllText(Path.Combine(requestDirectory, "key.pem"),      Key.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(Path.Combine(requestDirectory, "request.pem"),  new CertificateRequest(Subject, Key, HashAlgorithmName.SHA256).CreateSigningRequestPem());
            File.WriteAllText(Path.Combine(requestDirectory, "meta.json"),    new JObject(
                                                                                  new JProperty("id",           Id),
                                                                                  new JProperty("listener",     Listener),
                                                                                  new JProperty("createdAt",    DateTimeOffset.UtcNow.AddDays(-20).ToString("o")),
                                                                                  new JProperty("subject",      Subject),
                                                                                  new JProperty("dnsNames",     new JArray(DNSNames    ?? [])),
                                                                                  new JProperty("ipAddresses",  new JArray(IPAddresses ?? [])),
                                                                                  new JProperty("keyType",      KeyType),
                                                                                  new JProperty("note",         Note),
                                                                                  new JProperty("answeredBy",   new JArray(AnsweredBy  ?? []))
                                                                              ).ToString());

            return requestDirectory;

        }

        #endregion

    }

}
