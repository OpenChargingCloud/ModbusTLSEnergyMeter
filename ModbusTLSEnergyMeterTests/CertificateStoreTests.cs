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
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The meter's certificates in the node's store: what a meter started the
    /// old way puts into it, and what a meter from before its certificates were
    /// the node's finds in it.
    /// </summary>
    public class CertificateStoreTests
    {

        #region Data

        private String? directory;

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


        #region AMeterFromBefore_FindsItsCertificatesInTheNodesStore()

        /// <summary>
        /// A meter from before kept its certificates in stores of its own:
        /// "modbus" and "web" with a directory per certificate - the one it was
        /// started with as base64 text - and "trust" with a file per accepted CA.
        /// Started again, each is in the node's store, told the listener it was
        /// for and keeping its note and its switch; the keys that asked for them
        /// are signing requests; and the old directories are below "moved".
        /// </summary>
        [Test]
        public async Task AMeterFromBefore_FindsItsCertificatesInTheNodesStore()
        {

            var certificates  = Path.Combine(directory!, "data", "certificates");
            var now           = DateTimeOffset.UtcNow;

            #region modbus: the certificate it was started with, as base64 text

            using var modbusKey   = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var modbusCert  = new CertificateRequest("CN=old modbus", modbusKey, HashAlgorithmName.SHA256).
                                        CreateSelfSigned(now.AddDays(-10), now.AddDays(100));

            var modbusEntry       = Path.Combine(certificates, "modbus", "20260101-000000-aaaaaa");
            Directory.CreateDirectory(modbusEntry);

            File.WriteAllText(Path.Combine(modbusEntry, "certificate.pfx"), Convert.ToBase64String(modbusCert.Export(X509ContentType.Pkcs12)));
            File.WriteAllText(Path.Combine(modbusEntry, "meta.json"),       Meta("20260101-000000-aaaaaa", "CN=old modbus", "ec256", "the old one it was started with").ToString());

            #endregion

            #region web: a certificate asked for here, and a request still waiting

            using var webKey      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var webRequest        = new CertificateRequest("CN=old web", webKey, HashAlgorithmName.SHA256);
            using var webCert     = webRequest.CreateSelfSigned(now.AddDays(-5), now.AddDays(200));

            var webEntry          = Path.Combine(certificates, "web", "20260102-000000-bbbbbb");
            Directory.CreateDirectory(webEntry);

            File.WriteAllText(Path.Combine(webEntry, "key.pem"),          webKey.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(Path.Combine(webEntry, "request.pem"),      webRequest.CreateSigningRequestPem());
            File.WriteAllText(Path.Combine(webEntry, "certificate.pem"),  new String(PemEncoding.Write("CERTIFICATE", webCert.RawData)));
            File.WriteAllText(Path.Combine(webEntry, "meta.json"),        Meta("20260102-000000-bbbbbb", "CN=old web", "ecdsa-p256", "the operator's web certificate").ToString());

            using var waitingKey  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var waitingEntry      = Path.Combine(certificates, "web", "20260103-000000-cccccc");
            Directory.CreateDirectory(waitingEntry);

            File.WriteAllText(Path.Combine(waitingEntry, "key.pem"),      waitingKey.ExportPkcs8PrivateKeyPem());
            File.WriteAllText(Path.Combine(waitingEntry, "request.pem"),  new CertificateRequest("CN=still waiting", waitingKey, HashAlgorithmName.SHA256).CreateSigningRequestPem());
            File.WriteAllText(Path.Combine(waitingEntry, "meta.json"),    Meta("20260103-000000-cccccc", "CN=still waiting", "ecdsa-p256", "still waiting").ToString());

            #endregion

            #region trust: a CA somebody stopped accepting

            using var caKey       = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var caRequest         = new CertificateRequest("CN=Old Clients CA", caKey, HashAlgorithmName.SHA256);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var caCert      = caRequest.CreateSelfSigned(now.AddDays(-30), now.AddDays(3000));

            var trust             = Path.Combine(certificates, "trust");
            Directory.CreateDirectory(trust);

            File.WriteAllText(Path.Combine(trust, "20260104-000000-dddddd.pem"),   caCert.ExportCertificatePem());
            File.WriteAllText(Path.Combine(trust, "20260104-000000-dddddd.json"),  new JObject(
                                                                                        new JProperty("id",       "20260104-000000-dddddd"),
                                                                                        new JProperty("name",     "the old clients CA"),
                                                                                        new JProperty("addedAt",  now.AddDays(-30).ToString("o")),
                                                                                        new JProperty("enabled",  false)
                                                                                    ).ToString());

            #endregion

            await using var meter = NewMeter();

            var store             = meter.Certificates;
            var oldModbus         = store.Entries.FirstOrDefault(entry => entry.Label == "the old one it was started with");
            var oldWeb            = store.Entries.FirstOrDefault(entry => entry.Label == "the operator's web certificate");
            var oldCA             = store.Entries.FirstOrDefault(entry => entry.Label == "the old clients CA");
            var answered          = meter.SigningRequests.Get("20260102-000000-bbbbbb");
            var waiting           = meter.SigningRequests.Get("20260103-000000-cccccc");

            Assert.Multiple(() => {

                Assert.That(oldModbus?.Kind,                              Is.EqualTo(CertificateKind.TLSIdentity));
                Assert.That(oldModbus?.Usages,                            Is.EqualTo(new[] { ListenerCertificates.Modbus }));
                Assert.That(oldModbus?.HasPrivateKey,                     Is.True, "the base64 text was read as the PKCS#12 it is");

                Assert.That(oldWeb?.Kind,                                 Is.EqualTo(CertificateKind.TLSIdentity));
                Assert.That(oldWeb?.Usages,                               Is.EqualTo(new[] { ListenerCertificates.Web }));
                Assert.That(oldWeb?.HasPrivateKey,                        Is.True, "paired with the key that asked for it");

                Assert.That(oldCA?.Kind,                                  Is.EqualTo(CertificateKind.ClientRoot));
                Assert.That(oldCA?.IsActive,                              Is.False, "switched off where it was");

                Assert.That(answered?.Listener,                           Is.EqualTo(ListenerCertificates.Web));
                Assert.That(answered?.AnsweredBy,                         Is.EqualTo(new[] { oldWeb?.Id }), "the request that key made, answered by it");
                Assert.That(waiting?.AnsweredBy,                          Is.Empty, "and one still waiting, still waiting");
                Assert.That(waiting?.KeyType,                             Is.EqualTo("ecdsa-p256"));

                Assert.That(Directory.Exists(Path.Combine(certificates, "modbus")),                                   Is.False);
                Assert.That(Directory.Exists(Path.Combine(certificates, "web")),                                      Is.False);
                Assert.That(Directory.Exists(Path.Combine(certificates, "trust")),                                    Is.False);
                Assert.That(Directory.Exists(Path.Combine(certificates, "moved", "modbus", "20260101-000000-aaaaaa")), Is.True, "moved, not deleted");
                Assert.That(File.Exists(Path.Combine(certificates, "moved", "trust", "20260104-000000-dddddd.pem")),  Is.True);

            });

        }

        #endregion

        #region TheCertificateItWasStartedWith_KeepsItsIntermediates()

        /// <summary>
        /// The meter's own store kept the certificate it was started with
        /// without the intermediates its file brings. The file is put into the
        /// node's store before the old store is moved, so the one that stays is
        /// the one with its chain - found again, not put in twice.
        /// </summary>
        [Test]
        public async Task TheCertificateItWasStartedWith_KeepsItsIntermediates()
        {

            using var startedWith  = X509CertificateLoader.LoadPkcs12FromFile(Path.Combine(directory!, "pki", "server.pfx"),
                                                                            "demo",
                                                                            X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable);

            var oldEntry           = Path.Combine(directory!, "data", "certificates", "modbus", "20260101-000000-eeeeee");
            Directory.CreateDirectory(oldEntry);

            File.WriteAllText(Path.Combine(oldEntry, "certificate.pfx"), Convert.ToBase64String(startedWith.Export(X509ContentType.Pkcs12)));
            File.WriteAllText(Path.Combine(oldEntry, "meta.json"),       Meta("20260101-000000-eeeeee", startedWith.Subject, "ec256", "the certificate this meter was started with").ToString());

            await using var meter  = NewMeter();

            var identities         = meter.Certificates.ByKind(CertificateKind.TLSIdentity);

            Assert.Multiple(() => {
                Assert.That(identities.Count,           Is.EqualTo(1), "one certificate, found twice");
                Assert.That(identities[0].Thumbprint,   Is.EqualTo(CertificateEntry.ThumbprintOf(startedWith)));
                Assert.That(identities[0].ChainLength,  Is.GreaterThan(0), "with the intermediates of the file it came in");
                Assert.That(identities[0].Usages,       Is.EqualTo(new[] { ListenerCertificates.Modbus }));
            });

        }

        #endregion

        #region WhatTheMeterWasStartedWith_IsPutInOnce()

        /// <summary>
        /// The certificate and the CA a meter is started with are put into the
        /// store at the first start and found there at every one after: not
        /// twice, and not over what somebody did with them since.
        /// </summary>
        [Test]
        public async Task WhatTheMeterWasStartedWith_IsPutInOnce()
        {

            String identityId;

            await using (var first = NewMeter())
            {

                var identity  = first.Certificates.ByKind(CertificateKind.TLSIdentity).Single();
                identityId    = identity.Id;

                Assert.That(first.Certificates.Relabel(identityId, "renamed since", out _, out var error), Is.True, error);

            }

            await using var second = NewMeter();

            var identities  = second.Certificates.ByKind(CertificateKind.TLSIdentity);
            var clientRoots = second.Certificates.ByKind(CertificateKind.ClientRoot);

            Assert.Multiple(() => {
                Assert.That(identities. Select(entry => entry.Id),       Is.EqualTo(new[] { identityId }), "found again, not put in again");
                Assert.That(identities[0].Label,                          Is.EqualTo("renamed since"),       "and what was done with it stands");
                Assert.That(clientRoots.Count,                            Is.EqualTo(1));
                Assert.That(second.ModbusCertificates.Current?.Entry.Id,  Is.EqualTo(identityId));
            });

        }

        #endregion


        #region (private) NewMeter() / Meta(...)

        /// <summary>
        /// A meter on the data directory of this test, started with the demo
        /// PKI's certificate and clients CA - not listening, which the store does
        /// not need.
        /// </summary>
        private ModbusTLSEnergyMeter NewMeter()

            => new (
                   SerialNumber:       "meter-test-002",
                   ServerPfxPath:      Path.Combine(directory!, "pki", "server.pfx"),
                   ServerPfxPassword:  "demo",
                   ClientCACertPath:   Path.Combine(directory!, "pki", "issuing-clients-ca.crt"),
                   ListenAddress:      NetIPAddress.Loopback,
                   ListenPort:         TestPorts.Free(),
                   HTTPHostname:       IPv4Address.Localhost,
                   HTTPPort:           IPPort.Parse(TestPorts.Free()),
                   DataPath:           Path.Combine(directory!, "data"),
                   ConfigFile:         new WWCPConfigFile(Path.Combine(directory!, "configuration.json")),
                   LogToConsole:       false
               );

        /// <summary>
        /// What the meter's own store wrote beside a certificate.
        /// </summary>
        private static JObject Meta(String  Id,
                                    String  Subject,
                                    String  KeyType,
                                    String  Note)

            => new (
                   new JProperty("id",           Id),
                   new JProperty("createdAt",    DateTimeOffset.UtcNow.AddDays(-20).ToString("o")),
                   new JProperty("subject",      Subject),
                   new JProperty("dnsNames",     new JArray()),
                   new JProperty("ipAddresses",  new JArray()),
                   new JProperty("keyType",      KeyType),
                   new JProperty("note",         Note)
               );

        #endregion

    }

}
