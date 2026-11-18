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

using cloud.charging.open.protocols.WWCP.Node.Logging;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// Which certificate a listener shows: of the identities for it that are
    /// switched on, valid now and readable with their key, the one whose
    /// validity began last - so that one put in before the old one runs out
    /// takes over by itself.
    /// </summary>
    /// <remarks>
    /// The node's store asks the machine's clock whether a certificate is
    /// valid, so a certificate that becomes valid here does so in real
    /// seconds, and a few of them are waited for.
    /// </remarks>
    public class MeterListenersTests
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


        #region ACertificateThatIsNotValidYet_IsNext_AndTakesOverWhenItIs()

        /// <summary>
        /// The whole point: put tomorrow's certificate in today, and have
        /// nothing to do tomorrow. Until it is valid it is what comes next and
        /// the old one is shown; then it is shown, and the node says so once -
        /// which is what the log book hears.
        /// </summary>
        [Test]
        public async Task ACertificateThatIsNotValidYet_IsNext_AndTakesOverWhenItIs()
        {

            var store      = NewStore();
            var now        = DateTimeOffset.UtcNow;
            var today      = Put(store, MeterListeners.Modbus, "CN=today", now.AddDays(-30), now.AddDays(10));

            using var all  = new ListenerCertificates(store, TimeProvider.System, new EventLog());
            var modbus     = all.For(MeterListeners.Modbus, "Modbus/TLS");
            var changes    = new List<String?>();

            all.OnShownChanged += (listener, before, after) => changes.Add($"{listener}:{after?.Id}");

            // Asked once before the clock matters, so that the seconds below are
            // not spent reading the certificate.
            Assert.That(modbus.Entry?.Id, Is.EqualTo(today.Id));

            // Valid in a few seconds - and one for the web interface, valid even
            // sooner, which is none of this listener's business.
            var soon       = Put(store, MeterListeners.Modbus, "CN=soon",     DateTimeOffset.UtcNow.AddSeconds(3), now.AddDays(400));
            var webSoon    = Put(store, MeterListeners.Web,    "CN=web soon", DateTimeOffset.UtcNow.AddSeconds(2), now.AddDays(400));

            all.Check();

            Assert.Multiple(() => {
                Assert.That(modbus.Entry?.Id,                                                         Is.EqualTo(today.Id), "not valid yet, so not shown yet");
                Assert.That(modbus.Candidates.Select(entry => entry.Id),                              Does.Not.Contain(soon.Id));
                Assert.That(MeterListeners.NextFor(store, MeterListeners.Modbus, DateTimeOffset.UtcNow)?.Id, Is.EqualTo(soon.Id),  "but lined up to take over");
                Assert.That(changes,                                                                  Is.Empty);
            });

            var deadline = DateTimeOffset.UtcNow.AddSeconds(30);

            while (DateTimeOffset.UtcNow <= soon.NotBefore.AddSeconds(1) && DateTimeOffset.UtcNow < deadline)
                await Task.Delay(100);

            all.Check();

            Assert.Multiple(() => {
                Assert.That(modbus.Entry?.Id,                                                         Is.EqualTo(soon.Id),  "the newer one takes over by itself");
                Assert.That(modbus.Current?.Certificate.HasPrivateKey,                                Is.True);
                Assert.That(MeterListeners.NextFor(store, MeterListeners.Modbus, DateTimeOffset.UtcNow),     Is.Null);
                Assert.That(changes,                                                                  Is.EqualTo(new[] { $"modbus:{soon.Id}" }), "said once, when it happened");
                Assert.That(modbus.Candidates.Select(entry => entry.Id),                              Does.Not.Contain(webSoon.Id),  "the web interface's, valid by now as well, is not this listener's");
            });

        }

        #endregion

        #region WhatCannotBeShown_IsPassedOver_AndKept()

        /// <summary>
        /// A certificate that has run out is not shown, however late its
        /// validity began; and one that cannot be read with its key is passed
        /// over for the next, rather than handed to the TLS stack to fail every
        /// handshake with. Both stay in the store.
        /// </summary>
        /// <remarks>
        /// A file whose key is gone stands in for what cannot be presented:
        /// the store still holds it as an identity, and no TLS stack can
        /// present it.
        /// </remarks>
        [Test]
        public void WhatCannotBeShown_IsPassedOver_AndKept()
        {

            var store    = NewStore();
            var now      = DateTimeOffset.UtcNow;

            var shown    = Put(store, MeterListeners.Modbus, "CN=shown",   now.AddDays(-30), now.AddDays(300));
            var expired  = Put(store, MeterListeners.Modbus, "CN=expired", now.AddDays(-3),  now.AddDays(-1));
            var keyless  = Put(store, MeterListeners.Modbus, "CN=keyless", now.AddDays(-2),  now.AddDays(300));

            Assert.That(store.TryLoad(keyless, out var loaded, out var error), Is.True, error);

            using (var withKey = loaded!)
            {
                using var withoutKey = X509CertificateLoader.LoadCertificate(withKey.RawData);
                File.WriteAllBytes(store.FullPath(keyless), withoutKey.Export(X509ContentType.Pkcs12));
            }

            using var modbus = new ListenerCertificate(store, MeterListeners.Modbus, new EventLog(), "Modbus/TLS");

            Assert.Multiple(() => {

                Assert.That(modbus.Candidates.Select(entry => entry.Id), Does.Not.Contain(expired.Id), "run out");
                Assert.That(modbus.Candidates.First().Id,                Is.EqualTo(keyless.Id),       "the newest valid one is asked first");
                Assert.That(modbus.Entry?.Id,                            Is.EqualTo(shown.Id),         "and passed over, as it cannot be presented");
                Assert.That(modbus.Current?.Certificate.Subject,         Is.EqualTo("CN=shown"));

                Assert.That(store.Get(expired.Id),                       Is.Not.Null, "kept all the same");
                Assert.That(store.Get(keyless.Id),                       Is.Not.Null, "kept all the same");

            });

        }

        #endregion


        #region (private) NewStore() / Put(Store, Listener, Subject, NotBefore, NotAfter)

        /// <summary>
        /// A store as the meter's: the TLS kinds, and its two listeners.
        /// </summary>
        private CertificateStore NewStore()

            => new (Path.Combine(directory!, "certificates"),
                    new EventLog(),
                    ModbusTLSEnergyMeter.CertificateKinds,
                    Listeners: MeterListeners.All);

        /// <summary>
        /// Put an identity for the given listener into the store, valid for the
        /// given stretch of time.
        /// </summary>
        private static CertificateEntry Put(CertificateStore  Store,
                                            String            Listener,
                                            String            Subject,
                                            DateTimeOffset    NotBefore,
                                            DateTimeOffset    NotAfter)
        {

            using var key          = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var certificate  = new CertificateRequest(Subject, key, HashAlgorithmName.SHA256).CreateSelfSigned(NotBefore, NotAfter);

            Assert.That(Store.Import(certificate.Export(X509ContentType.Pkcs12), CertificateKind.TLSServerIdentity, null, Subject, [ Listener ], out var entry, out var error),
                        Is.True, error);

            return entry!;

        }

        #endregion

    }

}
