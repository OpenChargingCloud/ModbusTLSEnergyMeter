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

using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using cloud.charging.open.protocols.WWCP.Node.Certificates;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;
using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

using MeterLogLevel = cloud.charging.open.protocols.WWCP.Node.Logging.LogLevel;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// How often this meter looks whether what its listeners show is about
        /// to run out with nothing to follow it.
        /// </summary>
        /// <remarks>
        /// The rollover itself does not depend on this: both listeners ask the
        /// node at every handshake, so a certificate that becomes valid at
        /// 03:00 is shown to the first peer that connects at 03:00, and the
        /// node says so in the log book by its own clock - see
        /// WWCPNode.ListenerCertificates.
        /// </remarks>
        public static readonly TimeSpan DefaultCertificateCheckEvery = TimeSpan.FromMinutes(1);

        /// <summary>
        /// How close to running out a certificate has to be before this meter
        /// starts saying so.
        /// </summary>
        public static readonly TimeSpan CertificateExpiryWarning     = TimeSpan.FromDays(21);

        #endregion

        #region (private) StartWatchingTheCertificates()

        /// <summary>
        /// Begin noticing when a certificate takes over, runs out, or is about
        /// to.
        /// </summary>
        private void StartWatchingTheCertificates()
        {

            certificateTimer?.Dispose();

            certificateTimer = TimeProvider.CreateTimer(
                                   _ => CheckTheCertificates(),
                                   null,
                                   DefaultCertificateCheckEvery,
                                   DefaultCertificateCheckEvery
                               );

            foreach (var shownBy in new[] { modbusCertificates, webCertificates })
            {

                String listener = shownBy.Listener;
                var    chain    = shownBy.Current;

                if (chain is not null)
                    Log.Info(
                        $"The {listener} listener shows '{chain.Certificate.Subject}', valid until {chain.Certificate.NotAfter:yyyy-MM-dd}.",
                        "certificates", listener
                    );

                else if (listener == MeterListeners.Modbus || HTTPS)
                    Log.Warning(
                        $"There is no valid {listener} certificate: every handshake on that listener will fail.",
                        "certificates", listener
                    );

                if (MeterListeners.NextFor(Certificates, listener, TimeProvider.GetUtcNow()) is CertificateEntry next)
                    Log.Info(
                        $"A newer {listener} certificate takes over on {next.NotBefore.UtcDateTime:yyyy-MM-dd HH:mm}.",
                        "certificates", listener
                    );

                // Said out loud rather than left to be discovered as a
                // handshake that fails for no visible reason: the chain is
                // handed to the TLS stack either way, and on Windows the TLS
                // stack does not send it.
                if (chain is not null && chain.HasIntermediates)
                    Log.Log(
                        RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                            ? MeterLogLevel.Warning
                            : MeterLogLevel.Info,
                        RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
                            ? $"The {listener} certificate came with {chain.Intermediates.Count} intermediate(s), and Windows will not put them on the wire: " +
                               "SChannel builds the chain it sends from this machine's certificate stores and ignores what a program hands it. " +
                               "Install them in the local computer's intermediate CA store, or run this meter on Linux, where they are sent."
                            : $"The {listener} listener sends {chain.Intermediates.Count} intermediate(s) with its certificate.",
                        "certificates", listener
                    );

            }

        }

        #endregion

        #region (private) CheckTheCertificates()

        /// <summary>
        /// Grumble about what a listener shows when it is running out and
        /// nothing is lined up to follow it.
        /// </summary>
        private void CheckTheCertificates()
        {

            var now = TimeProvider.GetUtcNow();

            foreach (var shownBy in new[] { modbusCertificates, webCertificates })
            {

                String listener = shownBy.Listener;

                try
                {

                    var shown = shownBy.Choose();

                    // Only worth saying when nothing else is lined up to take
                    // over: a certificate running out next week with its
                    // successor already in the store is not a problem, it is
                    // the arrangement working. Nor for the carrier of a server
                    // key, which is dated to the year 9999.
                    if (shown is not null &&
                        !shown.IsCarrier  &&
                        MeterListeners.NextFor(Certificates, listener, now) is null &&
                        shown.Chain.Certificate.NotAfter - now < CertificateExpiryWarning)
                    {
                        Log.Warning(
                            $"The {listener} certificate runs out on {shown.Chain.Certificate.NotAfter:yyyy-MM-dd} and nothing has been put in to follow it.",
                            "certificates", listener
                        );
                    }

                }
                catch (Exception e)
                {
                    Log.Warning($"The {listener} certificates could not be checked: {e.Message}", "certificates", listener);
                }

            }

        }

        #endregion


        #region (private) AnnounceTheSigningKeys()

        /// <summary>
        /// Make the meter's own key if it has none, and say which key it is
        /// signing readings with.
        /// </summary>
        /// <remarks>
        /// Said out loud at every start, because it is the one thing about this
        /// meter that somebody checking a reading months from now has to have
        /// written down. A meter that made a key quietly would be a meter whose
        /// signatures nobody could attribute to it.
        /// </remarks>
        private void AnnounceTheSigningKeys()
        {

            try
            {

                if (signingKeys.EnsureIdentity() is MeterKey made)
                    Log.Notice(
                        $"No signing key yet, so this meter made itself one: '{made.Id}' ({made.Algorithm}), " +
                        $"fingerprint {made.Fingerprint}. It is the identity of this meter and does not change.",
                        "signing"
                    );

                var identity = signingKeys.Default;

                if (identity is null)
                    Log.Warning(
                        "This meter has no signing key, so nothing it measures can be shown to have come from it.",
                        "signing"
                    );

                else
                {

                    Log.Info(
                        $"Readings are signed with '{identity.Id}' ({identity.Algorithm}), fingerprint {identity.Fingerprint}" +
                        (OCMFWriter.AlgorithmFor(identity.Algorithm) is String sa ? $", written in OCMF as {sa}" : "") + ".",
                        "signing"
                    );

                    var others = signingKeys.Keys.Count() - 1;

                    if (others > 0)
                        Log.Info($"There {(others == 1 ? "is" : "are")} {others} further signing key{(others == 1 ? "" : "s")} " +
                                  "for the formats that ask for a different algorithm.",
                                 "signing");

                }

                if (signingKeys.LastError is String problem)
                    Log.Warning(problem, "signing");

            }
            catch (Exception e)
            {
                Log.Error($"The signing keys could not be prepared: {e.Message}", "signing");
            }

        }

        #endregion

        #region ListenerCertificatesFor(Listener)

        /// <summary>
        /// What the listener a request names shows, or null when it names
        /// neither.
        /// </summary>
        public ListenerCertificate? ListenerCertificatesFor(String? Listener)

            => Listener?.Trim().ToLowerInvariant() switch {
                   MeterListeners.Modbus  => modbusCertificates,
                   MeterListeners.Web     => webCertificates,
                   _                      => null
               };

        #endregion

        #region ShownOn(Id)

        /// <summary>
        /// The listeners that show the certificate with the given id now.
        /// </summary>
        public IEnumerable<String> ShownOn(String? Id)

            => MeterListeners.All.Where(listener => Id is not null &&
                                                    ListenerCertificatesFor(listener)?.Entry?.Id == Id);

        #endregion

        #region (protected override) CompleteCertificatesJSON(JSON)

        /// <summary>
        /// What a meter's store says beyond every node's: the listeners an
        /// identity may be told it is for, on each identity the listeners that
        /// show it now, and for each listener what it shows now and what takes
        /// over next - so that a page can mark them without asking twice.
        /// </summary>
        protected override void CompleteCertificatesJSON(JObject JSON)
        {

            JSON["listeners"] = new JArray(Certificates.Listeners.Select(listener => listener.ToString()));

            if (JSON["certificates"]?[CertificateKind.TLSServerIdentity.AsText()] is JArray identities)
                foreach (var identity in identities.OfType<JObject>())
                    identity["shownOn"] = new JArray(ShownOn(identity["id"]?.Value<String>()));

            var shown = new JObject();

            var now = TimeProvider.GetUtcNow();

            foreach (var listener in MeterListeners.All)
            {

                var next = MeterListeners.NextFor(Certificates, listener, now);

                shown.Add(listener, new JObject(
                                        new JProperty("current",  ListenerCertificatesFor(listener)?.Entry?.Id),
                                        new JProperty("next",     next?.Id),
                                        new JProperty("nextAt",   next?.NotBefore.UtcDateTime),
                                        new JProperty("used",     listener == MeterListeners.Modbus || HTTPS)
                                    ));

            }

            JSON["shown"] = shown;

        }

        #endregion

        #region (override) WhatWouldLose(Entry, ActiveAfter, UsagesAfter)

        /// <summary>
        /// What of this meter a change of a certificate would leave with
        /// nothing: a listener, when it is the only certificate the listener
        /// could show, or the Modbus/TLS clients, when it is the last CA they
        /// may be issued by - as the sentence of the 409 the node's API refuses
        /// the change with, or null.
        /// </summary>
        /// <remarks>
        /// Asked by the node before a certificate is switched off, told other
        /// listeners or deleted, and before any of it is done. Nothing of the
        /// meter names a certificate - the listeners choose among what is
        /// valid - so there is no <see cref="WWCPNode.WhatUses"/> of its own.
        /// </remarks>
        /// <param name="Entry">The certificate as it is now.</param>
        /// <param name="ActiveAfter">Whether it would be switched on afterwards; false for a deletion.</param>
        /// <param name="UsagesAfter">What it would be for afterwards, as the store keeps usages; null for every use.</param>
        public override String? WhatWouldLose(CertificateEntry                  Entry,
                                              Boolean                           ActiveAfter,
                                              IReadOnlyList<CertificateUsage>?  UsagesAfter)
        {

            if (Entry.Kind == CertificateKind.TLSServerIdentity)
            {

                foreach (var listener in MeterListeners.All)
                {

                    // The web interface shows nothing without HTTPS, and so
                    // cannot be left with nothing either.
                    if (listener == MeterListeners.Web && !HTTPS)
                        continue;

                    var candidates     = ListenerCertificatesFor(listener)?.Candidates ?? [];
                    var stillShowable  = ActiveAfter && (UsagesAfter is null || UsagesAfter.Contains(listener));

                    if (!stillShowable && candidates.Count == 1 && candidates[0].Id == Entry.Id)
                        return $"That is the only certificate the {listener} listener could show. Put another one in first.";

                }

            }

            if (Entry.Kind == CertificateKind.ClientRoot && !ActiveAfter)
            {

                var usable = ClientRoots.Usable;

                if (usable.Count == 1 && usable[0].Id == Entry.Id)
                    return "That is the last CA Modbus/TLS clients may be issued by. Put another one in first - " +
                           "otherwise no charging station could connect.";

            }

            return null;

        }

        #endregion

        #region (private) AdoptAtTheStart(File, Password, Certificate, Kind, Label, Usages)

        /// <summary>
        /// Put a certificate this meter was started with into the store, unless
        /// it is there already - in which case whatever somebody did with it
        /// since stands.
        /// </summary>
        /// <remarks>
        /// From the file rather than from the certificate read out of it: a
        /// PKCS#12 brings the intermediates above the certificate, and a
        /// listener that does not send them leaves a client to find them.
        /// </remarks>
        private void AdoptAtTheStart(String                File,
                                     String?               Password,
                                     X509Certificate2      Certificate,
                                     CertificateKind       Kind,
                                     String                Label,
                                     IEnumerable<String>?  Usages)
        {

            if (Certificates.ByFingerprint(CertificateEntry.ThumbprintOf(Certificate)) is not null)
                return;

            if (!Certificates.Import(System.IO.File.ReadAllBytes(File), Kind, Password, Label, Usages, out _, out var error))
                Log.Warning($"'{Label}' could not be put into the certificate store: {error}", "certificates", "meter");

        }

        #endregion

        #region (private) SignTheWebInterfaceItself()

        /// <summary>
        /// How long a certificate the web interface signs for itself is good for.
        /// </summary>
        public static readonly TimeSpan SelfSignedLifetime = TimeSpan.FromDays(825);

        /// <summary>
        /// Give the web interface a certificate it signed for itself, so that it
        /// has something to show before anybody has been to a CA.
        /// </summary>
        /// <remarks>
        /// Named so that it cannot be mistaken for the device certificate in a
        /// log line: they are two identities, and nobody is to conflate them.
        /// </remarks>
        private void SignTheWebInterfaceItself()
        {

            using var key  = ECDsa.Create(ECCurve.NamedCurves.nistP256);

            var request    = new CertificateRequest($"CN={SerialNumber} web interface", key, HashAlgorithmName.SHA256);
            var names      = new SubjectAlternativeNameBuilder();

            names.AddDnsName  ("localhost");
            names.AddDnsName  ($"{SerialNumber}.local");
            names.AddIpAddress(IPAddress.Loopback);
            names.AddIpAddress(IPAddress.IPv6Loopback);

            request.CertificateExtensions.Add(names.Build());
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension([ new Oid("1.3.6.1.5.5.7.3.1", "serverAuth") ], false));

            // A few minutes back, because a meter and whoever looks at it do not
            // always agree about the time to the second.
            var now                = TimeProvider.GetUtcNow();
            using var certificate  = request.CreateSelfSigned(now.AddMinutes(-5), now.Add(SelfSignedLifetime));

            if (!Certificates.Import(certificate.Export(X509ContentType.Pkcs12),
                                     CertificateKind.TLSServerIdentity,
                                     null,
                                     "made by this meter at the first start",
                                     [ MeterListeners.Web ],
                                     out _,
                                     out var error))
            {
                Log.Warning($"The web interface could not be given a certificate of its own: {error}", "certificates", MeterListeners.Web);
            }

        }

        #endregion

    }

}
