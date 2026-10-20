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
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Certificates;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;
using cloud.charging.open.EnergyMeters.ModbusTLS.Upstream;

using LogLevel = cloud.charging.open.protocols.WWCP.Node.Logging.LogLevel;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// The meter in front of which this one stands, where it stands in front
    /// of one: what it measures with then, instead of its own simulation.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This is what makes the meter a wrapper around any Modbus device: every
    /// request a client asks is passed on to the meter behind it, over plain
    /// Modbus/TCP or over Modbus/TLS, and what this meter adds - the session
    /// model, which begins and ends charging sessions and signs them - sits
    /// behind that meter's models. What it signs is what that meter counted.
    /// </para>
    /// <para>
    /// Whom this meter is to it, over TLS, is a TLS identity of its store whose
    /// certificate carries a SunSpec role; whom it is believed to be is judged
    /// as every server a node connects to is judged - issued for its host, and
    /// chained to a root of the machine or a TLS root of the store for
    /// "upstream" - and, where its section says so, held to a certificate or a
    /// root, or learning one the first time it is believed.
    /// </para>
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// How long learning a pin waits for the configuration file before it
        /// gives up for this handshake.
        /// </summary>
        private static readonly TimeSpan  UpstreamLearningWait = TimeSpan.FromSeconds(5);

        private UpstreamConfiguration?  upstreamFile;

        #endregion

        #region Properties

        /// <summary>
        /// The meter in front of which this one stands, as the file says; null
        /// while it measures with its own simulation.
        /// </summary>
        public UpstreamConfiguration?  Upstream
            => upstreamFile;

        #endregion


        #region (private) ReadTheUpstream()

        /// <summary>
        /// The "upstream" section of the configuration file, as it is when the
        /// meter starts.
        /// </summary>
        /// <exception cref="InvalidOperationException">When the section says something this meter cannot do: it would measure with something else than it was told to.</exception>
        private UpstreamConfiguration? ReadTheUpstream()
        {

            if (!ConfigFile.TryLoadDocument(out var document, out _) ||
                document[UpstreamConfiguration.SectionName] is not JToken section ||
                section.Type == JTokenType.Null)
                return null;

            if (section is not JObject json)
                throw new InvalidOperationException($"'{ConfigFile.Path}': '{UpstreamConfiguration.SectionName}' must be an object: the meter in front of which this one stands.");

            if (!UpstreamConfiguration.TryParse(json, UpstreamConfiguration.SectionName, out var upstream, out var error))
                throw new InvalidOperationException($"'{ConfigFile.Path}': {error}");

            return upstream;

        }

        #endregion

        #region (private) MeasureWith(Upstream, Said = true)

        /// <summary>
        /// Measure with the meter in front of which this one stands from now on
        /// - or with the simulation, where there is none.
        /// </summary>
        private void MeasureWith(UpstreamConfiguration?  Upstream,
                                 Boolean                 Said = true)
        {

            upstreamFile = Upstream;

            UpstreamDevice? before;

            if (Upstream is null)
                before = backends.MeasureWith(simulation, device.CommandedAddresses, device.ProtectedAddresses, null);

            else
            {

                var upstream = new UpstreamDevice(
                                   Upstream,
                                   IdentityForUpstream,
                                   JudgeUpstream,
                                   TimeProvider,
                                   (news, failure) => {
                                       if (failure)
                                           Log.Warning(news, "upstream", "modbus");
                                       else
                                           Log.Notice (news, "upstream", "modbus");
                                   }
                               );

                // Its registers are its own, and nothing about them is known
                // here: what is passed on to it is written by an administrator
                // alone.
                before = backends.MeasureWith(upstream, new HashSet<UInt16>(), new HashSet<UInt16>(), upstream);

            }

            if (before is not null)
                _ = before.Close();

            // What this meter measures with is what everything it signs means.
            if (Said)
                Log.Metrological(
                    LogLevel.Notice,
                    Upstream is null
                        ? "This meter measures with its own simulation now."
                        : $"This meter stands in front of the meter at {Upstream} now, and measures with it.",
                    "upstream", "meter"
                );

            if (Upstream is not null && started)
                _ = backends.Locate();

        }

        #endregion

        #region (private) Description()

        /// <summary>
        /// What a document says about the meter that measured: this one, while
        /// it measures with its simulation, and the one in front of which it
        /// stands otherwise, as its common model says.
        /// </summary>
        private MeterDescription Description()
        {

            if (backends.Upstream is null)
                return new MeterDescription(SerialNumber, Version, device.DisplayName);

            return backends.Who is { } who
                       ? new MeterDescription(SerialNumber, Version, who.Model, who.Manufacturer, who.SerialNumber, who.Version)
                       : new MeterDescription(SerialNumber, Version, $"meter at {backends.Upstream.Configuration.Server}", "unknown", "unknown", "unknown");

        }

        #endregion


        #region (private) IdentityForUpstream()

        /// <summary>
        /// Whom this meter is to the meter in front of which it stands: the
        /// identity its section names, or - where it names none - the one with
        /// the least role that may read.
        /// </summary>
        private (UpstreamIdentity? Identity, String? Why) IdentityForUpstream()
        {

            var named = upstreamFile?.Identity;

            if (named is not null)
            {

                if (Certificates.Get(named) is not CertificateEntry entry || entry.Kind != CertificateKind.TLSIdentity)
                    return (null, $"The TLS identity '{named}' to show the meter in front of which this one stands is not in the certificate store.");

                return TryLoadUpstreamIdentity(entry, out var identity)
                           ? (identity, null)
                           : (null, $"The TLS identity '{entry.Label}' carries no SunSpec role a meter knows, or has no private key.");

            }

            UpstreamIdentity? least = null;

            foreach (var entry in Certificates.UsableByKind(CertificateKind.TLSIdentity))
            {

                if (!TryLoadUpstreamIdentity(entry, out var identity))
                    continue;

                if (least is null || RankOf(identity.Role) < RankOf(least.Role))
                {
                    least?.Dispose();
                    least = identity;
                }
                else
                    identity.Dispose();

            }

            return least is not null
                       ? (least, null)
                       : (null, "There is no TLS identity in this meter's certificate store whose certificate carries a SunSpec role, to show the meter in front of which it stands.");

        }

        private static Int32 RankOf(String Role)

            => Role switch {
                   SunSpecRoles.ReadOnly             => 0,
                   SunSpecRoles.GridService          => 1,
                   SunSpecRoles.NetworkAdministrator => 2,
                   _                                 => 3
               };

        /// <summary>
        /// A TLS identity of the store, with its private key and the CAs between
        /// it and its root - where its certificate carries a SunSpec role.
        /// </summary>
        private Boolean TryLoadUpstreamIdentity(CertificateEntry                         Entry,
                                                [NotNullWhen(true)] out UpstreamIdentity?  Identity)
        {

            Identity = null;

            X509Certificate2Collection collection;

            try
            {
                // On Windows into a key store of the user's for as long as it is
                // held: SChannel will not show a certificate whose key is in no
                // store, and a key read from a file is in none.
                collection = X509CertificateLoader.LoadPkcs12CollectionFromFile(
                                 Certificates.FullPath(Entry),
                                 null,
                                 OperatingSystem.IsWindows()
                                     ? X509KeyStorageFlags.UserKeySet | X509KeyStorageFlags.Exportable
                                     : X509KeyStorageFlags.EphemeralKeySet
                             );
            }
            catch
            {
                return false;
            }

            var leaf = collection.FirstOrDefault(certificate => certificate.HasPrivateKey);
            var role = leaf is null ? null : RoleExtractor.TryExtractRole(leaf);

            if (leaf is null || !SunSpecRoles.IsMandatoryRole(role))
            {
                foreach (var certificate in collection)
                    certificate.Dispose();
                return false;
            }

            Identity = new UpstreamIdentity(
                           leaf,
                           [.. collection.Where(certificate => !ReferenceEquals(certificate, leaf))],
                           role!,
                           Entry.Label,
                           Entry.Id
                       );

            return true;

        }

        #endregion

        #region (private) JudgeUpstream(Certificate, Chain, PolicyErrors)

        private UpstreamJudgement JudgeUpstream(X509Certificate2?  Certificate,
                                                X509Chain?         Chain,
                                                SslPolicyErrors    PolicyErrors)
        {

            var upstream  = upstreamFile;

            if (upstream is null)
                return new UpstreamJudgement(false, "refused", "This meter stands in front of no meter any more.");

            var judgement = JudgeServer(UpstreamConfiguration.Usage,
                                        upstream.Server,
                                        upstream.Pins,
                                        Certificate,
                                        Chain,
                                        PolicyErrors,
                                        Evidence:  true,
                                        Learn:     (what, fingerprint) => LearnUpstreamPin(upstream, what, fingerprint));

            // Every step that refused it, and not only the last.
            var refusals = judgement.Steps.Where (step => step.Level == "error").
                                           Select(step => step.Text).
                                           ToArray();

            return new UpstreamJudgement(
                       judgement.Accepted,
                       judgement.Outcome,
                       refusals.Length > 0 ? String.Join(" ", refusals) : null
                   );

        }

        #endregion

        #region (private) LearnUpstreamPin(Upstream, What, Fingerprint)

        private Boolean LearnUpstreamPin(UpstreamConfiguration  Upstream,
                                         TrustOnFirstUse        What,
                                         String                 Fingerprint)
        {

            if (!reconfigureLock.Wait(UpstreamLearningWait))
                return false;

            try
            {

                // Reached elsewhere now - changed while it was being judged.
                if (upstreamFile is not UpstreamConfiguration now || now.Server != Upstream.Server)
                    return false;

                var pins = now.Pins ?? ServerPins.None;

                if ((What == TrustOnFirstUse.Root ? pins.Roots : pins.Certificates).Count > 0)
                    return true;

                var changed = now with { Pins = pins.Learning(What, Fingerprint) };

                if (!ConfigFile.TryReplaceSection(UpstreamConfiguration.SectionName, changed.ToJSON(), out var error))
                {
                    Log.Error($"What the meter in front of this one is held to from now on could not be written into '{ConfigFile.Path}': {error}",
                              "upstream", "certificates", "security");
                    return false;
                }

                upstreamFile = changed;

                return true;

            }
            finally
            {
                reconfigureLock.Release();
            }

        }

        #endregion


        #region UpstreamJSON()

        /// <summary>
        /// The upstream page's: the meter in front of which this one stands, as
        /// the file says it and as it goes, what its certificate was last
        /// judged, and the identities it can be shown.
        /// </summary>
        public JObject UpstreamJSON()
        {

            var upstream   = upstreamFile;
            var judgement  = upstream is null || !upstream.TLS ? null : LastJudgementOf(UpstreamConfiguration.Usage, upstream.Server);

            JObject? judged = null;

            if (judgement is not null)
            {
                judged = judgement.ToJSON();
                judged["steps"] = new JArray(judgement.Steps.Select(step => new JObject(
                                                 new JProperty("level",  step.Level),
                                                 new JProperty("text",   step.Text)
                                             )));
            }

            return new JObject(

                       new JProperty("upstream",    upstream is not null),
                       new JProperty("host",        upstream?.Host),
                       new JProperty("port",        upstream?.Port),
                       new JProperty("unit",        upstream?.Unit),
                       new JProperty("tls",         upstream?.TLS ?? false),
                       new JProperty("identity",    upstream?.Identity),
                       new JProperty("server",      upstream?.Server),
                       new JProperty("heldTo",      upstream?.Pins is { SaysAnything: true } pins ? pins.ToJSON() : null),
                       new JProperty("judgement",   judged),
                       new JProperty("known",       upstream is { TLS: true } && KnownServers.Get(UpstreamConfiguration.Usage, upstream.Server) is KnownServer known
                                                        ? new JObject(
                                                              new JProperty("certificate",  known.Certificate),
                                                              new JProperty("root",         known.Root),
                                                              new JProperty("since",        known.Since.ToString("o"))
                                                          )
                                                        : null),

                       new JProperty("state",       backends.Upstream?.StatusJSON()),
                       new JProperty("identities",  UpstreamIdentitiesJSON()),
                       new JProperty("usage",       UpstreamConfiguration.Usage),
                       new JProperty("defaults",    new JObject(
                                                        new JProperty("tcpPort",  UpstreamConfiguration.DefaultTCPPort),
                                                        new JProperty("tlsPort",  UpstreamConfiguration.DefaultTLSPort),
                                                        new JProperty("unit",     UpstreamConfiguration.DefaultUnit)
                                                    )),
                       new JProperty("file",        ConfigFile.Path)

                   );

        }

        /// <summary>
        /// The TLS identities of the store whose certificate carries a SunSpec
        /// role: what a meter in front of which this one stands can be shown.
        /// </summary>
        private JArray UpstreamIdentitiesJSON()
        {

            var identities = new JArray();

            foreach (var entry in Certificates.ByKind(CertificateKind.TLSIdentity))
            {

                String? role = null;

                if (Certificates.TryLoad(entry, out var certificate, out _))
                    using (certificate)
                        role = RoleExtractor.TryExtractRole(certificate);

                if (!SunSpecRoles.IsMandatoryRole(role))
                    continue;

                identities.Add(new JObject(
                                   new JProperty("id",       entry.Id),
                                   new JProperty("label",    entry.Label),
                                   new JProperty("role",     role),
                                   new JProperty("subject",  entry.Subject)
                               ));

            }

            return identities;

        }

        #endregion

        #region UpdateUpstream(JSON, CancellationToken = default)

        /// <summary>
        /// Stand in front of another meter from now on - {"host": …, "port": …,
        /// "unit": …, "tls": …, "identity": …, and what its certificate is held
        /// to} - or in front of none, where the host is blank, and measure with
        /// the simulation again.
        /// </summary>
        /// <remarks>
        /// What its certificate is held to is taken as a page saved it - see
        /// <see cref="ServerPins.TryAfterAPageSaved"/>. A meter reached as it was
        /// is not reached anew.
        /// </remarks>
        /// <returns>Whether it was changed; why not; and whether that was the configuration file's doing.</returns>
        public async Task<(Boolean Success, String? Error, Boolean NotSaved)> UpdateUpstream(JObject            JSON,
                                                                                            CancellationToken  CancellationToken   = default)
        {

            var path = UpstreamConfiguration.SectionName;

            if (!UpstreamConfiguration.TryParse(JSON, path, out var sent, out var error))
                return (false, error, false);

            ServerPins? shown    = null;
            var         hasShown = false;

            if (JSON[ServerPins.AsShownKey] is JToken shownToken && shownToken.Type != JTokenType.Null)
            {

                if (shownToken is not JObject shownJSON)
                    return (false, $"'{path}.{ServerPins.AsShownKey}' must be an object: what the page showed the meter held to.", false);

                if (!ServerPins.TryParse(shownJSON, $"{path}.{ServerPins.AsShownKey}", out shown, out error))
                    return (false, error, false);

                hasShown = true;

            }

            if (sent?.Identity is String id)
            {

                if (Certificates.Get(id) is not CertificateEntry entry || entry.Kind != CertificateKind.TLSIdentity)
                    return (false, $"'{id}' is no TLS identity of the certificate store, so it cannot be shown to the meter in front of this one.", false);

                if (!TryLoadUpstreamIdentity(entry, out var identity))
                    return (false, $"The TLS identity '{entry.Label}' carries no SunSpec role a meter knows, or has no private key, so a meter would not let it in.", false);

                identity.Dispose();

            }

            await reconfigureLock.WaitAsync(CancellationToken);

            UpstreamConfiguration? changed;
            Boolean                reachedAnew;

            try
            {

                if (!ConfigFile.TryLoadDocument(out var document, out error))
                    return (false, error, true);

                UpstreamConfiguration? inTheFile = null;

                if (document[UpstreamConfiguration.SectionName] is JObject section &&
                    !UpstreamConfiguration.TryParse(section, path, out inTheFile, out error))
                    return (false, error, true);

                changed = sent;

                if (sent is not null && hasShown)
                {

                    if (!ServerPins.TryAfterAPageSaved(inTheFile?.Pins, shown, sent.Pins, path, out var pins, out error))
                        return (false, error, false);

                    changed = sent with { Pins = pins };

                }

                if (!ConfigFile.TryReplaceSection(UpstreamConfiguration.SectionName,
                                                  changed is not null ? changed.ToJSON() : JValue.CreateNull(),
                                                  out error))
                    return (false, error, true);

                reachedAnew = !(changed?.SameAs(upstreamFile) ?? upstreamFile is null);

                if (!reachedAnew)
                    upstreamFile = changed;

            }
            finally
            {
                reconfigureLock.Release();
            }

            if (reachedAnew)
                MeasureWith(changed);

            return (true, null, false);

        }

        #endregion

    }

}
