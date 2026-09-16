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

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// One chain this meter accepts a Modbus/TLS client certificate from: a
    /// root, and whatever intermediates came with it.
    /// </summary>
    public class TrustedChain
    {

        public String                           Id            { get; }
        public String                           Name          { get; internal set; }
        public DateTimeOffset                   AddedAt       { get; }
        public Boolean                          Enabled       { get; internal set; }
        public IReadOnlyList<X509Certificate2>  Certificates  { get; internal set; } = [];

        internal TrustedChain(String          Id,
                              String          Name,
                              DateTimeOffset  AddedAt,
                              Boolean         Enabled)
        {
            this.Id       = Id;
            this.Name     = Name;
            this.AddedAt  = AddedAt;
            this.Enabled  = Enabled;
        }

        public JObject ToJSON(DateTimeOffset Now)

            => new (
                   new JProperty("id",            Id),
                   new JProperty("name",          Name),
                   new JProperty("addedAt",       AddedAt.ToString("o")),
                   new JProperty("enabled",       Enabled),
                   new JProperty("certificates",  new JArray(
                       Certificates.Select(certificate => new JObject(
                           new JProperty("subject",     certificate.Subject),
                           new JProperty("issuer",      certificate.Issuer),
                           new JProperty("notBefore",   certificate.NotBefore.ToUniversalTime().ToString("o")),
                           new JProperty("notAfter",    certificate.NotAfter. ToUniversalTime().ToString("o")),
                           new JProperty("thumbprint",  certificate.Thumbprint),
                           new JProperty("expired",     Now > certificate.NotAfter),
                           new JProperty("isRoot",      certificate.SubjectName.RawData.SequenceEqual(certificate.IssuerName.RawData))
                       ))
                   ))
               );

        internal JObject MetadataJSON()

            => new (
                   new JProperty("id",       Id),
                   new JProperty("name",     Name),
                   new JProperty("addedAt",  AddedAt.ToString("o")),
                   new JProperty("enabled",  Enabled)
               );

    }


    /// <summary>
    /// Which CAs a Modbus/TLS client certificate may chain to.
    /// </summary>
    /// <remarks>
    /// More than one, and that is the point. A meter in the field is reached by
    /// peers whose certificates were issued by different people - the site
    /// operator's PKI and a manufacturer's, say - and even with only one
    /// issuer, replacing it is a thing that happens while both the old and the
    /// new one still have to work. A single pinned CA makes that a flag day.
    ///
    /// This is only about Modbus/TLS. The web interface does not authenticate
    /// anybody by certificate; there a person signs in with an account.
    /// </remarks>
    public class ClientTrustStore
    {

        #region Data

        private readonly Dictionary<String, TrustedChain>  chains    = [];
        private readonly Lock                              chainLock = new();

        #endregion

        #region Properties

        /// <summary>
        /// The directory this store keeps its chains in.
        /// </summary>
        public String        Path          { get; }

        /// <summary>
        /// Where this store reads the time.
        /// </summary>
        public TimeProvider  TimeProvider  { get; }

        /// <summary>
        /// What went wrong while reading the store, if anything did.
        /// </summary>
        public String?       LastError     { get; private set; }

        /// <summary>
        /// Every chain, newest first.
        /// </summary>
        public IEnumerable<TrustedChain> Chains
        {
            get
            {
                lock (chainLock)
                    return [.. chains.Values.OrderByDescending(chain => chain.Id)];
            }
        }

        #endregion

        #region Events

        /// <summary>
        /// Raised when what this meter accepts has changed, with what it now
        /// accepts. A change here decides who can reach the meter at all, and
        /// is worth a line whoever made it.
        /// </summary>
        public event Action<String>? OnChanged;

        #endregion

        #region Constructor(s)

        public ClientTrustStore(String         Path,
                                TimeProvider?  TimeProvider   = null)
        {

            this.Path          = System.IO.Path.GetFullPath(Path);
            this.TimeProvider  = TimeProvider ?? System.TimeProvider.System;

            try
            {
                Directory.CreateDirectory(this.Path);
                Reload();
            }
            catch (Exception e)
            {
                LastError = $"The client trust store at '{this.Path}' could not be read: {e.Message}";
            }

        }

        #endregion


        #region Anchors()

        /// <summary>
        /// What a client certificate may chain to at this moment. Handed to the
        /// Modbus/TLS frontend, which asks at every handshake.
        /// </summary>
        public IReadOnlyCollection<X509Certificate2> Anchors()
        {
            lock (chainLock)
                return [.. chains.Values.
                              Where     (chain => chain.Enabled).
                              SelectMany(chain => chain.Certificates)];
        }

        #endregion

        #region TryAdd(Name, PEM, out Chain, out Error)

        /// <summary>
        /// Accept certificates from one more CA.
        /// </summary>
        public Boolean TryAdd(String             Name,
                              String             PEM,
                              out TrustedChain?  Chain,
                              out String?        Error)
        {

            Chain = null;
            Error = null;

            var certificates = new X509Certificate2Collection();

            try
            {
                certificates.ImportFromPem(PEM);
            }
            catch (Exception e)
            {
                Error = $"That is not a PEM encoded certificate: {e.Message}";
                return false;
            }

            if (certificates.Count == 0)
            {
                Error = "There was no certificate in that.";
                return false;
            }

            // A trust anchor is a CA. Accepting a leaf certificate here would
            // look like it worked and then trust exactly one peer, which is
            // not what anybody means by "this chain is accepted".
            var notACA = certificates.Cast<X509Certificate2>().
                             FirstOrDefault(certificate =>
                                 certificate.Extensions.OfType<X509BasicConstraintsExtension>().
                                     FirstOrDefault()?.CertificateAuthority != true);

            if (notACA is not null)
            {
                Error = $"'{notACA.Subject}' is not a CA certificate. What belongs here is the CA that signs your clients, not a client.";
                return false;
            }

            var now = TimeProvider.GetUtcNow();
            var id  = $"{now:yyyyMMdd-HHmmss}-{Convert.ToHexString(RandomNumberGenerator.GetBytes(3)).ToLowerInvariant()}";

            var chain = new TrustedChain(
                            id,
                            Name.Trim().Length > 0 ? Name.Trim() : certificates[0].Subject,
                            now,
                            true
                        ) {
                            Certificates = [.. certificates.Cast<X509Certificate2>()]
                        };

            try
            {
                File.WriteAllText(System.IO.Path.Combine(Path, $"{id}.pem"),  PEM);
                File.WriteAllText(System.IO.Path.Combine(Path, $"{id}.json"), chain.MetadataJSON().ToString());
            }
            catch (Exception e)
            {
                Error = $"The chain could not be kept: {e.Message}";
                return false;
            }

            lock (chainLock)
                chains[id] = chain;

            Chain = chain;
            OnChanged?.Invoke($"'{chain.Name}' is now accepted for Modbus/TLS clients.");

            return true;

        }

        #endregion

        #region TrySetEnabled(Id, Enabled, out Error)

        /// <summary>
        /// Stop accepting a chain without throwing it away, or start again.
        /// </summary>
        public Boolean TrySetEnabled(String       Id,
                                     Boolean      Enabled,
                                     out String?  Error)
        {

            Error = null;

            TrustedChain? chain;

            lock (chainLock)
            {

                if (!chains.TryGetValue(Id, out chain))
                {
                    Error = "There is no chain with that id.";
                    return false;
                }

                if (!Enabled && !chains.Values.Any(other => other.Id != Id && other.Enabled))
                {
                    Error = "That is the only chain still accepted, and a meter that accepts none refuses every Modbus/TLS client. Add another one first.";
                    return false;
                }

                chain.Enabled = Enabled;

            }

            try
            {
                File.WriteAllText(System.IO.Path.Combine(Path, $"{Id}.json"), chain.MetadataJSON().ToString());
            }
            catch (Exception e)
            {
                Error = $"The change could not be written down: {e.Message}";
                return false;
            }

            OnChanged?.Invoke($"'{chain.Name}' is {(Enabled ? "now" : "no longer")} accepted for Modbus/TLS clients.");

            return true;

        }

        #endregion

        #region TryRemove(Id, out Error)

        public Boolean TryRemove(String       Id,
                                 out String?  Error)
        {

            Error = null;

            TrustedChain? chain;

            lock (chainLock)
            {

                if (!chains.TryGetValue(Id, out chain))
                {
                    Error = "There is no chain with that id.";
                    return false;
                }

                if (chain.Enabled && !chains.Values.Any(other => other.Id != Id && other.Enabled))
                {
                    Error = "That is the only chain still accepted, and a meter that accepts none refuses every Modbus/TLS client. Add another one first.";
                    return false;
                }

                try
                {
                    File.Delete(System.IO.Path.Combine(Path, $"{Id}.pem"));
                    File.Delete(System.IO.Path.Combine(Path, $"{Id}.json"));
                }
                catch (Exception e)
                {
                    Error = $"The chain could not be removed: {e.Message}";
                    return false;
                }

                chains.Remove(Id);

            }

            OnChanged?.Invoke($"'{chain.Name}' is no longer accepted for Modbus/TLS clients.");

            return true;

        }

        #endregion

        #region Adopt(Certificate, Name)

        /// <summary>
        /// Take the CA this meter was started with into the store, so that
        /// there is one place that decides who is let in.
        /// </summary>
        public TrustedChain? Adopt(X509Certificate2  Certificate,
                                   String            Name)
        {

            lock (chainLock)
            {
                var known = chains.Values.FirstOrDefault(chain =>
                                chain.Certificates.Any(certificate => certificate.Thumbprint == Certificate.Thumbprint));
                if (known is not null)
                    return known;
            }

            return TryAdd(Name, PemEncoding.WriteString("CERTIFICATE", Certificate.RawData), out var chain, out _)
                       ? chain
                       : null;

        }

        #endregion

        #region (private) Reload()

        private void Reload()
        {

            foreach (var metaFile in Directory.GetFiles(Path, "*.json"))
            {

                var id = System.IO.Path.GetFileNameWithoutExtension(metaFile);

                try
                {

                    var json    = JObject.Parse(File.ReadAllText(metaFile));
                    var pemFile = System.IO.Path.Combine(Path, $"{id}.pem");

                    if (!File.Exists(pemFile))
                        continue;

                    var certificates = new X509Certificate2Collection();
                    certificates.ImportFromPem(File.ReadAllText(pemFile));

                    chains[id] = new TrustedChain(
                                     id,
                                     json["name"]?.Value<String>() ?? id,
                                     CertificateEntry.Moment(json["addedAt"]),
                                     json["enabled"]?.Value<Boolean>() ?? true
                                 ) {
                                     Certificates = [.. certificates.Cast<X509Certificate2>()]
                                 };

                }
                catch (Exception e)
                {
                    LastError = $"The trusted chain '{id}' could not be read: {e.Message}";
                }

            }

        }

        #endregion

        #region ToJSON()

        public JObject ToJSON()
        {

            var now = TimeProvider.GetUtcNow();

            return new JObject(
                       new JProperty("path",    Path),
                       new JProperty("chains",  new JArray(Chains.Select(chain => chain.ToJSON(now))))
                   );

        }

        #endregion

    }

}
