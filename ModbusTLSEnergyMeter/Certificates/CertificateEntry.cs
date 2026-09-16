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

using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Certificates
{

    /// <summary>
    /// One identity this meter can show: a private key that never leaves it,
    /// the request that was handed out for that key, and - once somebody has
    /// had it signed and brought it back - the certificate itself.
    /// </summary>
    /// <remarks>
    /// An entry without a certificate is a request still out for signing, and
    /// is kept for exactly that reason: the key it belongs to is here, and a
    /// certificate is only worth anything against the key it was asked for.
    /// </remarks>
    public class CertificateEntry
    {

        #region Properties

        /// <summary>
        /// Sortable, and the name of the directory this entry lives in.
        /// </summary>
        public String                  Id            { get; }

        /// <summary>
        /// When the key was made and the request written.
        /// </summary>
        public DateTimeOffset          CreatedAt     { get; }

        /// <summary>
        /// The subject that was asked for. What a CA made of it is in the
        /// certificate, and need not be the same.
        /// </summary>
        public String                  Subject       { get; }

        /// <summary>
        /// The DNS names that were asked for.
        /// </summary>
        public IReadOnlyList<String>   DNSNames      { get; }

        /// <summary>
        /// The IP addresses that were asked for.
        /// </summary>
        public IReadOnlyList<String>   IPAddresses   { get; }

        /// <summary>
        /// What kind of key this is, for a page that has to say so.
        /// </summary>
        public String                  KeyType       { get; }

        /// <summary>
        /// A line somebody wrote to remember what this is for.
        /// </summary>
        public String?                 Note          { get; internal set; }

        /// <summary>
        /// The PKCS#10 request, PEM encoded. Null for an entry that was
        /// adopted rather than requested - the certificate this meter was
        /// started with, say.
        /// </summary>
        public String?                 RequestPEM    { get; internal set; }

        /// <summary>
        /// The certificate, with its private key, ready to be shown to a peer.
        /// Null while the request is still out.
        /// </summary>
        public X509Certificate2?       Certificate   { get; internal set; }

        /// <summary>
        /// The certificate and whatever intermediates came with it, as they
        /// were uploaded.
        /// </summary>
        public IReadOnlyList<X509Certificate2>  Chain  { get; internal set; } = [];

        #endregion

        #region Derived

        /// <summary>
        /// Whether a certificate has come back for this request.
        /// </summary>
        public Boolean           HasCertificate
            => Certificate is not null;

        public DateTimeOffset?   NotBefore
            => Certificate?.NotBefore;

        public DateTimeOffset?   NotAfter
            => Certificate?.NotAfter;

        /// <summary>
        /// Whether this entry could be shown to a peer at that moment.
        /// </summary>
        public Boolean IsValidAt(DateTimeOffset Now)

            => Certificate is not null &&
               Certificate.HasPrivateKey &&
               Now >= Certificate.NotBefore &&
               Now <= Certificate.NotAfter &&

               // A certificate this machine cannot present is never the answer
               // to "what should this listener show?". This used to follow from
               // the private key: there was no way to attach one to an Ed448 or
               // an ML-DSA certificate, so such an entry fell out here by
               // itself. Hermod can attach one now, so the question has to be
               // asked on purpose - and it is a better question, because it is
               // asked of the machine rather than of a list.
               ServedByTLS;

        /// <summary>
        /// What this entry is at that moment, in one word, for a page and for
        /// a log line.
        /// </summary>
        public String StateAt(DateTimeOffset Now)

            => Certificate is null            ? "awaiting a certificate"
             : Now <  Certificate.NotBefore   ? "not valid yet"
             : Now >  Certificate.NotAfter    ? "expired"

             // One state and not two. A certificate can fail to be presentable
             // because this machine's TLS stack will not authenticate a server
             // with that kind of key, or because .NET could not hold the
             // private key in the first place - and for somebody looking at
             // this meter those are the same fact: no listener will show it.
             // Asked last, because it is the only one of these that costs a
             // handshake.
             : !ServedByTLS                   ? "not for a listener"

             :                                  "valid";

        /// <summary>
        /// Whether a TLS listener of this meter could show this one.
        /// </summary>
        /// <remarks>
        /// Found out by trying, once per algorithm, and true for a certificate
        /// that is not here yet - nothing is being kept out until there is
        /// something to keep out.
        /// </remarks>
        public Boolean ServedByTLS

            => Certificate is null ||
               CertificateStore.ServedByTLS(KeyType, Certificate);

        #endregion

        #region Constructor(s)

        internal CertificateEntry(String                 Id,
                                  DateTimeOffset         CreatedAt,
                                  String                 Subject,
                                  IReadOnlyList<String>  DNSNames,
                                  IReadOnlyList<String>  IPAddresses,
                                  String                 KeyType,
                                  String?                Note   = null)
        {

            this.Id           = Id;
            this.CreatedAt    = CreatedAt;
            this.Subject      = Subject;
            this.DNSNames     = DNSNames;
            this.IPAddresses  = IPAddresses;
            this.KeyType      = KeyType;
            this.Note         = Note;

        }

        #endregion


        #region ToJSON(Now)

        /// <summary>
        /// What a page needs to show this entry and decide what to offer.
        /// </summary>
        public JObject ToJSON(DateTimeOffset Now)

            => new (

                   new JProperty("id",             Id),
                   new JProperty("createdAt",      CreatedAt.ToString("o")),
                   new JProperty("subject",        Subject),
                   new JProperty("dnsNames",       new JArray(DNSNames)),
                   new JProperty("ipAddresses",    new JArray(IPAddresses)),
                   new JProperty("keyType",        KeyType),
                   new JProperty("note",           Note),
                   new JProperty("hasRequest",     RequestPEM is not null),
                   // Three answers, not two. Until a certificate is here there
                   // is nothing to ask the question of, and saying "yes" then
                   // would be a promise about a certificate that has not
                   // arrived - one on an Edwards curve will very likely turn
                   // out to be a no.
                   Certificate is not null
                       ? new JProperty("servedByTLS",  ServedByTLS)
                       : new JProperty("servedByTLS",  JValue.CreateNull()),
                   new JProperty("state",          StateAt(Now)),

                   // JValue.CreateNull() rather than a bare null: a literal
                   // null binds to JProperty's params overload as a null
                   // ARRAY, and the constructor then dereferences it.
                   Certificate is not null
                       ? new JProperty("certificate", new JObject(
                             new JProperty("subject",      Certificate.Subject),
                             new JProperty("issuer",       Certificate.Issuer),
                             new JProperty("notBefore",    Certificate.NotBefore.ToUniversalTime().ToString("o")),
                             new JProperty("notAfter",     Certificate.NotAfter. ToUniversalTime().ToString("o")),
                             new JProperty("thumbprint",   Certificate.Thumbprint),
                             new JProperty("chainLength",  Chain.Count)
                         ))
                       : new JProperty("certificate", JValue.CreateNull())

               );

        #endregion

        #region (internal) MetadataJSON()

        /// <summary>
        /// What is written beside the key: everything that cannot be read back
        /// out of the PEM files themselves.
        /// </summary>
        internal JObject MetadataJSON()

            => new (
                   new JProperty("id",           Id),
                   new JProperty("createdAt",    CreatedAt.ToString("o")),
                   new JProperty("subject",      Subject),
                   new JProperty("dnsNames",     new JArray(DNSNames)),
                   new JProperty("ipAddresses",  new JArray(IPAddresses)),
                   new JProperty("keyType",      KeyType),
                   new JProperty("note",         Note)
               );

        #endregion

        #region (internal static) Moment(Token)

        /// <summary>
        /// A timestamp out of JSON, read from its text as written.
        /// </summary>
        /// <remarks>
        /// One line now, because the reason it exists moved somewhere every
        /// store can use it. See <see cref="MeterJSON"/> for what Newtonsoft
        /// does to a timestamp that is left to it.
        /// </remarks>
        internal static DateTimeOffset Moment(JToken? Token)

            => MeterJSON.Moment(Token);

        #endregion

        #region (internal static) TryParseMetadata(JSON, out Entry)

        internal static Boolean TryParseMetadata(JObject             JSON,
                                                 out CertificateEntry?  Entry)
        {

            Entry = null;

            var id = JSON["id"]?.Value<String>();

            if (id is null)
                return false;

            Entry = new CertificateEntry(
                        id,
                        // Read as text and parsed, not cast: Newtonsoft turns
                        // an ISO 8601 string into a DateTime token, and asking
                        // that for a DateTimeOffset throws - which used to
                        // lose the whole entry, and with it the certificate a
                        // restarted meter was meant to come back up with.
                        Moment(JSON["createdAt"]),
                        JSON["subject"]?.Value<String>() ?? "",
                        [.. (JSON["dnsNames"]    as JArray)?.Values<String>().Where(name => name is not null).Cast<String>() ?? []],
                        [.. (JSON["ipAddresses"] as JArray)?.Values<String>().Where(name => name is not null).Cast<String>() ?? []],
                        JSON["keyType"]?.Value<String>() ?? "unknown",
                        JSON["note"]?.Value<String>()
                    );

            return true;

        }

        #endregion

    }

}
