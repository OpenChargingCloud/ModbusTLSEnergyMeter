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

using Newtonsoft.Json.Linq;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// One signing key of this meter: the pair it puts its name to a reading
    /// with.
    /// </summary>
    /// <remarks>
    /// Not a TLS key and not kept with them. A TLS key says "this listener is
    /// this host" for the length of a connection and is replaced whenever a CA
    /// issues a new certificate; this one says "this meter measured this" and
    /// has to go on meaning that for as long as anybody may want to check a
    /// reading - years after the connection, and after the certificate it was
    /// taken under has expired.
    ///
    /// There is more than one because the data formats disagree about
    /// cryptography and cannot be talked out of it: OCMF's own algorithm is
    /// ECDSA over secp256r1, Alfen's format is secp192r1 and nothing else, and
    /// anybody who wants a signature that outlives a quantum computer wants
    /// ML-DSA. A meter that held one key could speak one of those.
    /// </remarks>
    /// <param name="Id">What this key is called here.</param>
    /// <param name="Algorithm">The signature suite it belongs to, e.g. "ECDSA-P256".</param>
    /// <param name="CreatedAt">When it was made.</param>
    /// <param name="PublicKey">The public half, which is meant to be handed out.</param>
    /// <param name="PrivateKey">The private half, which is not.</param>
    /// <param name="Note">A line to remember what it is for.</param>
    public class MeterKey(String          Id,
                          String          Algorithm,
                          DateTimeOffset  CreatedAt,
                          Byte[]          PublicKey,
                          Byte[]          PrivateKey,
                          String?         Note   = null)
    {

        #region Properties

        /// <summary>What this key is called here.</summary>
        public String          Id           { get; }      = Id;

        /// <summary>The signature suite it belongs to.</summary>
        public String          Algorithm    { get; }      = Algorithm;

        /// <summary>When it was made.</summary>
        public DateTimeOffset  CreatedAt    { get; }      = CreatedAt;

        /// <summary>The public half, which is meant to be handed out.</summary>
        public Byte[]          PublicKey    { get; }      = PublicKey;

        /// <summary>
        /// The private half.
        /// </summary>
        /// <remarks>
        /// Internal, and deliberately so: nothing outside the store has any
        /// business reading it, and <see cref="ToJSON"/> - the one way this
        /// class becomes an HTTP response - cannot reach it either.
        /// </remarks>
        internal Byte[]        PrivateKey   { get; }      = PrivateKey;

        /// <summary>A line to remember what it is for.</summary>
        public String?         Note         { get; set; } = Note;

        /// <summary>
        /// Whether this is the key the meter signs with when nobody names one.
        /// </summary>
        public Boolean         IsDefault    { get; internal set; }

        #endregion


        #region PublicKeyHEX / Fingerprint

        /// <summary>
        /// The public key as the data formats carry it: uppercase hexadecimal.
        /// </summary>
        public String PublicKeyHEX

            => Convert.ToHexString(PublicKey);

        /// <summary>
        /// A short name for this key that a person can compare by eye.
        /// </summary>
        /// <remarks>
        /// The first eight bytes of the SHA-256 of the public key. Not a
        /// security boundary - anything that decides something uses the whole
        /// key - but the difference between a page that shows two keys and a
        /// page on which two keys can be told apart.
        /// </remarks>
        public String Fingerprint

            => Convert.ToHexString(
                   System.Security.Cryptography.SHA256.HashData(PublicKey).AsSpan(0, 8)
               ).ToLowerInvariant();

        #endregion

        #region MetadataJSON() / ToJSON()

        /// <summary>
        /// What is written beside the private key on disk.
        /// </summary>
        internal JObject MetadataJSON()

            => new (
                   new JProperty("id",          Id),
                   new JProperty("algorithm",   Algorithm),
                   new JProperty("createdAt",   CreatedAt.UtcDateTime.ToString("o")),
                   new JProperty("publicKey",   PublicKeyHEX),
                   new JProperty("isDefault",   IsDefault),
                   Note is not null
                       ? new JProperty("note",  Note)
                       : new JProperty("note",  JValue.CreateNull())
               );

        /// <summary>
        /// What a page and an API answer see. The private key is not reachable
        /// from here.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("id",           Id),
                   new JProperty("algorithm",    Algorithm),
                   new JProperty("createdAt",    CreatedAt.UtcDateTime.ToString("o")),
                   new JProperty("publicKey",    PublicKeyHEX),
                   new JProperty("fingerprint",  Fingerprint),
                   new JProperty("isDefault",    IsDefault),
                   Note is not null
                       ? new JProperty("note",   Note)
                       : new JProperty("note",   JValue.CreateNull())
               );

        #endregion

        #region (override) ToString()

        public override String ToString()

            => $"{Id} ({Algorithm}, {Fingerprint}){(IsDefault ? " - the meter's identity" : "")}";

        #endregion

    }

}
