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

using System.Globalization;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using cloud.charging.open.chargy.Crypto;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// One reading as it goes into an OCMF document.
    /// </summary>
    /// <param name="Timestamp">When it was measured.</param>
    /// <param name="Value">What the meter stood at.</param>
    /// <param name="Transaction">Where in a charging session it was taken: "B" to begin, "E" to end, null for a reading that belongs to no session.</param>
    /// <param name="OBIS">What was measured, as an OBIS code.</param>
    /// <param name="Unit">The unit, one of "kWh", "Wh", "mOhm", "uOhm".</param>
    /// <param name="CurrentType">"AC" or "DC".</param>
    /// <param name="TimeSync">How far the clock can be trusted: "S" when a time server was reached, "I" when it was not, "U" when nobody knows.</param>
    /// <param name="Status">The status word of the meter; "G" is "good".</param>
    public record OCMFReadingToWrite(DateTimeOffset  Timestamp,
                                     Decimal         Value,
                                     String?         Transaction,
                                     String          OBIS         = "1-b:1.8.0",
                                     String          Unit         = "kWh",
                                     String          CurrentType  = "AC",
                                     String          TimeSync     = "I",
                                     String          Status       = "G");


    /// <summary>
    /// Writes OCMF documents: "OCMF|{payload}|{signature}".
    /// </summary>
    /// <remarks>
    /// ChargyCore reads OCMF and does not write it, because nothing that
    /// verifies a charging session has any business producing one. A meter is
    /// the other end of that: producing them is the whole job, and the reason
    /// this lives here rather than there.
    ///
    /// The payload is serialised exactly once and that string is what gets
    /// signed and what goes into the document. Re-serialising the parsed JSON
    /// to embed it would be the obvious shortcut and would reorder keys, change
    /// the spacing or normalise a number - and any of those turns a perfectly
    /// good signature into an invalid one.
    /// </remarks>
    public static class OCMFWriter
    {

        #region AlgorithmFor(Algorithm)

        /// <summary>
        /// The OCMF "SA" name of one of this meter's signing algorithms, or null
        /// when OCMF has no name for it.
        /// </summary>
        /// <remarks>
        /// Only the combinations that are both sane and writable. OCMF also
        /// names two that pair a 384 bit curve with SHA-256, and ChargyCore goes
        /// on verifying documents signed that way because meters were built
        /// like that - but nothing new should be written with them, so there is
        /// no way to ask for one here.
        /// </remarks>
        public static String? AlgorithmFor(String Algorithm)

            => Algorithm switch {
                   "ECDSA-P256"       => "ECDSA-secp256r1-SHA256",
                   "ECDSA-P384"       => "ECDSA-secp384r1-SHA384",
                   "ECDSA-P521"       => "ECDSA-secp521r1-SHA512",
                   "ECDSA-secp256k1"  => "ECDSA-secp256k1-SHA256",
                   "ECDSA-secp192r1"  => "ECDSA-secp192r1-SHA256",
                   "Ed25519"          => "EdDSA-Ed25519",
                   "Ed448"            => "EdDSA-Ed448",
                   "ML-DSA-44"        => "ML-DSA-44",
                   "ML-DSA-65"        => "ML-DSA-65",
                   "ML-DSA-87"        => "ML-DSA-87",
                   _                  => null
               };

        /// <summary>
        /// Every algorithm of this meter that an OCMF document can be signed
        /// with.
        /// </summary>
        public static IEnumerable<String> SigningAlgorithms

            => MeterKeyStore.Algorithms.Where(algorithm => AlgorithmFor(algorithm) is not null);

        #endregion

        #region Timestamp(Moment, TimeSync)

        /// <summary>
        /// An OCMF timestamp: "2019-06-26T08:57:44,337+0000 U".
        /// </summary>
        /// <remarks>
        /// A comma before the milliseconds, exactly three of them, and an offset
        /// with no colon in it - none of which is what "o" or "s" produces. The
        /// letter after the space says how far the clock behind the reading can
        /// be trusted, and is part of what gets signed.
        /// </remarks>
        public static String Timestamp(DateTimeOffset  Moment,
                                       String          TimeSync)
        {

            var offset  = Moment.Offset;
            var sign    = offset < TimeSpan.Zero ? "-" : "+";
            var hours   = Math.Abs(offset.Hours);
            var minutes = Math.Abs(offset.Minutes);

            return $"{Moment.ToString("yyyy-MM-ddTHH:mm:ss", CultureInfo.InvariantCulture)}," +
                   $"{Moment.Millisecond:D3}{sign}{hours:D2}{minutes:D2} {TimeSync}";

        }

        #endregion

        #region Build(Keys, Key, Payload, Readings)

        /// <summary>
        /// Build and sign one OCMF document.
        /// </summary>
        /// <param name="Keys">The store holding the private half of the key.</param>
        /// <param name="Key">The key to sign with.</param>
        /// <param name="Payload">Everything about the meter and the session; the readings are added to it.</param>
        /// <param name="Readings">The readings, in the order they were taken.</param>
        /// <exception cref="ArgumentException">When OCMF has no name for the key's algorithm.</exception>
        public static String Build(MeterKeyStore                    Keys,
                                   MeterKey                         Key,
                                   JObject                          Payload,
                                   IEnumerable<OCMFReadingToWrite>  Readings)
        {

            var algorithm = AlgorithmFor(Key.Algorithm)
                                ?? throw new ArgumentException(
                                       $"OCMF has no name for '{Key.Algorithm}', so a document cannot say what it was signed with.",
                                       nameof(Key));

            Payload["RD"] = new JArray(Readings.Select(ReadingJSON));

            // Serialised once. This exact string is what is signed and what the
            // document carries; anything that re-serialises it in between would
            // be signing a different text than the one a reader checks.
            var rawPayload = Payload.ToString(Formatting.None);
            var payloadUTF8 = Encoding.UTF8.GetBytes(rawPayload);

            var signature  = Sign(Keys, Key, Key.Algorithm, payloadUTF8);

            var signatureJSON = new JObject(
                                    new JProperty("SD",  Convert.ToHexString(signature).ToLowerInvariant()),
                                    new JProperty("SA",  algorithm),
                                    new JProperty("SE",  "hex")
                                );

            return $"OCMF|{rawPayload}|{signatureJSON.ToString(Formatting.None)}";

        }

        #endregion

        #region (private static) Sign(Keys, Key, Algorithm, Payload)

        /// <summary>
        /// Sign the payload the way its algorithm expects it to be signed.
        /// </summary>
        /// <remarks>
        /// Two different things happen here. EdDSA and ML-DSA sign the payload
        /// itself and their signature is the opaque byte string they return.
        /// ECDSA signs a digest and OCMF carries the result DER encoded, which
        /// is not the suite's compact default - a compact signature would be
        /// read as a malformed DER structure and reported as an invalid
        /// signature rather than as the encoding mistake it is.
        /// </remarks>
        private static Byte[] Sign(MeterKeyStore  Keys,
                                   MeterKey       Key,
                                   String         Algorithm,
                                   Byte[]         Payload)

            => MeterPublicKey.CurveOf(Algorithm) is not null
                   ? Keys.Sign(Key, Payload, new SignatureOptions(Encoding: SignatureEncoding.DER))
                   : Keys.Sign(Key, Payload);

        #endregion

        #region (private static) ReadingJSON(Reading)

        private static JObject ReadingJSON(OCMFReadingToWrite Reading)
        {

            var json = new JObject(
                           new JProperty("TM",  Timestamp(Reading.Timestamp, Reading.TimeSync))
                       );

            // Absent rather than empty for a reading that belongs to no charging
            // session: OCMF checks "TX" against a list of the places a reading
            // can sit in one, and a fiscal reading sits in none of them.
            if (Reading.Transaction is not null)
                json.Add("TX", Reading.Transaction);

            json.Add("RV",  JToken.FromObject(Reading.Value));
            json.Add("RI",  Reading.OBIS);
            json.Add("RU",  Reading.Unit);
            json.Add("RT",  Reading.CurrentType);
            json.Add("EF",  "");
            json.Add("ST",  Reading.Status);

            return json;

        }

        #endregion

    }

}
