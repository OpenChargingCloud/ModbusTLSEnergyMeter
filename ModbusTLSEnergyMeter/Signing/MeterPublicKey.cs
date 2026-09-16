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

using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// How a public key of this meter has to be written down for somebody to
    /// check a signature with it.
    /// </summary>
    /// <remarks>
    /// There is no single answer, which is the whole reason this exists. An
    /// OCMF reader hands an ECDSA key to a DER parser and expects a
    /// SubjectPublicKeyInfo; the same reader hands an Ed25519 or ML-DSA key
    /// straight to the signature suite and expects the raw key. An Alfen
    /// record carries a 25 byte compressed point in base32 and would not know
    /// what to do with either.
    ///
    /// Getting this wrong does not fail loudly. It produces a document that is
    /// signed correctly and reads as an invalid signature, which is the worst
    /// of the possible outcomes: it looks like the meter is lying.
    /// </remarks>
    public static class MeterPublicKey
    {

        #region ForOCMF(Key)

        /// <summary>
        /// The public key as an OCMF reader wants it, and what encoding to tell
        /// it that is.
        /// </summary>
        /// <remarks>
        /// ECDSA keys go out as a DER SubjectPublicKeyInfo, which is what
        /// ChargyCore's OCMF validator parses. Ed25519, Ed448 and ML-DSA go out
        /// as the raw key, which is what its direct-signing path hands to the
        /// suite.
        /// </remarks>
        public static (String Value, String Encoding) ForOCMF(MeterKey Key)

            => CurveOf(Key.Algorithm) is String curve
                   ? (Convert.ToHexString(SubjectPublicKeyInfoDER(curve, Key.PublicKey)), "hex")
                   : (Key.PublicKeyHEX,                                                    "hex");

        #endregion

        #region ForAlfen(Key)

        /// <summary>
        /// The 25 byte compressed secp192r1 point an Alfen record carries, as
        /// base32.
        /// </summary>
        /// <exception cref="InvalidOperationException">When the key is not a secp192r1 key.</exception>
        public static Byte[] ForAlfen(MeterKey Key)
        {

            if (Key.Algorithm != MeterKeyStore.AlfenAlgorithm)
                throw new InvalidOperationException(
                          $"An Alfen record needs a {MeterKeyStore.AlfenAlgorithm} key; '{Key.Id}' is {Key.Algorithm}. " +
                           "The format carries a 25 byte compressed point and parses nothing else.");

            var curve = ECNamedCurveTable.GetByName("secp192r1")!;

            return curve.Curve.DecodePoint(Key.PublicKey).GetEncoded(true);

        }

        #endregion

        #region ToJSON(Key)

        /// <summary>
        /// The public key of a meter as an answer hands it out: the value, how
        /// it is encoded, and what it is - so that whoever checks a signature
        /// later does not have to guess any of the three.
        /// </summary>
        public static JObject ToJSON(MeterKey Key)
        {

            var (value, encoding) = ForOCMF(Key);

            return new JObject(

                       new JProperty("keyId",        Key.Id),
                       new JProperty("algorithm",    Key.Algorithm),
                       new JProperty("fingerprint",  Key.Fingerprint),

                       // What an OCMF reader is given, in the shape it expects.
                       new JProperty("publicKey",    value),
                       new JProperty("encoding",     encoding),
                       new JProperty("format",       CurveOf(Key.Algorithm) is not null
                                                         ? "SubjectPublicKeyInfo"
                                                         : "raw"),

                       // And the bare key beside it, because a reader that wants
                       // the point rather than the wrapper should not have to
                       // unwrap one.
                       new JProperty("rawPublicKey", Key.PublicKeyHEX),

                       new JProperty("ocmfAlgorithm", OCMFWriter.AlgorithmFor(Key.Algorithm) is String sa
                                                          ? sa
                                                          : JValue.CreateNull())

                   );

        }

        #endregion


        #region (internal static) CurveOf(Algorithm)

        /// <summary>
        /// The SEC name of the curve an algorithm signs on, or null when it is
        /// not an elliptic curve algorithm at all.
        /// </summary>
        internal static String? CurveOf(String Algorithm)

            => Algorithm switch {
                   "ECDSA-P256"       => "secp256r1",
                   "ECDSA-P384"       => "secp384r1",
                   "ECDSA-P521"       => "secp521r1",
                   "ECDSA-secp256k1"  => "secp256k1",
                   "ECDSA-secp192r1"  => "secp192r1",
                   _                  => null
               };

        #endregion

        #region (private static) SubjectPublicKeyInfoDER(Curve, Point)

        /// <summary>
        /// Wrap an uncompressed SEC1 point in the DER SubjectPublicKeyInfo that
        /// names the curve it lies on.
        /// </summary>
        private static Byte[] SubjectPublicKeyInfoDER(String  Curve,
                                                      Byte[]  Point)
        {

            var oid        = ECNamedCurveTable.GetOid(Curve)
                                 ?? throw new ArgumentException($"Unknown elliptic curve '{Curve}'!", nameof(Curve));

            var parameters = ECNamedCurveTable.GetByName(Curve)!;

            // Named, not plain ECDomainParameters. A plain one writes the curve
            // out field by field - a mathematically complete description that
            // every reader of these keys rejects, because they all expect the
            // curve's object identifier and ask for it by name. The key would
            // be correct and unreadable.
            var domain     = new ECNamedDomainParameters(oid, parameters);

            return SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
                       new ECPublicKeyParameters(
                           parameters.Curve.DecodePoint(Point),
                           domain
                       )
                   ).GetDerEncoded();

        }

        #endregion

    }

}
