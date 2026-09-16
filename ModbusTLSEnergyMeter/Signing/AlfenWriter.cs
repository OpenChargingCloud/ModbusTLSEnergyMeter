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

using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.chargy;
using cloud.charging.open.chargy.Crypto;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// Writes signed meter values in the format of an Alfen charging station:
    ///
    ///     AP;0;3;{public key};{data set};{signature};
    ///
    /// </summary>
    /// <remarks>
    /// Six fields, everything after the version base32 because the whole thing
    /// has to survive being printed on a receipt and typed back in by hand. The
    /// data set is 82 bytes, little endian throughout, with no separators: the
    /// layout is the specification, and one byte in the wrong place produces a
    /// record that verifies as a forgery rather than as a mistake.
    ///
    /// What this meter is not, and says so: an Alfen adapter. The format has
    /// fields for one - an adapter identification, its firmware version and the
    /// checksum of that firmware - and this fills them from its own serial
    /// number and version, because leaving them empty would fail the signature
    /// they are part of. A record from here is an Alfen-shaped record signed by
    /// this meter, which is what makes it useful for exercising software that
    /// reads the format and what stops it being an Alfen meter value.
    ///
    /// The curve is not a choice either. The format carries a 25 byte
    /// compressed public key and a 48 byte signature, which is secp192r1 and
    /// nothing else - 192 bits, well below what anybody should choose today,
    /// and unchangeable without ceasing to be this format.
    /// </remarks>
    public static class AlfenWriter
    {

        #region Data

        /// <summary>
        /// The blob version this writes, and the only one the format defines.
        /// </summary>
        public const String BlobVersion = "3";

        #endregion

        #region TypeOf(Transaction)

        /// <summary>
        /// The second field: where in a charging session this reading sits.
        /// </summary>
        /// <remarks>
        /// "0" begins one, "1" is a reading inside it and "2" ends it. A reading
        /// that belongs to no session is written as a start, because the format
        /// has no word for "neither".
        /// </remarks>
        public static String TypeOf(String? Transaction)

            => Transaction switch {
                   "E"  => "2",
                   "C"  => "1",
                   _    => "0"
               };

        #endregion

        #region Build(Keys, Key, ...)

        /// <summary>
        /// Build and sign one Alfen signed meter value.
        /// </summary>
        /// <param name="Keys">The store holding the private half of the key.</param>
        /// <param name="Key">A secp192r1 key; the format takes no other.</param>
        /// <param name="Timestamp">When the reading was taken.</param>
        /// <param name="Value">What the meter stood at, already scaled to whole units of <paramref name="Scale"/>.</param>
        /// <param name="Scale">The power of ten the value is in, e.g. -1 for tenths of a Wh.</param>
        /// <param name="MeterId">The identification of the meter, up to 10 bytes of hexadecimal.</param>
        /// <param name="AdapterId">The identification of the signing adapter, up to 10 bytes of hexadecimal.</param>
        /// <param name="AdapterFirmware">Its firmware version, exactly 4 characters.</param>
        /// <param name="AdapterFirmwareChecksum">The checksum of that firmware, 2 bytes of hexadecimal.</param>
        /// <param name="OBIS">What was measured.</param>
        /// <param name="Transaction">"B" to begin a session, "E" to end one, "C" for a reading inside it, null for neither.</param>
        /// <param name="SecondsIndex">The meter's own seconds counter.</param>
        /// <param name="SessionId">The internal number of the charging session.</param>
        /// <param name="Pagination">The number of this reading.</param>
        /// <param name="Authorization">Who authorised the session, up to 20 characters.</param>
        /// <param name="StatusMeter">The status word of the meter, 2 bytes of hexadecimal.</param>
        /// <param name="StatusAdapter">The status word of the adapter, 2 bytes of hexadecimal.</param>
        /// <exception cref="InvalidOperationException">When the key is not a secp192r1 key.</exception>
        public static String Build(MeterKeyStore   Keys,
                                   MeterKey        Key,
                                   DateTimeOffset  Timestamp,
                                   UInt64          Value,
                                   SByte           Scale,
                                   String          MeterId,
                                   String          AdapterId,
                                   String          AdapterFirmware,
                                   String          AdapterFirmwareChecksum,
                                   String          OBIS,
                                   String?         Transaction,
                                   UInt32          SecondsIndex,
                                   UInt32          SessionId,
                                   UInt32          Pagination,
                                   String?         Authorization   = null,
                                   String          StatusMeter     = "0000",
                                   String          StatusAdapter   = "0000")
        {

            var publicKey = MeterPublicKey.ForAlfen(Key);

            #region The 82 bytes, in the order the format puts them

            var buffer = new Byte[82];

            ChargyLib.SetHex        (buffer, AdapterId,                            0);
            ChargyLib.SetText       (buffer, Fit(AdapterFirmware, 4),             10);
            ChargyLib.SetHex        (buffer, AdapterFirmwareChecksum,             14);
            ChargyLib.SetHex        (buffer, MeterId,                             16);
            ChargyLib.SetHex        (buffer, StatusMeter,                         26, true);
            ChargyLib.SetHex        (buffer, StatusAdapter,                       28, true);
            ChargyLib.SetUInt32     (buffer, SecondsIndex,                        30, true);

            // A plain UTC UNIX timestamp: no local offset is added, because the
            // format stores none and a reader adding one back would move the
            // reading by exactly the meter's summer time.
            ChargyLib.SetTimestamp32(buffer, Timestamp.UtcDateTime.ToString("o"), 34, AddMeterOffset: false);

            ChargyLib.SetHex        (buffer, ChargyLib.OBIS2Hex(OBIS),            38);

            // 30 is "Wh" in the format's unit table.
            ChargyLib.SetInt8       (buffer, 30,                                  44);
            ChargyLib.SetInt8       (buffer, Scale,                               45);
            ChargyLib.SetUInt64     (buffer, (Int64) Value,                       46, true);
            ChargyLib.SetText       (buffer, Fit(Authorization ?? "", 20),        54);
            ChargyLib.SetUInt32     (buffer, SessionId,                           74, true);
            ChargyLib.SetUInt32     (buffer, Pagination,                          78, true);

            #endregion

            #region Signed over the SHA-256 of those bytes, as a compact r||s pair

            // Compact and not DER: the format gives the signature exactly 48
            // bytes, which is r and s of a 192 bit curve side by side and has no
            // room for a DER wrapper.
            var signature = Keys.Sign(
                                Key,
                                SHA256.HashData(buffer),
                                new SignatureOptions(
                                    Prehashed:  true,
                                    Encoding:   SignatureEncoding.Compact
                                )
                            );

            #endregion

            return $"AP;{TypeOf(Transaction)};{BlobVersion};" +
                   $"{Base32(publicKey)};{Base32(buffer)};{Base32(signature)};";

        }

        #endregion

        #region (private static) Base32(Bytes)

        /// <summary>
        /// RFC 4648 base32, padded to a multiple of eight characters.
        /// </summary>
        /// <remarks>
        /// Written out here rather than taken from Illias, whose ToBase32 is not
        /// the inverse of the FromBASE32 every reader of this format decodes
        /// with: twenty-five bytes through the pair come back as thirty-eight.
        /// What matters for a record that has to be read by somebody else is
        /// being the exact inverse of their decoder, so this is that.
        /// </remarks>
        private static String Base32(ReadOnlySpan<Byte> Bytes)
        {

            const String alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

            var result    = new System.Text.StringBuilder((Bytes.Length + 4) / 5 * 8);
            var buffer    = 0;
            var bitsLeft  = 0;

            foreach (var value in Bytes)
            {

                buffer    = (buffer << 8) | value;
                bitsLeft += 8;

                while (bitsLeft >= 5)
                {
                    bitsLeft -= 5;
                    result.Append(alphabet[(buffer >> bitsLeft) & 31]);
                }

            }

            // The bits of the last byte that did not fill a character, padded
            // with zeroes on the right.
            if (bitsLeft > 0)
                result.Append(alphabet[(buffer << (5 - bitsLeft)) & 31]);

            while (result.Length % 8 != 0)
                result.Append('=');

            return result.ToString();

        }

        #endregion

        #region (private static) Fit(Text, Length)

        /// <summary>
        /// Text cut or padded to exactly the bytes the layout gives it.
        /// </summary>
        /// <remarks>
        /// Cut, rather than refused: a field one character too long would
        /// otherwise write over the field after it and produce a record whose
        /// signature is good and whose contents are nonsense.
        /// </remarks>
        private static String Fit(String  Text,
                                  Int32   Length)

            => Text.Length > Length
                   ? Text[..Length]
                   : Text;

        #endregion

    }

}
