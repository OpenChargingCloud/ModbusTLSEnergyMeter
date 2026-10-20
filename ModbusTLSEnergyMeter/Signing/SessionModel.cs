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

using System.Text;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// What a command written to the session model asks for.
    /// </summary>
    public enum SessionCommand : UInt16
    {

        /// <summary>
        /// Nothing; what the command register reads.
        /// </summary>
        None   = 0,

        /// <summary>
        /// Begin a charging session with what this connection wrote before.
        /// </summary>
        Start  = 1,

        /// <summary>
        /// End the charging session that is running, into one signed document.
        /// </summary>
        Stop   = 2

    }


    /// <summary>
    /// Where the session model stands, for everybody connected.
    /// </summary>
    public enum SessionModelState : UInt16
    {

        /// <summary>
        /// No session is running, and there is no document to read.
        /// </summary>
        None     = 0,

        /// <summary>
        /// A session is running.
        /// </summary>
        Running  = 1,

        /// <summary>
        /// The last session was stopped, and its document can be read.
        /// </summary>
        Stopped  = 2

    }


    /// <summary>
    /// Why a command written to the session model was refused, as its error
    /// register says.
    /// </summary>
    public enum SessionRefusalKind : UInt16
    {

        /// <summary>
        /// The last command of this connection was done.
        /// </summary>
        None              = 0,

        /// <summary>
        /// A session is running already.
        /// </summary>
        AlreadyRunning    = 1,

        /// <summary>
        /// No session is running.
        /// </summary>
        NotRunning        = 2,

        /// <summary>
        /// The session that is running is not the one this stop named.
        /// </summary>
        NotThisSession    = 3,

        /// <summary>
        /// Something written for the command is not what it may be.
        /// </summary>
        InvalidParameter  = 4,

        /// <summary>
        /// There is no key to sign the session with.
        /// </summary>
        NoKey             = 5,

        /// <summary>
        /// The energy counter could not be read.
        /// </summary>
        Unreadable        = 6,

        /// <summary>
        /// The energy counter stands below where the session began.
        /// </summary>
        CounterBackwards  = 7,

        /// <summary>
        /// The session could not be signed.
        /// </summary>
        SigningFailed     = 8,

        /// <summary>
        /// The command register was written with a number that is no command.
        /// </summary>
        UnknownCommand    = 9

    }


    /// <summary>
    /// The session model: a SunSpec model of this meter's own, behind the
    /// models of the device it measures with, through which a charging station
    /// begins and ends a charging session and reads the signed document it
    /// ends in.
    /// </summary>
    /// <remarks>
    /// <para>
    /// There is no standard for this. The German calibration law asks that a
    /// charging session's energy be signed by the meter that measured it, with
    /// who charged and on which terms inside what was signed; SunSpec has
    /// models for what a meter measures and none for whom. So this is a model
    /// in the range SunSpec leaves to manufacturers, found the way every SunSpec
    /// model is found - by walking the list from "SunS" - and documented in the
    /// README, register by register.
    /// </para>
    /// <para>
    /// The registers a command is given are each connection's own. What one
    /// connection wrote is what that connection's next command is done with,
    /// and nothing is left over afterwards: an identification written for one
    /// session and still standing in a register shared by everybody would be
    /// signed into the next session of whoever forgot to write one.
    /// </para>
    /// <para>
    /// Texts are UTF-8, two bytes to a register with the first in the high
    /// byte, padded with NUL - SunSpec's strings, with room for a tariff that
    /// says "Euro" in some other way than "EUR".
    /// </para>
    /// </remarks>
    public static class SessionModel
    {

        #region Data

        /// <summary>
        /// The id of the model, in the range SunSpec leaves to manufacturers.
        /// </summary>
        public const UInt16  Id                 = 64900;

        // Where each field is, counted from the first register after the
        // model's id and length - as SunSpec counts the points of a model.

        /// <summary>The command register: 1 start, 2 stop. It reads 0.</summary>
        public const UInt16  Command            = 0;

        /// <summary>The state of the model, for everybody: 0 none, 1 running, 2 stopped.</summary>
        public const UInt16  State              = 1;

        /// <summary>Why this connection's last command was refused, or 0.</summary>
        public const UInt16  Error              = 2;

        /// <summary>Padding, which reads 0.</summary>
        public const UInt16  Pad                = 3;

        /// <summary>Why, in words.</summary>
        public const UInt16  ErrorText          = 4;
        public const UInt16  ErrorTextLength    = 64;

        /// <summary>The session id of whoever starts or stops: for a start, what the session is to be known by; for a stop, the session that is meant.</summary>
        public const UInt16  SessionId          = 68;
        public const UInt16  SessionIdLength    = 32;

        /// <summary>OCMF "IT": how whoever charges was identified.</summary>
        public const UInt16  IdentificationType          = 100;
        public const UInt16  IdentificationTypeLength    = 8;

        /// <summary>OCMF "ID": whom they were identified as.</summary>
        public const UInt16  Identification              = 108;
        public const UInt16  IdentificationLength        = 40;

        /// <summary>OCMF "CT": what the charge point is identified by.</summary>
        public const UInt16  ChargePointIdType           = 148;
        public const UInt16  ChargePointIdTypeLength     = 8;

        /// <summary>OCMF "CI": the charge point.</summary>
        public const UInt16  ChargePointId               = 156;
        public const UInt16  ChargePointIdLength         = 40;

        /// <summary>OCMF "TT": the tariff.</summary>
        public const UInt16  TariffText                  = 196;
        public const UInt16  TariffTextLength            = 128;

        /// <summary>The session id the running session, or the stopped one whose document is here, is known by.</summary>
        public const UInt16  CurrentSessionId            = 324;

        /// <summary>How many bytes of public key follow.</summary>
        public const UInt16  PublicKeyLength             = 356;

        /// <summary>The public key the session is signed with, as hex: a SubjectPublicKeyInfo for ECDSA, the raw key for EdDSA and ML-DSA.</summary>
        public const UInt16  PublicKey                   = 357;
        public const UInt16  PublicKeyRegisters          = 2600;

        /// <summary>How many bytes of document follow.</summary>
        public const UInt16  DocumentLength              = 2957;

        /// <summary>The OCMF document of the last session that was stopped.</summary>
        public const UInt16  Document                    = 2958;
        public const UInt16  DocumentRegisters           = 8192;

        /// <summary>
        /// How many registers follow the model's length register.
        /// </summary>
        public const UInt16  Length                      = Document + DocumentRegisters;

        /// <summary>
        /// Every register a command is given, and the command register: what
        /// may be written, by a role that may write what is commanded.
        /// </summary>
        public static readonly IReadOnlyList<(UInt16 Offset, UInt16 Length)> Writable = [
            (Command,             1),
            (SessionId,           SessionIdLength),
            (IdentificationType,  IdentificationTypeLength),
            (Identification,      IdentificationLength),
            (ChargePointIdType,   ChargePointIdTypeLength),
            (ChargePointId,       ChargePointIdLength),
            (TariffText,          TariffTextLength)
        ];

        #endregion


        #region (static) WritableAddresses(ModelAddress)

        /// <summary>
        /// The absolute addresses that may be written, for a model whose id is
        /// at the given address.
        /// </summary>
        public static IEnumerable<UInt16> WritableAddresses(UInt16 ModelAddress)
        {
            foreach (var (offset, length) in Writable)
                for (var i = 0; i < length; i++)
                    yield return (UInt16) (ModelAddress + 2 + offset + i);
        }

        #endregion

        #region (static) IsWritable(Offset)

        /// <summary>
        /// Whether the register at this offset may be written.
        /// </summary>
        public static Boolean IsWritable(Int32 Offset)

            => Writable.Any(field => Offset >= field.Offset && Offset < field.Offset + field.Length);

        #endregion

        #region (static) Encode(Text, Registers) / Decode(Registers)

        /// <summary>
        /// A text as registers: UTF-8, the first byte high, padded with NUL.
        /// </summary>
        /// <exception cref="ArgumentException">When it does not fit.</exception>
        public static UInt16[] Encode(String?  Text,
                                      Int32    Registers)
        {

            var bytes = Encoding.UTF8.GetBytes(Text ?? "");

            if (bytes.Length > Registers * 2)
                throw new ArgumentException($"{bytes.Length} bytes do not fit into {Registers} registers.", nameof(Text));

            var registers = new UInt16[Registers];

            for (var i = 0; i < bytes.Length; i++)
                registers[i / 2] |= (UInt16) (i % 2 == 0 ? bytes[i] << 8 : bytes[i]);

            return registers;

        }

        /// <summary>
        /// The text in some registers, up to the first NUL - or null when it is
        /// not UTF-8.
        /// </summary>
        public static String? Decode(ReadOnlySpan<UInt16> Registers)
        {

            var bytes = new List<Byte>(Registers.Length * 2);

            foreach (var register in Registers)
            {

                var high = (Byte) (register >> 8);
                var low  = (Byte) (register & 0xFF);

                if (high == 0)
                    break;

                bytes.Add(high);

                if (low == 0)
                    break;

                bytes.Add(low);

            }

            try
            {
                return new UTF8Encoding(false, true).GetString(bytes.ToArray());
            }
            catch (DecoderFallbackException)
            {
                return null;
            }

        }

        #endregion

    }

}
