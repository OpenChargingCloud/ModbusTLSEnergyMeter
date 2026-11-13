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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    /// <summary>
    /// Read holding registers of this meter as a Modbus client reads them:
    /// "readRegisters 40069 4", or "readRegisters 0x9C85".
    /// </summary>
    /// <remarks>
    /// <para>
    /// Asked of what every Modbus/TLS connection is handed - the device, be
    /// it the simulation or the meter in front of which this one stands, and
    /// the session model behind its models - with function code 03, so that
    /// what is read here is what a client would be answered, a Modbus
    /// exception included.
    /// </para>
    /// <para>
    /// Needs "meter:read", as GET /api/v1/meter/registers does.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line of the meter.</param>
    public class ReadRegistersCommand(MeterCLI CLI) : ACLICommand<MeterCLI>(CLI),
                                                      ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(ReadRegistersCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// How many registers one request may read: what Modbus allows.
        /// </summary>
        public const UInt16 MaxCount = 125;

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => Arguments.Length == 1 && CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? SuggestionResponse.CommandHelp(Help())
                           : SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(MeterAccess.Meter), CommandName, out var refused))
                return [ refused ];

            if (Arguments.Length is < 2 or > 3)
                return [ $"Usage: {CommandName} <address> [<count>] - an address as 40069 or 0x9C85, and up to {MaxCount} registers; one without a count." ];

            if (!TryParseRegister(Arguments[1], out var first))
                return [ $"'{Arguments[1]}' is no register address: 0 to 65535, or 0x0000 to 0xFFFF." ];

            UInt16 count = 1;

            if (Arguments.Length == 3 &&
                (!UInt16.TryParse(Arguments[2], NumberStyles.None, CultureInfo.InvariantCulture, out count) || count == 0 || count > MaxCount))
            {
                return [ $"'{Arguments[2]}' is no count of registers: 1 to {MaxCount}." ];
            }

            if (first + count - 1 > UInt16.MaxValue)
                return [ $"{first}..{first + count - 1} ends behind the last register there is, 65535." ];

            Byte[] answer;

            await using (var backend = await cli.Meter.Backends.Direct(CancellationToken: CancellationToken))
            {
                answer = await backend.ProcessRequestAsync(
                                   1,
                                   ModbusPDU.BuildReadHoldingRegisters(first, count),
                                   CancellationToken
                               );
            }

            if (ModbusPDU.TryGetException(answer) is ModbusExceptionCode code)
                return [ $"{Range(first, count)} was answered with {code}." ];

            var registers = ModbusPDU.DecodeReadResponse(answer);

            return [
                .. registers.Select((register, index) =>
                       $"{first + index,5}  0x{register:X4}  {register,5}" +
                       (register > Int16.MaxValue ? $"  {(Int16) register,6}" : "        ") +
                       (TextOf(register) is String text ? $"  \"{text}\"" : "")).
                   Select(line => line.TrimEnd())
            ];

        }

        #endregion

        #region (internal static) TryParseRegister(Text, out Register) / Range(First, Count)

        /// <summary>
        /// A register address, or the unsigned value of one: decimal, or
        /// hexadecimal behind "0x".
        /// </summary>
        internal static Boolean TryParseRegister(String      Text,
                                                 out UInt16  Register)

            => Text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                   ? UInt16.TryParse(Text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out Register)
                   : UInt16.TryParse(Text,           NumberStyles.None,              CultureInfo.InvariantCulture, out Register);

        /// <summary>
        /// Registers as a Modbus person names them: one, or the first and the last.
        /// </summary>
        internal static String Range(UInt16  First,
                                     Int32   Count)

            => Count == 1
                   ? $"Register {First}"
                   : $"Registers {First}..{First + Count - 1}";

        #endregion

        #region (private static) TextOf(Register)

        /// <summary>
        /// The two characters a register holds where it is part of a SunSpec
        /// string - both printable, or one and a NUL that pads it; null for
        /// anything else.
        /// </summary>
        private static String? TextOf(UInt16 Register)
        {

            var high = (Char) (Register >> 8);
            var low  = (Char) (Register & 0xFF);

            static Boolean Printable(Char Character)
                => Character is >= ' ' and <= '~';

            return Printable(high) && (Printable(low) || low == '\0')
                       ? low == '\0' ? $"{high}" : $"{high}{low}"
                       : null;

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <address> [<count>] - read holding registers as a Modbus client would, e.g. '{CommandName} 40069 4' or '{CommandName} 0x9C85'";

        #endregion

    }

}
