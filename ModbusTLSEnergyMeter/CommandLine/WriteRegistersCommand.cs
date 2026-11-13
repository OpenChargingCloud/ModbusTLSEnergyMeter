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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Web;

using LogLevel = cloud.charging.open.protocols.WWCP.Node.Logging.LogLevel;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    /// <summary>
    /// Write holding registers of this meter as a Modbus client writes them:
    /// "writeRegisters 40094 1", or "writeRegisters 0x9C9E 0x0001".
    /// </summary>
    /// <remarks>
    /// <para>
    /// Written to what every Modbus/TLS connection is handed - the device, be
    /// it the simulation or the meter in front of which this one stands, and
    /// the session model behind its models - with function code 16 and the
    /// values one behind the other from the address on. What the device does
    /// with a write is the device's to say: a register that cannot be written
    /// is answered with a Modbus exception here as it is there.
    /// </para>
    /// <para>
    /// The policy of the Modbus/TLS frontend decides by the SunSpec role in
    /// a client's certificate, and nobody showed one here. What decides
    /// instead is what decides on the web interface: "meter:edit", which is
    /// the administrators' alone unless the configuration file says
    /// otherwise - and the console, which has the process.
    /// </para>
    /// <para>
    /// Every write is in the log book, with who made it and what the device
    /// answered: a write changes what this meter is or counts.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line of the meter.</param>
    public class WriteRegistersCommand(MeterCLI CLI) : ACLICommand<MeterCLI>(CLI),
                                                       ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(WriteRegistersCommand)[..^7].ToLowerFirstChar();

        /// <summary>
        /// How many registers one request may write: what Modbus allows.
        /// </summary>
        public const Int32 MaxCount = 123;

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

            if (!cli.MayDo(Permission.Edit(MeterAccess.Meter), CommandName, out var refused))
                return [ refused ];

            if (Arguments.Length < 3)
                return [ $"Usage: {CommandName} <address> <value> [<value> ...] - an address as 40094 or 0x9C9E; values as 1, -1 or 0xFFFF, written one behind the other." ];

            if (!ReadRegistersCommand.TryParseRegister(Arguments[1], out var first))
                return [ $"'{Arguments[1]}' is no register address: 0 to 65535, or 0x0000 to 0xFFFF." ];

            if (Arguments.Length - 2 > MaxCount)
                return [ $"{Arguments.Length - 2} values are more than one request may write: {MaxCount}." ];

            var values = new UInt16[Arguments.Length - 2];

            for (var i = 0; i < values.Length; i++)
                if (!TryParseValue(Arguments[i + 2], out values[i]))
                    return [ $"'{Arguments[i + 2]}' is no value of a register: 0 to 65535, -32768 to -1, or 0x0000 to 0xFFFF." ];

            if (first + values.Length - 1 > UInt16.MaxValue)
                return [ $"{first}..{first + values.Length - 1} ends behind the last register there is, 65535." ];

            var meter = cli.Meter;
            var range = ReadRegistersCommand.Range(first, values.Length);
            var said  = String.Join(" ", values.Select(value => $"0x{value:X4}"));
            var where = meter.Upstream is { } upstream
                            ? $" of the meter at {upstream.Server}"
                            : "";

            var data  = new JObject(
                            new JProperty("address",  first),
                            new JProperty("values",   new JArray(values.Select(value => (Int32) value)))
                        );

            Byte[] answer;

            await using (var backend = await meter.Backends.Direct(CancellationToken: CancellationToken))
            {
                answer = await backend.ProcessRequestAsync(
                                   1,
                                   ModbusPDU.BuildWriteMultipleRegisters(first, values),
                                   CancellationToken
                               );
            }

            if (ModbusPDU.TryGetException(answer) is ModbusExceptionCode code)
            {

                data.Add("exceptionCode", code.ToString());

                meter.Log.Metrological(
                    LogLevel.Warning,
                    $"{cli.Caller.Asker} wrote {said} to {range.ToLowerFirstChar()}{where}, which was answered with {code}.",
                    data,
                    cli.Caller.Tags("meter", "modbus", "write")
                );

                return [ $"{range}{where} was answered with {code}: nothing was written." ];

            }

            meter.Log.Metrological(
                LogLevel.Notice,
                $"{cli.Caller.Asker} wrote {said} to {range.ToLowerFirstChar()}{where}.",
                data,
                cli.Caller.Tags("meter", "modbus", "write")
            );

            return [ $"{range}{where} written: {said}." ];

        }

        #endregion

        #region (internal static) TryParseValue(Text, out Value)

        /// <summary>
        /// What a register is to hold: unsigned, hexadecimal behind "0x", or
        /// a negative number as the sixteen bits of its two's complement.
        /// </summary>
        internal static Boolean TryParseValue(String      Text,
                                              out UInt16  Value)
        {

            if (ReadRegistersCommand.TryParseRegister(Text, out Value))
                return true;

            if (Int16.TryParse(Text, NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var signed) && signed < 0)
            {
                Value = unchecked((UInt16) signed);
                return true;
            }

            return false;

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} <address> <value> [<value> ...] - write holding registers as a Modbus client would, e.g. '{CommandName} 40094 1'; into the log book";

        #endregion

    }

}
