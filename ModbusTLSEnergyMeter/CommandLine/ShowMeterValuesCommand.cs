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

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    /// <summary>
    /// What this meter is measuring now: who it is, the three phases and their
    /// total, the frequency and the two energy counters.
    /// </summary>
    /// <remarks>
    /// What the web interface shows on its first page and GET /api/v1/meter
    /// answers, for whoever is at the command line - and needing what those
    /// need, "meter:read".
    /// </remarks>
    /// <param name="CLI">The command line of the meter.</param>
    public class ShowMeterValuesCommand(MeterCLI CLI) : ACLICommand<MeterCLI>(CLI),
                                                        ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(ShowMeterValuesCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override async Task<String[]> Execute(String[]           Arguments,
                                                     CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(MeterAccess.Meter), CommandName, out var refused))
                return [ refused ];

            var meter = cli.Meter;

            JObject values;

            try
            {
                values = await meter.ReadMeterValues();
            }
            catch (Exception e) when (e is EnergyUnreadable or ModbusException)
            {
                return [
                    meter.Upstream is { } unreadable
                        ? $"The meter at {unreadable.Server} could not be read: {(e is ModbusException modbus ? $"{modbus.Code}." : e.Message)}"
                        : e.Message
                ];
            }

            var lines = new List<String> {
                            $"{Said(values, "manufacturer")} {Said(values, "model")}, serial number {Said(values, "serialNumber")}" +
                            (values["meterMode"]?["description"]?.Value<String>() is String mode ? $" - {mode}" : "")
                        };

            if (meter.Upstream is { } upstream)
                lines.Add($"Measured by the meter at {upstream.Server}, in front of which this one stands.");

            lines.Add("");

            foreach (var phase in (values["phases"] as JArray ?? []).OfType<JObject>().Append(values["total"] as JObject).OfType<JObject>())
                lines.Add($"{Said(phase, "name"),-5}  {Number(phase["voltage_V"]),9} V  {Number(phase["current_A"]),9} A  {Number(phase["power_W"]),10} W");

            lines.Add("");
            lines.Add($"Frequency  {Number(values["frequency_Hz"])} Hz");
            lines.Add($"Imported   {Number(values["energy"]?["imported_Wh"])} Wh");
            lines.Add($"Exported   {Number(values["energy"]?["exported_Wh"])} Wh");

            return [ .. lines ];

        }

        #endregion

        #region (private static) Said(Values, Name) / Number(Value)

        /// <summary>
        /// A text among the values, or a dash for one the meter did not say.
        /// </summary>
        private static String Said(JObject  Values,
                                   String   Name)

            => Values[Name]?.Value<String>() is String text && text.Length > 0
                   ? text
                   : "-";

        /// <summary>
        /// A number as somebody reads it, whatever the machine's language: a
        /// point for the decimals, and as many of them as the meter said -
        /// 230.9, and not the 230.900000000000005684 a binary fraction turns
        /// into when it is asked for all it has. A dash for one the meter
        /// did not say.
        /// </summary>
        private static String Number(JToken? Value)

            => Value?.Type switch {
                   JTokenType.Integer  => Value.Value<Int64>(). ToString(CultureInfo.InvariantCulture),
                   JTokenType.Float    => Value.Value<Double>().ToString(CultureInfo.InvariantCulture),
                   null or
                   JTokenType.Null or
                   JTokenType.Undefined => "-",
                   _                   => Value.ToString()
               };

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - what this meter is measuring now: the phases and their total, the frequency and the energy counters";

        #endregion

    }

}
