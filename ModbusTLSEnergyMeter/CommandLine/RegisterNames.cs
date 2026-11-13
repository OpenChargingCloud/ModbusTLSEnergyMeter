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
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    /// <summary>
    /// The registers of this meter's own simulation by the names SunSpec
    /// gives their points - "TotWhImp" rather than 40091 - for whoever types
    /// at the command line.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The names of the simulation's map and of nothing else. A meter in
    /// front of which this one stands has a map of its own - other models,
    /// at other addresses - and a name resolved against the simulation's
    /// would read, or write, a register that is something else there. So a
    /// name is taken only while this meter measures with its simulation, and
    /// is refused in a sentence otherwise; an address is taken always.
    /// </para>
    /// <para>
    /// A name brings how many registers the point has: the serial number is
    /// sixteen, an energy counter two. A count that was typed wins.
    /// </para>
    /// </remarks>
    public static class RegisterNames
    {

        #region Data

        /// <summary>
        /// The points of the simulation's map: the common model, the meter
        /// model, and the two registers that command the simulation.
        /// </summary>
        public static readonly IReadOnlyList<(String Name, UInt16 Address, UInt16 Count, String Is)>  All  = [

            ("Mn",           SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonMn),          16, "the manufacturer"),
            ("Md",           SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonMd),          16, "the model"),
            ("Opt",          SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonOpt),          8, "the options"),
            ("Vr",           SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonVr),           8, "the version"),
            ("SN",           SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonSN),          16, "the serial number"),
            ("DA",           SunSpecMeterMap.Addr(SunSpecMeterMap.OffCommonDA),           1, "the unit address"),

            ("A",            SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterA),             1, "the total current"),
            ("AphA",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterAphA),          1, "the current of L1"),
            ("AphB",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterAphB),          1, "the current of L2"),
            ("AphC",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterAphC),          1, "the current of L3"),
            ("A_SF",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterA_SF),          1, "the scale factor of the currents"),

            ("PhV",          SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterPhV),           1, "the average voltage"),
            ("PhVphA",       SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterPhVphA),        1, "the voltage of L1"),
            ("PhVphB",       SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterPhVphB),        1, "the voltage of L2"),
            ("PhVphC",       SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterPhVphC),        1, "the voltage of L3"),
            ("V_SF",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterV_SF),          1, "the scale factor of the voltages"),

            ("Hz",           SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterHz),            1, "the frequency"),
            ("Hz_SF",        SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterHz_SF),         1, "the scale factor of the frequency"),

            ("W",            SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterW),             1, "the total power"),
            ("WphA",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterWphA),          1, "the power of L1"),
            ("WphB",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterWphB),          1, "the power of L2"),
            ("WphC",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterWphC),          1, "the power of L3"),
            ("W_SF",         SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterW_SF),          1, "the scale factor of the powers"),

            ("TotWhExp",     SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterTotWhExp),      2, "the exported energy"),
            ("TotWhImp",     SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterTotWhImp),      2, "the imported energy"),
            ("Wh_SF",        SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterWh_SF),         1, "the scale factor of the energies"),

            ("MeterMode",    SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterMeterMode),     1, "the meter mode: 0 net, 1 import only, 2 export only"),
            ("ResetEnergy",  SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterResetEnergy),   1, "clears both energy counters when 0xCAFE is written to it")

        ];

        #endregion


        #region TryResolve(Meter, Text, out Address, out Count, out Error)

        /// <summary>
        /// A register as it was typed: an address - decimal, or hexadecimal
        /// behind "0x" - or the name of a point of the simulation's map, in
        /// any case.
        /// </summary>
        /// <param name="Meter">The meter the register is one of.</param>
        /// <param name="Text">What was typed.</param>
        /// <param name="Address">The address.</param>
        /// <param name="Count">How many registers the point has; 1 for an address.</param>
        /// <param name="Error">Why it is neither.</param>
        public static Boolean TryResolve(ModbusTLSEnergyMeter  Meter,
                                         String                Text,
                                         out UInt16            Address,
                                         out UInt16            Count,
                                         out String?           Error)
        {

            Count  = 1;
            Error  = null;

            if (TryParseAddress(Text, out Address))
                return true;

            foreach (var point in All)
            {

                if (!point.Name.Equals(Text, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (Meter.Upstream is { } upstream)
                {
                    Error = $"'{point.Name}' is a name of this meter's own simulation, and this meter stands in front of the meter at {upstream.Server}, " +
                             "whose registers are where its models put them: say an address.";
                    return false;
                }

                Address  = point.Address;
                Count    = point.Count;
                return true;

            }

            Error = $"'{Text}' is neither a register address - 0 to 65535, or 0x0000 to 0xFFFF - nor the name of one, as {All[^4].Name} or {All[^2].Name}.";
            return false;

        }

        #endregion

        #region TryParseAddress(Text, out Address)

        /// <summary>
        /// A register address, or the unsigned value of one: decimal, or
        /// hexadecimal behind "0x".
        /// </summary>
        public static Boolean TryParseAddress(String      Text,
                                              out UInt16  Address)

            => Text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
                   ? UInt16.TryParse(Text.AsSpan(2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out Address)
                   : UInt16.TryParse(Text,           NumberStyles.None,              CultureInfo.InvariantCulture, out Address);

        #endregion

        #region Suggest(Meter, CommandName, Help, Arguments)

        /// <summary>
        /// What Tab offers for a command whose first argument is a register:
        /// the command itself, then the names that begin with what was typed
        /// - while the meter measures with its simulation, where they mean
        /// something.
        /// </summary>
        /// <param name="Meter">The meter.</param>
        /// <param name="CommandName">The name the command is typed as.</param>
        /// <param name="Help">What it says about itself.</param>
        /// <param name="Arguments">What was typed so far.</param>
        public static IEnumerable<SuggestionResponse> Suggest(ModbusTLSEnergyMeter  Meter,
                                                              String                CommandName,
                                                              String                Help,
                                                              String[]              Arguments)
        {

            if (Arguments.Length == 1)
                return CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase)
                           ? [ SuggestionResponse.CommandHelp(Help) ]
                           : CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                                 ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                                 : [];

            if (Arguments.Length != 2 ||
                !CommandName.Equals(Arguments[0], StringComparison.OrdinalIgnoreCase) ||
                Meter.Upstream is not null)
            {
                return [];
            }

            return [
                .. All.Where (point => point.Name.StartsWith(Arguments[1], StringComparison.OrdinalIgnoreCase)).
                       Select(point => point.Name.Equals(Arguments[1], StringComparison.OrdinalIgnoreCase)
                                           ? SuggestionResponse.ParameterCompleted($"{CommandName} {point.Name}")
                                           : SuggestionResponse.ParameterPrefix   ($"{CommandName} {point.Name}"))
            ];

        }

        #endregion

    }

}
