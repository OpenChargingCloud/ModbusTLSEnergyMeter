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

using Newtonsoft.Json.Linq;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Upstream
{

    /// <summary>
    /// What the meter in front of which this one stands measures, in the shape
    /// the meter page reads its own simulation's readings in.
    /// </summary>
    /// <remarks>
    /// Its common model for who it is, and its first meter model by its layout:
    /// integers with scale factors for 201 to 204, floats for 211 to 214,
    /// Hermod's 24 registers under 213. What it does not measure - 0x8000, a
    /// scale factor that is none, not a number - is null.
    /// </remarks>
    public static class UpstreamReadings
    {

        #region (static) Read(Read)

        /// <summary>
        /// Read it, once.
        /// </summary>
        /// <exception cref="EnergyUnreadable">When it is no SunSpec meter this meter can read, with why.</exception>
        public static async Task<JObject> Read(ReadRegisters Read)
        {

            var chain  = await SunSpecChain.Walk(Read);

            var common = chain.Models.FirstOrDefault(model => model.Id == 1);
            var meter  = chain.Models.FirstOrDefault(model => model.Id is >= 201 and <= 204 or >= 211 and <= 214);

            if (meter.Id == 0)
                throw new EnergyUnreadable($"None of the models of the meter is a meter: {String.Join(", ", chain.Models.Select(model => model.Id))}.");

            UInt16[] who = common.Id == 1 && common.Length >= 64
                             ? await SunSpecChain.ReadBlock(Read, common.Address, common.Length + 2)
                             : [];

            var block  = await SunSpecChain.ReadBlock(Read, (UInt16) (meter.Address + 2), meter.Length);

            var json   = new JObject(
                             new JProperty("manufacturer",  Text(who,  2, 16)),
                             new JProperty("model",         Text(who, 18, 16)),
                             new JProperty("options",       Text(who, 34,  8)),
                             new JProperty("version",       Text(who, 42,  8)),
                             new JProperty("serialNumber",  Text(who, 50, 16)),
                             new JProperty("unitAddress",   who.Length > 66 ? who[66] : null),
                             new JProperty("sunSpecModel",  meter.Id)
                         );

            if (meter.Id == 213 && meter.Length == 24)
                Integers(json, block, current: 0, currentSF: 4, voltage: 5, voltageSF: 9, frequency: 10, frequencySF: 11,
                                      power: 12, powerSF: 16, exported: 17, imported: 19, energySF: 21);

            else if (meter.Id is >= 201 and <= 204 && meter.Length > 52)
                Integers(json, block, current: 0, currentSF: 4, voltage: 5, voltageSF: 13, frequency: 14, frequencySF: 15,
                                      power: 16, powerSF: 20, exported: 36, imported: 44, energySF: 52);

            else if (meter.Id is >= 211 and <= 214 && meter.Length > 67)
                Floats(json, block);

            else
                throw new EnergyUnreadable($"Its meter model is {meter.Id} with {meter.Length} registers, which is no layout of model {meter.Id} this meter can read.");

            return json;

        }

        #endregion


        #region (private static) Integers(...) / Floats(...)

        private static void Integers(JObject   JSON,
                                     UInt16[]  Block,
                                     Int32     current,
                                     Int32     currentSF,
                                     Int32     voltage,
                                     Int32     voltageSF,
                                     Int32     frequency,
                                     Int32     frequencySF,
                                     Int32     power,
                                     Int32     powerSF,
                                     Int32     exported,
                                     Int32     imported,
                                     Int32     energySF)
        {

            Double? At(Int32 Offset, Int32 ScaleFactorAt)
            {

                var value = Block[Offset];
                var sf    = (Int16) Block[ScaleFactorAt];

                if (value == 0x8000 || sf == Int16.MinValue)
                    return null;

                return Math.Round((Int16) value * Math.Pow(10, sf), Math.Max(0, -sf));

            }

            Double? Counter(Int32 Offset)
            {

                var sf = (Int16) Block[energySF];

                if (sf == Int16.MinValue)
                    return null;

                var raw = ((UInt32) Block[Offset] << 16) | Block[Offset + 1];

                return Math.Round(raw * Math.Pow(10, sf), Math.Max(0, -sf));

            }

            JSON["frequency_Hz"] = At(frequency, frequencySF);

            JSON["phases"] = new JArray(
                                 Phase("L1", At(voltage + 1, voltageSF), At(current + 1, currentSF), At(power + 1, powerSF)),
                                 Phase("L2", At(voltage + 2, voltageSF), At(current + 2, currentSF), At(power + 2, powerSF)),
                                 Phase("L3", At(voltage + 3, voltageSF), At(current + 3, currentSF), At(power + 3, powerSF))
                             );

            JSON["total"]  = Phase("total", At(voltage, voltageSF), At(current, currentSF), At(power, powerSF));

            JSON["energy"] = new JObject(
                                 new JProperty("exported_Wh",  Counter(exported)),
                                 new JProperty("imported_Wh",  Counter(imported))
                             );

        }

        private static void Floats(JObject   JSON,
                                   UInt16[]  Block)
        {

            Double? At(Int32 Offset)
            {
                var value = BitConverter.UInt32BitsToSingle(((UInt32) Block[Offset] << 16) | Block[Offset + 1]);
                return Single.IsFinite(value) ? Math.Round((Double) value, 3) : null;
            }

            JSON["frequency_Hz"] = At(24);

            JSON["phases"] = new JArray(
                                 Phase("L1", At(10), At(2), At(28)),
                                 Phase("L2", At(12), At(4), At(30)),
                                 Phase("L3", At(14), At(6), At(32))
                             );

            JSON["total"]  = Phase("total", At(8), At(0), At(26));

            JSON["energy"] = new JObject(
                                 new JProperty("exported_Wh",  At(58)),
                                 new JProperty("imported_Wh",  At(66))
                             );

        }

        private static JObject Phase(String Name, Double? Voltage, Double? Current, Double? Power)

            => new (
                   new JProperty("name",       Name),
                   new JProperty("voltage_V",  Voltage),
                   new JProperty("current_A",  Current),
                   new JProperty("power_W",    Power)
               );

        #endregion

        #region (private static) Text(Registers, Offset, Length)

        private static String? Text(UInt16[]  Registers,
                                    Int32     Offset,
                                    Int32     Length)
        {

            if (Registers.Length < Offset + Length)
                return null;

            var text = new StringBuilder(Length * 2);

            for (var i = 0; i < Length; i++)
                foreach (var character in new[] { (Char) (Registers[Offset + i] >> 8), (Char) (Registers[Offset + i] & 0xFF) })
                    if (character is >= ' ' and <= '~')
                        text.Append(character);

            return text.ToString().Trim();

        }

        #endregion

    }

}
