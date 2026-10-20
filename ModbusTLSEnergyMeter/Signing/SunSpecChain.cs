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

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Signing
{

    /// <summary>
    /// Reads registers of a device: the first, and how many.
    /// </summary>
    /// <exception cref="ModbusException">When the device answers with a Modbus exception.</exception>
    public delegate Task<UInt16[]> ReadRegisters(UInt16 First, UInt16 Count);


    /// <summary>
    /// Why the energy a session is signed with could not be read.
    /// </summary>
    public sealed class EnergyUnreadable(String Message) : Exception(Message);


    /// <summary>
    /// The models of a SunSpec device, as its list says: where it begins,
    /// which models it has where, and where the list ends.
    /// </summary>
    /// <remarks>
    /// What the session model is put behind, and what the energy a session is
    /// signed with is read from - of whatever device it is: this meter's own
    /// simulation, or a meter it stands in front of.
    /// </remarks>
    /// <param name="Base">Where "SunS" is.</param>
    /// <param name="Models">Its models: id, where the id is, and how many registers follow the length.</param>
    /// <param name="End">Where the id 0xFFFF that ends the list is.</param>
    public sealed record SunSpecChain(UInt16                                                Base,
                                      IReadOnlyList<(UInt16 Id, UInt16 Address, UInt16 Length)>  Models,
                                      UInt16                                                End)
    {

        #region Data

        /// <summary>
        /// Where a SunSpec device may begin, in the order they are tried.
        /// </summary>
        public static readonly IReadOnlyList<UInt16>  Bases        = [ 40000, 50000, 0 ];

        public const UInt16  MarkerHigh   = 0x5375;
        public const UInt16  MarkerLow    = 0x6E53;
        public const UInt16  EndOfModels  = 0xFFFF;
        public const Int32   MaxModels    = 64;
        public const UInt16  MaxRead      = 125;

        #endregion


        #region (static) Of(Backend, Unit)

        /// <summary>
        /// Reading the registers of a device behind a Modbus backend.
        /// </summary>
        public static ReadRegisters Of(IModbusBackend     Backend,
                                       Byte               Unit               = 1,
                                       CancellationToken  CancellationToken  = default)

            => async (first, count) => {

                   var answer = await Backend.ProcessRequestAsync(
                                          Unit,
                                          ModbusPDU.BuildReadHoldingRegisters(first, count),
                                          CancellationToken
                                      );

                   if (ModbusPDU.TryGetException(answer) is ModbusExceptionCode code)
                       throw new ModbusException(code);

                   return ModbusPDU.DecodeReadResponse(answer);

               };

        #endregion

        #region (static) Walk(Read)

        /// <summary>
        /// Find where a device begins and walk its list of models.
        /// </summary>
        /// <exception cref="EnergyUnreadable">When it is no SunSpec device, or its list does not end.</exception>
        public static async Task<SunSpecChain> Walk(ReadRegisters Read)
        {

            UInt16? found = null;

            foreach (var candidate in Bases)
            {

                try
                {

                    var marker = await Read(candidate, 2);

                    if (marker.Length >= 2 && marker[0] == MarkerHigh && marker[1] == MarkerLow)
                    {
                        found = candidate;
                        break;
                    }

                }
                catch (ModbusException)
                { }

            }

            if (found is not UInt16 @base)
                throw new EnergyUnreadable($"There is no \"SunS\" at {String.Join(", ", Bases)}, so the device behind this meter is no SunSpec device.");

            var models  = new List<(UInt16, UInt16, UInt16)>();
            var address = @base + 2;

            while (true)
            {

                if (address + 1 > UInt16.MaxValue)
                    throw new EnergyUnreadable("The list of models of the device behind this meter runs past the last register.");

                var header = await Read((UInt16) address, 2);

                if (header.Length < 2)
                    throw new EnergyUnreadable($"The device behind this meter answered {header.Length} register(s) for the header of a model at {address}.");

                if (header[0] == EndOfModels)
                    return new SunSpecChain(@base, models, (UInt16) address);

                if (models.Count >= MaxModels)
                    throw new EnergyUnreadable($"The list of models of the device behind this meter does not end after {MaxModels} of them.");

                models.Add((header[0], (UInt16) address, header[1]));

                address += 2 + header[1];

            }

        }

        #endregion

        #region ImportedWh(Read)

        /// <summary>
        /// What the imported energy counter of the first meter model stands at,
        /// in Wh.
        /// </summary>
        /// <remarks>
        /// <para>
        /// Integers with a scale factor for 201 to 204, a float for 211 to 214,
        /// and the 24 registers of Hermod's simulated meter under 213 - the
        /// layouts a charging station reads, and so the ones a document it is
        /// handed can be checked against.
        /// </para>
        /// <para>
        /// A counter the device says it does not have - 0x8000 for a scale
        /// factor, not a number for a float - is unreadable, and a session is
        /// not begun or ended on it: a signed reading of nothing is worse than
        /// no reading.
        /// </para>
        /// </remarks>
        /// <exception cref="EnergyUnreadable">With why.</exception>
        public async Task<Decimal> ImportedWh(ReadRegisters Read)
        {

            var meter = Models.FirstOrDefault(model => model.Id is >= 201 and <= 204 or >= 211 and <= 214);

            if (meter.Id == 0)
                throw new EnergyUnreadable($"None of the models of the device behind this meter is a meter: {String.Join(", ", Models.Select(model => model.Id))}.");

            var data = (UInt16) (meter.Address + 2);

            try
            {

                // Hermod's simulated meter: model 213 with 24 registers of
                // integers, the imported energy at 19 and its scale factor at 21.
                if (meter.Id == 213 && meter.Length == 24)
                {
                    var registers = await Read((UInt16) (data + 19), 3);
                    return Scaled(((UInt32) registers[0] << 16) | registers[1], (Int16) registers[2]);
                }

                // 201 to 204: TotWhImp, an acc32, at 44, and TotWh_SF at 52.
                if (meter.Id is >= 201 and <= 204 && meter.Length > 52)
                {
                    var registers = await Read((UInt16) (data + 44), 9);
                    return Scaled(((UInt32) registers[0] << 16) | registers[1], (Int16) registers[8]);
                }

                // 211 to 214: TotWhImp, a float32, at 66.
                if (meter.Id is >= 211 and <= 214 && meter.Length > 67)
                {

                    var registers = await Read((UInt16) (data + 66), 2);
                    var value     = BitConverter.UInt32BitsToSingle(((UInt32) registers[0] << 16) | registers[1]);

                    if (!Single.IsFinite(value) || value < 0)
                        throw new EnergyUnreadable($"The imported energy of model {meter.Id} is {value}, which is no counter.");

                    return (Decimal) value;

                }

            }
            catch (ModbusException e)
            {
                throw new EnergyUnreadable($"The device behind this meter answered {e.Code} when its imported energy was read.");
            }

            throw new EnergyUnreadable($"Its meter model is {meter.Id} with {meter.Length} registers, which is no layout of model {meter.Id} this meter can read.");

        }

        #endregion

        #region (private static) Scaled(Value, ScaleFactor)

        private static Decimal Scaled(UInt32  Value,
                                      Int16   ScaleFactor)
        {

            if (ScaleFactor == Int16.MinValue)
                throw new EnergyUnreadable("The scale factor of the imported energy is 0x8000: the device does not have one.");

            if (ScaleFactor is < -10 or > 10)
                throw new EnergyUnreadable($"The scale factor of the imported energy is {ScaleFactor}, which no counter has.");

            Decimal value = Value;

            for (var i = 0; i < Math.Abs((Int32) ScaleFactor); i++)
                value = ScaleFactor > 0 ? value * 10 : value / 10;

            return value;

        }

        #endregion

    }

}
