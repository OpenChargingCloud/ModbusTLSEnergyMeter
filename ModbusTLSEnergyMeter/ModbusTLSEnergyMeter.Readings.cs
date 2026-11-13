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

using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI;
using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;
using cloud.charging.open.EnergyMeters.ModbusTLS.Upstream;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// What this meter is measuring now, as numbers rather than as registers.
    /// </summary>
    public partial class ModbusTLSEnergyMeter
    {

        #region ReadMeterValues()

        /// <summary>
        /// What this meter is measuring now - who it is, the phases, their
        /// total, the frequency and the two energy counters - as GET
        /// /api/v1/meter says it: read from its simulation, or from the meter
        /// in front of which it stands.
        /// </summary>
        /// <exception cref="EnergyUnreadable">When the meter in front of which this one stands could not be read, with why.</exception>
        /// <exception cref="ModbusException">What that meter answered instead.</exception>
        public async Task<JObject> ReadMeterValues()
        {

            if (backends.Upstream is not null)
                return await UpstreamReadings.Read(backends.Read);

            return MeterHTTPAPI.ReadingsJSON(
                       device.ReadHolding(
                           SunSpecMeterMap.BaseAddress,
                           SunSpecMeterMap.RegisterCount
                       )
                       ?? throw new EnergyUnreadable("The register block of this meter could not be read.")
                   );

        }

        #endregion

    }

}
