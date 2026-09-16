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

using cloud.charging.open.EnergyMeters.ModbusTLS.Logging;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// What was asked of this meter over Modbus/TLS, and what it answered.
    /// </summary>
    /// <remarks>
    /// Every request is written down, whether the policy allowed it or refused
    /// it. A log that records only what was permitted cannot answer the
    /// question it is usually opened for - who was turned away, how often, and
    /// with which certificate - and a refusal that leaves no trace is
    /// indistinguishable, afterwards, from a request nobody made.
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region (private) RecordModbusRequest(Info)

        /// <summary>
        /// One Modbus request, as an entry somebody can read and a browser can
        /// filter.
        /// </summary>
        /// <remarks>
        /// A refusal is a warning and an ordinary read is info, so that the
        /// default view of the log is not drowned by a client polling once a
        /// second - the refusals stand out of it without anybody filtering.
        ///
        /// A Modbus exception the device itself returned (an address outside
        /// the map, say) is a warning too: the policy allowed the request, but
        /// the peer still did not get what it asked for, and that is worth
        /// seeing without going looking.
        /// </remarks>
        private void RecordModbusRequest(ModbusRequestInfo Info)
        {

            var level    = !Info.Allowed   ? LogLevel.Warning
                               : Info.IsException ? LogLevel.Warning
                                                  : LogLevel.Info;

            var role     = Info.Role ?? "(none)";

            var message  = Info.Allowed

                               ? $"{role} {Describe(Info)} -> {(Info.IsException ? Info.ExceptionCode.ToString() : "ok")}"

                               : $"{role} {Describe(Info)} -> refused: {Info.DenyReason}";

            Log.Log(

                level,
                message,

                new JObject(

                    new JProperty("connectionId",   Info.ConnectionId),
                    new JProperty("peer",           Info.Peer),
                    new JProperty("role",           Info.Role),
                    new JProperty("unitId",         Info.UnitId),
                    new JProperty("transactionId",  Info.TransactionId),

                    new JProperty("functionCode",   Info.FunctionCodeLabel),
                    new JProperty("function",       Info.FunctionCode.ToString()),
                    new JProperty("address",        Info.Address),
                    new JProperty("quantity",       Info.Quantity),

                    new JProperty("allowed",        Info.Allowed),
                    new JProperty("denyReason",     Info.DenyReason),
                    new JProperty("exceptionCode",  Info.ExceptionCode?.ToString()),
                    new JProperty("responseBytes",  Info.ResponseLength),
                    new JProperty("duration_ms",    Info.Duration.TotalMilliseconds)

                ),

                // "denied" as a tag of its own, because "show me everything that
                // was refused" is the one query this log exists for.
                Info.Allowed
                    ? [ "modbus", "request" ]
                    : [ "modbus", "request", "denied" ]

            );

        }

        #endregion

        #region (private static) Describe(Info)

        /// <summary>
        /// The request in the words a Modbus person uses: what, where, how much.
        /// </summary>
        private static String Describe(ModbusRequestInfo Info)

            => Info.Quantity == 0

                   // A PDU that could not be parsed has no address range to
                   // name, and inventing 0..0 for it would read like a request
                   // that was actually made.
                   ? $"{Info.FunctionCodeLabel} (malformed)"

                   : Info.Quantity == 1
                         ? $"{Info.FunctionCodeLabel} @{Info.Address}"
                         : $"{Info.FunctionCodeLabel} @{Info.Address}+{Info.Quantity}";

        #endregion

    }

}
