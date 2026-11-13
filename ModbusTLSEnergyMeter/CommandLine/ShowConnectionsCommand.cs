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

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    /// <summary>
    /// Who is connected to this meter over Modbus/TLS now: which connection,
    /// the SunSpec role in the certificate its client showed and whose
    /// certificate that is, from where, since when, and what it has asked
    /// so far.
    /// </summary>
    /// <remarks>
    /// <para>
    /// What 'who' is for SSH, for the door the meter is read through. A
    /// connection is listed from the moment its TLS handshake held, whether
    /// it has asked anything or not - what GET /api/v1/meter/connections
    /// answers and the Connections page shows.
    /// </para>
    /// <para>
    /// Needs what the log needs, "log:read": who asks this meter what, and
    /// from where, is what the log is, and is more than somebody who was given
    /// a look at the readings was given.
    /// </para>
    /// </remarks>
    /// <param name="CLI">The command line of the meter.</param>
    public class ShowConnectionsCommand(MeterCLI CLI) : ACLICommand<MeterCLI>(CLI),
                                                        ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public static readonly String CommandName = nameof(ShowConnectionsCommand)[..^7].ToLowerFirstChar();

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(MeterAccess.Log), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var connections = cli.Meter.ModbusConnections;

            if (connections.Count == 0)
                return Task.FromResult<String[]>([ "Nobody is connected to this meter over Modbus/TLS." ]);

            var ids   = connections.Max(connection => connection.Id.ToString().Length);
            var roles = connections.Max(connection => RoleOf(connection.Role).Length);

            return Task.FromResult<String[]>([
                       .. connections.Select(connection =>
                              $"#{connection.Id.ToString().PadRight(ids)}  {RoleOf(connection.Role).PadRight(roles)}  " +
                              $"from {connection.Peer ?? "somewhere"}, since {connection.Since.ToLocalTime():HH:mm:ss}, " +
                              (connection.Requests == 0
                                   ? "no request"
                                   : $"{connection.Requests} request{(connection.Requests == 1 ? "" : "s")}" +
                                     (connection.Refused > 0 ? $" ({connection.Refused} refused)" : "") +
                                     (connection.LastRequest is { } last ? $", the last at {last.ToLocalTime():HH:mm:ss}" : "")) +
                              $" - {connection.ClientSubject}, {connection.Protocol}")
                   ]);

        }

        #endregion

        #region (private static) RoleOf(Role)

        /// <summary>
        /// The SunSpec role as it is written, or what a certificate without
        /// one is: no role, which may do nothing.
        /// </summary>
        private static String RoleOf(String? Role)

            => Role ?? "(no role)";

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - who is connected over Modbus/TLS now: the connection, its SunSpec role, from where, since when, how much it asked, and whose certificate it showed";

        #endregion

    }

}
