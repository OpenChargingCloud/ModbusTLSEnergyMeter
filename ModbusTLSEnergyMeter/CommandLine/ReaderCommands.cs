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

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.CLI;
using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Logins;
using cloud.charging.open.protocols.WWCP.Node.CommandLine;

using ConnectionType = cloud.charging.open.protocols.WWCP.Node.Connections.ConnectionType;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine
{

    #region ReadersCommand

    /// <summary>
    /// What reads this meter over a WebSocket or SSH, as it is written down:
    /// the server it connects to, and every reader with its connection, what
    /// it signs in with, the SunSpec role of its group and whether it is
    /// connected.
    /// </summary>
    /// <remarks>
    /// Not who is connected over Modbus/TLS - that is showConnections -, but
    /// who may connect without it.
    /// </remarks>
    /// <param name="CLI">The command line of the meter.</param>
    public class ReadersCommand(MeterCLI CLI) : ACLICommand<MeterCLI>(CLI),
                                                ICLICommand
    {

        #region Data

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "readers";

        #endregion

        #region Suggest(Arguments)

        public override IEnumerable<SuggestionResponse> Suggest(String[] Arguments)

            => Arguments.Length == 1 && CommandName.StartsWith(Arguments[0], StringComparison.OrdinalIgnoreCase)
                   ? [ SuggestionResponse.CommandCompleted(CommandName) ]
                   : [];

        #endregion

        #region Execute(Arguments, CancellationToken)

        public override Task<String[]> Execute(String[]           Arguments,
                                               CancellationToken  CancellationToken)
        {

            if (!cli.MayDo(Permission.Read(MeterAccess.MeterReaders), CommandName, out var refused))
                return Task.FromResult<String[]>([ refused ]);

            var meter      = cli.Meter;
            var settings   = meter.MeterReaderSettings;
            var connected  = meter.MeterReadersIn.ToHashSet(StringComparer.Ordinal);
            var lines      = new List<String>();

            #region The server

            lines.Add(settings.IsEnabled
                          ? meter.MeterReaderServerRunning
                                ? $"The WebSocket server of Modbus listens at port {settings.TCPPort?.ToUInt16()}{(meter.MeterReaderServerTLS ? ", with TLS" : ", without TLS")}."
                                : $"The WebSocket server of Modbus is switched on at port {settings.TCPPort?.ToUInt16()}, and does not listen."
                          : "The WebSocket server of Modbus is switched off.");

            lines.Add(meter.ModbusOverSSHServed
                          ? $"Modbus is served over SSH, at port {meter.SSHPort?.ToUInt16()}."
                          : "Modbus is not served over SSH.");

            #endregion

            #region Every reader

            var entries = meter.Connections.Connections.
                              Where  (entry => entry.Inbound && entry.ConnectionType == ConnectionType.MeterReader).
                              OrderBy(entry => entry.InboundName, StringComparer.Ordinal).
                              ToArray();

            var named   = entries.Select(entry => entry.InboundName).OfType<String>().ToHashSet(StringComparer.Ordinal);

            if (entries.Length == 0)
                lines.Add("No meter reader is written down: none may connect.");

            foreach (var entry in entries)
            {

                var name = entry.InboundName ?? "?";

                lines.Add($"{name}  {(entry.AutoConnect ? "on" : "off")}  {(connected.Contains(name) ? "connected" : "not connected")}  " +
                          $"{entry.URL}  {entry.Description.FirstText()}");

                if (User_Id.TryParse(name) is User_Id login && meter.WebSocketLogins.TryGet(login, out var signsIn))
                    lines.Add($"  signs in with {String.Join(", ", WaysIn(signsIn))}, in the group '{signsIn.GroupId}'" +
                              $"{(signsIn.Enabled ? "" : ", switched off")} - " +
                              (meter.SunSpecRoleOf(login) is String role ? $"reads as {role}" : "no SunSpec role: every request is refused"));
                else
                    lines.Add("  has no login: it cannot sign in.");

            }

            // A login without a connection signs in and is let go of.
            foreach (var login in meter.WebSocketLogins.Logins.Where(login => !named.Contains(login.Login.ToString())).OrderBy(login => login.Login))
                lines.Add($"{login.Login}  has a login and no connection: it is let go of when it connects.");

            #endregion

            return Task.FromResult<String[]>([ .. lines ]);

        }

        #endregion

        #region Help()

        public override String Help()

            => $"{CommandName} - what reads this meter over a WebSocket or SSH: the server, every reader, what it signs in with, its SunSpec role and whether it is connected";

        #endregion


        #region (private static) WaysIn(Login)

        private static IEnumerable<String> WaysIn(WebSocketLogin Login)
        {

            var ways = new List<String>();

            if (Login.HasPassword)
                ways.Add("a password");

            if (Login.HasTOTP)
                ways.Add("TOTP");

            if (Login.HasSSHKey)
                ways.Add($"{Login.Keys.Count} SSH key(s)");

            if (Login.HasKeyPin)
                ways.Add($"{Login.Pins.Count} key pin(s)");

            return ways.Count > 0 ? ways : [ "nothing yet" ];

        }

        #endregion

    }

    #endregion

    #region ReaderKeysCommand

    /// <summary>
    /// The SSH keys what reads this meter signs in to Modbus over SSH with.
    /// </summary>
    /// <param name="CLI">The command line of the meter.</param>
    public class ReaderKeysCommand(MeterCLI CLI) : LoginKeysCommand(CLI, CommandName, MeterAccess.MeterReaders)
    {

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "readerKeys";

        private ModbusTLSEnergyMeter Meter
            => ((MeterCLI) cli).Meter;

        protected override WebSocketLogins        Logins      => Meter.WebSocketLogins;
        protected override String                 LoginNoun   => "meter reader";
        protected override String                 LoginWord   => "login";
        protected override String                 KeysAreFor  => "for Modbus over SSH";
        protected override IReadOnlyList<String>  LogTags     => [ "modbus", "reader" ];

        /// <summary>
        /// Refused for a name that is an account of this meter as well.
        /// </summary>
        protected override Boolean TryAddKey(User_Id                               Login,
                                             String                                Line,
                                             String                                CreatedBy,
                                             [NotNullWhen(true)]  out UserSSHKey?  Key,
                                             [NotNullWhen(false)] out String?      Error)

            => Meter.TryAddMeterReaderSSHKey(Login, Line, null, null, null, CreatedBy, out Key, out Error, out _);

        protected override IEnumerable<String> WhyNoLoginSignsIn()
        {
            if (!Meter.ModbusOverSSHServed)
                yield return "Modbus is not served over SSH: no meter reader signs in over SSH.";
        }

    }

    #endregion

    #region ReaderPinsCommand

    /// <summary>
    /// The key pins what reads this meter is let in with on the WebSocket port of Modbus.
    /// </summary>
    /// <param name="CLI">The command line of the meter.</param>
    public class ReaderPinsCommand(MeterCLI CLI) : LoginPinsCommand(CLI, CommandName, MeterAccess.MeterReaders)
    {

        /// <summary>
        /// The name this is typed as.
        /// </summary>
        public const String CommandName = "readerPins";

        private ModbusTLSEnergyMeter Meter
            => ((MeterCLI) cli).Meter;

        protected override WebSocketLogins        Logins      => Meter.WebSocketLogins;
        protected override String                 LoginNoun   => "meter reader";
        protected override String                 LoginWord   => "login";
        protected override String                 PinsAreFor  => "on the WebSocket port of Modbus";
        protected override IReadOnlyList<String>  LogTags     => [ "modbus", "reader" ];

        protected override IEnumerable<String> WhyNoLoginSignsIn()
        {

            if (!Meter.MeterReaderSettings.IsEnabled)
                yield return "The WebSocket server of Modbus is switched off: no meter reader signs in.";

            else if (Meter.MeterReaderServerRunning && !Meter.MeterReaderServerTLS)
                yield return "The WebSocket port of Modbus is not encrypted: no key pin lets a meter reader in until it is.";

        }

    }

    #endregion

}
