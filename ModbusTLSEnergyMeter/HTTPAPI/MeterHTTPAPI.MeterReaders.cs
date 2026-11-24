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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.EnergyMeters.ModbusTLS.MeterReaders;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The part of the JSON API about what reads this meter over a WebSocket
    /// or SSH, without Modbus/TLS: its connections, its logins and what they
    /// sign in with, the groups that are its SunSpec roles, the chains a client
    /// certificate may lead to, and the server it connects to.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The routes of the connections and of the logins are every node's - see
    /// <see cref="NodeHTTPAPI.RegisterConnectionRoutes"/> and
    /// <see cref="NodeHTTPAPI.RegisterWebSocketLoginRoutes"/> in WWCP_Node -,
    /// so the meter's pages and a CSMS's are the same pages. All of them at
    /// the resource <see cref="MeterAccess.MeterReaders"/>: who may let a
    /// reader in, and put it into a group, decides who reads this meter.
    /// </para>
    /// <para>
    /// A reader is written down twice, as everybody who connects to a node
    /// is: as an inbound connection of the type "MeterReader" - which says
    /// that it may connect, and which is switched off to shut it out - and as
    /// a login, which says what it signs in with and, by its group, as which
    /// SunSpec role it reads.
    /// </para>
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region Data

        /// <summary>
        /// Where the routes of the WebSocket server of Modbus and its logins are.
        /// </summary>
        public static readonly HTTPPath ReaderServerPath = HTTPPath.Root + "v1/configuration/reader-server";

        #endregion


        #region (private) RegisterMeterReaderTemplates()

        private void RegisterMeterReaderTemplates()
        {

            RegisterConnectionRoutes(MeterAccess.MeterReaders);

            AddHandler(ReaderServerPath, GetReaderServer, HTTPMethod.GET);

            RegisterWebSocketLoginRoutes(
                new WebSocketLoginRoutes(
                    ReaderServerPath,
                    () => meter.WebSocketLogins,
                    () => meter.ClientTrust,
                    MeterAccess.MeterReaders,
                    "meter reader",
                    [ "modbus", "reader" ],
                    WhyGroupStays: groupId => SunSpecLoginGroups.RoleOf(groupId) is String role
                                                  ? $"The group '{groupId}' is the SunSpec role {role}, which a reader is put into to read this meter at all: it stays."
                                                  : null
                )
            );

        }

        #endregion

        #region (private) GetReaderServer(Request)

        /// <summary>
        /// GET /api/v1/configuration/reader-server: the server what reads this
        /// meter connects to - as the file says it, and as it is -, who is
        /// connected now, and the SunSpec role each login reads as.
        /// </summary>
        /// <remarks>
        /// The server is changed in the "webSocketServer" section of the file,
        /// and the meter started again.
        /// </remarks>
        private Task<HTTPResponse> GetReaderServer(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.MeterReaders), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, new JObject(
                           new JProperty("configuration",  meter.MeterReaderSettings.ToJSON()),
                           new JProperty("state",          new JObject(
                               new JProperty("running",    meter.MeterReaderServerRunning),
                               new JProperty("tls",        meter.MeterReaderServerTLS),
                               new JProperty("ssh",        meter.ModbusOverSSHServed),
                               new JProperty("sshPort",    meter.SSHPort?.ToUInt16())
                           )),
                           new JProperty("connected",      new JArray(meter.MeterReadersIn.Order(StringComparer.Ordinal))),
                           new JProperty("roles",          new JObject(
                               meter.WebSocketLogins.Logins.
                                     OrderBy(login => login.Login.ToString(), StringComparer.Ordinal).
                                     Select (login => new JProperty(login.Login.ToString(), meter.SunSpecRoleOf(login.Login)))
                           ))
                       ))
                   );

        }

        #endregion

    }

}
