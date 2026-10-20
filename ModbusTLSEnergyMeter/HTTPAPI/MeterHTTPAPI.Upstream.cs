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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;

using cloud.charging.open.EnergyMeters.ModbusTLS.Upstream;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The meter in front of which this one stands: GET and PUT
    /// /api/v1/configuration/upstream.
    /// </summary>
    /// <remarks>
    /// Read by whoever may read the meter, and changed by whoever may change
    /// it: what it measures with is what it is, more than its mode is.
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region (private) RegisterUpstreamTemplates()

        private void RegisterUpstreamTemplates()
        {
            AddHandler(HTTPPath.Root + "v1/configuration/upstream",  GetUpstream,  HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/upstream",  PutUpstream,  HTTPMethod.PUT);
        }

        #endregion


        #region (private) GetUpstream(Request)

        /// <summary>
        /// GET /api/v1/configuration/upstream: the meter in front of which this
        /// one stands, as the file says it and as it goes.
        /// </summary>
        private Task<HTTPResponse> GetUpstream(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Meter), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.UpstreamJSON()));

        }

        #endregion

        #region (private) PutUpstream(Request)

        /// <summary>
        /// PUT /api/v1/configuration/upstream: stand in front of another meter,
        /// or - with a blank host - in front of none.
        /// </summary>
        private async Task<HTTPResponse> PutUpstream(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(MeterAccess.Meter), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var (success, error, notSaved) = await meter.UpdateUpstream(json);

            if (!success)
                return ErrorJSON(Request, notSaved ? HTTPStatusCode.InternalServerError : HTTPStatusCode.BadRequest, error!);

            meter.Log.Notice(meter.Upstream is UpstreamConfiguration upstream
                                 ? $"'{user.Id}' set the meter in front of which this one stands: {upstream}."
                                 : $"'{user.Id}' set this meter to stand in front of no meter, and measure with its own simulation.",
                             "upstream", "web");

            return JSONResponse(Request, HTTPStatusCode.OK, meter.UpstreamJSON());

        }

        #endregion

    }

}
