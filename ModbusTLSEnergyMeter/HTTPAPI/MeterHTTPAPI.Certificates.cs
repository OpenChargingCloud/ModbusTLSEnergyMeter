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

using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The certificates this meter shows, and the CAs it accepts.
    /// </summary>
    /// <remarks>
    /// Two server stores and one trust store, kept apart because they answer
    /// different questions. "servers/modbus" is what a charging station checks
    /// and comes from a device PKI; "servers/web" is what a browser checks and
    /// comes from wherever the operator's web certificates come from; "clients"
    /// is which CAs a Modbus/TLS peer may chain to, which is who may talk to
    /// this meter at all.
    ///
    /// The private key of a server certificate is made in the meter and never
    /// leaves it. What goes out is a PKCS#10 request; what comes back is a
    /// certificate, which is checked against the key that asked for it before
    /// it is kept.
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region (private) RegisterCertificateTemplates()

        private void RegisterCertificateTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/certificates",                                  GetCertificateOverview, HTTPMethod.GET);

            AddHandler(HTTPPath.Root + "v1/certificates/servers/{purpose}",                GetServerStore,         HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/servers/{purpose}/requests",       PostCertificateRequest, HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/servers/{purpose}/{id}/request",   GetCertificateRequest,  HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/servers/{purpose}/{id}",           PutCertificate,         HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/certificates/servers/{purpose}/{id}",           DeleteCertificate,      HTTPMethod.DELETE);

            AddHandler(HTTPPath.Root + "v1/certificates/clients",                          GetTrustedChains,       HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/clients",                          PostTrustedChain,       HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/clients/{id}",                     PutTrustedChain,        HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/certificates/clients/{id}",                     DeleteTrustedChain,     HTTPMethod.DELETE);

        }

        #endregion


        #region (private) GetCertificateOverview(Request)

        /// <summary>
        /// GET /api/v1/certificates: both server stores and the trusted client
        /// chains, in one answer, so that a page can be drawn from one request.
        /// </summary>
        private Task<HTTPResponse> GetCertificateOverview(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               new JProperty("modbus",   meter.ModbusCertificates.ToJSON()),
                               new JProperty("web",      meter.WebCertificates.   ToJSON()),
                               new JProperty("clients",  meter.ClientTrust.       ToJSON()),
                               new JProperty("https",    meter.HTTPSEnabled),

                               // What a request may ask for, with what each one
                               // is called and what somebody choosing it should
                               // know. Said once here rather than repeated in a
                               // page that would then have to be changed
                               // alongside Hermod's list.
                               new JProperty("keyTypes", new JArray(KeyAlgorithm.All.Select(algorithm => algorithm.ToJSON())))
                           ))
                   );

        }

        #endregion

        #region (private) GetServerStore        (Request)

        /// <summary>
        /// GET /api/v1/certificates/servers/{modbus|web}
        /// </summary>
        private Task<HTTPResponse> GetServerStore(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryGetStore(Request, out var store, out var unknown))
                return Task.FromResult(unknown);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, store.ToJSON()));

        }

        #endregion

        #region (private) PostCertificateRequest(Request)

        /// <summary>
        /// POST /api/v1/certificates/servers/{purpose}/requests with
        /// {"subject": "CN=...", "dnsNames": [...], "ipAddresses": [...],
        ///  "keyType": "ec256"|"rsa3072", "note": "..."}
        /// </summary>
        /// <remarks>
        /// Makes a key and writes the request for it. The key stays here: what
        /// this answers with is the request, and the only thing that ever has
        /// to come back is a certificate.
        /// </remarks>
        private Task<HTTPResponse> PostCertificateRequest(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageCertificates, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetStore(Request, out var store, out var unknown))
                return Task.FromResult(unknown);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var subject = json["subject"]?.Value<String>()?.Trim();

            if (subject is null || subject.Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 "A 'subject' is required, e.g. \"CN=meter7.lan, O=Acme\"."));

            var keyType = json["keyType"]?.Value<String>()?.Trim().ToLowerInvariant() ?? "ec256";

            if (!CertificateStore.KeyTypes.Contains(keyType))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"'keyType' is one of: {String.Join(", ", CertificateStore.KeyTypes)}."));

            try
            {

                var entry = store.CreateRequest(
                                subject,
                                Strings(json["dnsNames"]),
                                Strings(json["ipAddresses"]),
                                keyType,
                                json["note"]?.Value<String>()
                            );

                meter.Log.Notice(
                    $"'{user.Id}' asked for a new {store.Purpose} certificate: {subject}.",
                    "certificates", store.Purpose, "web"
                );

                return Task.FromResult(
                           JSONResponse(Request, HTTPStatusCode.Created, entry.ToJSON(meter.TimeProvider.GetUtcNow()))
                       );

            }
            catch (Exception e)
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"That request could not be made: {e.Message}"));
            }

        }

        #endregion

        #region (private) GetCertificateRequest (Request)

        /// <summary>
        /// GET /api/v1/certificates/servers/{purpose}/{id}/request: the PKCS#10
        /// request, as a file to hand to a CA.
        /// </summary>
        private Task<HTTPResponse> GetCertificateRequest(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryGetStore(Request, out var store, out var unknown))
                return Task.FromResult(unknown);

            var id    = Request.ParsedURLParameters.Length > 1 ? Request.ParsedURLParameters[1] : "";
            var entry = store.Entries.FirstOrDefault(entry => entry.Id == id);

            if (entry?.RequestPEM is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound,
                                                 "There is no signing request with that id."));

            return Task.FromResult(
                       new HTTPResponse.Builder(Request) {
                           HTTPStatusCode      = HTTPStatusCode.OK,
                           ContentType         = HTTPContentType.Application.OCTETSTREAM,
                           Content             = Encoding.ASCII.GetBytes(entry.RequestPEM),
                           ContentDisposition  = $"attachment; filename=\"{store.Purpose}-{entry.Id}.csr\"",
                           CacheControl        = "no-store",
                           Connection          = ConnectionType.Close
                       }.AsImmutable
                   );

        }

        #endregion

        #region (private) PutCertificate        (Request)

        /// <summary>
        /// PUT /api/v1/certificates/servers/{purpose}/{id} with {"pem": "..."}:
        /// the signed certificate coming back.
        /// </summary>
        /// <remarks>
        /// Nothing takes effect here and nothing needs to: both listeners ask
        /// the store at every handshake, so a certificate that is valid now is
        /// shown to the next peer, and one that becomes valid in two days is
        /// shown from the second it does.
        /// </remarks>
        private Task<HTTPResponse> PutCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageCertificates, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetStore(Request, out var store, out var unknown))
                return Task.FromResult(unknown);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var id  = Request.ParsedURLParameters.Length > 1 ? Request.ParsedURLParameters[1] : "";
            var pem = json["pem"]?.Value<String>();

            if (pem is null || pem.Trim().Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 "A 'pem' with the signed certificate is required."));

            if (!store.TryImportCertificate(id, pem, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error ?? "That certificate was refused."));

            var entry = store.Entries.First(entry => entry.Id == id);
            var now   = meter.TimeProvider.GetUtcNow();

            meter.Log.Notice(
                $"'{user.Id}' put a {store.Purpose} certificate in: {entry.Certificate?.Subject}, " +
                (entry.IsValidAt(now)
                     ? $"valid until {entry.Certificate?.NotAfter:yyyy-MM-dd} and in use from now."
                     : $"which takes over on {entry.Certificate?.NotBefore:yyyy-MM-dd HH:mm}."),
                "certificates", store.Purpose, "web"
            );

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, store.ToJSON()));

        }

        #endregion

        #region (private) DeleteCertificate     (Request)

        /// <summary>
        /// DELETE /api/v1/certificates/servers/{purpose}/{id}
        /// </summary>
        private Task<HTTPResponse> DeleteCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageCertificates, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetStore(Request, out var store, out var unknown))
                return Task.FromResult(unknown);

            var id = Request.ParsedURLParameters.Length > 1 ? Request.ParsedURLParameters[1] : "";

            if (!store.TryRemove(id, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, error ?? "That entry could not be removed."));

            meter.Log.Notice($"'{user.Id}' threw away the {store.Purpose} certificate '{id}' and its key.",
                             "certificates", store.Purpose, "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, store.ToJSON()));

        }

        #endregion


        #region (private) GetTrustedChains      (Request)

        /// <summary>
        /// GET /api/v1/certificates/clients: which CAs a Modbus/TLS client
        /// certificate may chain to.
        /// </summary>
        private Task<HTTPResponse> GetTrustedChains(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.ClientTrust.ToJSON()));

        }

        #endregion

        #region (private) PostTrustedChain      (Request)

        /// <summary>
        /// POST /api/v1/certificates/clients with {"name": "...", "pem": "..."}
        /// </summary>
        private Task<HTTPResponse> PostTrustedChain(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageCertificates, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var pem = json["pem"]?.Value<String>();

            if (pem is null || pem.Trim().Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 "A 'pem' with the CA certificate, and any intermediates, is required."));

            if (!meter.ClientTrust.TryAdd(json["name"]?.Value<String>() ?? "", pem, out var chain, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error ?? "That chain was refused."));

            meter.Log.Notice($"'{user.Id}' added '{chain?.Name}' to the CAs this meter accepts Modbus/TLS clients from.",
                             "certificates", "trust", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, meter.ClientTrust.ToJSON()));

        }

        #endregion

        #region (private) PutTrustedChain       (Request)

        /// <summary>
        /// PUT /api/v1/certificates/clients/{id} with {"enabled": true|false}
        /// </summary>
        private Task<HTTPResponse> PutTrustedChain(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageCertificates, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var id      = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : "";
            var enabled = json["enabled"]?.Value<Boolean>();

            if (enabled is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "An 'enabled' is required."));

            if (!meter.ClientTrust.TrySetEnabled(id, enabled.Value, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, error ?? "That could not be changed."));

            meter.Log.Notice($"'{user.Id}' {(enabled.Value ? "re-enabled" : "switched off")} the trusted chain '{id}'.",
                             "certificates", "trust", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.ClientTrust.ToJSON()));

        }

        #endregion

        #region (private) DeleteTrustedChain    (Request)

        /// <summary>
        /// DELETE /api/v1/certificates/clients/{id}
        /// </summary>
        private Task<HTTPResponse> DeleteTrustedChain(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageCertificates, true, out var user, out var refused))
                return Task.FromResult(refused);

            var id = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : "";

            if (!meter.ClientTrust.TryRemove(id, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, error ?? "That chain could not be removed."));

            meter.Log.Notice($"'{user.Id}' removed the trusted chain '{id}'.", "certificates", "trust", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.ClientTrust.ToJSON()));

        }

        #endregion


        #region (private) TryGetStore(Request, out Store, out Unknown)

        /// <summary>
        /// Which of the two server stores a request names.
        /// </summary>
        private Boolean TryGetStore(HTTPRequest            Request,
                                    out CertificateStore   Store,
                                    out HTTPResponse       Unknown)
        {

            var purpose = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : null;
            var store   = meter.CertificateStoreFor(purpose);

            if (store is null)
            {
                Store   = null!;
                Unknown = ErrorJSON(Request, HTTPStatusCode.NotFound,
                                    "There are two certificate stores here: 'modbus' for what charging stations check, and 'web' for what a browser checks.");
                return false;
            }

            Store   = store;
            Unknown = null!;

            return true;

        }

        #endregion

        #region (private static) Strings(Token)

        private static IEnumerable<String> Strings(JToken? Token)

            => Token is JArray array
                   ? array.Values<String>().Where(value => value is not null).Cast<String>()
                   : [];

        #endregion

    }

}
