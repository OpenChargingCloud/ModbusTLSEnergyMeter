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

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Certificates;

using cloud.charging.open.EnergyMeters.ModbusTLS.Certificates;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The keys and certificate signing requests made in this meter, beside
    /// the node's certificate store.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The store itself is the node's, and so are its routes below
    /// /v1/certificates - see <see cref="NodeHTTPAPI"/>: the TLS identities the
    /// two listeners show, each told which listener it is for; the client roots
    /// Modbus/TLS clients are issued by; and the TLS roots and server
    /// certificates of the time and name servers it asks. What a meter's store
    /// says beyond every node's, and what it keeps from being taken away, the
    /// meter says itself - see its CompleteCertificatesJSON and WhatWouldLose.
    /// </para>
    /// <para>
    /// The private key of a certificate asked for here is made in the meter and
    /// never leaves it. What goes out is a PKCS#10 request; what comes back is a
    /// certificate, which is checked against the key that asked for it before
    /// it becomes an identity.
    /// </para>
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region (private) RegisterCertificateTemplates()

        /// <summary>
        /// The signing requests, below the node's store: "requests" is matched
        /// as a segment of its own before the store's "{id}" is.
        /// </summary>
        private void RegisterCertificateTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/certificates/requests",       GetSigningRequests,       HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/requests",       PostSigningRequest,       HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/requests/{id}",  GetSigningRequestFile,    HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/requests/{id}",  PutSigningRequestAnswer,  HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/certificates/requests/{id}",  DeleteSigningRequest,     HTTPMethod.DELETE);

        }

        #endregion


        #region (private) GetSigningRequests    (Request)

        /// <summary>
        /// GET /api/v1/certificates/requests: the keys made here and their signing
        /// requests, and the kinds of key a new one can be asked for with.
        /// </summary>
        private Task<HTTPResponse> GetSigningRequests(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, SigningRequestsJSON()));

        }

        #endregion

        #region (private) PostSigningRequest    (Request)

        /// <summary>
        /// POST /api/v1/certificates/requests with {"listener", "subject",
        /// "dnsNames", "ipAddresses", "keyType", "note"}: make a key and a
        /// signing request for it.
        /// </summary>
        private Task<HTTPResponse> PostSigningRequest(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var subject = json["subject"]?.Value<String>()?.Trim();

            if (String.IsNullOrEmpty(subject))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "A 'subject' is required, e.g. \"CN=meter7.lan, O=Acme\"."));

            if (!meter.SigningRequests.TryCreate(json["listener"]?.Value<String>()?.Trim().ToLowerInvariant() ?? "",
                                                 subject,
                                                 Strings(json["dnsNames"]),
                                                 Strings(json["ipAddresses"]),
                                                 json["keyType"]?.Value<String>(),
                                                 json["note"]?.   Value<String>(),
                                                 out var request,
                                                 out var error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            meter.Log.Notice($"'{user.Id}' asked for a new {request.Listener} certificate: {request.Subject}.", "certificates", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, request.ToJSON(meter.Certificates)));

        }

        #endregion

        #region (private) GetSigningRequestFile (Request)

        /// <summary>
        /// GET /api/v1/certificates/requests/{id}: the PKCS#10 request, as a file
        /// to hand to a CA.
        /// </summary>
        private Task<HTTPResponse> GetSigningRequestFile(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            var id       = HandleOf(Request);
            var request  = meter.SigningRequests.Get(id);
            var pem      = meter.SigningRequests.RequestPEM(id);

            if (request is null || pem is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no signing request with that id."));

            return Task.FromResult(
                       new HTTPResponse.Builder(Request) {
                           HTTPStatusCode      = HTTPStatusCode.OK,
                           ContentType         = HTTPContentType.Application.OCTETSTREAM,
                           Content             = Encoding.ASCII.GetBytes(pem),
                           ContentDisposition  = $"attachment; filename=\"{request.Listener}-{request.Id}.csr\"",
                           CacheControl        = "no-store",
                           Connection          = ConnectionType.Close
                       }.AsImmutable
                   );

        }

        #endregion

        #region (private) PutSigningRequestAnswer (Request)

        /// <summary>
        /// PUT /api/v1/certificates/requests/{id} with {"pem"}: the certificate a
        /// CA signed for a request, and the intermediates above it - which become
        /// an identity of the listener it was asked for.
        /// </summary>
        /// <remarks>
        /// A second answer for the same request is a renewal for the same key,
        /// and a second identity: the newer one takes over when it becomes valid.
        /// </remarks>
        private Task<HTTPResponse> PutSigningRequestAnswer(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var id = HandleOf(Request);

            if (meter.SigningRequests.Get(id) is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no signing request with that id."));

            if (json["pem"]?.Value<String>() is not String pem || pem.Trim().Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'pem' has to be the certificate, and the intermediates above it."));

            if (!meter.SigningRequests.TryAnswer(id, pem, meter.Certificates, out var entry, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            meter.Log.Notice($"'{user.Id}' put the certificate for the signing request {id} in: '{entry.Label}' ({entry.Id}).",
                             "certificates", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK,
                                                new JObject(
                                                    new JProperty("request",      meter.SigningRequests.Get(id)?.ToJSON(meter.Certificates)),
                                                    new JProperty("certificate",  EntryJSON(entry))
                                                )));

        }

        #endregion

        #region (private) DeleteSigningRequest  (Request)

        /// <summary>
        /// DELETE /api/v1/certificates/requests/{id}: throw a request away, and
        /// its key with it. What was put into the store from it stays there.
        /// </summary>
        private Task<HTTPResponse> DeleteSigningRequest(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            var id = HandleOf(Request);

            if (meter.SigningRequests.Get(id) is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no signing request with that id."));

            // 500 where the disk refused a removal that was right in itself,
            // as every node answers a change its file cannot take - it was
            // 409, as if something were wrong with asking.
            if (!meter.SigningRequests.TryRemove(id, out var error, out var notSaved, out var leftBehind))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.Conflict, error, notSaved));

            meter.Log.Notice($"'{user.Id}' threw the signing request {id} away, and its key with it.", "certificates", "web");

            if (leftBehind is not null)
                meter.Log.Warning($"The signing request {id} is gone, but its directory could not be deleted: what is left of it, " +
                                  $"its private key among it, is in '{leftBehind}', which this meter does not read again. Delete it by hand.",
                                  "certificates");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, SigningRequestsJSON()));

        }

        #endregion


        #region (private) EntryJSON(Entry) / SigningRequestsJSON()

        /// <summary>
        /// One certificate as a page reads it: the store's entry, and which
        /// listener shows it now.
        /// </summary>
        private JObject EntryJSON(CertificateEntry Entry)
        {

            var json = Entry.ToJSON(WithDiagnostics: true);

            if (Entry.Kind == CertificateKind.TLSIdentity)
                json.Add("shownOn", new JArray(meter.ShownOn(Entry.Id)));

            return json;

        }

        /// <summary>
        /// The signing requests, and the kinds of key a new one may be asked for with.
        /// </summary>
        private JObject SigningRequestsJSON()

            => new (
                   new JProperty("requests",        new JArray(meter.SigningRequests.All.Select(request => request.ToJSON(meter.Certificates)))),
                   new JProperty("listeners",       new JArray(ListenerCertificates.All)),
                   new JProperty("keyTypes",        new JArray(SigningRequests.KeyTypes.Select(keyType => keyType.ToJSON()))),
                   new JProperty("defaultKeyType",  SigningRequests.DefaultKeyType)
               );

        #endregion

        #region (private static) Strings(Token)

        /// <summary>
        /// The names a request lists: a JSON list, or one string of names
        /// separated by commas.
        /// </summary>
        private static IEnumerable<String> Strings(JToken? Token)

            => Token switch {
                   JArray array  => array.Values<String>().OfType<String>(),
                   JValue value  when value.Type == JTokenType.String
                                 => (value.Value<String>() ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                   _             => []
               };

        #endregion

    }

}
