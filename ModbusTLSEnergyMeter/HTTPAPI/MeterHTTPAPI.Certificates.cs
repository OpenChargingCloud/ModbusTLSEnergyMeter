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
    /// The certificates this meter shows and believes - the node's certificate
    /// store - and the keys and signing requests made here.
    /// </summary>
    /// <remarks>
    /// <para>
    /// One store for all of them, as on every node, addressed by a short
    /// handle rather than by a path: the TLS identities its two listeners show,
    /// each told which listener it is for; the client roots Modbus/TLS clients
    /// are issued by; and the TLS roots and server certificates of the time and
    /// name servers it asks.
    /// </para>
    /// <para>
    /// The private key of a certificate asked for here is made in the meter and
    /// never leaves it. What goes out is a PKCS#10 request; what comes back is a
    /// certificate, which is checked against the key that asked for it before
    /// it becomes an identity. A store is a collection rather than a setting,
    /// which is why it is not below "configuration".
    /// </para>
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region (private) RegisterCertificateTemplates()

        private void RegisterCertificateTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/certificates",                GetCertificateStore,      HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates",                PostCertificate,          HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/reload",         PostCertificateReload,    HTTPMethod.POST);

            AddHandler(HTTPPath.Root + "v1/certificates/requests",       GetSigningRequests,       HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/requests",       PostSigningRequest,       HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/certificates/requests/{id}",  GetSigningRequestFile,    HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/requests/{id}",  PutSigningRequestAnswer,  HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/certificates/requests/{id}",  DeleteSigningRequest,     HTTPMethod.DELETE);

            AddHandler(HTTPPath.Root + "v1/certificates/{id}",           GetCertificate,           HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/certificates/{id}",           PatchCertificate,         HTTPMethod.PATCH);
            AddHandler(HTTPPath.Root + "v1/certificates/{id}",           DeleteCertificate,        HTTPMethod.DELETE);

        }

        #endregion


        #region (private) GetCertificateStore   (Request)

        /// <summary>
        /// GET /api/v1/certificates: the store, every certificate in it by kind,
        /// and what each listener shows.
        /// </summary>
        private Task<HTTPResponse> GetCertificateStore(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CertificatesJSON()));

        }

        #endregion

        #region (private) PostCertificate       (Request)

        /// <summary>
        /// POST /api/v1/certificates with {"kind", "content" (base64), "password",
        /// "label", "usages"}: put a certificate into the store.
        /// </summary>
        /// <remarks>
        /// The same certificate again is the same entry, and may change its label
        /// and what it is for: 200 rather than 201.
        /// </remarks>
        private Task<HTTPResponse> PostCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var store = meter.Certificates;

            if (!CertificateKindExtensions.TryParseKind(json["kind"]?.Value<String>(), out var kind) || !store.Kinds.Contains(kind))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"'kind' has to be one of {String.Join(", ", store.Kinds.Select(one => one.AsText()))}."));

            if (json["content"]?.Value<String>() is not String base64 || base64.Trim().Length == 0)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'content' has to be the certificate file, base64-encoded."));

            Byte[] content;

            try
            {
                content = Convert.FromBase64String(base64.Trim());
            }
            catch (FormatException)
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'content' is not valid base64."));
            }

            if (!TryReadUsages(Request, json, out var usages, out var badUsages))
                return Task.FromResult(badUsages);

            var before = store.Entries.Count;

            if (!store.Import(content,
                              kind,
                              json["password"]?.Value<String>(),
                              json["label"]?.   Value<String>(),
                              usages,
                              out var entry,
                              out var error))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));
            }

            AfterACertificateChanged();

            meter.Log.Notice($"'{user.Id}' put '{entry.Label}' into the certificate store as a {entry.Kind.AsText()} ({entry.Id}).",
                             "certificates", "web");

            return Task.FromResult(JSONResponse(Request,
                                                store.Entries.Count > before
                                                    ? HTTPStatusCode.Created
                                                    : HTTPStatusCode.OK,
                                                EntryJSON(entry)));

        }

        #endregion

        #region (private) PostCertificateReload (Request)

        /// <summary>
        /// POST /api/v1/certificates/reload: read the store's directory again -
        /// adopting what was copied into it by hand, and forgetting what was
        /// taken out of it.
        /// </summary>
        private Task<HTTPResponse> PostCertificateReload(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out _, out var refused))
                return Task.FromResult(refused);

            meter.Certificates.Reload();

            AfterACertificateChanged();

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CertificatesJSON()));

        }

        #endregion

        #region (private) GetCertificate        (Request)

        /// <summary>
        /// GET /api/v1/certificates/{id}: one certificate.
        /// </summary>
        private Task<HTTPResponse> GetCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
                return Task.FromResult(refused);

            if (!TryGetEntry(Request, out var entry, out var unknown))
                return Task.FromResult(unknown);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, EntryJSON(entry)));

        }

        #endregion

        #region (private) PatchCertificate      (Request)

        /// <summary>
        /// PATCH /api/v1/certificates/{id} with any of {"label", "active",
        /// "usages"}: rename a certificate, switch it on or off, or say what it
        /// is for.
        /// </summary>
        /// <remarks>
        /// Refused when it would leave a listener with nothing to show, or
        /// Modbus/TLS clients with no CA to be issued by - before anything is
        /// changed.
        /// </remarks>
        private Task<HTTPResponse> PatchCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetEntry(Request, out var entry, out var unknown))
                return Task.FromResult(unknown);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            Boolean? active = null;

            if (json.TryGetValue("active", out var activeToken))
            {

                if (activeToken.Type != JTokenType.Boolean)
                    return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'active' has to be true or false."));

                active = activeToken.Value<Boolean>();

            }

            IReadOnlyList<String>? usages     = null;
            var                    newUsages  = json.ContainsKey("usages");

            if (newUsages && !TryReadUsages(Request, json, out usages, out var badUsages))
                return Task.FromResult(badUsages);

            // What the entry would be for afterwards, to be asked before it is.
            var wouldBeActive  = active ?? entry.IsActive;
            var wouldBeFor     = newUsages ? usages : entry.Usages;

            if (RefuseLeavingNothing(Request, entry, wouldBeActive, wouldBeFor) is HTTPResponse leavesNothing)
                return Task.FromResult(leavesNothing);

            var store = meter.Certificates;

            if (json.ContainsKey("label") &&
                !store.Relabel(entry.Id, json["label"]?.Type == JTokenType.Null ? null : json["label"]?.Value<String>(), out _, out var labelError))
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, labelError));
            }

            if (active is Boolean on && !store.SetActive(entry.Id, on, out _, out var activeError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, activeError));

            if (newUsages && !store.SetUsages(entry.Id, usages, out _, out var usagesError))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, usagesError));

            AfterACertificateChanged();

            var changed = store.Get(entry.Id) ?? entry;

            meter.Log.Notice($"'{user.Id}' changed the certificate '{changed.Label}' ({changed.Id}) in the certificate store.",
                             "certificates", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, EntryJSON(changed)));

        }

        #endregion

        #region (private) DeleteCertificate     (Request)

        /// <summary>
        /// DELETE /api/v1/certificates/{id}: take a certificate out of the store,
        /// and its file with it.
        /// </summary>
        private Task<HTTPResponse> DeleteCertificate(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(NodeResources.Certificates), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryGetEntry(Request, out var entry, out var unknown))
                return Task.FromResult(unknown);

            if (RefuseLeavingNothing(Request, entry, false, entry.Usages) is HTTPResponse leavesNothing)
                return Task.FromResult(leavesNothing);

            if (!meter.Certificates.Remove(entry.Id, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, error));

            AfterACertificateChanged();

            meter.Log.Notice($"'{user.Id}' took the certificate '{entry.Label}' ({entry.Id}) out of the certificate store.",
                             "certificates", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, CertificatesJSON()));

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

            AfterACertificateChanged();

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

            if (!meter.SigningRequests.TryRemove(id, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict, error));

            meter.Log.Notice($"'{user.Id}' threw the signing request {id} away, and its key with it.", "certificates", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, SigningRequestsJSON()));

        }

        #endregion


        #region (private) CertificatesJSON() / EntryJSON(Entry) / SigningRequestsJSON()

        /// <summary>
        /// The store as a page reads it: the kinds it keeps and what each may be
        /// told it is for, every certificate by kind, and what each listener
        /// shows now and next.
        /// </summary>
        private JObject CertificatesJSON()
        {

            var store         = meter.Certificates;
            var kinds         = store.Kinds;

            var certificates  = new JObject();

            foreach (var kind in kinds)
                certificates.Add(kind.AsText(), new JArray(store.ByKind(kind).Select(EntryJSON)));

            var shown         = new JObject();

            foreach (var listener in ListenerCertificates.All)
            {

                var certificatesOf  = meter.ListenerCertificatesFor(listener)!;
                var next            = certificatesOf.Next;

                shown.Add(listener, new JObject(
                                        new JProperty("current",  certificatesOf.Current?.Entry.Id),
                                        new JProperty("next",     next?.Id),
                                        new JProperty("nextAt",   next?.NotBefore.UtcDateTime),
                                        new JProperty("used",     listener == ListenerCertificates.Modbus || meter.HTTPS)
                                    ));

            }

            return new JObject(
                       new JProperty("directory",           store.Directory),
                       new JProperty("trustAnchors",        new JArray(kinds.Where(kind =>  kind.IsTrustAnchor()).                                    Select(kind => kind.AsText()))),
                       new JProperty("credentials",         new JArray(kinds.Where(kind => !kind.IsTrustAnchor() && !kind.MustNotCarryPrivateKey()).  Select(kind => kind.AsText()))),
                       new JProperty("recognised",          new JArray(kinds.Where(kind => !kind.IsTrustAnchor() &&  kind.MustNotCarryPrivateKey()).  Select(kind => kind.AsText()))),
                       new JProperty("kinds",               new JObject(kinds.Select(kind => new JProperty(kind.AsText(), new JObject(
                                                                                                 new JProperty("description",      kind.Describe()),
                                                                                                 new JProperty("trustAnchor",      kind.IsTrustAnchor()),
                                                                                                 new JProperty("needsPrivateKey",  kind.NeedsPrivateKey()),
                                                                                                 new JProperty("hasUsages",        store.HasUsages(kind)),
                                                                                                 new JProperty("usages",           new JArray(store.UsagesFor(kind)))
                                                                                             ))))),
                       new JProperty("usages",              new JArray(store.Usages)),
                       new JProperty("listeners",           new JArray(store.Listeners)),
                       new JProperty("certificates",        certificates),
                       new JProperty("shown",               shown),
                       new JProperty("keysAreUnencrypted",  store.Entries.Any(entry => entry.HasPrivateKey))
                   );

        }

        /// <summary>
        /// One certificate as a page reads it: the store's entry, and which
        /// listener shows it now.
        /// </summary>
        private JObject EntryJSON(CertificateEntry Entry)
        {

            var json = Entry.ToJSON(WithDiagnostics: true);

            if (Entry.Kind == CertificateKind.TLSIdentity)
                json.Add("shownOn", new JArray(ListenerCertificates.All.Where(listener => meter.ListenerCertificatesFor(listener)?.Current?.Entry.Id == Entry.Id)));

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

        #region (private) RefuseLeavingNothing(Request, Entry, Active, Usages)

        /// <summary>
        /// The 409 for a change that would leave a listener with nothing to show,
        /// or Modbus/TLS clients with no CA they may be issued by - or null when
        /// it would not.
        /// </summary>
        /// <param name="Request">The request.</param>
        /// <param name="Entry">The certificate to be changed or removed.</param>
        /// <param name="Active">Whether it would be switched on afterwards; false for a removal.</param>
        /// <param name="Usages">What it would be for afterwards; null for every use.</param>
        private HTTPResponse? RefuseLeavingNothing(HTTPRequest             Request,
                                                  CertificateEntry        Entry,
                                                  Boolean                 Active,
                                                  IReadOnlyList<String>?  Usages)
        {

            if (Entry.Kind == CertificateKind.TLSIdentity)
            {

                foreach (var listener in ListenerCertificates.All)
                {

                    if (listener == ListenerCertificates.Web && !meter.HTTPS)
                        continue;

                    var candidates     = meter.ListenerCertificatesFor(listener)!.Candidates;
                    var stillShowable  = Active && (Usages is null || Usages.Contains(listener));

                    if (!stillShowable && candidates.Count == 1 && candidates[0].Id == Entry.Id)
                        return ErrorJSON(Request, HTTPStatusCode.Conflict,
                                         $"That is the only certificate the {listener} listener could show. Put another one in first.");

                }

            }

            if (Entry.Kind == CertificateKind.ClientRoot && !Active)
            {

                var usable = meter.ClientRoots.Usable;

                if (usable.Count == 1 && usable[0].Id == Entry.Id)
                    return ErrorJSON(Request, HTTPStatusCode.Conflict,
                                     "That is the last CA Modbus/TLS clients may be issued by. Put another one in first - " +
                                     "otherwise no charging station could connect.");

            }

            return null;

        }

        #endregion

        #region (private) TryGetEntry(Request, out Entry, out Unknown) / HandleOf(Request)

        private Boolean TryGetEntry(HTTPRequest                                   Request,
                                    [NotNullWhen(true)]  out CertificateEntry?    Entry,
                                    [NotNullWhen(false)] out HTTPResponse?        Unknown)
        {

            Entry = meter.Certificates.Get(HandleOf(Request));

            if (Entry is null)
            {
                Unknown = ErrorJSON(Request, HTTPStatusCode.NotFound, "There is no such certificate in this store.");
                return false;
            }

            Unknown = null;
            return true;

        }

        /// <summary>
        /// The handle in the path, as the store spells handles: in lower case.
        /// </summary>
        private static String HandleOf(HTTPRequest Request)

            => Request.ParsedURLParameters.Length > 0
                   ? Request.ParsedURLParameters[0].Trim().ToLowerInvariant()
                   : "";

        #endregion

        #region (private static) TryReadUsages(Request, JSON, out Usages, out Refused) / Strings(Token)

        /// <summary>
        /// The usages a request names: null for every use, when they are left
        /// out or null, and a list of names otherwise.
        /// </summary>
        private static Boolean TryReadUsages(HTTPRequest                             Request,
                                             JObject                                 JSON,
                                             out IReadOnlyList<String>?              Usages,
                                             [NotNullWhen(false)] out HTTPResponse?  Refused)
        {

            Usages   = null;
            Refused  = null;

            var token = JSON["usages"];

            if (token is null || token.Type == JTokenType.Null)
                return true;

            if (token is not JArray list || list.Any(item => item.Type != JTokenType.String))
            {
                Refused = ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                    "'usages' has to be a list of usages, such as [\"nts\"] or [\"modbus\"], or null for every use.");
                return false;
            }

            Usages = [.. list.Values<String>().OfType<String>()];
            return true;

        }

        private static IEnumerable<String> Strings(JToken? Token)

            => Token switch {
                   JArray array  => array.Values<String>().OfType<String>(),
                   JValue value  when value.Type == JTokenType.String
                                 => (value.Value<String>() ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries),
                   _             => []
               };

        #endregion

        #region (private) AfterACertificateChanged()

        /// <summary>
        /// Say so at once when a change means a listener shows another
        /// certificate, rather than at the next minute's check.
        /// </summary>
        private void AfterACertificateChanged()
        {
            meter.ModbusCertificates.CheckRollover();
            meter.WebCertificates.   CheckRollover();
        }

        #endregion

    }

}
