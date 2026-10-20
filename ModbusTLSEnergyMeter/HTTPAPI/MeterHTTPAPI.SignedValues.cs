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
using System.Security.Cryptography;

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node.Web;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// Readings this meter has put its name to, and the charging sessions they
    /// belong to.
    /// </summary>
    /// <remarks>
    /// A reading over the JSON API is a number this meter says it measured. A
    /// signed one is a number somebody can still check in a year, against a key
    /// that was this meter's before the reading was taken - which is the whole
    /// difference, and the reason these live apart from the plain readings.
    ///
    /// The document formats do not agree about anything: what fields a reading
    /// has, how a public key is written down, which curve is allowed. What they
    /// have in common is this meter's keys, so that is what is shared here and
    /// the rest is left to the writers.
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region (private) RegisterSignedValueTemplates()

        private void RegisterSignedValueTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/signedMeterValues",   GetSignedMeterValue,  HTTPMethod.GET);

            AddHandler(HTTPPath.Root + "v1/sessions",            GetSession,           HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/sessions/start",      PostSessionStart,     HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/sessions/stop",       PostSessionStop,      HTTPMethod.POST);

            AddHandler(HTTPPath.Root + "v1/keys",                GetKeys,              HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/keys",                PostKey,              HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/keys/{id}/default",   PutKeyDefault,        HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/keys/{id}",           DeleteKey,            HTTPMethod.DELETE);

        }

        #endregion


        #region (private) GetSignedMeterValue(Request)

        /// <summary>
        /// GET /api/v1/signedMeterValues?format=ocmf|alfen&amp;key={id}: what
        /// this meter stands at, signed.
        /// </summary>
        /// <remarks>
        /// A reading that belongs to no charging session - OCMF calls that a
        /// fiscal reading and counts it in a sequence of its own. What a
        /// charging session looks like is two of these in one document, and that
        /// is what /sessions/stop answers with.
        /// </remarks>
        private async Task<HTTPResponse> GetSignedMeterValue(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Meter), false, out _, out var refused))
                return refused;

            var format = (Request.QueryString.GetString("format") ?? "ocmf").Trim().ToLowerInvariant();

            if (!TryGetSigningKey(Request, Request.QueryString.GetString("key"), format, out var key, out var noKey))
                return noKey;

            Decimal importedWh;

            try
            {
                importedWh = await meter.Signer.ReadImportedWh();
            }
            catch (EnergyUnreadable e)
            {
                return ErrorJSON(Request, HTTPStatusCode.InternalServerError, e.Message);
            }

            var now = meter.TimeProvider.GetUtcNow();

            try
            {

                return format switch {

                    "ocmf"   => JSONResponse(Request, HTTPStatusCode.OK,
                                    new JObject(
                                        new JProperty("format",     "OCMF"),
                                        new JProperty("timestamp",  now.UtcDateTime.ToString("o")),
                                        new JProperty("ocmf",       OCMFWriter.Build(
                                                                        meter.SigningKeys,
                                                                        key,
                                                                        meter.Signer.Payload($"F{meter.Sessions.NextFiscal()}"),
                                                                        [ meter.Signer.Reading(now, importedWh / 1000m, null) ]
                                                                    )),
                                        new JProperty("publicKey",  MeterPublicKey.ToJSON(key))
                                    )),

                    "alfen"  => JSONResponse(Request, HTTPStatusCode.OK,
                                    new JObject(
                                        new JProperty("format",     "Alfen"),
                                        new JProperty("timestamp",  now.UtcDateTime.ToString("o")),
                                        new JProperty("alfen",      AlfenRecord(key, now, importedWh, null, 0,
                                                                                (UInt32) meter.Sessions.NextFiscal())),
                                        new JProperty("publicKey",  MeterPublicKey.ToJSON(key)),
                                        new JProperty("note",       "An Alfen-shaped record signed by this meter, not an Alfen adapter: " +
                                                                    "the adapter fields are filled from this meter's own serial number and version.")
                                    )),

                    _        => ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                          $"Unknown format '{format}'. This meter writes 'ocmf' and 'alfen'.")

                };

            }
            catch (Exception e)
            {
                return ErrorJSON(Request, HTTPStatusCode.InternalServerError,
                                 $"That reading could not be signed: {e.Message}");
            }

        }

        #endregion

        #region (private) GetSession        (Request)

        /// <summary>
        /// GET /api/v1/sessions: the charging session that is running, if one
        /// is, and the document the last one ended in, until the next begins.
        /// </summary>
        private Task<HTTPResponse> GetSession(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Meter), false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               new JProperty("running",  meter.Sessions.Current is not null),
                               meter.Sessions.Current is ChargingSession session
                                   ? new JProperty("session", session.ToJSON())
                                   : new JProperty("session", JValue.CreateNull()),
                               meter.Sessions.Last is SignedSession last
                                   ? new JProperty("last",    last.ToJSON())
                                   : new JProperty("last",    JValue.CreateNull())
                           ))
                   );

        }

        #endregion

        #region (private) PostSessionStart  (Request)

        /// <summary>
        /// POST /api/v1/sessions/start with an optional
        /// {"key": "...", "identification": "...", "identificationType": "...",
        /// "chargePointIdType": "...", "chargePointId": "...", "tariffText": "...",
        /// "stationSessionId": "..."}.
        /// </summary>
        /// <remarks>
        /// Answers with the time and the public key, because those are the two
        /// things whoever will check this session later needs to have from
        /// before it happened. The reading itself is kept here until the session
        /// stops: a start reading handed out on its own is a number that says a
        /// meter stood somewhere at some moment, which is not evidence of
        /// anything.
        /// </remarks>
        private async Task<HTTPResponse> PostSessionStart(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run(MeterAccess.Meter), true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (!TryGetSigningKey(Request, json["key"]?.Value<String>(), "ocmf", out var key, out var noKey))
                return noKey;

            if (!SessionParameters.TryParse(json, out var parameters, out var invalid))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, invalid);

            var answer = await meter.Signer.Start(parameters, key);

            if (answer.Value is not StartedSession started)
                return Refused(Request, answer.Refusal!);

            var session = started.Session;

            meter.Log.Notice(
                $"'{user.Id}' started the charging session '{session.Id}'" +
                (session.Parameters.StationSessionId is String id ? $" ('{id}')" : "") +
                $" at {session.StartValue} kWh, to be signed with '{key.Id}'.",
                "sessions", "signing", "web"
            );

            return JSONResponse(Request, HTTPStatusCode.Created,
                           new JObject(

                               new JProperty("timestamp",   session.StartedAt.UtcDateTime.ToString("o")),
                               new JProperty("sessionId",   session.Id),
                               new JProperty("startValue",  session.StartValue),
                               new JProperty("unit",        "kWh"),

                               // The whole point of answering at all: whoever
                               // gets this now can check the document that comes
                               // back at the end against a key they were given
                               // before the session began.
                               new JProperty("publicKey",   MeterPublicKey.ToJSON(key))

                           ));

        }

        #endregion

        #region (private) PostSessionStop   (Request)

        /// <summary>
        /// POST /api/v1/sessions/stop: the session as one OCMF document, with
        /// the reading it started at and the one it ended at.
        /// </summary>
        /// <remarks>
        /// One document and not two, because that is what makes it a charging
        /// session: two separately signed readings are two facts about a meter,
        /// and the energy between them is an inference somebody else has to be
        /// trusted to have drawn correctly. Here the subtraction is inside what
        /// was signed.
        /// </remarks>
        private async Task<HTTPResponse> PostSessionStop(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Run(MeterAccess.Meter), true, out var user, out var refused))
                return refused;

            // A body is optional: {"stationSessionId": "..."} stops only the
            // session that is known by it.
            String? stationSessionId = null;

            if (!String.IsNullOrWhiteSpace(Request.HTTPBodyAsUTF8String))
            {

                if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                    return errorResponse;

                if (json["stationSessionId"] is JToken token && token.Type != JTokenType.Null)
                {

                    if (token.Type != JTokenType.String)
                        return ErrorJSON(Request, HTTPStatusCode.BadRequest, "'stationSessionId' is a text.");

                    stationSessionId = token.Value<String>();

                }

            }

            var answer = await meter.Signer.Stop(stationSessionId);

            if (answer.Value is not SignedSession signed)
                return Refused(Request, answer.Refusal!);

            meter.Log.Notice(
                $"'{user.Id}' stopped the charging session '{signed.SessionId}'" +
                (signed.StationSessionId is String id ? $" ('{id}')" : "") +
                $": {signed.StartValue} kWh to {signed.StopValue} kWh, {signed.StopValue - signed.StartValue} kWh in all.",
                "sessions", "signing", "web"
            );

            return JSONResponse(Request, HTTPStatusCode.OK,
                       new JObject(

                           new JProperty("timestamp",         signed.StoppedAt.UtcDateTime.ToString("o")),
                           new JProperty("sessionId",         signed.SessionId),
                           new JProperty("stationSessionId",  signed.StationSessionId),
                           new JProperty("startValue",        signed.StartValue),
                           new JProperty("stopValue",         signed.StopValue),
                           new JProperty("energy_kWh",        signed.StopValue - signed.StartValue),
                           new JProperty("unit",              "kWh"),

                           new JProperty("ocmf",              signed.Document),
                           new JProperty("publicKey",         meter.SigningKeys.Get(signed.KeyId) is MeterKey key
                                                                  ? MeterPublicKey.ToJSON(key)
                                                                  : new JObject(
                                                                        new JProperty("publicKey",  signed.PublicKey),
                                                                        new JProperty("encoding",   signed.PublicKeyEncoding)
                                                                    ))

                       ));

        }

        #endregion

        #region (private) Refused(Request, Refusal)

        /// <summary>
        /// A session that was not begun or not ended, as the answer that says
        /// why.
        /// </summary>
        private static HTTPResponse Refused(HTTPRequest     Request,
                                            SessionRefusal  Refusal)

            => ErrorJSON(Request,
                         Refusal.Kind switch {
                             SessionRefusalKind.InvalidParameter  => HTTPStatusCode.BadRequest,
                             SessionRefusalKind.Unreadable        => HTTPStatusCode.InternalServerError,
                             SessionRefusalKind.SigningFailed     => HTTPStatusCode.InternalServerError,
                             _                                    => HTTPStatusCode.Conflict
                         },
                         Refusal.Why);

        #endregion


        #region (private) GetKeys / PostKey / PutKeyDefault / DeleteKey

        /// <summary>
        /// GET /api/v1/keys: the signing keys of this meter, without their
        /// private halves.
        /// </summary>
        private Task<HTTPResponse> GetKeys(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Keys), false, out _, out var refused))
                return Task.FromResult(refused);

            var json = meter.SigningKeys.ToJSON();

            json.Add("ocmfAlgorithms",  new JArray(OCMFWriter.SigningAlgorithms));
            json.Add("alfenAlgorithm",  MeterKeyStore.AlfenAlgorithm);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, json));

        }

        /// <summary>
        /// POST /api/v1/keys with {"algorithm": "Ed25519", "note": "..."}.
        /// </summary>
        private Task<HTTPResponse> PostKey(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(MeterAccess.Keys), true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var algorithm = json["algorithm"]?.Value<String>()?.Trim();

            if (algorithm is null || MeterKeyStore.SuiteFor(algorithm) is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"An 'algorithm' is required, one of: {String.Join(", ", MeterKeyStore.Algorithms)}."));

            try
            {

                var key = meter.SigningKeys.Create(algorithm, json["note"]?.Value<String>());

                meter.Log.Notice(
                    $"'{user.Id}' made a new signing key '{key.Id}' ({key.Algorithm}), fingerprint {key.Fingerprint}.",
                    "signing", "web"
                );

                return Task.FromResult(JSONResponse(Request, HTTPStatusCode.Created, MeterPublicKey.ToJSON(key)));

            }
            catch (Exception e)
            {
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"That key could not be made: {e.Message}"));
            }

        }

        /// <summary>
        /// PUT /api/v1/keys/{id}/default: sign with this one from now on.
        /// </summary>
        /// <remarks>
        /// Changes nothing about what was signed before. Every document says
        /// which algorithm it was signed with and is checked against the key
        /// that signed it, so a meter that changes its identity does not
        /// invalidate its past - it only stops adding to it under the old key.
        /// </remarks>
        private Task<HTTPResponse> PutKeyDefault(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(MeterAccess.Keys), true, out var user, out var refused))
                return Task.FromResult(refused);

            var id = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : "";

            if (!meter.SigningKeys.SetDefault(id, out var problem))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.NotFound, problem));

            meter.Log.Notice($"'{user.Id}' made '{id}' the signing identity of this meter.", "signing", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.SigningKeys.ToJSON()));

        }

        /// <summary>
        /// DELETE /api/v1/keys/{id}
        /// </summary>
        private Task<HTTPResponse> DeleteKey(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Edit(MeterAccess.Keys), true, out var user, out var refused))
                return Task.FromResult(refused);

            var id = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : "";

            if (meter.Sessions.Current?.KeyId == id)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.Conflict,
                                                 $"The running charging session was started with '{id}' and has to be signed with it. " +
                                                  "Stop the session first."));

            // 500 where the disk refused a removal that was right in itself,
            // as every node answers a change its file cannot take - it was
            // 409, as if something were wrong with asking.
            if (!meter.SigningKeys.TryRemove(id, out var problem, out var notSaved, out var leftBehind))
                return Task.FromResult(NotChanged(Request, HTTPStatusCode.Conflict, problem, notSaved));

            meter.Log.Warning(
                $"'{user.Id}' removed the signing key '{id}'. Everything it signed can no longer be checked against this meter.",
                "signing", "web"
            );

            if (leftBehind is not null)
                meter.Log.Warning($"The signing key '{id}' is gone, but its directory could not be deleted: what is left of it, " +
                                  $"its private key among it, is in '{leftBehind}', which this meter does not read again. Delete it by hand.",
                                  "signing");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.SigningKeys.ToJSON()));

        }

        #endregion


        #region (private) TryGetSigningKey(Request, Id, Format, out Key, out Refused)

        /// <summary>
        /// The key a request named, or the one the format requires, or the
        /// meter's identity.
        /// </summary>
        private Boolean TryGetSigningKey(HTTPRequest                             Request,
                                         String?                                 Id,
                                         String                                  Format,
                                         [NotNullWhen(true)]  out MeterKey?      Key,
                                         [NotNullWhen(false)] out HTTPResponse?  Refused)
        {

            // Alfen takes one curve and no other, so naming nothing cannot mean
            // the identity here: it means the one key that would work.
            if (Format == "alfen" && String.IsNullOrWhiteSpace(Id))
            {

                Key = meter.SigningKeys.Keys.FirstOrDefault(key => key.Algorithm == MeterKeyStore.AlfenAlgorithm);

                if (Key is null)
                {
                    Refused = ErrorJSON(Request, HTTPStatusCode.Conflict,
                                        $"The Alfen format carries a 25 byte compressed point and parses no other curve, " +
                                        $"so it needs a {MeterKeyStore.AlfenAlgorithm} key. This meter has none - make one first.");
                    return false;
                }

                Refused = null;
                return true;

            }

            Key = meter.SigningKeys.Get(Id);

            if (Key is null)
            {
                Refused = ErrorJSON(Request, HTTPStatusCode.NotFound,
                                    String.IsNullOrWhiteSpace(Id)
                                        ? "This meter has no signing key at all."
                                        : $"There is no signing key '{Id}'.");
                return false;
            }

            if (Format == "ocmf" && OCMFWriter.AlgorithmFor(Key.Algorithm) is null)
            {
                Refused = ErrorJSON(Request, HTTPStatusCode.Conflict,
                                    $"OCMF has no name for '{Key.Algorithm}', so a document cannot say what it was signed with. " +
                                    $"Sign with one of: {String.Join(", ", OCMFWriter.SigningAlgorithms)}.");
                Key = null;
                return false;
            }

            Refused = null;
            return true;

        }

        #endregion

        #region (private) AlfenRecord(...)

        /// <summary>
        /// One Alfen-shaped record, with this meter's own values in the fields
        /// the format keeps for an adapter.
        /// </summary>
        private String AlfenRecord(MeterKey        Key,
                                   DateTimeOffset  Timestamp,
                                   Decimal         ImportedWh,
                                   String?         Transaction,
                                   UInt32          SessionId,
                                   UInt32          Pagination)
        {

            // Ten bytes of identification out of the serial number, because the
            // format wants ten bytes and this meter has a name instead. The same
            // name always gives the same bytes, which is what matters: a reader
            // has to be able to tell two of these meters apart.
            var meterId   = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(meter.SerialNumber)).AsSpan(0, 10));
            var adapterId = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes($"adapter:{meter.SerialNumber}")).AsSpan(0, 10));
            var checksum  = Convert.ToHexString(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(meter.Version)).AsSpan(0, 2));

            return AlfenWriter.Build(
                       meter.SigningKeys,
                       Key,
                       Timestamp,
                       (UInt64) Math.Max(0, Math.Round(ImportedWh)),
                       Scale:                    0,
                       MeterId:                  meterId,
                       AdapterId:                adapterId,
                       AdapterFirmware:          (meter.Version + "    ")[..4],
                       AdapterFirmwareChecksum:  checksum,
                       OBIS:                     "1-0:1.8.0",
                       Transaction:              Transaction,
                       SecondsIndex:             (UInt32) Math.Max(0, (Timestamp - startedAt).TotalSeconds),
                       SessionId:                SessionId,
                       Pagination:               Pagination
                   );

        }

        #endregion

    }

}
