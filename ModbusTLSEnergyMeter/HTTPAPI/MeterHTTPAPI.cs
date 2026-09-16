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
using System.Globalization;
using System.Text;

using Microsoft.Extensions.Logging;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The JSON API of this energy meter, registered at "/api": what the meter
    /// is measuring, how it is configured, and the few things about it that can
    /// be changed from a browser.
    /// </summary>
    /// <remarks>
    /// It lives in its own HTTPAPI below the account API so that an unknown
    /// /api path answers with a JSON 404 rather than falling through to the
    /// accounts at "/" - Hermod dispatches a request to the most specific
    /// HTTPAPI first.
    ///
    /// Signing in is not here: that is <see cref="HTTPExtAPI"/>'s
    /// "/auth/login", and the session cookie it sets is what every resource
    /// below is read with. This API only ever asks who the cookie belongs to
    /// and what that person's role in the meter's organization allows.
    /// </remarks>
    public partial class MeterHTTPAPI : org.GraphDefined.Vanaheimr.Hermod.HTTP.HTTPAPI
    {

        #region Data

        /// <summary>
        /// The default root path of this API.
        /// </summary>
        public static readonly HTTPPath  DefaultAPIPath      = HTTPPath.Parse("/api");

        /// <summary>
        /// The name of the Server-Sent Events stream.
        /// </summary>
        public const           String    EventSourceName     = "events";

        /// <summary>
        /// The sub-event every log entry is published as.
        /// </summary>
        public const           String    LogEventName        = "log";

        /// <summary>
        /// The most entries one request for the log may ask for.
        /// </summary>
        public const           Int32     MaxLogPageSize      = 2_000;

        /// <summary>
        /// How many it gets when it does not say.
        /// </summary>
        public const           Int32     DefaultLogPageSize  = 500;

        private readonly ModbusTLSEnergyMeter     meter;
        private readonly HTTPExtAPI               accounts;
        private readonly ILogger                  logger;
        private readonly DateTimeOffset           startedAt;

        /// <summary>
        /// Ends every open event stream when this meter stops, which the
        /// request's own token knows nothing about.
        /// </summary>
        private readonly CancellationTokenSource  shutdown = new ();

        #endregion

        #region Properties

        /// <summary>
        /// The version reported by the status resource.
        /// </summary>
        public String                 Version   { get; }

        /// <summary>
        /// The stream every browser hangs on.
        /// </summary>
        public IHTTPEventSource<JObject>  Events    { get; }

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create and register the JSON API of a meter within its HTTP server.
        /// </summary>
        /// <param name="Meter">The meter this API speaks for.</param>
        /// <param name="Accounts">Who is signed in, and what they belong to.</param>
        /// <param name="APIPath">The root path of the API, "/api" by default.</param>
        /// <param name="Logger">Where this API writes what was done through it.</param>
        public MeterHTTPAPI(ModbusTLSEnergyMeter  Meter,
                            HTTPExtAPI            Accounts,
                            HTTPPath?             APIPath   = null,
                            ILogger?              Logger    = null)

            : base(Meter.HTTPServer,
                   RootPath:     APIPath ?? DefaultAPIPath,
                   Description:  I18NString.Create("The JSON API of this energy meter"))

        {

            this.meter      = Meter;
            this.accounts   = Accounts;
            this.logger     = Logger ?? Meter.Logger;
            this.startedAt  = Meter.TimeProvider.GetUtcNow();
            this.Version    = Meter.Version;

            // Hermod caches the last events and replays them to a new client.
            // The browser ignores everything older than the snapshot it loaded,
            // so a replay costs nothing but bytes; what it buys is that a
            // browser which reconnects after a hiccup gets what it missed.
            this.Events     = this.AddJSONEventSource(
                                  HTTPEventSource_Id.Parse(EventSourceName),
                                  MaxNumberOfCachedEvents:  500,
                                  RetryInterval:            TimeSpan.FromSeconds(2),
                                  EnableLogging:            false
                              );

            Meter.Log.OnLogged += entry => Publish(LogEventName, entry.ToJSON());

            RegisterURLTemplates();

        }

        #endregion


        #region (private) RegisterURLTemplates()

        private void RegisterURLTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/me",                        Me,                    HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/status",                    GetStatus,             HTTPMethod.GET);

            AddHandler(HTTPPath.Root + "v1/meter",                     GetMeter,              HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/meter/registers",           GetRegisters,          HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/meter/mode",                PutMeterMode,          HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/meter/energy/reset",        PostResetEnergy,       HTTPMethod.POST);

            AddHandler(HTTPPath.Root + "v1/configuration",             GetConfiguration,      HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/dns",         GetDNSConfiguration,   HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/dns",         PutDNSConfiguration,   HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/configuration/nts",         GetNTSConfiguration,   HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/nts",         PutNTSConfiguration,   HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/configuration/nts/sync",    PostNTSSync,           HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/configuration/time",        GetClock,              HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/configuration/certificates", GetCertificates,      HTTPMethod.GET);

            RegisterCertificateTemplates();
            RegisterAccountTemplates();
            RegisterSignedValueTemplates();

            AddHandler(HTTPPath.Root + "v1/logs",                      GetLogs,               HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/logs/verify",               GetLogVerification,    HTTPMethod.GET);

            AddHandler(HTTPMethod.GET,
                       HTTPPath.Root + "v1/events",
                       HTTPContentType.Text.EVENTSTREAM,
                       StreamEvents);

            // Everything else below /api answers with a JSON 404 rather than
            // falling through to the account API at "/".
            foreach (var method in new[] { HTTPMethod.GET, HTTPMethod.HEAD, HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.DELETE })
                AddHandler(HTTPPath.Root + "{path..}", UnknownPath, method);

        }

        #endregion


        #region (private) Me              (Request)

        /// <summary>
        /// GET /api/v1/me: who is signed in, and what they may do here.
        /// </summary>
        /// <remarks>
        /// The permissions travel to the browser so that a page can grey out
        /// what this person may not do, rather than offering it and letting
        /// them find out by being refused. They are a copy of what this meter
        /// enforces and not the enforcement: every request is checked again on
        /// arrival, so a browser that edits this list gains nothing but a
        /// button that answers 403.
        ///
        /// The role travels twice: once as this meter spells it and once as a
        /// person would say it. Every page that tells somebody what they may
        /// not do here names their role in the same breath, and "IsAdminReadOnly"
        /// is not a thing anybody says. Sending the readable form with the role
        /// it belongs to is one field; the alternative is every page fetching
        /// the role table to translate one word.
        /// </remarks>
        private Task<HTTPResponse> Me(HTTPRequest Request)
        {

            if (!TryGetUser(Request, out var user, out var unauthorized))
                return Task.FromResult(unauthorized);

            var role        = RoleOf(user);
            var permissions = role?.PermissionsOf() ?? MeterPermissions.None;

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               new JProperty("userId",       user.Id.ToString()),
                               new JProperty("name",         user.Name.FirstText()),
                               new JProperty("organization", ModbusTLSEnergyMeter.MeterOrganizationId),
                               role.HasValue
                                   ? new JProperty("role",             role.Value.ToString())
                                   : new JProperty("role",             JValue.CreateNull()),

                               role.HasValue
                                   ? new JProperty("roleTitle",        role.Value.AsText())
                                   : new JProperty("roleTitle",        JValue.CreateNull()),

                               role.HasValue
                                   ? new JProperty("roleDescription",  role.Value.Description())
                                   : new JProperty("roleDescription",  JValue.CreateNull()),

                               new JProperty("permissions",  new JArray(permissions.Names()))
                           ))
                   );

        }

        #endregion

        #region (private) GetStatus       (Request)

        /// <summary>
        /// GET /api/v1/status: what this meter is and how long it has been it.
        /// </summary>
        private Task<HTTPResponse> GetStatus(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadMeter, false, out _, out var refused))
                return Task.FromResult(refused);

            var now = meter.TimeProvider.GetUtcNow();

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(

                               new JProperty("version",       Version),
                               new JProperty("serialNumber",  meter.SerialNumber),
                               new JProperty("device",        meter.Device.DisplayName),
                               new JProperty("startedAt",     startedAt.ToString("o")),
                               new JProperty("uptime_s",      (now - startedAt).TotalSeconds),

                               new JProperty("modbus",        new JObject(
                                   new JProperty("address",        meter.ListenAddress.ToString()),
                                   new JProperty("port",           meter.ListenPort),
                                   new JProperty("running",        meter.IsRunning),
                                   new JProperty("baseAddress",    meter.Device.BaseAddress),
                                   new JProperty("registerCount",  meter.Device.RegisterCount)
                               )),

                               new JProperty("web",           new JObject(
                                   new JProperty("url",            meter.WebInterfaceURL.ToString())
                               ))

                           ))
                   );

        }

        #endregion

        #region (private) GetMeter        (Request)

        /// <summary>
        /// GET /api/v1/meter: what the meter is measuring, as numbers rather
        /// than as registers.
        /// </summary>
        private Task<HTTPResponse> GetMeter(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadMeter, false, out _, out var refused))
                return Task.FromResult(refused);

            var registers = meter.Device.ReadHolding(
                                SunSpecMeterMap.BaseAddress,
                                SunSpecMeterMap.RegisterCount
                            );

            if (registers is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.InternalServerError,
                                                 "The register block of this meter could not be read."));

            var readings = ReadingsJSON(registers);

            // What the simulated site is doing, which is in no register: the
            // load and the generation are what the mode selects BETWEEN, so a
            // page that shows only the result cannot say why a meter in front
            // of a generator is reading zero at three in the morning.
            readings.Add("simulation",
                         new JObject(
                             new JProperty("load_W",        meter.Device.LoadW),
                             new JProperty("generation_W",  meter.Device.GenerationW),
                             new JProperty("timeOfDay",     meter.Device.SimulatedTime.ToString("o")),
                             new JProperty("dayLength_s",   meter.Device.SimulatedDayLength.TotalSeconds)
                         ));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, readings)
                   );

        }

        #endregion

        #region (private) GetRegisters    (Request)

        /// <summary>
        /// GET /api/v1/meter/registers?start=40000&amp;count=98: the raw
        /// register block, for whoever would rather read it as SunSpec wrote it.
        /// </summary>
        private Task<HTTPResponse> GetRegisters(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadMeter, false, out _, out var refused))
                return Task.FromResult(refused);

            var start = SunSpecMeterMap.BaseAddress;
            var count = SunSpecMeterMap.RegisterCount;

            if (Request.QueryString.GetString("start") is String startText &&
                !UInt16.TryParse(startText, out start))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'start' must be a register address."));

            if (Request.QueryString.GetString("count") is String countText &&
                (!UInt16.TryParse(countText, out count) || count == 0 || count > 125))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "'count' must be between 1 and 125."));

            var registers = meter.Device.ReadHolding(start, count);

            if (registers is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 $"{start}..{start + count - 1} is outside this meter's registers."));

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               new JProperty("start",      start),
                               new JProperty("count",      count),
                               new JProperty("registers",  new JArray(registers.Select(register => (Int32) register)))
                           ))
                   );

        }

        #endregion

        #region (private) PutMeterMode    (Request)

        /// <summary>
        /// PUT /api/v1/meter/mode with {"mode": 0|1|2} or {"mode": "net"|"import"|"export"}:
        /// the meter mode register.
        /// </summary>
        private Task<HTTPResponse> PutMeterMode(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.WriteRegisters, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            var requested = json["mode"];

            if (requested is null)
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, "A 'mode' is required."));

            // The number a Modbus client would write, or the word a person
            // would type. The same three things either way.
            if (!SunSpecMeterModeExtensions.TryParse(requested.Value<String>(), out var mode))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                                 "'mode' is 0/'net', 1/'import' or 2/'export'."));

            if (!meter.Device.WriteHolding(SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterMeterMode), (UInt16) mode))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.InternalServerError,
                                                 "The meter mode register refused the write."));

            // What it now is rather than what was asked for: the device has
            // the last word on that, and this is where it says so.
            var now = meter.Device.Mode;

            meter.Log.Notice($"'{user.Id}' set the mode of this meter to {now.AsText()} ({(UInt16) now}).", "meter", "web");

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK, ModeJSON(now))
                   );

        }

        #endregion

        #region (private) PostResetEnergy (Request)

        /// <summary>
        /// POST /api/v1/meter/energy/reset: clear the energy counters.
        /// </summary>
        /// <remarks>
        /// The same magic value a Modbus client would write, through the same
        /// register, so that there is one way of clearing the counters and one
        /// place that reacts to it.
        /// </remarks>
        private Task<HTTPResponse> PostResetEnergy(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.WriteRegisters, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!meter.Device.WriteHolding(SunSpecMeterMap.Addr(SunSpecMeterMap.OffMeterResetEnergy), 0xCAFE))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.InternalServerError,
                                                 "The reset register refused the write."));

            meter.Log.Warning($"'{user.Id}' cleared the energy counters of this meter.", "meter", "web");

            var registers = meter.Device.ReadHolding(SunSpecMeterMap.BaseAddress, SunSpecMeterMap.RegisterCount);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           registers is not null
                               ? ReadingsJSON(registers)
                               : new JObject(new JProperty("ok", true)))
                   );

        }

        #endregion


        #region (private) GetConfiguration(Request)

        /// <summary>
        /// GET /api/v1/configuration: every section at once, for a page that
        /// would otherwise ask three times.
        /// </summary>
        private Task<HTTPResponse> GetConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               new JProperty("file",  meter.ConfigFile.Path),
                               new JProperty("dns",   meter.DNSConfigurationJSON()),
                               new JProperty("nts",   meter.NTSConfigurationJSON()),
                               new JProperty("time",  meter.ClockJSON())
                           ))
                   );

        }

        #endregion

        #region (private) GetDNSConfiguration(Request) / PutDNSConfiguration(Request)

        /// <summary>
        /// GET /api/v1/configuration/dns: how this meter resolves names.
        /// </summary>
        private Task<HTTPResponse> GetDNSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.DNSConfigurationJSON()));

        }

        /// <summary>
        /// PUT /api/v1/configuration/dns: change what may be changed about it.
        /// Answers with the whole section as it now stands, so that the page
        /// does not have to ask again to find out what it got.
        /// </summary>
        private Task<HTTPResponse> PutDNSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ChangeNetworkSettings, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!meter.TryUpdateDNSConfiguration(json, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            meter.Log.Notice($"'{user.Id}' changed the name resolution of this meter.", "dns", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.DNSConfigurationJSON()));

        }

        #endregion

        #region (private) GetNTSConfiguration(Request) / PutNTSConfiguration(Request) / PostNTSSync(Request)

        /// <summary>
        /// GET /api/v1/configuration/nts: where this meter reads the time.
        /// </summary>
        private Task<HTTPResponse> GetNTSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.NTSConfigurationJSON()));

        }

        /// <summary>
        /// PUT /api/v1/configuration/nts: point it at another time server.
        /// </summary>
        private Task<HTTPResponse> PutNTSConfiguration(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ChangeNetworkSettings, true, out var user, out var refused))
                return Task.FromResult(refused);

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return Task.FromResult(errorResponse);

            if (!meter.TryUpdateNTSConfiguration(json, out var error))
                return Task.FromResult(ErrorJSON(Request, HTTPStatusCode.BadRequest, error));

            meter.Log.Notice($"'{user.Id}' changed the time source of this meter.", "nts", "web");

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.NTSConfigurationJSON()));

        }

        /// <summary>
        /// POST /api/v1/configuration/nts/sync: check the clock now, and say
        /// what the time server answered.
        /// </summary>
        /// <remarks>
        /// A POST although it changes nothing here, because it makes this meter
        /// send traffic to a host somebody named - which is not something to
        /// leave sitting in a URL that a browser may repeat, prefetch or put in
        /// a history.
        /// </remarks>
        private async Task<HTTPResponse> PostNTSSync(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.RunDiagnostics, true, out var user, out var refused))
                return refused;

            meter.Log.Notice($"'{user.Id}' asked this meter to check its clock.", "nts", "web");

            return JSONResponse(
                       Request,
                       HTTPStatusCode.OK,
                       await meter.SyncTimeAsync(Request.CancellationToken)
                   );

        }

        #endregion

        #region (private) GetClock        (Request)

        /// <summary>
        /// GET /api/v1/configuration/time: what time it is here, and what that
        /// is worth.
        /// </summary>
        private Task<HTTPResponse> GetClock(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(JSONResponse(Request, HTTPStatusCode.OK, meter.ClockJSON()));

        }

        #endregion

        #region (private) GetCertificates (Request)

        /// <summary>
        /// GET /api/v1/configuration/certificates: which certificate this meter
        /// shows its Modbus/TLS clients, and which CA it lets them in by.
        /// </summary>
        /// <remarks>
        /// Subjects and validity only. A certificate is public by nature, but
        /// there is no reason for a browser to be handed the whole of one when
        /// the question behind the page is "which of them is this meter using,
        /// and has it expired".
        /// </remarks>
        private Task<HTTPResponse> GetCertificates(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(

                               new JProperty("meter",     new JObject(
                                   new JProperty("subject",     meter.MeterCertificate.Subject),
                                   new JProperty("issuer",      meter.MeterCertificate.Issuer),
                                   new JProperty("thumbprint",  meter.MeterCertificate.Thumbprint),
                                   new JProperty("notBefore",   meter.MeterCertificate.NotBefore.ToUniversalTime().ToString("o")),
                                   new JProperty("notAfter",    meter.MeterCertificate.NotAfter. ToUniversalTime().ToString("o"))
                               )),

                               new JProperty("clientCA",  new JObject(
                                   new JProperty("subject",     meter.ClientCA.Subject),
                                   new JProperty("issuer",      meter.ClientCA.Issuer),
                                   new JProperty("thumbprint",  meter.ClientCA.Thumbprint),
                                   new JProperty("notBefore",   meter.ClientCA.NotBefore.ToUniversalTime().ToString("o")),
                                   new JProperty("notAfter",    meter.ClientCA.NotAfter. ToUniversalTime().ToString("o"))
                               )),

                               new JProperty("sunSpecRoles",  new JArray(SunSpecRoles.AllMandatory))

                           ))
                   );

        }

        #endregion

        #region (private) GetLogs         (Request)

        /// <summary>
        /// GET /api/v1/logs?limit=&amp;after=&amp;tag=: what happened, oldest of
        /// the returned entries first.
        /// </summary>
        /// <remarks>
        /// This is the snapshot a browser loads before it starts following the
        /// event stream; "lastId" says how far it reaches, and everything the
        /// stream delivers with a greater id is new.
        ///
        /// Reading the configuration and not merely the meter, because the log
        /// holds the addresses peers connect from and every certificate that
        /// was turned away - which is more than somebody allowed to watch a
        /// meter's readings was given.
        /// </remarks>
        private Task<HTTPResponse> GetLogs(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            var limit = Request.QueryString.GetInt32 ("limit") ?? DefaultLogPageSize;
            var after = Request.QueryString.GetUInt64("after");
            var tag   = Request.QueryString.GetString("tag");

            if (limit < 1 || limit > MaxLogPageSize)
                return Task.FromResult(
                           ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'limit' must be between 1 and {MaxLogPageSize}.")
                       );

            var entries = meter.Log.Recent(limit, after, tag).ToArray();

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               // The whole log's last id and not the last of
                               // this page: a page filtered by a tag would
                               // otherwise make the browser ask again for
                               // everything between the two.
                               new JProperty("lastId",    meter.Log.LastId),
                               new JProperty("capacity",  meter.Log.Capacity),
                               new JProperty("tags",      new JArray(meter.Log.KnownTags)),
                               new JProperty("entries",   new JArray(entries.Select(entry => entry.ToJSON())))
                           ))
                   );

        }

        #endregion

        #region (private) GetLogVerification(Request)

        /// <summary>
        /// GET /api/v1/logs/verify: walk the log on disk and say whether it
        /// still leads to where it says it does.
        /// </summary>
        /// <remarks>
        /// The whole of it, every line, which is why this is its own resource
        /// and not part of reading the log: it is the expensive question, asked
        /// rarely and deliberately.
        ///
        /// The answer carries the public key and the head of the chain, because
        /// both are what somebody checking this from outside needs - the key to
        /// check the signatures themselves, and the head to compare against
        /// whatever they wrote down last time.
        /// </remarks>
        private Task<HTTPResponse> GetLogVerification(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out var user, out var refused))
                return Task.FromResult(refused);

            var store = meter.Log.Store;

            if (store is null)
                return Task.FromResult(
                           JSONResponse(Request, HTTPStatusCode.OK,
                               new JObject(
                                   new JProperty("persisted",  false),
                                   new JProperty("why",        "This meter keeps its log in memory only, so there is nothing signed to check.")
                               ))
                       );

            var result = store.Verify();

            meter.Log.Log(
                result.IsIntact ? Logging.LogLevel.Notice : Logging.LogLevel.Error,
                result.IsIntact
                    ? $"'{user.Id}' checked the log: {result.Entries} entries, intact."
                    : $"'{user.Id}' checked the log: {result.FirstProblem}",
                "meter", "log", "web"
            );

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(

                               new JProperty("persisted",     true),
                               new JProperty("intact",        result.IsIntact),
                               new JProperty("entries",       result.Entries),
                               new JProperty("head",          result.Head),
                               new JProperty("keyId",         result.KeyId),
                               new JProperty("publicKey",     store.Signer.PublicKeyPem),
                               new JProperty("path",          store.Path),
                               new JProperty("keepDays",      store.KeepDays),
                               new JProperty("firstProblem",  result.FirstProblem),

                               new JProperty("files",         new JArray(
                                   result.Files.Select(file => new JObject(
                                       new JProperty("name",     file.Name),
                                       new JProperty("entries",  file.Entries),
                                       new JProperty("intact",   file.IsIntact),
                                       new JProperty("problem",  file.Problem)
                                   ))
                               ))

                           ))
                   );

        }

        #endregion

        #region (private) StreamEvents    (Request)

        /// <summary>
        /// GET /api/v1/events: the Server-Sent Events stream every browser
        /// hangs on. Modelled on Hermod's MapEventSource, with the permission
        /// checked first and without opening the stream to other origins.
        /// </summary>
        private Task<HTTPResponse> StreamEvents(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ReadConfiguration, false, out _, out var refused))
                return Task.FromResult(refused);

            var clientId = Request.RemoteSocket.ToString();

            return Task.FromResult(
                       new HTTPResponse.Builder(Request) {

                           HTTPStatusCode  = HTTPStatusCode.OK,
                           Server          = HTTPServer.HTTPServerName,
                           ContentType     = HTTPContentType.Text.EVENTSTREAM,
                           CacheControl    = "no-cache",
                           Connection      = ConnectionType.KeepAlive,

                           HTTPSSEWorker   = async (response, stream) => {

                               // Either the browser going away or this meter
                               // shutting down ends the stream. The second one
                               // is not something the request's own token knows
                               // about - see CloseEventStreams().
                               using var ending = CancellationTokenSource.CreateLinkedTokenSource(
                                                      Request.CancellationToken,
                                                      shutdown.Token
                                                  );

                               try
                               {

                                   await stream.WriteAsync("retry: ");
                                   await stream.WriteAsync(((UInt32) Events.RetryInterval.TotalMilliseconds).ToString());
                                   await stream.WriteAsync("\n\n");

                                   // The preamble has to leave the buffer now,
                                   // not with the first event: on a quiet meter
                                   // the browser would otherwise wait for its
                                   // first byte until its own read timeout
                                   // expired.
                                   await stream.FlushAsync(ending.Token);

                                   await foreach (var httpEvent in Events.GetAllEventsGreater(
                                                                       clientId,
                                                                       Request.GetHeaderField(HTTPRequestHeaderField.LastEventId),
                                                                       ending.Token
                                                                   ))
                                   {
                                       await stream.WriteAsync(httpEvent.SerializedHeader);
                                       await stream.WriteAsync(httpEvent.SerializedData);
                                       await stream.WriteAsync("\n\n");
                                       await stream.FlushAsync(ending.Token);
                                   }

                               }
                               catch (OperationCanceledException)
                               {
                                   await Events.Unsubscribe(clientId);
                               }
                               catch (ObjectDisposedException)
                               {
                                   await Events.Unsubscribe(clientId);
                               }
                               catch (Exception e)
                               {
                                   await Events.Unsubscribe(clientId);

                                   // Not through the event log: an event stream
                                   // that ends because the browser went away is
                                   // the normal end of one, and logging it here
                                   // would publish an event to the very streams
                                   // that are closing.
                                   System.Diagnostics.Debug.WriteLine($"The event stream of {clientId} ended: {e.Message}");
                               }

                           }

                       }.AsImmutable
                   );

        }

        #endregion

        #region CloseEventStreams()

        /// <summary>
        /// End every open event stream, so that the HTTP server can stop.
        /// </summary>
        /// <remarks>
        /// An SSE response never completes by itself: it is a write loop
        /// waiting for the next event. Without this the server would wait for
        /// every browser that still has the page open.
        /// </remarks>
        public void CloseEventStreams()
        {
            try   { shutdown.Cancel(); }
            catch { }
        }

        #endregion

        #region (private) Publish        (SubEvent, JSON)

        /// <summary>
        /// Hands an event to every browser. Fire-and-forget on purpose: this is
        /// called from inside whatever wrote the log entry, and none of those
        /// should wait for a slow browser.
        /// </summary>
        private void Publish(String   SubEvent,
                             JObject  JSON)
        {

            Events.SubmitEvent(SubEvent, JSON).
                   ContinueWith(task => System.Diagnostics.Debug.WriteLine($"Publishing a '{SubEvent}' event failed: {task.Exception?.GetBaseException().Message}"),
                                TaskContinuationOptions.OnlyOnFaulted);

        }

        #endregion

        #region (private) UnknownPath     (Request)

        private Task<HTTPResponse> UnknownPath(HTTPRequest Request)

            => Task.FromResult(
                   ErrorJSON(Request, HTTPStatusCode.NotFound, $"Unknown resource '{Request.Path}'.")
               );

        #endregion


        #region (private) TryGetUser  (Request, out User, out Unauthorized)

        /// <summary>
        /// The person behind the session cookie, or the 401 that says there is
        /// none.
        /// </summary>
        private Boolean TryGetUser(HTTPRequest                             Request,
                                   [NotNullWhen(true)]  out IUser?         User,
                                   [NotNullWhen(false)] out HTTPResponse?  Unauthorized)
        {

            if (accounts.TryGetHTTPUser(Request, out var user) && user is not null)
            {
                User          = user;
                Unauthorized  = null;
                return true;
            }

            User          = null;
            Unauthorized  = ErrorJSON(Request, HTTPStatusCode.Unauthorized, "Sign in first.");
            return false;

        }

        #endregion

        #region (private) RoleOf      (User)

        /// <summary>
        /// The role this person holds in the meter's organization, or null when
        /// they hold none.
        /// </summary>
        /// <remarks>
        /// The strongest of them when there are several. Somebody made both a
        /// member and an administrator is an administrator; taking the first
        /// edge found instead would make their rights depend on the order the
        /// account database happened to be written in.
        /// </remarks>
        private User2OrganizationEdgeLabel? RoleOf(IUser User)
        {

            User2OrganizationEdgeLabel? strongest   = null;
            var                         permissions = MeterPermissions.None;

            foreach (var edge in User.User2Organization_OutEdges)
            {

                if (edge.Target.Id.ToString() != ModbusTLSEnergyMeter.MeterOrganizationId)
                    continue;

                var candidate = edge.EdgeLabel.PermissionsOf();

                if (strongest is null || candidate > permissions)
                {
                    strongest    = edge.EdgeLabel;
                    permissions  = candidate;
                }

            }

            return strongest;

        }

        #endregion

        #region (private) TryAuthorize(Request, Required, StateChanging, out User, out Refused)

        /// <summary>
        /// The person behind the request, when they are allowed to do this - or
        /// the response that says why not.
        /// </summary>
        /// <remarks>
        /// Three refusals, in the order they have to happen: a request from
        /// another site is turned away before it is read at all, a request
        /// without a session is a 401, and a request from somebody signed in
        /// who may not do this is a 403 naming the permission they are short
        /// of. The difference between the last two matters to a browser: 401
        /// means sign in again, 403 means signing in again will not help.
        /// </remarks>
        /// <param name="Request">The request.</param>
        /// <param name="Required">What this request needs permission to do.</param>
        /// <param name="StateChanging">Whether it changes something, and is therefore also checked for being cross-site.</param>
        /// <param name="User">The person behind it.</param>
        /// <param name="Refused">The response to send instead.</param>
        internal Boolean TryAuthorize(HTTPRequest                             Request,
                                     MeterPermissions                        Required,
                                     Boolean                                 StateChanging,
                                     [NotNullWhen(true)]  out IUser?         User,
                                     [NotNullWhen(false)] out HTTPResponse?  Refused)
        {

            User = null;

            if (StateChanging && RefuseCrossSite(Request) is HTTPResponse crossSite)
            {
                Refused = crossSite;
                return false;
            }

            if (!TryGetUser(Request, out User, out Refused))
                return false;

            var role        = RoleOf(User);
            var permissions = role?.PermissionsOf() ?? MeterPermissions.None;

            if (!permissions.HasFlag(Required))
            {

                Refused = JSONResponse(Request, HTTPStatusCode.Forbidden,
                              new JObject(
                                  new JProperty("error",     $"'{User.Id}' may not do this."),
                                  new JProperty("required",  Required.ToString()),
                                  new JProperty("role",      role?.ToString()),
                                  new JProperty("granted",   new JArray(permissions.Names()))
                              ));

                User = null;
                return false;

            }

            Refused = null;
            return true;

        }

        #endregion

        #region (private static) RefuseCrossSite(Request)

        /// <summary>
        /// The 403 for a request that another site made the browser send, or
        /// null when the request is our own page's.
        /// </summary>
        /// <remarks>
        /// The session cookie is SameSite=strict, so a cross-site request would
        /// arrive without a session anyway. This is the second lock on the same
        /// door: browsers say where a request came from (Sec-Fetch-Site,
        /// Origin), and a state-changing request from anywhere but this origin
        /// is refused before it is even read.
        /// </remarks>
        private static HTTPResponse? RefuseCrossSite(HTTPRequest Request)
        {

            var site = Request.GetHeaderField("Sec-Fetch-Site");

            if (site is not null && site is not ("same-origin" or "none"))
                return ErrorJSON(Request, HTTPStatusCode.Forbidden, "Cross-site requests are refused.");

            var origin = Request.GetHeaderField("Origin");

            if (origin is not null && origin != "null")
            {

                var host = Request.GetHeaderField("Host") ?? "";

                if (!Uri.TryCreate(origin, UriKind.Absolute, out var uri) ||
                    !uri.Authority.Equals(host, StringComparison.OrdinalIgnoreCase))
                {
                    return ErrorJSON(Request, HTTPStatusCode.Forbidden, "Cross-site requests are refused.");
                }

            }

            return null;

        }

        #endregion

        #region (private static) TryParseJSONObject(Request, out JSON, out ErrorResponse)

        /// <summary>
        /// The request body as a JSON object, or the 400 response describing
        /// what is wrong with it.
        /// </summary>
        internal static Boolean TryParseJSONObject(HTTPRequest                             Request,
                                                  [NotNullWhen(true)]  out JObject?       JSON,
                                                  [NotNullWhen(false)] out HTTPResponse?  ErrorResponse)
        {

            JSON           = null;
            ErrorResponse  = null;

            var text = Request.HTTPBodyAsUTF8String;

            if (String.IsNullOrWhiteSpace(text))
            {
                ErrorResponse = ErrorJSON(Request, HTTPStatusCode.BadRequest, "The request body must be a JSON object!");
                return false;
            }

            try
            {
                JSON = JObject.Parse(text);
                return true;
            }
            catch (JsonException e)
            {
                ErrorResponse = ErrorJSON(Request, HTTPStatusCode.BadRequest, $"Invalid JSON: {e.Message}");
                return false;
            }

        }

        #endregion

        #region (private static) ReadingsJSON(Registers)

        /// <summary>
        /// The register block as the numbers it stands for: the scale factors
        /// applied, the strings unpacked, the two energy counters put back
        /// together.
        /// </summary>
        private static JObject ReadingsJSON(UInt16[] Registers)
        {

            var currentSF    = (Int16) Registers[SunSpecMeterMap.OffMeterA_SF];
            var voltageSF    = (Int16) Registers[SunSpecMeterMap.OffMeterV_SF];
            var frequencySF  = (Int16) Registers[SunSpecMeterMap.OffMeterHz_SF];
            var powerSF      = (Int16) Registers[SunSpecMeterMap.OffMeterW_SF];
            var energySF     = (Int16) Registers[SunSpecMeterMap.OffMeterWh_SF];

            return new JObject(

                       new JProperty("manufacturer",  Text(Registers, SunSpecMeterMap.OffCommonMn,  16)),
                       new JProperty("model",         Text(Registers, SunSpecMeterMap.OffCommonMd,  16)),
                       new JProperty("options",       Text(Registers, SunSpecMeterMap.OffCommonOpt,  8)),
                       new JProperty("version",       Text(Registers, SunSpecMeterMap.OffCommonVr,   8)),
                       new JProperty("serialNumber",  Text(Registers, SunSpecMeterMap.OffCommonSN,  16)),
                       new JProperty("unitAddress",   Registers[SunSpecMeterMap.OffCommonDA]),
                       new JProperty("sunSpecModel",  Registers[SunSpecMeterMap.OffMeterId]),

                       new JProperty("frequency_Hz",  Scaled((Int16) Registers[SunSpecMeterMap.OffMeterHz], frequencySF)),

                       new JProperty("phases",        new JArray(
                           PhaseJSON("L1", Registers, SunSpecMeterMap.OffMeterPhVphA, SunSpecMeterMap.OffMeterAphA, SunSpecMeterMap.OffMeterWphA, voltageSF, currentSF, powerSF),
                           PhaseJSON("L2", Registers, SunSpecMeterMap.OffMeterPhVphB, SunSpecMeterMap.OffMeterAphB, SunSpecMeterMap.OffMeterWphB, voltageSF, currentSF, powerSF),
                           PhaseJSON("L3", Registers, SunSpecMeterMap.OffMeterPhVphC, SunSpecMeterMap.OffMeterAphC, SunSpecMeterMap.OffMeterWphC, voltageSF, currentSF, powerSF)
                       )),

                       new JProperty("total",         PhaseJSON("total", Registers, SunSpecMeterMap.OffMeterPhV, SunSpecMeterMap.OffMeterA, SunSpecMeterMap.OffMeterW, voltageSF, currentSF, powerSF)),

                       new JProperty("energy",        new JObject(
                           new JProperty("exported_Wh",  Scaled((Int64) UInt32At(Registers, SunSpecMeterMap.OffMeterTotWhExp), energySF)),
                           new JProperty("imported_Wh",  Scaled((Int64) UInt32At(Registers, SunSpecMeterMap.OffMeterTotWhImp), energySF))
                       )),

                       new JProperty("meterMode",     ModeJSON((SunSpecMeterMode) Registers[SunSpecMeterMap.OffMeterMeterMode]))

                   );

        }

        /// <summary>
        /// The mode register as a number, a word and a sentence: the number is
        /// what a Modbus client writes, and the other two are so that nobody
        /// reading this has to keep a table of three integers in their head.
        /// </summary>
        private static JObject ModeJSON(SunSpecMeterMode Mode)

            => new (
                   new JProperty("value",        (UInt16) Mode),
                   new JProperty("name",         Mode.AsText()),
                   new JProperty("description",  Mode.Description())
               );

        private static JObject PhaseJSON(String    Name,
                                         UInt16[]  Registers,
                                         UInt16    VoltageOffset,
                                         UInt16    CurrentOffset,
                                         UInt16    PowerOffset,
                                         Int16     VoltageSF,
                                         Int16     CurrentSF,
                                         Int16     PowerSF)

            => new (
                   new JProperty("name",       Name),
                   new JProperty("voltage_V",  Scaled((Int16) Registers[VoltageOffset], VoltageSF)),
                   new JProperty("current_A",  Scaled((Int16) Registers[CurrentOffset], CurrentSF)),
                   new JProperty("power_W",    Scaled((Int16) Registers[PowerOffset],   PowerSF))
               );

        /// <summary>
        /// A SunSpec value and its decimal scale factor, as the number it means.
        /// </summary>
        private static Double Scaled(Int64  Value,
                                     Int16  ScaleFactor)

            => Math.Round(Value * Math.Pow(10, ScaleFactor), Math.Max(0, -ScaleFactor));

        /// <summary>
        /// A SunSpec string: ASCII, two characters per register, padded with NUL.
        /// </summary>
        private static String Text(UInt16[]  Registers,
                                   UInt16    Offset,
                                   Int32     Length)
        {

            var bytes = new Byte[Length * 2];

            for (var i = 0; i < Length; i++)
            {
                bytes[2 * i]     = (Byte) (Registers[Offset + i] >> 8);
                bytes[2 * i + 1] = (Byte) (Registers[Offset + i] & 0xFF);
            }

            return Encoding.ASCII.GetString(bytes).TrimEnd('\0', ' ');

        }

        private static UInt32 UInt32At(UInt16[]  Registers,
                                       UInt16    Offset)

            => ((UInt32) Registers[Offset] << 16) | Registers[Offset + 1];

        #endregion

        #region (private static) ErrorJSON(...) / JSONResponse(...)

        internal static HTTPResponse ErrorJSON(HTTPRequest     Request,
                                              HTTPStatusCode  StatusCode,
                                              String          Message)

            => JSONResponse(
                   Request,
                   StatusCode,
                   new JObject(new JProperty("error", Message))
               );


        internal static HTTPResponse JSONResponse(HTTPRequest     Request,
                                                 HTTPStatusCode  StatusCode,
                                                 JToken          JSON)

            => new HTTPResponse.Builder(Request) {
                   HTTPStatusCode  = StatusCode,
                   ContentType     = HTTPContentType.Application.JSON_UTF8,
                   Content         = Encoding.UTF8.GetBytes(JSON.ToString(Formatting.None)),
                   CacheControl    = "no-store"
               }.AsImmutable;

        #endregion

    }

}
