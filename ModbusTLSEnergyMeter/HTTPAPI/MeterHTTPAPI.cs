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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Web;

using LogLevel = cloud.charging.open.protocols.WWCP.Node.Logging.LogLevel;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// The JSON API of this energy meter, registered at "/api": what every
    /// node has - see <see cref="NodeHTTPAPI"/> - and what only a meter has on
    /// top: what it is measuring, its signed values and charging sessions, its
    /// signing keys, its accounts, its certificate signing requests, and its
    /// log book to be checked.
    /// </summary>
    /// <remarks>
    /// Signing out and who is signed in, the status and the clock, the
    /// configuration, name resolution and the time servers, the certificate
    /// store, the log and the event stream are the node's, as they are the
    /// vehicle's and the local controller's; this class used to have its own
    /// copy of all of them. What is left here is registered on top: see
    /// MeterHTTPAPI.Accounts.cs, MeterHTTPAPI.Certificates.cs and
    /// MeterHTTPAPI.SignedValues.cs.
    ///
    /// Signing in is not here: that is the node's <see cref="HTTPExtAPI"/>'s
    /// "/ext/auth/login", and the session cookie it sets is what every resource
    /// below is read with.
    /// </remarks>
    public partial class MeterHTTPAPI : NodeHTTPAPI
    {

        #region Data

        /// <summary>
        /// The default root path of this API.
        /// </summary>
        public static readonly HTTPPath  DefaultAPIPath          = HTTPPath.Parse("/api");

        /// <summary>
        /// What the files of the web interface are called as resources of this
        /// assembly: the namespace, "HTTPRoot", and the path below dist/ with
        /// dots - see the Frontend targets in the project file.
        /// </summary>
        public const           String    FrontendResourcePrefix  = "cloud.charging.open.EnergyMeters.ModbusTLS.HTTPRoot.";

        private readonly ModbusTLSEnergyMeter  meter;
        private readonly DateTimeOffset        startedAt;

        #endregion

        #region Properties

        /// <summary>
        /// The meter this API speaks for.
        /// </summary>
        public ModbusTLSEnergyMeter  Meter
            => meter;

        /// <summary>
        /// Who is signed in, and what they belong to: the node's accounts.
        /// </summary>
        private HTTPExtAPI accounts
            => ExtAPI;

        #endregion

        #region Constructor(s)

        /// <summary>
        /// Create and register the JSON API of a meter within its HTTP server.
        /// </summary>
        /// <param name="Meter">The meter this API speaks for.</param>
        /// <param name="Accounts">Who is signed in, and what they belong to.</param>
        /// <param name="APIPath">The root path of the API, "/api" by default.</param>
        public MeterHTTPAPI(ModbusTLSEnergyMeter  Meter,
                            HTTPExtAPI            Accounts,
                            HTTPPath?             APIPath   = null)

            : base(Meter.HTTPServer,
                   Meter,
                   Accounts,
                   Meter.Log,
                   APIPath ?? DefaultAPIPath,
                   Meter.Version)

        {

            this.meter      = Meter;
            this.startedAt  = Meter.TimeProvider.GetUtcNow();

            RegisterURLTemplates();

        }

        #endregion


        #region (private) RegisterURLTemplates()

        /// <summary>
        /// What only a meter has, on top of what every node has.
        /// </summary>
        private void RegisterURLTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/meter",                      GetMeter,            HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/meter/registers",            GetRegisters,        HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/meter/mode",                 PutMeterMode,        HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/meter/energy/reset",         PostResetEnergy,     HTTPMethod.POST);

            AddHandler(HTTPPath.Root + "v1/configuration/certificates", GetCertificates,     HTTPMethod.GET);

            RegisterCertificateTemplates();
            RegisterAccountTemplates();
            RegisterSignedValueTemplates();

            AddHandler(HTTPPath.Root + "v1/logs/verify",                GetLogVerification,  HTTPMethod.GET);

        }

        #endregion

        #region (protected override) ProductMe(User) / ProductStatus() / ToReadTheClock / ToReadTheLog

        /// <summary>
        /// What a meter says about who is signed in beyond every node's: their
        /// name and organization, and their strongest role here - as this meter
        /// spells it and as a person would say it, with what it grants.
        /// </summary>
        /// <remarks>
        /// The role travels twice: once as this meter spells it and once as a
        /// person would say it. Every page that tells somebody what they may
        /// not do here names their role in the same breath, and "systemadmin"
        /// is not a thing anybody says. Sending the readable form with the role
        /// it belongs to is one field; the alternative is every page fetching
        /// the role table to translate one word. Null for somebody who holds no
        /// role here, so that a page can fall back to its own wording.
        /// </remarks>
        protected override IEnumerable<JProperty> ProductMe(IUser User)
        {

            var role = MeterAccess.Strongest(meter.Access, meter.RolesOf(User));

            yield return new JProperty("name",             User.Name.FirstText());
            yield return new JProperty("organization",     meter.Kind.Organization);
            yield return new JProperty("role",             role?.Name);
            yield return new JProperty("roleTitle",        role is not null ? MeterAccess.TitleOf(role)       : null);
            yield return new JProperty("roleDescription",  role is not null ? MeterAccess.DescriptionOf(role) : null);

        }

        /// <summary>
        /// What the status of a meter says beyond every node's: which meter it
        /// is, where Modbus/TLS listens, and where the web interface is.
        /// </summary>
        protected override IEnumerable<JProperty> ProductStatus()
        {

            yield return new JProperty("serialNumber",  meter.SerialNumber);
            yield return new JProperty("device",        meter.Device.DisplayName);

            yield return new JProperty("modbus",        new JObject(
                             new JProperty("address",        meter.ListenAddress.ToString()),
                             new JProperty("port",           meter.ListenPort),
                             new JProperty("running",        meter.IsRunning),
                             new JProperty("baseAddress",    meter.Device.BaseAddress),
                             new JProperty("registerCount",  meter.Device.RegisterCount)
                         ));

            yield return new JProperty("web",           new JObject(
                             new JProperty("url",            meter.WebInterfaceURL.ToString())
                         ));

        }

        /// <summary>
        /// Reading the clock needs the reading permission of the time servers,
        /// as it did at its old path: what time it is here is what every
        /// reading is stamped with, and whether that is worth anything is the
        /// time servers' business.
        /// </summary>
        protected override Permission? ToReadTheClock
            => Permission.Read(NodeResources.NTS);

        /// <summary>
        /// The log and its event stream need the meter's own "log:read": the
        /// log holds the addresses peers connect from and every certificate
        /// that was turned away - which is more than somebody allowed to watch
        /// a meter's readings was given.
        /// </summary>
        protected override Permission? ToReadTheLog
            => Permission.Read(MeterAccess.Log);

        #endregion


        #region (private) GetMeter        (Request)

        /// <summary>
        /// GET /api/v1/meter: what the meter is measuring, as numbers rather
        /// than as registers.
        /// </summary>
        private Task<HTTPResponse> GetMeter(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Meter), false, out _, out var refused))
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

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Meter), false, out _, out var refused))
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

            if (!TryAuthorize(Request, Permission.Edit(MeterAccess.Meter), true, out var user, out var refused))
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

            if (!TryAuthorize(Request, Permission.Edit(MeterAccess.Meter), true, out var user, out var refused))
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

            if (!TryAuthorize(Request, Permission.Read(NodeResources.Certificates), false, out _, out var refused))
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

        #region (private) GetLogVerification(Request)

        /// <summary>
        /// GET /api/v1/logs/verify: walk the log book - the node's metrological
        /// log - on disk and say whether it still leads to where it says it
        /// does.
        /// </summary>
        /// <remarks>
        /// The whole of it, every line, which is why this is its own resource
        /// and not part of reading the log: it is the expensive question, asked
        /// rarely and deliberately. The log book, which is what is signed: the
        /// ordinary log files beside it are for reading.
        ///
        /// The answer carries the public key and the head of the chain, because
        /// both are what somebody checking this from outside needs - the key to
        /// check the signatures themselves, and the head to compare against
        /// whatever they wrote down last time.
        /// </remarks>
        private Task<HTTPResponse> GetLogVerification(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, Permission.Read(MeterAccess.Log), false, out var user, out var refused))
                return Task.FromResult(refused);

            var store = meter.MetrologicalLog;

            if (store is null)
                return Task.FromResult(
                           JSONResponse(Request, HTTPStatusCode.OK,
                               new JObject(
                                   new JProperty("persisted",  false),
                                   new JProperty("why",        "This meter writes no log files, and so keeps no log book to check.")
                               ))
                       );

            var result = store.Verify();

            meter.Log.Log(
                result.IsIntact ? LogLevel.Notice : LogLevel.Error,
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
                               new JProperty("metrological",  true),
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

    }

}
