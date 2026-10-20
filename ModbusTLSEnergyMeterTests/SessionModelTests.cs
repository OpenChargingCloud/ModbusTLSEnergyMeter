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

using System.Buffers.Binary;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.chargy;
using cloud.charging.open.chargy.Formats.OCMF;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;

using cloud.charging.open.EnergyMeters.ModbusTLS.Signing;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// The session model: a charging session begun and ended over Modbus, and
    /// the document it ends in.
    /// </summary>
    /// <remarks>
    /// Most of these talk to the session model's backend directly, as the
    /// Modbus/TLS frontend does once it has let a request through. What the
    /// frontend decides - which role may begin a session - is asked of a meter
    /// over Modbus/TLS at the end. Every document is checked by ChargyCore and
    /// not by anything written here.
    /// </remarks>
    public class SessionModelTests
    {

        #region Data

        private String?              workingDirectory;
        private SunSpecMeterDevice?  device;
        private MeterKeyStore?       keys;
        private SessionSigner?       signer;

        private const String         ATariff = "001;EUR;0;35;0;0";

        #endregion

        #region Setup / TearDown

        [SetUp]
        public void Setup()
        {

            workingDirectory = Path.Combine(
                                   Path.GetTempPath(),
                                   "ModbusTLSEnergyMeterTests",
                                   Guid.NewGuid().ToString("N")
                               );

            Directory.CreateDirectory(workingDirectory);

            device = new SunSpecMeterDevice("meter-session-001", SunSpecMeterMode.ImportOnly, runSimulation: false);

            Assert.That(device.RestoreEnergyCounters(12500, 0, 0), Is.True);

            keys   = new MeterKeyStore(Path.Combine(workingDirectory, "keys"));
            keys.EnsureIdentity();

            signer = SignerOn(new SunSpecBackendFactory(device), Path.Combine(workingDirectory, "sessions"));

        }

        [TearDown]
        public void TearDown()
        {

            device?.Dispose();

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file still held is not what is under test */ }
            }

        }

        #endregion


        #region TheSessionModel_FollowsTheModelsOfTheDevice()

        /// <summary>
        /// Whoever walks the list of models from "SunS" finds the device's
        /// models, then the session model, then the end of the list.
        /// </summary>
        [Test]
        public async Task TheSessionModel_FollowsTheModelsOfTheDevice()
        {

            var model  = await ModelBehind(new SunSpecBackendFactory(device!));
            var chain  = await SunSpecChain.Walk(SunSpecChain.Of(await model.CreateAsync(1, SunSpecRoles.ReadOnly, default)));

            Assert.Multiple(() => {

                Assert.That(chain.Models.Select(m => m.Id),  Is.EqualTo(new UInt16[] { 1, 213, SessionModel.Id }));
                Assert.That(chain.Models[2].Address,         Is.EqualTo(40096), "the session model is where the device's list ended");
                Assert.That(chain.Models[2].Length,          Is.EqualTo(SessionModel.Length));
                Assert.That(chain.End,                       Is.EqualTo(40096 + 2 + SessionModel.Length));

            });

        }

        #endregion

        #region AReadAcrossTheDeviceAndTheModel_GetsBoth()

        /// <summary>
        /// One read that begins in the device's registers and ends in the
        /// model's gets the device's from the device and the model's from the
        /// model.
        /// </summary>
        [Test]
        public async Task AReadAcrossTheDeviceAndTheModel_GetsBoth()
        {

            var model      = await ModelBehind(new SunSpecBackendFactory(device!));
            var connection = new Connection(await model.CreateAsync(1, SunSpecRoles.ReadOnly, default), model.ModelAddress);

            var registers  = await connection.Read(40091, 8);

            Assert.Multiple(() => {

                Assert.That(((UInt32) registers[0] << 16) | registers[1],  Is.EqualTo(12500), "the device's imported energy");
                Assert.That(registers[5],                                   Is.EqualTo(SessionModel.Id));
                Assert.That(registers[6],                                   Is.EqualTo(SessionModel.Length));
                Assert.That(registers[7 + 0],                               Is.EqualTo(0),    "the command register reads 0");

            });

        }

        #endregion

        #region AStartAndAStop_EndInOneDocumentChargyVerifies()

        /// <summary>
        /// Who charged, where, on which tariff, the reading it began at and the
        /// one it ended at - in one document that ChargyCore verifies against
        /// the key the model hands out beside it.
        /// </summary>
        [Test]
        public async Task AStartAndAStop_EndInOneDocumentChargyVerifies()
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            Assert.That(await connection.State(), Is.EqualTo(SessionModelState.None));

            await connection.Give(SessionModel.IdentificationType,  SessionModel.IdentificationTypeLength,  "ISO14443");
            await connection.Give(SessionModel.Identification,      SessionModel.IdentificationLength,      "DEADBEEF01");
            await connection.Give(SessionModel.ChargePointIdType,   SessionModel.ChargePointIdTypeLength,   "EVSEID");
            await connection.Give(SessionModel.ChargePointId,       SessionModel.ChargePointIdLength,       "DE*GEF*E12345678*1");
            await connection.Give(SessionModel.TariffText,          SessionModel.TariffTextLength,          ATariff);
            await connection.Give(SessionModel.SessionId,           SessionModel.SessionIdLength,           "station-session-1");

            Assert.That(await connection.Command(SessionCommand.Start), Is.Null, await connection.ErrorText());

            await Assert.MultipleAsync(async () => {
                Assert.That(await connection.State(),             Is.EqualTo(SessionModelState.Running));
                Assert.That(await connection.CurrentSessionId(),  Is.EqualTo("station-session-1"));
                Assert.That(await connection.Document(),          Is.Empty, "there is no document while a session runs");
            });

            Assert.That(device!.RestoreEnergyCounters(15750, 0, 0), Is.True);

            await connection.Give(SessionModel.SessionId, SessionModel.SessionIdLength, "station-session-1");

            Assert.That(await connection.Command(SessionCommand.Stop), Is.Null, await connection.ErrorText());

            var document  = await connection.Document();
            var publicKey = await connection.PublicKey();

            await Assert.MultipleAsync(async () => {
                Assert.That(await connection.State(),             Is.EqualTo(SessionModelState.Stopped));
                Assert.That(await connection.CurrentSessionId(),  Is.EqualTo("station-session-1"), "the document says whose it is");
                Assert.That(Verify(document, publicKey),          Is.EqualTo(VerificationResult.ValidSignature));
            });

            var payload = Payload(document);

            Assert.Multiple(() => {

                Assert.That(payload["FV"]?.Value<String>(),  Is.EqualTo("1.1"),                  "a document with a tariff text is of a version that has one");
                Assert.That(payload["IS"]?.Value<Boolean>(), Is.True);
                Assert.That(payload["IT"]?.Value<String>(),  Is.EqualTo("ISO14443"));
                Assert.That(payload["ID"]?.Value<String>(),  Is.EqualTo("DEADBEEF01"));
                Assert.That(payload["CT"]?.Value<String>(),  Is.EqualTo("EVSEID"));
                Assert.That(payload["CI"]?.Value<String>(),  Is.EqualTo("DE*GEF*E12345678*1"));
                Assert.That(payload["TT"]?.Value<String>(),  Is.EqualTo(ATariff));
                Assert.That(payload["PG"]?.Value<String>(),  Does.StartWith("T"));

                Assert.That(payload.ToString(),              Does.Not.Contain("station-session-1"),
                            "OCMF has no field for the station's session id, and none of this meter's own is signed");

                Assert.That(payload["RD"]!.Select(reading => reading["TX"]?.Value<String>()),  Is.EqualTo(new[] { "B", "E" }));
                Assert.That(payload["RD"]!.Select(reading => reading["RV"]!.Value<Decimal>()), Is.EqualTo(new[] { 12.5m, 15.75m }));

            });

        }

        #endregion

        #region WhatOneConnectionWrote_IsNotAnothersToStartWith()

        /// <summary>
        /// A card written by one connection is not signed into a session another
        /// connection begins.
        /// </summary>
        [Test]
        public async Task WhatOneConnectionWrote_IsNotAnothersToStartWith()
        {

            var model  = await ModelBehind(new SunSpecBackendFactory(device!));
            var first  = await StationOn(model);
            var second = await StationOn(model, 2);

            await first.Give(SessionModel.IdentificationType, SessionModel.IdentificationTypeLength, "ISO14443");
            await first.Give(SessionModel.Identification,     SessionModel.IdentificationLength,     "DEADBEEF01");

            await Assert.MultipleAsync(async () => {
                Assert.That(await second.Given(SessionModel.Identification, SessionModel.IdentificationLength), Is.Empty,
                            "what the first connection wrote is not in the second's registers");
                Assert.That(await second.Command(SessionCommand.Start), Is.Null, await second.ErrorText());
            });

            Assert.That(signer!.Sessions.Current!.Identification, Is.Null, "the second connection identified nobody");

        }

        #endregion

        #region NothingIsLeftOver_ForTheNextCommand()

        /// <summary>
        /// What was written for one start is gone once it was done: a second
        /// start that writes nothing identifies nobody.
        /// </summary>
        [Test]
        public async Task NothingIsLeftOver_ForTheNextCommand()
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            await connection.Give(SessionModel.IdentificationType, SessionModel.IdentificationTypeLength, "ISO14443");
            await connection.Give(SessionModel.Identification,     SessionModel.IdentificationLength,     "DEADBEEF01");
            await connection.Give(SessionModel.TariffText,         SessionModel.TariffTextLength,         ATariff);

            Assert.That(await connection.Command(SessionCommand.Start), Is.Null);
            Assert.That(await connection.Command(SessionCommand.Stop),  Is.Null);

            Assert.That(await connection.Given(SessionModel.Identification, SessionModel.IdentificationLength), Is.Empty);

            Assert.That(await connection.Command(SessionCommand.Start), Is.Null);

            Assert.Multiple(() => {
                Assert.That(signer!.Sessions.Current!.Identification,         Is.Null);
                Assert.That(signer!.Sessions.Current!.Parameters.TariffText,  Is.Null);
            });

        }

        #endregion

        #region AStopNamingAnotherSession_IsRefused_AndTheSessionRuns()

        /// <summary>
        /// A stop that names a session other than the one running is refused,
        /// says why, and leaves the running one running.
        /// </summary>
        [Test]
        public async Task AStopNamingAnotherSession_IsRefused_AndTheSessionRuns()
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            await connection.Give(SessionModel.SessionId, SessionModel.SessionIdLength, "station-session-1");
            Assert.That(await connection.Command(SessionCommand.Start), Is.Null);

            await connection.Give(SessionModel.SessionId, SessionModel.SessionIdLength, "station-session-2");

            await Assert.MultipleAsync(async () => {

                Assert.That(await connection.Command(SessionCommand.Stop),  Is.EqualTo(ModbusExceptionCode.IllegalDataValue));
                Assert.That(await connection.Error(),                        Is.EqualTo(SessionRefusalKind.NotThisSession));
                Assert.That(await connection.ErrorText(),                    Does.Contain("station-session-1").And.Contain("station-session-2"));
                Assert.That(await connection.State(),                        Is.EqualTo(SessionModelState.Running));

            });

            Assert.That(await connection.Command(SessionCommand.Stop), Is.Null, "a stop naming nobody stops whatever runs");
            Assert.That(await connection.Error(),                      Is.EqualTo(SessionRefusalKind.None), "and the error is gone with it");

        }

        #endregion

        #region AStartWhileOneRuns_IsRefused()

        [Test]
        public async Task AStartWhileOneRuns_IsRefused()
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            Assert.That(await connection.Command(SessionCommand.Start), Is.Null);

            await Assert.MultipleAsync(async () => {
                Assert.That(await connection.Command(SessionCommand.Start),  Is.EqualTo(ModbusExceptionCode.IllegalDataValue));
                Assert.That(await connection.Error(),                         Is.EqualTo(SessionRefusalKind.AlreadyRunning));
                Assert.That(await connection.ErrorText(),                     Does.Contain("already running"));
            });

        }

        #endregion

        #region WhatOCMFDoesNotKnow_IsNotBegun()

        /// <summary>
        /// An identification type OCMF has no name for, and a charge point
        /// nothing says the kind of, begin no session.
        /// </summary>
        [TestCase("ISO14443X", "DEADBEEF01", null,     null,             "ISO14443X")]
        [TestCase(null,        null,         null,     "DE*GEF*E1*1",    "EVSEID")]
        [TestCase(null,        null,         "SOCKET", "DE*GEF*E1*1",    "SOCKET")]
        public async Task WhatOCMFDoesNotKnow_IsNotBegun(String?  IdentificationType,
                                                         String?  Identification,
                                                         String?  ChargePointIdType,
                                                         String?  ChargePointId,
                                                         String   Said)
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            await connection.Give(SessionModel.IdentificationType,  SessionModel.IdentificationTypeLength,  IdentificationType);
            await connection.Give(SessionModel.Identification,      SessionModel.IdentificationLength,      Identification);
            await connection.Give(SessionModel.ChargePointIdType,   SessionModel.ChargePointIdTypeLength,   ChargePointIdType);
            await connection.Give(SessionModel.ChargePointId,       SessionModel.ChargePointIdLength,       ChargePointId);

            await Assert.MultipleAsync(async () => {
                Assert.That(await connection.Command(SessionCommand.Start),  Is.EqualTo(ModbusExceptionCode.IllegalDataValue));
                Assert.That(await connection.Error(),                         Is.EqualTo(SessionRefusalKind.InvalidParameter));
                Assert.That(await connection.ErrorText(),                     Does.Contain(Said));
                Assert.That(signer!.Sessions.Current,                         Is.Null);
            });

        }

        #endregion

        #region WhatIsOnlyRead_IsNotWritten()

        /// <summary>
        /// The model's id, its state, its document and the end of the list are
        /// read and never written; neither is a write that is half the
        /// device's and half the model's.
        /// </summary>
        [TestCase(40096,                                              1)]
        [TestCase(40098 + SessionModel.State,                         1)]
        [TestCase(40098 + SessionModel.Document,                      4)]
        [TestCase(40098 + SessionModel.Length,                        2)]
        [TestCase(40094,                                              3)]
        public async Task WhatIsOnlyRead_IsNotWritten(Int32 First, Int32 Count)
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            Assert.That(await connection.Write((UInt16) First, new UInt16[Count]), Is.EqualTo(ModbusExceptionCode.IllegalDataAddress));

        }

        #endregion

        #region TheDocument_SurvivesARestart()

        /// <summary>
        /// The document of the last session is still there for whoever stopped
        /// it after the meter was restarted, and goes when the next begins.
        /// </summary>
        [Test]
        public async Task TheDocument_SurvivesARestart()
        {

            var connection = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            await connection.Give(SessionModel.SessionId, SessionModel.SessionIdLength, "station-session-1");
            Assert.That(await connection.Command(SessionCommand.Start), Is.Null);
            Assert.That(await connection.Command(SessionCommand.Stop),  Is.Null);

            var document  = await connection.Document();

            signer        = SignerOn(new SunSpecBackendFactory(device!), Path.Combine(workingDirectory!, "sessions"));
            var restarted = await StationOn(await ModelBehind(new SunSpecBackendFactory(device!)));

            await Assert.MultipleAsync(async () => {
                Assert.That(await restarted.State(),             Is.EqualTo(SessionModelState.Stopped));
                Assert.That(await restarted.Document(),          Is.EqualTo(document));
                Assert.That(await restarted.CurrentSessionId(),  Is.EqualTo("station-session-1"));
                Assert.That(Verify(await restarted.Document(), await restarted.PublicKey()), Is.EqualTo(VerificationResult.ValidSignature));
            });

            Assert.That(await restarted.Command(SessionCommand.Start), Is.Null);

            Assert.Multiple(() => {
                Assert.That(signer!.Sessions.Last,                                                  Is.Null, "a session beginning is the end of the last one's document");
                Assert.That(new ChargingSessions(Path.Combine(workingDirectory!, "sessions")).Last, Is.Null, "on disk too");
            });

        }

        #endregion

        #region TheEnergy_IsReadInTheLayoutOfTheMeter()

        /// <summary>
        /// Integers with a scale factor for 203, a float for 213: the same 15750
        /// Wh either way, wherever the meter model sits in the list.
        /// </summary>
        [TestCase(203, 40000)]
        [TestCase(213, 50000)]
        public async Task TheEnergy_IsReadInTheLayoutOfTheMeter(Int32 MeterModel, Int32 Base)
        {

            var image = MeterModel == 203
                            ? AnImage.IntegerMeter((UInt16) Base, 1575, 1)
                            : AnImage.FloatMeter  ((UInt16) Base, 15750f);

            var read  = SunSpecChain.Of(await image.CreateAsync(0, null, default));
            var chain = await SunSpecChain.Walk(read);

            Assert.That(await chain.ImportedWh(read), Is.EqualTo(15750m));

        }

        /// <summary>
        /// A counter the meter says it does not have is no reading a session is
        /// begun on.
        /// </summary>
        [Test]
        public async Task ACounterTheMeterDoesNotHave_BeginsNoSession()
        {

            var image  = AnImage.IntegerMeter(40000, 1575, unchecked((Int16) 0x8000));
            var signed = new SessionSigner(
                             new ChargingSessions(Path.Combine(workingDirectory!, "other")),
                             keys!,
                             await EnergyOf(image),
                             () => new MeterDescription("meter-session-002", "1.0", "Image"),
                             () => false,
                             () => { }
                         );

            var answer = await signed.Start(SessionParameters.Nothing);

            Assert.Multiple(() => {
                Assert.That(answer.Refusal?.Kind,  Is.EqualTo(SessionRefusalKind.Unreadable));
                Assert.That(answer.Refusal?.Why,   Does.Contain("0x8000"));
            });

        }

        #endregion

        #region TheJSONAPI_TakesTheSameParameters()

        [Test]
        public void TheJSONAPI_TakesTheSameParameters()
        {

            Assert.Multiple(() => {

                Assert.That(SessionParameters.TryParse(JObject.Parse("""{ "identificationType": "emaid", "identification": " DE-GDF-C12345678-X ", "tariffText": "001;EUR;0;35;0;0", "stationSessionId": "s-1" }"""),
                                                       out var parameters, out var error), Is.True, error);

                Assert.That(parameters, Is.EqualTo(new SessionParameters("EMAID", "DE-GDF-C12345678-X", null, null, "001;EUR;0;35;0;0", "s-1")));

                Assert.That(SessionParameters.TryParse(JObject.Parse("""{ "tariffText": 35 }"""), out _, out error), Is.False);
                Assert.That(error, Does.Contain("tariffText"));

            });

        }

        #endregion

        #region OverModbusTLS_AStationsRoleBeginsASession_AReadersDoesNot()

        /// <summary>
        /// Through the meter's Modbus/TLS listener: a certificate that may only
        /// read is refused a start by the frontend, one that may write what is
        /// commanded begins a session, and the log says who.
        /// </summary>
        [Test]
        public async Task OverModbusTLS_AStationsRoleBeginsASession_AReadersDoesNot()
        {

            var pki   = Path.Combine(workingDirectory!, "pki");

            await new ModbusPKI().BuildPKI(pki);

            var (serverPfx, serverPfxPassword) = ServerIdentity(pki);

            await using var meter = await TestPorts.StartedOnFreshPorts(() => new ModbusTLSEnergyMeter(
                                        SerialNumber:       "meter-session-tls",
                                        ServerPfxPath:      serverPfx,
                                        ServerPfxPassword:  serverPfxPassword,
                                        ClientCACertPath:   Path.Combine(pki, "issuing-clients-ca.crt"),
                                        ListenAddress:      NetIPAddress.Loopback,
                                        ListenPort:         TestPorts.Free(),
                                        HTTPHostname:       IPv4Address.Localhost,
                                        HTTPPort:           IPPort.Parse(TestPorts.Free()),
                                        DataPath:           Path.Combine(workingDirectory!, "data"),
                                        ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory!, "configuration.json")),
                                        LogToConsole:       false
                                    ));

            try
            {

                var command = (UInt16) (meter.SessionModelFactory.ModelAddress + 2 + SessionModel.Command);

                using (var reader = await TLSConnection.Open(meter.ListenPort, pki, SunSpecRoles.ReadOnly))
                    Assert.That(await reader.Write(command, new[] { (UInt16) SessionCommand.Start }), Is.EqualTo(ModbusExceptionCode.IllegalFunction));

                Assert.That(meter.Sessions.Current, Is.Null);

                using (var station = await TLSConnection.Open(meter.ListenPort, pki, SunSpecRoles.GridService))
                    Assert.That(await station.Write(command, new[] { (UInt16) SessionCommand.Start }), Is.Null);

                Assert.Multiple(() => {
                    Assert.That(meter.Sessions.Current, Is.Not.Null);
                    Assert.That(meter.Log.Recent(200, Tag: "sessions").Select(entry => entry.Message),
                                Has.Some.Matches<String?>(message => message is not null && message.Contains("started the charging session") && message.Contains(SunSpecRoles.GridService)));
                });

            }
            finally
            {
                TestAuthorities.RemoveInstalled(pki);
            }

        }

        #endregion


        #region (private) Helpers

        private SessionSigner SignerOn(IModbusBackendFactory  Device,
                                       String                 Path)

            => new (
                   new ChargingSessions(Path),
                   keys!,
                   EnergyOf(Device).GetAwaiter().GetResult(),
                   () => new MeterDescription("meter-session-001", "1.0", "SunSpec 3-Phase Meter (M213)"),
                   () => false,
                   () => { }
               );

        private static async Task<Func<Task<Decimal>>> EnergyOf(IModbusBackendFactory Device)
        {
            var read  = SunSpecChain.Of(await Device.CreateAsync(0, null, default));
            var chain = await SunSpecChain.Walk(read);
            return () => chain.ImportedWh(read);
        }

        private async Task<SessionModelBackendFactory> ModelBehind(IModbusBackendFactory Device)
        {
            var chain = await SunSpecChain.Walk(SunSpecChain.Of(await Device.CreateAsync(0, null, default)));
            return new SessionModelBackendFactory(Device, signer!, chain.End);
        }

        private static async Task<Connection> StationOn(SessionModelBackendFactory  Model,
                                                        Int64                       ConnectionId   = 1)

            => new (await Model.CreateAsync(ConnectionId, SunSpecRoles.GridService, default), Model.ModelAddress);

        /// <summary>
        /// The certificate the meter shows, with its key and its chain, under a
        /// password of this test's own - read from the PKI's PEM files.
        /// </summary>
        private (String Path, String Password) ServerIdentity(String PKI)
        {

            using var leaf = X509Certificate2.CreateFromPemFile(System.IO.Path.Combine(PKI, "server.crt"),
                                                                System.IO.Path.Combine(PKI, "server.key"));

            var chain = new X509Certificate2Collection();
            chain.ImportFromPemFile(System.IO.Path.Combine(PKI, "server.chain.crt"));

            var bag = new X509Certificate2Collection { leaf };

            foreach (var certificate in chain)
                if (certificate.Thumbprint != leaf.Thumbprint)
                    bag.Add(certificate);

            var password = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(16));
            var path     = System.IO.Path.Combine(workingDirectory!, "meter.pfx");

            File.WriteAllBytes(path, bag.Export(X509ContentType.Pkcs12, password)!);

            return (path, password);

        }

        private static JObject Payload(String Document)
        {
            var scanned = new OCMFDocumentScanner().Scan([ Document ]);
            Assert.That(scanned.Documents, Has.Count.EqualTo(1), "ChargyCore does not take it for an OCMF document");
            return scanned.Documents[0].Payload;
        }

        private static VerificationResult Verify(String  Document,
                                                 String  PublicKey)
        {

            var scanned = new OCMFDocumentScanner().Scan([ Document ]);

            if (scanned.Documents.Count == 0)
                return VerificationResult.UnknownSignatureFormat;

            return new OCMFSignatureValidator(I18NDictionary.Default()).
                       Validate(scanned.Documents[0], PublicKey, "hex");

        }


        /// <summary>
        /// One connection to the session model, as a charging station uses it.
        /// </summary>
        private sealed class Connection(IModbusBackend  Backend,
                                        UInt16          ModelAddress)
        {

            private UInt16 At(UInt16 Offset)
                => (UInt16) (ModelAddress + 2 + Offset);

            public Task<UInt16[]> Read(UInt16 First, UInt16 Count)
                => SunSpecChain.Of(Backend)(First, Count);

            public async Task<ModbusExceptionCode?> Write(UInt16 First, UInt16[] Values)
            {
                var answer = await Backend.ProcessRequestAsync(1, ModbusPDU.BuildWriteMultipleRegisters(First, Values), default);
                return ModbusPDU.TryGetException(answer);
            }

            /// <summary>
            /// A text into a field, in as many requests as Modbus needs for it:
            /// at most 123 registers at a time.
            /// </summary>
            public async Task Give(UInt16 Offset, UInt16 Length, String? Text)
            {

                var registers = SessionModel.Encode(Text, Length);

                for (var done = 0; done < registers.Length; done += 123)
                    Assert.That(await Write((UInt16) (At(Offset) + done), registers[done..Math.Min(registers.Length, done + 123)]), Is.Null);

            }

            public async Task<String> Given(UInt16 Offset, UInt16 Length)
                => SessionModel.Decode(await Read(At(Offset), Length)) ?? "?";

            public Task<ModbusExceptionCode?> Command(SessionCommand Command)
                => Write(At(SessionModel.Command), [ (UInt16) Command ]);

            public async Task<SessionModelState> State()
                => (SessionModelState) (await Read(At(SessionModel.State), 1))[0];

            public async Task<SessionRefusalKind> Error()
                => (SessionRefusalKind) (await Read(At(SessionModel.Error), 1))[0];

            public async Task<String> ErrorText()
                => SessionModel.Decode(await Read(At(SessionModel.ErrorText), SessionModel.ErrorTextLength)) ?? "?";

            public async Task<String> CurrentSessionId()
                => SessionModel.Decode(await Read(At(SessionModel.CurrentSessionId), SessionModel.SessionIdLength)) ?? "?";

            public Task<String> PublicKey()
                => Text(SessionModel.PublicKeyLength, SessionModel.PublicKey);

            public Task<String> Document()
                => Text(SessionModel.DocumentLength, SessionModel.Document);

            /// <summary>
            /// A text behind its length, read in as many requests as it takes -
            /// as a charging station reads it.
            /// </summary>
            private async Task<String> Text(UInt16 LengthOffset, UInt16 Offset)
            {

                var bytes     = (await Read(At(LengthOffset), 1))[0];
                var registers = new List<UInt16>();

                while (registers.Count * 2 < bytes)
                    registers.AddRange(await Read((UInt16) (At(Offset) + registers.Count),
                                                  (UInt16) Math.Min(125, (bytes + 1) / 2 - registers.Count)));

                return SessionModel.Decode(registers.ToArray()) ?? "?";

            }

        }


        /// <summary>
        /// A meter that is only its registers: a common model, and a meter model
        /// of the given layout.
        /// </summary>
        private sealed class AnImage(UInt16[] Registers, UInt16 Base) : IModbusBackendFactory, IModbusBackend
        {

            public static AnImage IntegerMeter(UInt16 Base, UInt32 ImportedWh, Int16 ScaleFactor)
            {
                var meter = new UInt16[105];
                meter[44] = (UInt16) (ImportedWh >> 16);
                meter[45] = (UInt16)  ImportedWh;
                meter[52] = (UInt16)  ScaleFactor;
                return Of(Base, 203, meter);
            }

            public static AnImage FloatMeter(UInt16 Base, Single ImportedWh)
            {
                var meter = new UInt16[124];
                var bits  = BitConverter.SingleToUInt32Bits(ImportedWh);
                meter[66] = (UInt16) (bits >> 16);
                meter[67] = (UInt16)  bits;
                // A model of the manufacturer's own before the meter.
                return Of(Base, 213, meter, 64001);
            }

            private static AnImage Of(UInt16 Base, UInt16 MeterModel, UInt16[] Meter, UInt16? Before = null)
            {
                var registers = new List<UInt16> { SunSpecChain.MarkerHigh, SunSpecChain.MarkerLow, 1, 66 };
                registers.AddRange(new UInt16[66]);
                if (Before is UInt16 vendor)
                {
                    registers.AddRange([ vendor, 4, 0, 0, 0, 0 ]);
                }
                registers.AddRange([ MeterModel, (UInt16) Meter.Length ]);
                registers.AddRange(Meter);
                registers.AddRange([ SunSpecChain.EndOfModels, 0 ]);
                return new AnImage([.. registers], Base);
            }

            public Task<IModbusBackend> CreateAsync(Int64 ConnectionId, String? Role, CancellationToken CancellationToken)
                => Task.FromResult<IModbusBackend>(this);

            public Task<Byte[]> ProcessRequestAsync(Byte UnitId, ReadOnlyMemory<Byte> RequestPDU, CancellationToken CancellationToken)
            {

                var pdu   = RequestPDU.Span;
                var first = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(1, 2));
                var count = BinaryPrimitives.ReadUInt16BigEndian(pdu.Slice(3, 2));

                if (pdu[0] != (Byte) ModbusFunctionCodes.ReadHoldingRegisters || first < Base || first + count > Base + Registers.Length)
                    return Task.FromResult(ModbusPDU.BuildException((ModbusFunctionCodes) pdu[0], ModbusExceptionCode.IllegalDataAddress));

                return Task.FromResult(ModbusPDU.BuildReadHoldingResponse(Registers.AsSpan(first - Base, count).ToArray()));

            }

            public ValueTask DisposeAsync()
                => ValueTask.CompletedTask;

        }


        /// <summary>
        /// A Modbus/TLS connection with the client certificate of a role.
        /// </summary>
        private sealed class TLSConnection : IDisposable
        {

            private readonly TcpClient  tcp;
            private readonly SslStream  tls;
            private UInt16              transaction;

            private TLSConnection(TcpClient TCP, SslStream TLS)
            {
                tcp = TCP;
                tls = TLS;
            }

            public static async Task<TLSConnection> Open(Int32 Port, String PKI, String Role)
            {

                using var pem   = X509Certificate2.CreateFromPemFile(Path.Combine(PKI, $"client-{Role}.crt"),
                                                                     Path.Combine(PKI, $"client-{Role}.key"));

                // A key read from PEM is ephemeral, and Windows' TLS will not
                // sign a handshake with one.
                var leaf  = X509CertificateLoader.LoadPkcs12(pem.Export(X509ContentType.Pkcs12), null, X509KeyStorageFlags.UserKeySet);

                var chain = new X509Certificate2Collection();
                chain.ImportFromPemFile(Path.Combine(PKI, $"client-{Role}.chain.crt"));

                var tcp   = new TcpClient();
                await tcp.ConnectAsync(NetIPAddress.Loopback, Port);

                var tls   = new SslStream(tcp.GetStream(), false, (_, _, _, _) => true);

                await tls.AuthenticateAsClientAsync(new SslClientAuthenticationOptions {
                          TargetHost                      = "localhost",
                          EnabledSslProtocols             = SslProtocols.Tls12 | SslProtocols.Tls13,
                          ClientCertificateContext        = SslStreamCertificateContext.Create(leaf, chain, offline: true),
                          CertificateRevocationCheckMode  = X509RevocationMode.NoCheck
                      });

                return new TLSConnection(tcp, tls);

            }

            public async Task<ModbusExceptionCode?> Write(UInt16 First, UInt16[] Values)
            {

                var pdu   = ModbusPDU.BuildWriteMultipleRegisters(First, Values);
                var frame = new Byte[7 + pdu.Length];

                BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(0, 2), ++transaction);
                BinaryPrimitives.WriteUInt16BigEndian(frame.AsSpan(4, 2), (UInt16) (pdu.Length + 1));
                frame[6] = 1;
                pdu.CopyTo(frame, 7);

                await tls.WriteAsync(frame);

                var header = new Byte[7];
                await tls.ReadExactlyAsync(header);

                var answer = new Byte[BinaryPrimitives.ReadUInt16BigEndian(header.AsSpan(4, 2)) - 1];
                await tls.ReadExactlyAsync(answer);

                return ModbusPDU.TryGetException(answer);

            }

            public void Dispose()
            {
                tls.Dispose();
                tcp.Dispose();
            }

        }

        #endregion

    }

}
