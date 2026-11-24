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

using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Web;
using cloud.charging.open.protocols.WWCP.Node.Modbus;
using cloud.charging.open.protocols.WWCP.Node.Streams;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.EnergyMeters.ModbusTLS.CommandLine;
using cloud.charging.open.EnergyMeters.ModbusTLS.MeterReaders;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What reads this meter over a WebSocket or SSH, over its JSON API and
    /// at its command line: the connections, the logins, their groups - the
    /// SunSpec roles - and the accepted chains, at WWCP_Node's routes below
    /// "v1/configuration/reader-server", and at the resource "meterReaders",
    /// which an administrator may change and a viewer and an auditor only read.
    /// </summary>
    [TestFixture]
    public class MeterReaderAPITests
    {

        #region Data

        private const UInt16           MeterMode  = 40094;

        private String                 directory  = "";
        private ModbusTLSEnergyMeter?  meter;

        #endregion

        #region SetUp / TearDown

        [SetUp]
        public async Task SetUp()
        {

            directory = Path.Combine(Path.GetTempPath(), "meter-reader-api-" + Guid.NewGuid().ToString("N")[..12]);
            Directory.CreateDirectory(directory);

            var configuration = Path.Combine(directory, WWCPConfigFile.DefaultFileName);

            File.WriteAllText(configuration, new JObject(
                new JProperty("nts",              new JObject(new JProperty("groups", new JObject(new JProperty("legal", new JObject(new JProperty("enabled", false))))))),
                new JProperty("webSocketServer",  new JObject(
                    new JProperty("enabled",               true),
                    new JProperty("address",               "127.0.0.1"),
                    new JProperty("port",                  TestPorts.Free().ToUInt16()),
                    new JProperty("clientAuthentication",  new JArray("httpAuthWithoutTLS"))
                ))
            ).ToString());

            var (serverPfx, clientCA) = ModbusTLSFiles(directory);

            meter = new ModbusTLSEnergyMeter(
                        SerialNumber:       "meter-reader-api",
                        ServerPfxPath:      serverPfx,
                        ServerPfxPassword:  "test",
                        ClientCACertPath:   clientCA,
                        ListenAddress:      NetIPAddress.Loopback,
                        ListenPort:         TestPorts.Free(),
                        HTTPHostname:       IPv4Address.Localhost,
                        HTTPPort:           TestPorts.Free(),
                        DataPath:           directory,
                        ConfigFile:         new WWCPConfigFile(configuration),
                        LogKeepDays:        0,
                        LogToConsole:       false,
                        BridgeDebugLog:     false
                    );

            await meter.Start();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (meter is not null)
            {
                await meter.Stop();
                await meter.DisposeAsync();
            }

            try
            {
                Directory.Delete(directory, recursive: true);
            }
            catch
            { }

        }

        #endregion


        #region (helpers)

        /// <summary>
        /// A certificate for 127.0.0.1 and the CA that issued it, for the
        /// Modbus/TLS port this test does not speak to.
        /// </summary>
        private static (String ServerPfx, String ClientCA) ModbusTLSFiles(String Directory)
        {

            using var caKey      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var caRequest        = new CertificateRequest($"CN=The CA of a meter reader API test {Guid.NewGuid()}", caKey, HashAlgorithmName.SHA256);
            caRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            caRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.KeyCertSign | X509KeyUsageFlags.CrlSign, true));
            using var ca         = caRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            using var serverKey  = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var serverRequest    = new CertificateRequest("CN=127.0.0.1", serverKey, HashAlgorithmName.SHA256);
            serverRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
            using var server     = serverRequest.Create(ca.SubjectName, X509SignatureGenerator.CreateForECDsa(caKey),
                                                        DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(29), Guid.NewGuid().ToByteArray());
            using var withKey    = server.CopyWithPrivateKey(serverKey);

            var serverPfx        = Path.Combine(Directory, "server.pfx");
            var clientCA         = Path.Combine(Directory, "clients-ca.crt");

            File.WriteAllBytes(serverPfx, withKey.Export(X509ContentType.Pkcs12, "test"));
            File.WriteAllText (clientCA,  ca.ExportCertificatePem());

            return (serverPfx, clientCA);

        }

        /// <summary>
        /// A client signed in as the given account: the administrator the meter
        /// made at its first start, where no role is given, and otherwise a new
        /// account in the group of the role.
        /// </summary>
        private async Task<HttpClient> SignedInAs(Role? Role)
        {

            var name      = ModbusTLSEnergyMeter.DefaultAdminUser.ToString();
            var password  = meter!.GeneratedPassword!;

            if (Role is not null)
            {

                name      = Role.Name + "1";
                password  = "Correct-Horse-" + Guid.NewGuid().ToString("N")[..8];

                var api   = meter.ExtAPI;
                var user  = new User(
                                User_Id.Parse(name),
                                I18NString.Create(name),
                                SimpleEMailAddress.Parse($"{name}@example.test"),
                                IsAuthenticated:  true,
                                DataSource:       "test"
                            );

                await api.AddUser(user, SkipNewUserEMail: true, SkipNewUserNotifications: true);
                await api.ChangePassword(user, password, SuppressNotifications: true);

                Assert.That(api.TryGetUserGroup(Role.GroupId, out var group) && group is UserGroup, Is.True, $"There is no {Role.Name} group.");
                Assert.That((await api.AddUserToUserGroup(user, User2UserGroupEdgeLabel.IsMember, (UserGroup) group!)).IsSuccess, Is.True);

            }

            var client = new HttpClient(new HttpClientHandler { UseCookies = true, CookieContainer = new CookieContainer() }) {
                             BaseAddress  = new Uri($"http://127.0.0.1:{meter.HTTPPort}/"),
                             Timeout      = TimeSpan.FromSeconds(30)
                         };

            var (status, json) = await Send(client, HttpMethod.Post, "ext/auth/login", new { login = name, password });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), $"'{name}' could not sign in: {json}");

            return client;

        }

        private static async Task<(HttpStatusCode Status, JObject JSON)> Send(HttpClient  Client,
                                                                              HttpMethod  Method,
                                                                              String      Path,
                                                                              Object?     Body = null)
        {

            using var request = new HttpRequestMessage(Method, Path);

            if (Body is not null)
                request.Content = new StringContent(JObject.FromObject(Body).ToString(), Encoding.UTF8, "application/json");

            using var response = await Client.SendAsync(request);

            var text = await response.Content.ReadAsStringAsync();

            JObject json;

            try
            {
                json = String.IsNullOrWhiteSpace(text) ? [] : JObject.Parse(text);
            }
            catch
            {
                json = new JObject(new JProperty("text", text));
            }

            return (response.StatusCode, json);

        }

        private static Task<(HttpStatusCode Status, JObject JSON)> Get   (HttpClient Client, String Path)               => Send(Client, HttpMethod.Get,    Path);
        private static Task<(HttpStatusCode Status, JObject JSON)> Post  (HttpClient Client, String Path, Object Body)  => Send(Client, HttpMethod.Post,   Path, Body);
        private static Task<(HttpStatusCode Status, JObject JSON)> Put   (HttpClient Client, String Path, Object Body)  => Send(Client, HttpMethod.Put,    Path, Body);
        private static Task<(HttpStatusCode Status, JObject JSON)> Delete(HttpClient Client, String Path)               => Send(Client, HttpMethod.Delete, Path);

        /// <summary>
        /// The login of the given name, as the list of the logins has it.
        /// </summary>
        private static JObject? LoginIn(JObject Logins, String Login)

            => (Logins["logins"] as JArray)?.OfType<JObject>().FirstOrDefault(login => login.Value<String>("login") == Login);

        private String ReaderURL(String Login)
            => $"ws://127.0.0.1:{meter!.MeterReaderSettings.TCPPort!.Value.ToUInt16()}/{Login}";

        #endregion


        #region AnAdministratorLetsAReaderIn()

        /// <summary>
        /// An administrator writes down a reader - its connection, inbound and
        /// of the type "MeterReader", and its login with a password in the group
        /// of ReadOnly -, which then reads the meter over a WebSocket and is
        /// listed as connected and as ReadOnly; a key pin is given, the login
        /// switched off and on, and both are forgotten again.
        /// </summary>
        [Test]
        public async Task AnAdministratorLetsAReaderIn()
        {

            using var admin = await SignedInAs(null);

            #region The server, with nobody in yet

            var (status, server) = await Get(admin, "api/v1/configuration/reader-server");

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), server.ToString());

            Assert.Multiple(() => {
                Assert.That(server["configuration"],                        Is.InstanceOf<JObject>());
                Assert.That(server["state"]?["running"]?.Value<Boolean>(),  Is.True);
                Assert.That(server["state"]?["tls"]?.Value<Boolean>(),      Is.False);
                Assert.That(server["connected"] as JArray,                  Is.Empty);
                Assert.That((server["roles"] as JObject)?.Count,            Is.EqualTo(0));
            });

            #endregion

            #region Its connection

            (status, var added) = await Post(admin, "api/v1/configuration/connections", new JObject(
                                      new JProperty("description",     new JObject(new JProperty("en", "The station's meter reader"))),
                                      new JProperty("url",             ReaderURL("reader-01")),
                                      new JProperty("connectionType",  "MeterReader"),
                                      new JProperty("autoConnect",     true),
                                      new JProperty("inbound",         true)
                                  ));

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), added.ToString());

            var connectionId = added["id"]!.Value<String>()!;

            Assert.That(meter!.Connections.Connections.Single(entry => entry.Id == connectionId).InboundName, Is.EqualTo("reader-01"));

            #endregion

            #region Its login, with a password, as ReadOnly

            var password = "a-long-password-" + Guid.NewGuid().ToString("N");

            (status, var logins) = await Post(admin, "api/v1/configuration/reader-server/logins", new {
                                       login     = "reader-01",
                                       password,
                                       group     = SunSpecLoginGroups.GroupOf(SunSpecRoles.ReadOnly)
                                   });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), logins.ToString());
            Assert.That(LoginIn((JObject) logins["logins"]!, "reader-01"), Is.Not.Null, logins.ToString());
            Assert.That(meter.SunSpecRoleOf(User_Id.Parse("reader-01")),  Is.EqualTo(SunSpecRoles.ReadOnly));

            #endregion

            #region It reads the meter over a WebSocket, and is listed so

            var webSocket = new StreamWebSocketClient(
                                URL.Parse(ReaderURL("reader-01")),
                                ModbusWireNames.Subprotocol,
                                HTTPBasicAuthentication.Create("reader-01", password),
                                null, null, null, null, null, null
                            );

            var (_, response) = await webSocket.Connect();

            Assert.That(response.HTTPStatusCode, Is.EqualTo(HTTPStatusCode.SwitchingProtocols), "The WebSocket of Modbus was not opened.");

            var client = ModbusTCPClient.Over(webSocket.Stream);

            try
            {

                Assert.That((await client.ReadHoldingRegistersAsync(1, MeterMode, 1)).Length, Is.EqualTo(1));

                (status, server) = await Get(admin, "api/v1/configuration/reader-server");

                Assert.Multiple(() => {
                    Assert.That(status,                                                 Is.EqualTo(HttpStatusCode.OK));
                    Assert.That((server["connected"] as JArray)?.Values<String>(),     Does.Contain("reader-01"));
                    Assert.That(server["roles"]?["reader-01"]?.Value<String>(),        Is.EqualTo(SunSpecRoles.ReadOnly));
                });

            }
            finally
            {
                await client.   DisposeAsync();
                await webSocket.DisposeAsync();
            }

            #endregion

            #region A key pin; switched off, and on again - and no mark of OCPP

            var pin = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("the public key of the reader")));

            (status, var pinned) = await Post(admin, "api/v1/configuration/reader-server/logins/reader-01/keyPins", new { pin, label = "the reader's TLS key" });

            Assert.That(status,                             Is.EqualTo(HttpStatusCode.OK), pinned.ToString());
            Assert.That(pinned["keyPin"]?.Value<String>(),  Is.EqualTo(pin).IgnoreCase);

            (status, var off) = await Put(admin, "api/v1/configuration/reader-server/logins/reader-01", new { enabled = false });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), off.ToString());
            Assert.That(meter.SunSpecRoleOf(User_Id.Parse("reader-01")), Is.Null, "A login switched off reads as no role.");

            (status, var marked) = await Put(admin, "api/v1/configuration/reader-server/logins/reader-01", new { gateway = true });

            Assert.That(status, Is.EqualTo(HttpStatusCode.BadRequest), marked.ToString());

            (status, var on) = await Put(admin, "api/v1/configuration/reader-server/logins/reader-01", new { enabled = true });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), on.ToString());

            #endregion

            #region The chains a client certificate may lead to

            (status, var trust) = await Get(admin, "api/v1/configuration/reader-server/trust");

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), trust.ToString());

            #endregion

            #region Forgotten again

            (status, var forgotten) = await Delete(admin, "api/v1/configuration/reader-server/logins/reader-01");

            Assert.That(status,                                                         Is.EqualTo(HttpStatusCode.OK), forgotten.ToString());
            Assert.That(meter.WebSocketLogins.TryGet(User_Id.Parse("reader-01"), out _), Is.False);

            (status, var removed) = await Post(admin, "api/v1/configuration/connections/remove", new { id = connectionId });

            Assert.That(status,                                                       Is.EqualTo(HttpStatusCode.OK), removed.ToString());
            Assert.That(meter.Connections.Connections.Any(entry => entry.Id == connectionId), Is.False);

            #endregion

        }

        #endregion

        #region TheGroupsOfTheRoles_StayWhenRemoved()

        /// <summary>
        /// A group of a SunSpec role is not removed over the JSON API, even
        /// where nobody is in it: the four roles are what a reader is put into
        /// to read this meter at all. The answer says so, and the group is
        /// there as it was.
        /// </summary>
        [Test]
        public async Task TheGroupsOfTheRoles_StayWhenRemoved()
        {

            using var admin = await SignedInAs(null);

            var gridService = SunSpecLoginGroups.GroupOf(SunSpecRoles.GridService);

            var (status, refusal) = await Delete(admin, $"api/v1/configuration/reader-server/groups/{gridService}");

            Assert.Multiple(() => {
                Assert.That(status,                                                Is.EqualTo(HttpStatusCode.Conflict), refusal.ToString());
                Assert.That(refusal.ToString(),                                    Does.Contain("SunSpec role"));
                Assert.That(meter!.WebSocketLogins.GetGroup(gridService)?.Name,    Is.EqualTo(SunSpecRoles.GridService));
            });

        }

        #endregion

        #region AViewerAndAnAuditorOnlyRead(Role)

        /// <summary>
        /// Who may let a reader in decides who reads this meter: a viewer and
        /// an auditor read the readers, and change nothing of them.
        /// </summary>
        [TestCase("viewer")]
        [TestCase("auditor")]
        public async Task AViewerAndAnAuditorOnlyRead(String RoleName)
        {

            using var user = await SignedInAs(RoleName == "viewer" ? MeterAccess.Viewer : MeterAccess.Auditor);

            var (status, server) = await Get(user, "api/v1/configuration/reader-server");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), server.ToString());

            (status, var logins) = await Get(user, "api/v1/configuration/reader-server/logins");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), logins.ToString());

            (status, var connections) = await Get(user, "api/v1/configuration/connections");
            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), connections.ToString());

            (status, var login) = await Post(user, "api/v1/configuration/reader-server/logins", new {
                                      login     = "reader-01",
                                      password  = "a-long-password-" + Guid.NewGuid().ToString("N")
                                  });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), login.ToString());

            (status, var group) = await Delete(user, $"api/v1/configuration/reader-server/groups/{SunSpecLoginGroups.GroupOf(SunSpecRoles.GridService)}");

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), group.ToString());

            (status, var connection) = await Post(user, "api/v1/configuration/connections", new JObject(
                                           new JProperty("url",             ReaderURL("reader-01")),
                                           new JProperty("connectionType",  "MeterReader"),
                                           new JProperty("inbound",         true)
                                       ));

            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), connection.ToString());

            Assert.Multiple(() => {
                Assert.That(meter!.WebSocketLogins.TryGet(User_Id.Parse("reader-01"), out _), Is.False);
                Assert.That(meter.Connections.Connections,                                    Is.Empty);
            });

        }

        #endregion

        #region SupportAndAGuestDoNotSeeTheReaders(Role)

        /// <summary>
        /// Support and a guest see the readings, and not who may read them.
        /// </summary>
        [TestCase("support")]
        [TestCase("guest")]
        public async Task SupportAndAGuestDoNotSeeTheReaders(String RoleName)
        {

            using var user = await SignedInAs(RoleName == "support" ? MeterAccess.Support : MeterAccess.Guest);

            var (status, server) = await Get(user, "api/v1/configuration/reader-server");
            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), server.ToString());

            (status, var logins) = await Get(user, "api/v1/configuration/reader-server/logins");
            Assert.That(status, Is.EqualTo(HttpStatusCode.Forbidden), logins.ToString());

        }

        #endregion

        #region AtTheConsoleReadersListsTheReaders()

        /// <summary>
        /// 'readers' says where the server is and lists every reader with its
        /// connection, what it signs in with and its SunSpec role; 'readerPins'
        /// and 'readerKeys' give and list its key pins and keys, and say what
        /// keeps it out.
        /// </summary>
        [Test]
        public async Task AtTheConsoleReadersListsTheReaders()
        {

            using var cli = new MeterCLI(meter!);

            var none = await cli.Execute("readers");

            Assert.Multiple(() => {
                Assert.That(none, Has.Some.Contains("listens at port"));
                Assert.That(none, Has.Some.EqualTo("No meter reader is written down: none may connect."));
            });

            Assert.That(meter!.Connections.TryAddConnection(I18NString.Create("A reader"),
                                                            URL.Parse(ReaderURL("reader-01")),
                                                            "MeterReader",
                                                            true,
                                                            null,
                                                            null,
                                                            out _,
                                                            out var error,
                                                            Inbound: true),
                        Is.True, error);

            var pin    = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("the public key of the reader")));
            var given  = await cli.Execute($"readerPins reader-01 add {pin} the-reader");

            Assert.That(String.Join(" | ", given), Does.Contain("is a meter reader of this").And.Contain("key pin"));

            Assert.That(meter.WebSocketLogins.TrySetGroup(User_Id.Parse("reader-01"), SunSpecLoginGroups.GroupOf(SunSpecRoles.GridService), out error),
                        Is.True, error);

            var listed = await cli.Execute("readers");

            Assert.Multiple(() => {
                Assert.That(listed, Has.Some.StartsWith("reader-01  on  not connected"));
                Assert.That(listed, Has.Some.Contains("signs in with 1 key pin(s)").And.Contains($"reads as {SunSpecRoles.GridService}"));
            });

            var pins   = await cli.Execute("readerPins");

            Assert.Multiple(() => {
                Assert.That(pins, Has.Some.EqualTo("reader-01:"));
                Assert.That(pins, Has.Some.Contains("WebSocket port of Modbus is not encrypted"));
            });

            var keys   = await cli.Execute("readerKeys");

            Assert.That(keys, Has.Some.EqualTo("No meter reader of this energy meter has an SSH key."));

        }

        #endregion

    }

}
