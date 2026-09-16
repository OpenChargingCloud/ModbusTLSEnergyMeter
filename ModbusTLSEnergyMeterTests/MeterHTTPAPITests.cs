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
using System.Net.Sockets;
using System.Text;

using Newtonsoft.Json.Linq;

using NUnit.Framework;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.EnergyMeters.ModbusTLS.Configuration;

using NetIPAddress = System.Net.IPAddress;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What the JSON API of a meter lets somebody do, and what it does not.
    /// </summary>
    /// <remarks>
    /// The refusals are the point of this. A route that answers correctly for
    /// an administrator proves only that it works; the question a meter with a
    /// web interface has to answer is what happens to everybody else, and that
    /// path is never walked by the person developing it.
    /// </remarks>
    public class MeterHTTPAPITests
    {

        #region Data

        private ModbusTLSEnergyMeter?  meter;
        private String?                workingDirectory;
        private Int32                  httpPort;

        #endregion

        #region Setup / TearDown

        [SetUp]
        public async Task Setup()
        {

            workingDirectory = Path.Combine(
                                   Path.GetTempPath(),
                                   "ModbusTLSEnergyMeterTests",
                                   Guid.NewGuid().ToString("N")
                               );

            Directory.CreateDirectory(workingDirectory);

            var pkiDirectory = Path.Combine(workingDirectory, "pki");

            await new ModbusPKI().BuildPKI(pkiDirectory);

            httpPort = FreeTCPPort();

            meter = new ModbusTLSEnergyMeter(
                        SerialNumber:       "meter-test-001",
                        ServerPfxPath:      Path.Combine(pkiDirectory, "server.pfx"),
                        ServerPfxPassword:  "demo",
                        ClientCACertPath:   Path.Combine(pkiDirectory, "issuing-clients-ca.crt"),
                        ListenAddress:      NetIPAddress.Loopback,
                        ListenPort:         FreeTCPPort(),
                        HTTPHostname:       IPv4Address.Localhost,
                        HTTPPort:           IPPort.Parse(httpPort),
                        DataPath:           Path.Combine(workingDirectory, "data"),
                        ConfigFile:         new MeterConfigFile(Path.Combine(workingDirectory, "configuration.json")),
                        LogToConsole:       false
                    );

            await meter.StartAsync();

        }

        [TearDown]
        public async Task TearDown()
        {

            if (meter is not null)
                await meter.DisposeAsync();

            meter = null;

            if (workingDirectory is not null && Directory.Exists(workingDirectory))
            {
                try { Directory.Delete(workingDirectory, recursive: true); }
                catch { /* a file the meter still holds is not what is under test */ }
            }

        }

        #endregion


        #region TheFirstAdministrator_MayDoEverything()

        /// <summary>
        /// The account made at the first start signs in, and holds every
        /// permission this meter knows.
        /// </summary>
        [Test]
        public async Task TheFirstAdministrator_MayDoEverything()
        {

            using var browser = await SignInAsAdministrator();

            var me = await browser.GetJSON("api/v1/me");

            Assert.Multiple(() => {

                Assert.That(me?["userId"]?.ToString(),        Is.EqualTo("admin"));
                Assert.That(me?["organization"]?.ToString(),  Is.EqualTo(ModbusTLSEnergyMeter.MeterOrganizationId));
                Assert.That(me?["role"]?.ToString(),          Is.EqualTo("IsAdmin"));

                Assert.That(me?["permissions"]?.Values<String>(),
                            Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration",
                                                    "ChangeNetworkSettings", "RunDiagnostics", "WriteRegisters" }));

            });

        }

        #endregion

        #region WithoutSigningIn_EverythingIs401()

        /// <summary>
        /// No session, no answer - not even to the resources that only read.
        /// </summary>
        [Test]
        public async Task WithoutSigningIn_EverythingIs401()
        {

            using var browser = NewBrowser();

            foreach (var path in new[] { "api/v1/me", "api/v1/status", "api/v1/meter",
                                         "api/v1/configuration", "api/v1/configuration/dns" })
            {
                Assert.That(await browser.StatusOf(HttpMethod.Get, path),
                            Is.EqualTo(HttpStatusCode.Unauthorized),
                            $"'{path}' without a session");
            }

        }

        #endregion

        #region AGuest_MayReadTheMeter_AndNothingElse()

        /// <summary>
        /// A guest of the meter's organization sees what it is measuring, and
        /// is refused everything else - with a 403, which says that signing in
        /// again will not help.
        /// </summary>
        [Test]
        public async Task AGuest_MayReadTheMeter_AndNothingElse()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", User2OrganizationEdgeLabel.IsGuest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var me = await browser.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),                Is.EqualTo("IsGuest"));
                Assert.That(me?["permissions"]?.Values<String>(),   Is.EquivalentTo(new[] { "ReadMeter" }));
            });

            Assert.Multiple(async () => {

                Assert.That(await browser.StatusOf(HttpMethod.Get, "api/v1/meter"),
                            Is.EqualTo(HttpStatusCode.OK),                  "a guest may read the meter");

                Assert.That(await browser.StatusOf(HttpMethod.Get, "api/v1/status"),
                            Is.EqualTo(HttpStatusCode.OK),                  "and its status");

                Assert.That(await browser.StatusOf(HttpMethod.Get, "api/v1/configuration"),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "but not how it is configured");

                Assert.That(await browser.StatusOf(HttpMethod.Put, "api/v1/configuration/dns", new { enabled = false }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "and may not change that");

                Assert.That(await browser.StatusOf(HttpMethod.Put, "api/v1/meter/mode", new { mode = 1 }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "nor write a register");

                Assert.That(await browser.StatusOf(HttpMethod.Post, "api/v1/meter/energy/reset"),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "nor clear the energy counters");

            });

        }

        #endregion

        #region AReadOnlyAdministrator_MayLookButNotTouch()

        /// <summary>
        /// A read-only administrator sees the configuration and may make the
        /// meter check its clock, but may not change anything.
        /// </summary>
        [Test]
        public async Task AReadOnlyAdministrator_MayLookButNotTouch()
        {

            await CreateUserAsync("rory", "Correct-Horse-2", User2OrganizationEdgeLabel.IsAdminReadOnly);

            using var browser = await SignIn("rory", "Correct-Horse-2");

            Assert.Multiple(async () => {

                Assert.That(await browser.StatusOf(HttpMethod.Get, "api/v1/configuration"),
                            Is.EqualTo(HttpStatusCode.OK),        "may read the configuration");

                Assert.That(await browser.StatusOf(HttpMethod.Put, "api/v1/configuration/nts", new { enabled = false }),
                            Is.EqualTo(HttpStatusCode.Forbidden), "but may not change it");

                Assert.That(await browser.StatusOf(HttpMethod.Put, "api/v1/meter/mode", new { mode = 2 }),
                            Is.EqualTo(HttpStatusCode.Forbidden), "and may not write a register");

            });

        }

        #endregion

        #region SomebodyWithNoRoleHere_IsRefusedEverything()

        /// <summary>
        /// An account that belongs to no organization of this meter holds no
        /// permission at all - not even to look.
        /// </summary>
        /// <remarks>
        /// The closed set, tested: a role this meter does not know grants
        /// nothing, rather than falling through to whatever the first case of a
        /// switch happens to be.
        /// </remarks>
        [Test]
        public async Task SomebodyWithNoRoleHere_IsRefusedEverything()
        {

            await CreateUserAsync("nora", "Correct-Horse-3", null);

            using var browser = await SignIn("nora", "Correct-Horse-3");

            var me = await browser.GetJSON("api/v1/me");

            Assert.Multiple(async () => {

                Assert.That(me?["role"]?.Type,                                  Is.EqualTo(JTokenType.Null));
                Assert.That(me?["permissions"]?.Values<String>(),               Is.Empty);

                Assert.That(await browser.StatusOf(HttpMethod.Get, "api/v1/meter"),
                            Is.EqualTo(HttpStatusCode.Forbidden));

            });

        }

        #endregion

        #region AnUnknownAPIPath_IsAJSON404()

        /// <summary>
        /// An unknown path below /api answers as this API, not as the accounts
        /// at "/".
        /// </summary>
        [Test]
        public async Task AnUnknownAPIPath_IsAJSON404()
        {

            using var browser  = await SignInAsAdministrator();
            var (status, json) = await browser.Call(HttpMethod.Get, "api/v1/nonsense");

            Assert.Multiple(() => {
                Assert.That(status,                     Is.EqualTo(HttpStatusCode.NotFound));
                Assert.That(json?["error"]?.ToString(), Does.Contain("nonsense"));
            });

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// Make a user with the given role in the meter's organization, or with
        /// no membership at all when the role is null.
        /// </summary>
        private async Task CreateUserAsync(String                       UserId,
                                           String                       Password,
                                           User2OrganizationEdgeLabel?  Role)
        {

            var api  = meter!.HTTPExtAPI;

            var user = new User(
                           User_Id.Parse(UserId),
                           I18NString.Create(UserId),
                           SimpleEMailAddress.Parse($"{UserId}@example.test"),
                           IsAuthenticated:  true,
                           DataSource:       "test"
                       );

            if (Role.HasValue &&
                api.TryGetOrganization(Organization_Id.Parse(ModbusTLSEnergyMeter.MeterOrganizationId), out var organization) &&
                organization is not null)
            {
                await api.AddUser(user, Role.Value, organization,
                                  SkipNewUserEMail: true, SkipNewUserNotifications: true);
            }

            else
                await api.AddUser(user,
                                  SkipNewUserEMail: true, SkipNewUserNotifications: true);

            await api.ChangePassword(user, Password, SuppressNotifications: true);

        }

        private Browser NewBrowser()
            => new ($"http://127.0.0.1:{httpPort}/");

        private async Task<Browser> SignInAsAdministrator()
            => await SignIn("admin", meter!.GeneratedPassword!);

        private async Task<Browser> SignIn(String UserId, String Password)
        {

            var browser        = NewBrowser();
            var (status, json) = await browser.Call(HttpMethod.Post, "accounts/auth/login",
                                                    new { login = UserId, password = Password });

            Assert.That(status, Is.EqualTo(HttpStatusCode.OK), $"'{UserId}' could not sign in: {json}");

            return browser;

        }

        private static Int32 FreeTCPPort()
        {

            var listener = new TcpListener(NetIPAddress.Loopback, 0);

            listener.Start();
            var port = ((System.Net.IPEndPoint) listener.LocalEndpoint).Port;
            listener.Stop();

            return port;

        }

        /// <summary>
        /// One browser: a client that keeps the cookies it was given, because
        /// what is under test is what a session is allowed to do.
        /// </summary>
        private sealed class Browser : IDisposable
        {

            private readonly HttpClient client;

            public Browser(String BaseAddress)
            {

                client = new HttpClient(new HttpClientHandler { UseCookies = true }) {
                             BaseAddress = new Uri(BaseAddress),
                             Timeout     = TimeSpan.FromSeconds(30)
                         };

            }

            public async Task<(HttpStatusCode, JObject?)> Call(HttpMethod  Method,
                                                               String      Path,
                                                               Object?     Body = null)
            {

                using var request = new HttpRequestMessage(Method, Path);

                if (Body is not null)
                    request.Content = new StringContent(JObject.FromObject(Body).ToString(),
                                                        Encoding.UTF8, "application/json");

                using var response = await client.SendAsync(request);

                var text = await response.Content.ReadAsStringAsync();

                JObject? json = null;

                if (!String.IsNullOrWhiteSpace(text))
                {
                    try   { json = JObject.Parse(text); }
                    catch { /* not every answer is JSON, and that is the caller's problem */ }
                }

                return (response.StatusCode, json);

            }

            public async Task<JObject?> GetJSON(String Path)
                => (await Call(HttpMethod.Get, Path)).Item2;

            public async Task<HttpStatusCode> StatusOf(HttpMethod  Method,
                                                       String      Path,
                                                       Object?     Body = null)
                => (await Call(Method, Path, Body)).Item1;

            public void Dispose()
                => client.Dispose();

        }

        #endregion

    }

}
