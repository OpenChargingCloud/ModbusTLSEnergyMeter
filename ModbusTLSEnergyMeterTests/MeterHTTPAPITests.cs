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

                // The readable form travels with it, because every page that
                // tells somebody what they may not do names their role in the
                // same sentence, and "IsAdmin" is not a thing anybody says.
                Assert.That(me?["roleTitle"]?.ToString(),        Is.EqualTo("Administrator"));
                Assert.That(me?["roleDescription"]?.ToString(),  Does.Contain("Everything"));

                Assert.That(me?["permissions"]?.Values<String>(),
                            Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration",
                                                    "ChangeNetworkSettings", "RunDiagnostics", "WriteRegisters",
                                                    "ManageCertificates", "ManageAccounts" }));

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
                Assert.That(me?["roleTitle"]?.ToString(),           Is.EqualTo("Guest"));
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

                // Null and not a placeholder: a page falls back to its own
                // wording for somebody holding no role, and "No role in this
                // meter" does not fit into "Signed in as ..., which may".
                Assert.That(me?["roleTitle"]?.Type,                             Is.EqualTo(JTokenType.Null));
                Assert.That(me?["roleDescription"]?.Type,                       Is.EqualTo(JTokenType.Null));

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

        #region ATimeServerTest_SaysWhoAskedAndWhereItGotTo()

        /// <summary>
        /// The Test of one time server, as the NTS page sends it: the answer is
        /// the steps, and the log says who asked, before anything is asked.
        /// </summary>
        /// <remarks>
        /// With a host that is neither a name nor an address, so that the test
        /// ends at its first step and nothing leaves the machine.
        /// </remarks>
        [Test]
        public async Task ATimeServerTest_SaysWhoAskedAndWhereItGotTo()
        {

            using var browser  = await SignInAsAdministrator();

            var before         = meter!.Log.LastId;
            var (status, json) = await browser.Call(HttpMethod.Post, "api/v1/configuration/nts/test", new { host = "not a host at all" });
            var said           = meter.Log.Recent(50, before, "test").ToArray();

            Assert.Multiple(() => {

                Assert.That(status,                                    Is.EqualTo(HttpStatusCode.OK));
                Assert.That(json?["ok"]?.Value<Boolean>(),             Is.False);
                Assert.That(json?["host"]?.ToString(),                 Is.EqualTo("not a host at all"));
                Assert.That(json?["steps"]?[0]?["text"]?.ToString(),   Is.EqualTo("'not a host at all' is neither a name nor an address that can be asked."));
                Assert.That(json?["steps"]?[0]?["level"]?.ToString(),  Is.EqualTo("error"));

                Assert.That(said.Select(entry => entry.Message),       Is.EqualTo(new[] { "'admin' asked this meter to test the time server 'not a host at all'." }));
                Assert.That(said.Select(entry => entry.Tags),          Has.All.EquivalentTo(new[] { "nts", "test", "web" }));

            });

        }

        #endregion

        #region TheRoleTable_SaysWhatEachRoleGrants()

        /// <summary>
        /// The table of roles is readable by anybody signed in - it names
        /// nobody - while the list of who holds them is not.
        /// </summary>
        [Test]
        public async Task TheRoleTable_SaysWhatEachRoleGrants()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", User2OrganizationEdgeLabel.IsGuest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var (rolesStatus, roles) = await browser.Call(HttpMethod.Get, "api/v1/accounts/roles");

            Assert.Multiple(() => {

                Assert.That(rolesStatus, Is.EqualTo(HttpStatusCode.OK), "a guest may read what the roles mean");

                Assert.That(roles?["roles"]?.Select(role => role["role"]?.ToString()),
                            Is.EquivalentTo(new[] { "IsAdmin", "IsAdminReadOnly", "IsMember", "IsGuest" }));

                // What the table promises has to be what the meter enforces,
                // otherwise it is a sentence somebody reads and believes.
                Assert.That(roles?["roles"]?.First(role => role["role"]?.ToString() == "IsMember")?["permissions"]?.Values<String>(),
                            Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration" }));

                Assert.That(roles?["roles"]?.First(role => role["role"]?.ToString() == "IsMember")?["title"]?.ToString(),
                            Is.EqualTo("Member"));

            });

            Assert.That(await browser.StatusOf(HttpMethod.Get, "api/v1/accounts"),
                        Is.EqualTo(HttpStatusCode.Forbidden),
                        "but not who holds them");

        }

        #endregion

        #region AnAdministrator_CanMakeAReadOnlyAccount()

        /// <summary>
        /// The whole point of this: somebody who has to watch a meter gets an
        /// account that can look and cannot touch, made from a browser rather
        /// than from a text editor on the meter's disk.
        /// </summary>
        [Test]
        public async Task AnAdministrator_CanMakeAReadOnlyAccount()
        {

            using var administrator = await SignInAsAdministrator();

            var (status, created) = await administrator.Call(
                                              HttpMethod.Post,
                                              "api/v1/accounts",
                                              new { userId = "rory", name = "Rory", role = "IsMember" }
                                          );

            var password = created?["password"]?.ToString();

            Assert.Multiple(() => {

                Assert.That(status,                                    Is.EqualTo(HttpStatusCode.Created));
                Assert.That(created?["account"]?["userId"]?.ToString(), Is.EqualTo("rory"));
                Assert.That(created?["account"]?["role"]?.ToString(),   Is.EqualTo("IsMember"));
                Assert.That(created?["account"]?["isYou"]?.Value<Boolean>(), Is.False);

                // No password was given, so the meter made one and this is the
                // only time it is ever shown.
                Assert.That(password,                                  Is.Not.Null.And.Not.Empty);

            });

            // And it works: an account that appears in a list and cannot sign in
            // would pass every assertion above.
            using var rory = await SignIn("rory", password!);

            var me = await rory.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["userId"]?.ToString(),              Is.EqualTo("rory"));
                Assert.That(me?["role"]?.ToString(),                Is.EqualTo("IsMember"));
                Assert.That(me?["permissions"]?.Values<String>(),   Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration" }));
            });

        }

        #endregion

        #region AReadOnlyAccount_MayLookAndNotTouch()

        /// <summary>
        /// What "read-only" has to mean if it is to be worth giving out: every
        /// reading resource answers, and everything that changes the meter,
        /// its certificates or its accounts is refused with a 403.
        /// </summary>
        [Test]
        public async Task AReadOnlyAccount_MayLookAndNotTouch()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(
                                         HttpMethod.Post,
                                         "api/v1/accounts",
                                         new { userId = "rory", role = "IsMember" }
                                     );

            using var rory = await SignIn("rory", created?["password"]?.ToString()!);

            Assert.Multiple(async () => {

                foreach (var path in new[] { "api/v1/meter", "api/v1/meter/registers",
                                             "api/v1/configuration", "api/v1/configuration/dns",
                                             "api/v1/configuration/nts", "api/v1/logs" })
                {
                    Assert.That(await rory.StatusOf(HttpMethod.Get, path),
                                Is.EqualTo(HttpStatusCode.OK),
                                $"reading '{path}'");
                }

                Assert.That(await rory.StatusOf(HttpMethod.Put, "api/v1/meter/mode", new { mode = "ImportOnly" }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "may not set the meter mode");

                Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/meter/energy/reset", new { }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "may not clear the energy counters");

                Assert.That(await rory.StatusOf(HttpMethod.Put, "api/v1/configuration/dns", new { enabled = false }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "may not repoint the name servers");

                Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/configuration/nts/sync", new { }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "may not make the meter send anything");

                Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/configuration/nts/test", new { host = "ptbtime2.ptb.de" }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "nor ask one time server everything");

                Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/certificates/servers/web/requests",
                                                new { subject = "CN=whoever" }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "may not ask for a certificate");

                Assert.That(await rory.StatusOf(HttpMethod.Get, "api/v1/accounts"),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "may not see the accounts");

                Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/accounts",
                                                new { userId = "smuggled", role = "IsAdmin" }),
                            Is.EqualTo(HttpStatusCode.Forbidden),           "and may not make itself company");

            });

        }

        #endregion

        #region MakingAnAccount_IsRefusedTwice_AndWithARoleThisMeterDoesNotHandOut()

        /// <summary>
        /// The two ways of asking for an account that cannot be made.
        /// </summary>
        /// <remarks>
        /// The second matters more than it looks: "follows" is a real label in
        /// Hermod's enumeration and grants nothing here, so taking it would
        /// make an account that can sign in and do nothing, which somebody
        /// would later have to work out the reason for.
        /// </remarks>
        [Test]
        public async Task MakingAnAccount_IsRefusedTwice_AndWithARoleThisMeterDoesNotHandOut()
        {

            using var administrator = await SignInAsAdministrator();

            await administrator.Call(HttpMethod.Post, "api/v1/accounts", new { userId = "rory", role = "IsGuest" });

            var (again,   conflict) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                               new { userId = "rory", role = "IsGuest" });

            var (unknown, refused)  = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                               new { userId = "nora", role = "follows" });

            var (none,    missing)  = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                               new { userId = "nora" });

            Assert.Multiple(() => {

                Assert.That(again,                          Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(conflict?["error"]?.ToString(), Does.Contain("already"));

                Assert.That(unknown,                        Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(refused?["error"]?.ToString(),  Does.Contain("IsMember"), "and says which roles there are");

                Assert.That(none,                           Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(missing?["error"]?.ToString(),  Does.Contain("role"));

            });

        }

        #endregion

        #region TheLastAdministrator_CannotBeDemotedOrRemoved()

        /// <summary>
        /// The rule that is not about tidiness: a meter with no administrator
        /// left cannot be given one from a browser, cannot be given a new
        /// certificate, and cannot be told which CAs to accept.
        /// </summary>
        [Test]
        public async Task TheLastAdministrator_CannotBeDemotedOrRemoved()
        {

            using var administrator = await SignInAsAdministrator();

            var (demoted, why)   = await administrator.Call(HttpMethod.Put, "api/v1/accounts/admin/role",
                                                            new { role = "IsGuest" });

            var (removed, why2)  = await administrator.Call(HttpMethod.Delete, "api/v1/accounts/admin");

            Assert.Multiple(() => {

                Assert.That(demoted,                   Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(why?["error"]?.ToString(), Does.Contain("only administrator"));

                Assert.That(removed,                    Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(why2?["error"]?.ToString(), Does.Contain("only administrator"));

            });

            // And the account is still there, still an administrator: a refusal
            // that half-happened would be worse than either outcome.
            var me = await administrator.GetJSON("api/v1/me");

            Assert.That(me?["role"]?.ToString(), Is.EqualTo("IsAdmin"));

        }

        #endregion

        #region AnAdministrator_CanStepDown_OnceThereIsAnother()

        /// <summary>
        /// Handing a meter over: make somebody else an administrator, then take
        /// your own account off it.
        /// </summary>
        [Test]
        public async Task AnAdministrator_CanStepDown_OnceThereIsAnother()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                        new { userId = "nora", role = "IsAdmin" });

            using var nora = await SignIn("nora", created?["password"]?.ToString()!);

            var (removed, json) = await nora.Call(HttpMethod.Delete, "api/v1/accounts/admin");

            Assert.Multiple(() => {
                Assert.That(removed,                            Is.EqualTo(HttpStatusCode.OK), $"{json}");
                Assert.That(json?["wasYou"]?.Value<Boolean>(),   Is.False);
            });

            // The session of the account that is gone goes with it.
            Assert.That(await administrator.StatusOf(HttpMethod.Get, "api/v1/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized));

            var accounts = await nora.GetJSON("api/v1/accounts");

            Assert.That(accounts?["accounts"]?.Select(account => account["userId"]?.ToString()),
                        Is.EquivalentTo(new[] { "nora" }));

        }

        #endregion

        #region ChangingARole_EndsTheSessionsOfThatAccount()

        /// <summary>
        /// A browser holding the old answer of /me would go on showing buttons
        /// that now answer 403. Signing it out is the honest way to say so.
        /// </summary>
        [Test]
        public async Task ChangingARole_EndsTheSessionsOfThatAccount()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                        new { userId = "rory", role = "IsAdminReadOnly" });

            var password = created?["password"]?.ToString()!;

            using var rory = await SignIn("rory", password);

            Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/configuration/nts/sync", new { }),
                        Is.EqualTo(HttpStatusCode.OK),
                        "a read-only administrator may ask a time server whether it answers");

            var (changed, account) = await administrator.Call(HttpMethod.Put, "api/v1/accounts/rory/role",
                                                              new { role = "IsGuest" });

            Assert.Multiple(() => {
                Assert.That(changed,                            Is.EqualTo(HttpStatusCode.OK));
                Assert.That(account?["role"]?.ToString(),       Is.EqualTo("IsGuest"));
                Assert.That(account?["roleTitle"]?.ToString(),  Is.EqualTo("Guest"));
            });

            Assert.That(await rory.StatusOf(HttpMethod.Get, "api/v1/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized),
                        "and the old session is gone rather than quietly weaker");

            // Signing in again shows what they may do now - and a role is the
            // one they were given, not the strongest of everything they ever held.
            using var again = await SignIn("rory", password);

            var me = await again.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),              Is.EqualTo("IsGuest"));
                Assert.That(me?["permissions"]?.Values<String>(), Is.EquivalentTo(new[] { "ReadMeter" }));
            });

        }

        #endregion

        #region ResettingAPassword_IsNotForYourOwnAccount()

        /// <summary>
        /// This route asks for no current password, because an administrator
        /// resetting somebody else's does not know it. Pointed at your own
        /// account that would be a way for whoever finds an unlocked browser to
        /// take it over, so it is refused and says where to go instead.
        /// </summary>
        [Test]
        public async Task ResettingAPassword_IsNotForYourOwnAccount()
        {

            using var administrator = await SignInAsAdministrator();

            var (status, json) = await administrator.Call(HttpMethod.Put, "api/v1/accounts/admin/password", new { });

            Assert.Multiple(() => {
                Assert.That(status,                     Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(json?["error"]?.ToString(), Does.Contain("your own"));
            });

            // And the password it refused to change still works.
            using var again = await SignInAsAdministrator();

            Assert.That(await again.StatusOf(HttpMethod.Get, "api/v1/me"), Is.EqualTo(HttpStatusCode.OK));

        }

        #endregion

        #region ResettingAPassword_TakesTheAccountBack()

        /// <summary>
        /// Somebody has lost their password, or should no longer have the one
        /// they have. A reset that left the old session alive would not have
        /// taken the account back.
        /// </summary>
        [Test]
        public async Task ResettingAPassword_TakesTheAccountBack()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                        new { userId = "rory", role = "IsMember" });

            using var rory = await SignIn("rory", created?["password"]?.ToString()!);

            var (status, reset) = await administrator.Call(HttpMethod.Put, "api/v1/accounts/rory/password", new { });

            var newPassword = reset?["password"]?.ToString();

            Assert.Multiple(() => {
                Assert.That(status,       Is.EqualTo(HttpStatusCode.OK), $"{reset}");
                Assert.That(newPassword,  Is.Not.Null.And.Not.Empty);
            });

            Assert.That(await rory.StatusOf(HttpMethod.Get, "api/v1/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized),
                        "the session that knew the old password is gone");

            using var afterwards = await SignIn("rory", newPassword!);

            Assert.That((await afterwards.GetJSON("api/v1/me"))?["userId"]?.ToString(), Is.EqualTo("rory"));

        }

        #endregion

        #region AnAccountThatIsNotThere_IsA404()

        /// <summary>
        /// Naming an account that does not exist is a 404 and not a 500, on
        /// every route that names one.
        /// </summary>
        [Test]
        public async Task AnAccountThatIsNotThere_IsA404()
        {

            using var administrator = await SignInAsAdministrator();

            Assert.Multiple(async () => {

                Assert.That(await administrator.StatusOf(HttpMethod.Delete, "api/v1/accounts/nobody"),
                            Is.EqualTo(HttpStatusCode.NotFound));

                Assert.That(await administrator.StatusOf(HttpMethod.Put, "api/v1/accounts/nobody/role",
                                                         new { role = "IsGuest" }),
                            Is.EqualTo(HttpStatusCode.NotFound));

                Assert.That(await administrator.StatusOf(HttpMethod.Put, "api/v1/accounts/nobody/password", new { }),
                            Is.EqualTo(HttpStatusCode.NotFound));

            });

        }

        #endregion

        #region SomebodyCanChangeTheirOwnPassword()

        /// <summary>
        /// The other half of handing out accounts: the person who was given a
        /// password the meter made can replace it with one of their own, and
        /// only by proving they know the current one.
        /// </summary>
        /// <remarks>
        /// Answered by Hermod at "/accounts/auth/password" rather than by this
        /// API, which is why it is worth a test here: the meter's web interface
        /// depends on it being there and on it asking.
        /// </remarks>
        [Test]
        public async Task SomebodyCanChangeTheirOwnPassword()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                        new { userId = "rory", role = "IsMember" });

            var given = created?["password"]?.ToString()!;

            using var rory = await SignIn("rory", given);

            Assert.That(await rory.StatusOf(HttpMethod.Post, "accounts/auth/password",
                                            new { currentPassword = "not-the-one", newPassword = "Correct-Horse-9" }),
                        Is.EqualTo(HttpStatusCode.Forbidden),
                        "not without the current one");

            Assert.That(await rory.StatusOf(HttpMethod.Post, "accounts/auth/password",
                                            new { currentPassword = given, newPassword = "Correct-Horse-9" }),
                        Is.EqualTo(HttpStatusCode.NoContent));

            using var afterwards = await SignIn("rory", "Correct-Horse-9");

            Assert.That((await afterwards.GetJSON("api/v1/me"))?["role"]?.ToString(), Is.EqualTo("IsMember"));

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
