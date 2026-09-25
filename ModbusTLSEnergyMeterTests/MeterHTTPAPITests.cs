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

using cloud.charging.open.protocols.WWCP.Node.Configuration;

using cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI;

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

            await new ModbusPKI().BuildPKI(Path.Combine(workingDirectory, "pki"));

            httpPort = FreeTCPPort();
            meter    = NewMeter();

            await meter.Start();

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

                Assert.That(me?["userId"]?.ToString(),        Is.EqualTo(ModbusTLSEnergyMeter.DefaultAdminUser));
                Assert.That(me?["organization"]?.ToString(),  Is.EqualTo(ModbusTLSEnergyMeter.MeterKind.Organization));
                Assert.That(me?["role"]?.ToString(),          Is.EqualTo("systemadmin"));
                Assert.That(me?["roles"]?.Values<String>(),   Is.EqualTo(new[] { "systemadmin" }));

                // The readable form travels with it, because every page that
                // tells somebody what they may not do names their role in the
                // same sentence, and "systemadmin" is not a thing anybody says.
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
        /// A guest of this meter sees what it is measuring, and
        /// is refused everything else - with a 403, which says that signing in
        /// again will not help.
        /// </summary>
        [Test]
        public async Task AGuest_MayReadTheMeter_AndNothingElse()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterRole.Guest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var me = await browser.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),                Is.EqualTo("guest"));
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

            await CreateUserAsync("rory", "Correct-Horse-2", MeterRole.Auditor);

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
        /// An account that is in none of this meter's groups holds no
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

                Assert.That(said.Select(entry => entry.Message),       Is.EqualTo(new[] { $"'{ModbusTLSEnergyMeter.DefaultAdminUser}' asked this meter to test the time server 'not a host at all'." }));
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

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterRole.Guest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var (rolesStatus, roles) = await browser.Call(HttpMethod.Get, "api/v1/accounts/roles");

            Assert.Multiple(() => {

                Assert.That(rolesStatus, Is.EqualTo(HttpStatusCode.OK), "a guest may read what the roles mean");

                Assert.That(roles?["roles"]?.Select(role => role["role"]?.ToString()),
                            Is.EquivalentTo(new[] { "systemadmin", "auditor", "viewer", "guest" }));

                // What the table promises has to be what the meter enforces,
                // otherwise it is a sentence somebody reads and believes.
                Assert.That(roles?["roles"]?.First(role => role["role"]?.ToString() == "viewer")?["permissions"]?.Values<String>(),
                            Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration" }));

                Assert.That(roles?["roles"]?.First(role => role["role"]?.ToString() == "viewer")?["title"]?.ToString(),
                            Is.EqualTo("Viewer"));

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
                                              new { userId = "rory", name = "Rory", role = "viewer" }
                                          );

            var password = created?["password"]?.ToString();

            Assert.Multiple(() => {

                Assert.That(status,                                    Is.EqualTo(HttpStatusCode.Created));
                Assert.That(created?["account"]?["userId"]?.ToString(), Is.EqualTo("rory"));
                Assert.That(created?["account"]?["role"]?.ToString(),   Is.EqualTo("viewer"));
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
                Assert.That(me?["role"]?.ToString(),                Is.EqualTo("viewer"));
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
                                         new { userId = "rory", role = "viewer" }
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
                                                new { userId = "smuggled", role = "systemadmin" }),
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

            await administrator.Call(HttpMethod.Post, "api/v1/accounts", new { userId = "rory", role = "guest" });

            var (again,   conflict) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                               new { userId = "rory", role = "guest" });

            var (unknown, refused)  = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                               new { userId = "nora", role = "follows" });

            var (none,    missing)  = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                               new { userId = "nora" });

            Assert.Multiple(() => {

                Assert.That(again,                          Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(conflict?["error"]?.ToString(), Does.Contain("already"));

                Assert.That(unknown,                        Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(refused?["error"]?.ToString(),  Does.Contain("viewer"), "and says which roles there are");

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

            var (demoted, why)   = await administrator.Call(HttpMethod.Put, $"api/v1/accounts/{ModbusTLSEnergyMeter.DefaultAdminUser}/role",
                                                            new { role = "guest" });

            var (removed, why2)  = await administrator.Call(HttpMethod.Delete, $"api/v1/accounts/{ModbusTLSEnergyMeter.DefaultAdminUser}");

            Assert.Multiple(() => {

                Assert.That(demoted,                   Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(why?["error"]?.ToString(), Does.Contain("only administrator"));

                Assert.That(removed,                    Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(why2?["error"]?.ToString(), Does.Contain("only administrator"));

            });

            // And the account is still there, still an administrator: a refusal
            // that half-happened would be worse than either outcome.
            var me = await administrator.GetJSON("api/v1/me");

            Assert.That(me?["role"]?.ToString(), Is.EqualTo("systemadmin"));

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
                                                        new { userId = "nora", role = "systemadmin" });

            using var nora = await SignIn("nora", created?["password"]?.ToString()!);

            var (removed, json) = await nora.Call(HttpMethod.Delete, $"api/v1/accounts/{ModbusTLSEnergyMeter.DefaultAdminUser}");

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
                                                        new { userId = "rory", role = "auditor" });

            var password = created?["password"]?.ToString()!;

            using var rory = await SignIn("rory", password);

            Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/configuration/nts/sync", new { }),
                        Is.EqualTo(HttpStatusCode.OK),
                        "a read-only administrator may ask a time server whether it answers");

            var (changed, account) = await administrator.Call(HttpMethod.Put, "api/v1/accounts/rory/role",
                                                              new { role = "guest" });

            Assert.Multiple(() => {
                Assert.That(changed,                            Is.EqualTo(HttpStatusCode.OK));
                Assert.That(account?["role"]?.ToString(),       Is.EqualTo("guest"));
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
                Assert.That(me?["role"]?.ToString(),              Is.EqualTo("guest"));
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

            var (status, json) = await administrator.Call(HttpMethod.Put, $"api/v1/accounts/{ModbusTLSEnergyMeter.DefaultAdminUser}/password", new { });

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
                                                        new { userId = "rory", role = "viewer" });

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
                                                         new { role = "guest" }),
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
        /// Answered by Hermod at "/ext/auth/password" rather than by this
        /// API, which is why it is worth a test here: the meter's web interface
        /// depends on it being there and on it asking.
        /// </remarks>
        [Test]
        public async Task SomebodyCanChangeTheirOwnPassword()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                        new { userId = "rory", role = "viewer" });

            var given = created?["password"]?.ToString()!;

            using var rory = await SignIn("rory", given);

            Assert.That(await rory.StatusOf(HttpMethod.Post, "ext/auth/password",
                                            new { currentPassword = "not-the-one", newPassword = "Correct-Horse-9" }),
                        Is.EqualTo(HttpStatusCode.Forbidden),
                        "not without the current one");

            Assert.That(await rory.StatusOf(HttpMethod.Post, "ext/auth/password",
                                            new { currentPassword = given, newPassword = "Correct-Horse-9" }),
                        Is.EqualTo(HttpStatusCode.NoContent));

            using var afterwards = await SignIn("rory", "Correct-Horse-9");

            Assert.That((await afterwards.GetJSON("api/v1/me"))?["role"]?.ToString(), Is.EqualTo("viewer"));

        }

        #endregion


        #region ARoleByItsOldName_IsTheGroupOfThatRole()

        /// <summary>
        /// A script from before the groups asks for "IsAdminReadOnly", and gets
        /// what that always meant: an auditor.
        /// </summary>
        /// <remarks>
        /// The names changed and what they grant did not, so a script that made
        /// accounts yesterday makes the same accounts today - and is told which
        /// group they are in, rather than having an old name echoed back.
        /// </remarks>
        [Test]
        public async Task ARoleByItsOldName_IsTheGroupOfThatRole()
        {

            using var administrator = await SignInAsAdministrator();

            var (status, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                             new { userId = "rory", role = "IsAdminReadOnly" });

            Assert.Multiple(() => {

                Assert.That(status,                                    Is.EqualTo(HttpStatusCode.Created), $"{created}");
                Assert.That(created?["account"]?["role"]?.ToString(),  Is.EqualTo("auditor"));

                Assert.That(meter!.RolesOf(meter.ExtAPI.Users.First(user => user.Id.ToString() == "rory")),
                            Is.EqualTo(new[] { MeterRole.Auditor }),
                            "and it is the group that says so");

            });

        }

        #endregion

        #region AnAccountFromBeforeTheGroups_KeepsItsRole()

        /// <summary>
        /// An account a meter from before the groups made - a role in its
        /// organization, and no group - is in the group of that role once the
        /// meter starts again, and may do what it could before.
        /// </summary>
        /// <remarks>
        /// Made while the meter runs and asked after a restart, because the
        /// start is when it is put right, before anybody can sign in. Until then
        /// the edge grants nothing, which is the other half of what is asserted:
        /// what somebody may do comes from the groups, and only from them.
        /// </remarks>
        [Test]
        public async Task AnAccountFromBeforeTheGroups_KeepsItsRole()
        {

            await CreateUserFromBeforeTheGroupsAsync("olga", "Correct-Horse-4", User2OrganizationEdgeLabel.IsAdminReadOnly);

            using (var before = await SignIn("olga", "Correct-Horse-4"))
                Assert.That((await before.GetJSON("api/v1/me"))?["permissions"]?.Values<String>(),
                            Is.Empty,
                            "a role in the organization grants nothing by itself");

            await RestartMeter();

            using var after = await SignIn("olga", "Correct-Horse-4");

            var me = await after.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),               Is.EqualTo("auditor"));
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration", "RunDiagnostics" }));
            });

        }

        #endregion

        #region AnAccountAlreadyInAGroup_IsLeftAsItIs()

        /// <summary>
        /// Somebody who was given a role since - in a group - keeps that one,
        /// whatever their old role in the organization said.
        /// </summary>
        [Test]
        public async Task AnAccountAlreadyInAGroup_IsLeftAsItIs()
        {

            await CreateUserFromBeforeTheGroupsAsync("olga", "Correct-Horse-4", User2OrganizationEdgeLabel.IsAdmin);

            var olga = meter!.ExtAPI.Users.First(user => user.Id.ToString() == "olga");

            Assert.That(meter.ExtAPI.TryGetUserGroup(MeterRole.Guest.GroupId, out var guests) && guests is UserGroup, Is.True);

            await meter.ExtAPI.AddUserToUserGroup((User) olga, User2UserGroupEdgeLabel.IsMember, (UserGroup) guests!);

            await RestartMeter();

            using var after = await SignIn("olga", "Correct-Horse-4");

            var me = await after.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["roles"]?.Values<String>(),        Is.EqualTo(new[] { "guest" }),
                            "an administrator of the organization from before is not made one again");
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "ReadMeter" }));
            });

        }

        #endregion

        #region TheAccountsOfAMeterFromBefore_AreFoundUnderTheirNewName()

        /// <summary>
        /// The accounts file of a meter from before, under the name Hermod gave
        /// it, is found and renamed to the one every node uses - and nobody is
        /// handed a new administrator's password in place of the one they wrote
        /// down.
        /// </summary>
        [Test]
        public async Task TheAccountsOfAMeterFromBefore_AreFoundUnderTheirNewName()
        {

            var password = meter!.GeneratedPassword!;

            await meter.DisposeAsync();
            meter = null;

            var accounts = Path.Combine(workingDirectory!, "data", "UsersAPI");

            // The file as a meter from before left it.
            File.Move(Path.Combine(accounts, ModbusTLSEnergyMeter.DefaultAccountsDatabaseFile),
                      Path.Combine(accounts, HTTPExtAPI.DefaultHTTPExtAPI_DatabaseFileName));

            httpPort = FreeTCPPort();
            meter    = NewMeter();

            await meter.Start();

            Assert.Multiple(() => {
                Assert.That(meter.GeneratedPassword,                                                              Is.Null, "no new administrator was made");
                Assert.That(File.Exists(Path.Combine(accounts, ModbusTLSEnergyMeter.DefaultAccountsDatabaseFile)),  Is.True);
                Assert.That(File.Exists(Path.Combine(accounts, HTTPExtAPI.DefaultHTTPExtAPI_DatabaseFileName)),     Is.False);
            });

            using var administrator = await SignIn(ModbusTLSEnergyMeter.DefaultAdminUser, password);

            Assert.That((await administrator.GetJSON("api/v1/me"))?["role"]?.ToString(), Is.EqualTo("systemadmin"));

        }

        #endregion


        #region AnAccountMadeAgain_HoldsOnlyTheRoleItIsGiven()

        /// <summary>
        /// An account removed and made again under the same name holds the
        /// role it is given now, and not the one the account before it held -
        /// neither straight away nor after a restart.
        /// </summary>
        /// <remarks>
        /// Hermod's groups hold their members by name. Until ce716a40 removing
        /// an account left it in them, and left its password behind: a guest
        /// made under an old administrator's name was an administrator, and
        /// could not be given a password of its own. The meter worked around
        /// both; this is what says Hermod does it now.
        /// </remarks>
        [Test]
        public async Task AnAccountMadeAgain_HoldsOnlyTheRoleItIsGiven()
        {

            using var administrator = await SignInAsAdministrator();

            await administrator.Call(HttpMethod.Post, "api/v1/accounts", new { userId = "rory", role = "systemadmin" });

            Assert.That(await administrator.StatusOf(HttpMethod.Delete, "api/v1/accounts/rory"),
                        Is.EqualTo(HttpStatusCode.OK));

            var (status, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts", new { userId = "rory", role = "guest" });
            var password          = created?["password"]?.ToString()!;

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), $"{created}");

            using (var rory = await SignIn("rory", password))
                Assert.That((await rory.GetJSON("api/v1/me"))?["roles"]?.Values<String>(),
                            Is.EqualTo(new[] { "guest" }),
                            "the account made again holds the role of the one removed");

            await RestartMeter();

            using var afterwards = await SignIn("rory", password);

            Assert.That((await afterwards.GetJSON("api/v1/me"))?["roles"]?.Values<String>(),
                        Is.EqualTo(new[] { "guest" }),
                        "and after a restart");

        }

        #endregion

        #region TheStrongestRoleFromBefore_IsTheOneKept()

        /// <summary>
        /// Somebody who was made both a member and an administrator of the
        /// organization before the groups was an administrator, and is one
        /// afterwards - in whichever order the two were given.
        /// </summary>
        [Test]
        public async Task TheStrongestRoleFromBefore_IsTheOneKept()
        {

            await CreateUserFromBeforeTheGroupsAsync("olga", "Correct-Horse-4",
                                                     User2OrganizationEdgeLabel.IsMember,
                                                     User2OrganizationEdgeLabel.IsAdmin);

            await RestartMeter();

            using var after = await SignIn("olga", "Correct-Horse-4");

            Assert.That((await after.GetJSON("api/v1/me"))?["roles"]?.Values<String>(),
                        Is.EqualTo(new[] { "systemadmin" }));

        }

        #endregion

        #region SomebodyInTwoGroups_IsNamedByTheStronger()

        /// <summary>
        /// An account in two of the meter's groups holds both roles, and is
        /// called by the stronger one wherever a single name is asked for.
        /// </summary>
        [Test]
        public async Task SomebodyInTwoGroups_IsNamedByTheStronger()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterRole.Guest);

            var gwen = meter!.ExtAPI.Users.First(user => user.Id.ToString() == "gwen");

            Assert.That(meter.ExtAPI.TryGetUserGroup(MeterRole.Auditor.GroupId, out var auditors) && auditors is UserGroup, Is.True);

            await meter.ExtAPI.AddUserToUserGroup((User) gwen, User2UserGroupEdgeLabel.IsMember, (UserGroup) auditors!);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var me = await browser.GetJSON("api/v1/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),               Is.EqualTo("auditor"));
                Assert.That(me?["roleTitle"]?.ToString(),          Is.EqualTo("Auditor"));
                Assert.That(me?["roles"]?.Values<String>(),        Is.EqualTo(new[] { "auditor", "guest" }));
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "ReadMeter", "ReadConfiguration", "RunDiagnostics" }));
            });

        }

        #endregion

        #region ARefusal_SaysWhichRolesMay()

        /// <summary>
        /// A 403 names the roles that may do what was refused, so that whoever
        /// reads it knows whom to ask - and not only that the answer was no.
        /// </summary>
        [Test]
        public async Task ARefusal_SaysWhichRolesMay()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterRole.Guest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var (changing, notChanged) = await browser.Call(HttpMethod.Put, "api/v1/configuration/dns", new { enabled = false });
            var (reading,  notRead)    = await browser.Call(HttpMethod.Get, "api/v1/configuration");

            Assert.Multiple(() => {

                Assert.That(changing,                                     Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(notChanged?["role"]?.ToString(),              Is.EqualTo("guest"));
                Assert.That(notChanged?["rolesThatMay"]?.Values<String>(), Is.EqualTo(new[] { "systemadmin" }));

                Assert.That(reading,                                      Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(notRead?["rolesThatMay"]?.Values<String>(),    Is.EqualTo(new[] { "systemadmin", "auditor", "viewer" }));

            });

        }

        #endregion

        #region TheLogBook_CanBeCheckedFromTheBrowser()

        /// <summary>
        /// The check of the log book on the Logs page walks the node's
        /// metrological log - the files the meter signs - and says so.
        /// </summary>
        [Test]
        public async Task TheLogBook_CanBeCheckedFromTheBrowser()
        {

            using var administrator = await SignInAsAdministrator();

            var (status, json) = await administrator.Call(HttpMethod.Get, "api/v1/logs/verify");

            Assert.Multiple(() => {

                Assert.That(status,                                  Is.EqualTo(HttpStatusCode.OK), $"{json}");
                Assert.That(json?["persisted"]?.Value<Boolean>(),    Is.True);
                Assert.That(json?["intact"]?.Value<Boolean>(),       Is.True,  $"{json?["firstProblem"]}");
                Assert.That(json?["metrological"]?.Value<Boolean>(), Is.True);

                Assert.That(json?["path"]?.ToString(),               Is.EqualTo(meter!.MetrologicalLog!.Path));
                Assert.That(json?["keyId"]?.ToString(),              Is.EqualTo(meter.MetrologicalLog.Signer.KeyId));
                Assert.That(json?["publicKey"]?.ToString(),          Is.EqualTo(meter.MetrologicalLog.Signer.PublicKeyPem));

            });

        }

        #endregion


        #region (private) Helpers

        /// <summary>
        /// The meter under test, on the working directory and the HTTP port
        /// of this test: the same at the start and after a restart.
        /// </summary>
        private ModbusTLSEnergyMeter NewMeter()

            => new (
                   SerialNumber:       "meter-test-001",
                   ServerPfxPath:      Path.Combine(workingDirectory!, "pki", "server.pfx"),
                   ServerPfxPassword:  "demo",
                   ClientCACertPath:   Path.Combine(workingDirectory!, "pki", "issuing-clients-ca.crt"),
                   ListenAddress:      NetIPAddress.Loopback,
                   ListenPort:         FreeTCPPort(),
                   HTTPHostname:       IPv4Address.Localhost,
                   HTTPPort:           IPPort.Parse(httpPort),
                   DataPath:           Path.Combine(workingDirectory!, "data"),
                   ConfigFile:         new WWCPConfigFile(Path.Combine(workingDirectory!, "configuration.json")),
                   LogToConsole:       false
               );

        /// <summary>
        /// Stop the meter and start another on the same data directory - what
        /// happens when the program is started again after an update.
        /// </summary>
        /// <remarks>
        /// On a port of its own rather than the old one again: that one may
        /// still be held by connections winding down, and what is under test is
        /// the data directory, not how soon a port is given back.
        /// </remarks>
        private async Task RestartMeter()
        {

            await meter!.DisposeAsync();

            httpPort = FreeTCPPort();
            meter    = NewMeter();

            await meter.Start();

        }

        /// <summary>
        /// Make a user in the group of the given role, or in none of this
        /// meter's groups when the role is null.
        /// </summary>
        private async Task CreateUserAsync(String      UserId,
                                           String      Password,
                                           MeterRole?  Role)
        {

            var api  = meter!.ExtAPI;
            var user = NewUser(UserId);

            await api.AddUser(user,
                              SkipNewUserEMail: true, SkipNewUserNotifications: true);

            await api.ChangePassword(user, Password, SuppressNotifications: true);

            if (Role is null)
                return;

            Assert.That(api.TryGetUserGroup(Role.GroupId, out var group) && group is UserGroup, Is.True,
                        $"There is no {Role.Name} group.");

            var joined = await api.AddUserToUserGroup(user,
                                                      Role == MeterRole.SystemAdmin
                                                          ? User2UserGroupEdgeLabel.IsAdmin
                                                          : User2UserGroupEdgeLabel.IsMember,
                                                      (UserGroup) group!);

            Assert.That(joined.IsSuccess, Is.True, $"'{UserId}' could not be put in the {Role.Name} group.");

        }

        /// <summary>
        /// Make a user the way a meter from before the groups did: with roles
        /// in its organization, in the order given, and in none of its groups.
        /// </summary>
        private async Task CreateUserFromBeforeTheGroupsAsync(String                               UserId,
                                                              String                               Password,
                                                              params User2OrganizationEdgeLabel[]  Roles)
        {

            var api = meter!.ExtAPI;

            Assert.That(api.TryGetOrganization(Organization_Id.Parse(ModbusTLSEnergyMeter.MeterKind.Organization), out var organization) &&
                        organization is not null,
                        Is.True,
                        "The meter has no organization to hold a role in.");

            var user = NewUser(UserId);

            await api.AddUser(user, Roles[0], organization!,
                              SkipNewUserEMail: true, SkipNewUserNotifications: true);

            foreach (var role in Roles.Skip(1))
                Assert.That((await api.AddUserToOrganization(user, role, organization!)).IsSuccess,
                            Is.True);

            await api.ChangePassword(user, Password, SuppressNotifications: true);

        }

        private static User NewUser(String UserId)

            => new (
                   User_Id.Parse(UserId),
                   I18NString.Create(UserId),
                   SimpleEMailAddress.Parse($"{UserId}@example.test"),
                   IsAuthenticated:  true,
                   DataSource:       "test"
               );

        private Browser NewBrowser()
            => new ($"http://127.0.0.1:{httpPort}/");

        private async Task<Browser> SignInAsAdministrator()
            => await SignIn(ModbusTLSEnergyMeter.DefaultAdminUser, meter!.GeneratedPassword!);

        private async Task<Browser> SignIn(String UserId, String Password)
        {

            var browser        = NewBrowser();
            var (status, json) = await browser.Call(HttpMethod.Post, "ext/auth/login",
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
