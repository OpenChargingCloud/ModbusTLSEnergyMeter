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
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.PKI;

using cloud.charging.open.protocols.WWCP.Node.Configuration;
using cloud.charging.open.protocols.WWCP.Node.TestKit;
using cloud.charging.open.protocols.WWCP.Node.Web;

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

            httpPort = TestPorts.Free();
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

            var me = await browser.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {

                Assert.That(me?["username"]?.ToString(),      Is.EqualTo(ModbusTLSEnergyMeter.DefaultAdminUser));
                Assert.That(me?["organization"]?.ToString(),  Is.EqualTo(ModbusTLSEnergyMeter.MeterKind.Organization));
                Assert.That(me?["role"]?.ToString(),          Is.EqualTo("systemadmin"));
                Assert.That(me?["roles"]?.Values<String>(),   Is.EqualTo(new[] { "systemadmin" }));

                // The readable form travels with it, because every page that
                // tells somebody what they may not do names their role in the
                // same sentence, and "systemadmin" is not a thing anybody says.
                Assert.That(me?["roleTitle"]?.ToString(),        Is.EqualTo("Administrator"));
                Assert.That(me?["roleDescription"]?.ToString(),  Does.Contain("Everything"));

                // Every operation on every resource, spelled out - "*" is the
                // node's shorthand and never reaches a page.
                Assert.That(me?["permissions"]?.Values<String>(),
                            Is.EquivalentTo(new[] { "configuration", "dns", "nts", "certificates", "meter", "keys", "log", "accounts" }.
                                                SelectMany(resource => new[] { "read", "edit", "run" }.Select(operation => $"{resource}:{operation}"))));

            });

        }

        #endregion

        #region WithoutSigningIn_EverythingIs401()

        /// <summary>
        /// No session, no answer - not even to the resources that only read.
        /// </summary>
        /// <remarks>
        /// The reads only a meter has. What every node reads - its status, who
        /// is signed in, its clock, its configuration, its log and its store -
        /// is asked by the node's conformance suite, in MeterConformance.
        /// </remarks>
        [Test]
        public async Task WithoutSigningIn_EverythingIs401()
        {

            using var browser = NewBrowser();

            foreach (var path in new[] { "api/v1/meter",              "api/v1/meter/registers",  "api/v1/configuration/certificates",
                                         "api/v1/accounts",           "api/v1/accounts/roles",   "api/v1/certificates/requests",
                                         "api/v1/signedMeterValues",  "api/v1/sessions",         "api/v1/keys",
                                         "api/v1/logs/verify" })
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

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterAccess.Guest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var me = await browser.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),                Is.EqualTo("guest"));
                Assert.That(me?["roleTitle"]?.ToString(),           Is.EqualTo("Guest"));
                Assert.That(me?["permissions"]?.Values<String>(),   Is.EquivalentTo(new[] { "meter:read" }));
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

            await CreateUserAsync("rory", "Correct-Horse-2", MeterAccess.Auditor);

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

            var me = await browser.GetJSON("api/v1/auth/me");

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

        #region TheRoleTable_SaysWhatEachRoleGrants()

        /// <summary>
        /// The table of roles is readable by anybody signed in - it names
        /// nobody - while the list of who holds them is not.
        /// </summary>
        [Test]
        public async Task TheRoleTable_SaysWhatEachRoleGrants()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterAccess.Guest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var (rolesStatus, roles) = await browser.Call(HttpMethod.Get, "api/v1/accounts/roles");

            Assert.Multiple(() => {

                Assert.That(rolesStatus, Is.EqualTo(HttpStatusCode.OK), "a guest may read what the roles mean");

                // In the node's order: the viewer first, the administrators last.
                Assert.That(roles?["roles"]?.Select(role => role["role"]?.ToString()),
                            Is.EqualTo(new[] { "viewer", "auditor", "guest", "systemadmin" }));

                // What the table promises has to be what the meter enforces,
                // otherwise it is a sentence somebody reads and believes.
                Assert.That(roles?["roles"]?.First(role => role["role"]?.ToString() == "viewer")?["permissions"]?.Values<String>(),
                            Is.EquivalentTo(new[] { "configuration:read", "dns:read", "nts:read", "certificates:read", "meter:read", "keys:read", "log:read" }));

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

            var me = await rory.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(me?["username"]?.ToString(),            Is.EqualTo("rory"));
                Assert.That(me?["role"]?.ToString(),                Is.EqualTo("viewer"));
                Assert.That(me?["permissions"]?.Values<String>(),   Is.EquivalentTo(new[] { "configuration:read", "dns:read", "nts:read", "certificates:read", "meter:read", "keys:read", "log:read" }));
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
                                             "api/v1/configuration/nts", "api/v1/logs",
                                             "api/v1/certificates", "api/v1/certificates/requests" })
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

                Assert.That(await rory.StatusOf(HttpMethod.Post, "api/v1/certificates/requests",
                                                new { listener = "web", subject = "CN=whoever" }),
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
            var me = await administrator.GetJSON("api/v1/auth/me");

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
            Assert.That(await administrator.StatusOf(HttpMethod.Get, "api/v1/auth/me"),
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

            Assert.That(await rory.StatusOf(HttpMethod.Get, "api/v1/auth/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized),
                        "and the old session is gone rather than quietly weaker");

            // Signing in again shows what they may do now - and a role is the
            // one they were given, not the strongest of everything they ever held.
            using var again = await SignIn("rory", password);

            var me = await again.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),              Is.EqualTo("guest"));
                Assert.That(me?["permissions"]?.Values<String>(), Is.EquivalentTo(new[] { "meter:read" }));
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

            Assert.That(await again.StatusOf(HttpMethod.Get, "api/v1/auth/me"), Is.EqualTo(HttpStatusCode.OK));

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

            Assert.That(await rory.StatusOf(HttpMethod.Get, "api/v1/auth/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized),
                        "the session that knew the old password is gone");

            using var afterwards = await SignIn("rory", newPassword!);

            Assert.That((await afterwards.GetJSON("api/v1/auth/me"))?["username"]?.ToString(), Is.EqualTo("rory"));

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

            Assert.That((await afterwards.GetJSON("api/v1/auth/me"))?["role"]?.ToString(), Is.EqualTo("viewer"));

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

                Assert.That(meter!.RolesOf(meter.ExtAPI.Users.First(user => user.Id.ToString() == "rory")).Select(role => role.Name),
                            Is.EqualTo(new[] { "auditor" }),
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
                Assert.That((await before.GetJSON("api/v1/auth/me"))?["permissions"]?.Values<String>(),
                            Is.Empty,
                            "a role in the organization grants nothing by itself");

            await RestartMeter();

            using var after = await SignIn("olga", "Correct-Horse-4");

            var me = await after.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),               Is.EqualTo("auditor"));
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "configuration:read", "dns:read", "nts:read", "certificates:read", "meter:read", "keys:read", "log:read", "nts:run" }));
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

            Assert.That(meter.ExtAPI.TryGetUserGroup(MeterAccess.Guest.GroupId, out var guests) && guests is UserGroup, Is.True);

            await meter.ExtAPI.AddUserToUserGroup((User) olga, User2UserGroupEdgeLabel.IsMember, (UserGroup) guests!);

            await RestartMeter();

            using var after = await SignIn("olga", "Correct-Horse-4");

            var me = await after.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(me?["roles"]?.Values<String>(),        Is.EqualTo(new[] { "guest" }),
                            "an administrator of the organization from before is not made one again");
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "meter:read" }));
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

            httpPort = TestPorts.Free();
            meter    = NewMeter();

            await meter.Start();

            Assert.Multiple(() => {
                Assert.That(meter.GeneratedPassword,                                                              Is.Null, "no new administrator was made");
                Assert.That(File.Exists(Path.Combine(accounts, ModbusTLSEnergyMeter.DefaultAccountsDatabaseFile)),  Is.True);
                Assert.That(File.Exists(Path.Combine(accounts, HTTPExtAPI.DefaultHTTPExtAPI_DatabaseFileName)),     Is.False);
            });

            using var administrator = await SignIn(ModbusTLSEnergyMeter.DefaultAdminUser, password);

            Assert.That((await administrator.GetJSON("api/v1/auth/me"))?["role"]?.ToString(), Is.EqualTo("systemadmin"));

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
                Assert.That((await rory.GetJSON("api/v1/auth/me"))?["roles"]?.Values<String>(),
                            Is.EqualTo(new[] { "guest" }),
                            "the account made again holds the role of the one removed");

            await RestartMeter();

            using var afterwards = await SignIn("rory", password);

            Assert.That((await afterwards.GetJSON("api/v1/auth/me"))?["roles"]?.Values<String>(),
                        Is.EqualTo(new[] { "guest" }),
                        "and after a restart");

        }

        #endregion

        #region AnAccountMadeAgain_IsNotSignedInByTheSessionsOfTheOneRemoved()

        /// <summary>
        /// The sessions of a removed account end with it: none of them signs in
        /// the account made again under the same name - neither straight away
        /// nor after a restart, which a session of somebody else outlives.
        /// </summary>
        /// <remarks>
        /// A session names its account by name, so one left behind signed in
        /// whoever was given that name next. Hermod ends them itself since
        /// db40ddf3; before that, the meter did after removing an account.
        /// </remarks>
        [Test]
        public async Task AnAccountMadeAgain_IsNotSignedInByTheSessionsOfTheOneRemoved()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                        new { userId = "rory", role = "systemadmin" });

            using var rory = await SignIn("rory", created?["password"]?.ToString()!);

            Assert.That(await administrator.StatusOf(HttpMethod.Delete, "api/v1/accounts/rory"),
                        Is.EqualTo(HttpStatusCode.OK));

            var (status, again) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                           new { userId = "rory", role = "guest" });

            Assert.That(status, Is.EqualTo(HttpStatusCode.Created), $"{again}");

            Assert.That(await rory.StatusOf(HttpMethod.Get, "api/v1/auth/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized),
                        "a session of the account removed signs in the one made again");

            await RestartMeter();

            using var administratorAfterwards = NewBrowser(administrator.Cookies);
            using var roryAfterwards          = NewBrowser(rory.Cookies);

            Assert.That(await administratorAfterwards.StatusOf(HttpMethod.Get, "api/v1/auth/me"),
                        Is.EqualTo(HttpStatusCode.OK),
                        "a session outlives a restart - without that, the next check proves nothing");

            Assert.That(await roryAfterwards.StatusOf(HttpMethod.Get, "api/v1/auth/me"),
                        Is.EqualTo(HttpStatusCode.Unauthorized),
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

            Assert.That((await after.GetJSON("api/v1/auth/me"))?["roles"]?.Values<String>(),
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

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterAccess.Guest);

            var gwen = meter!.ExtAPI.Users.First(user => user.Id.ToString() == "gwen");

            Assert.That(meter.ExtAPI.TryGetUserGroup(MeterAccess.Auditor.GroupId, out var auditors) && auditors is UserGroup, Is.True);

            await meter.ExtAPI.AddUserToUserGroup((User) gwen, User2UserGroupEdgeLabel.IsMember, (UserGroup) auditors!);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var me = await browser.GetJSON("api/v1/auth/me");

            Assert.Multiple(() => {
                Assert.That(me?["role"]?.ToString(),               Is.EqualTo("auditor"));
                Assert.That(me?["roleTitle"]?.ToString(),          Is.EqualTo("Auditor"));
                Assert.That(me?["roles"]?.Values<String>(),        Is.EqualTo(new[] { "auditor", "guest" }));
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "configuration:read", "dns:read", "nts:read", "certificates:read", "meter:read", "keys:read", "log:read", "nts:run" }));
            });

        }

        #endregion

        #region ARefusal_SaysWhichRolesMay()

        /// <summary>
        /// A 403 names the roles that may do what was refused, so that whoever
        /// reads it knows whom to ask - and not only that the answer was no.
        /// What was refused, and to whom, is in the log.
        /// </summary>
        [Test]
        public async Task ARefusal_SaysWhichRolesMay()
        {

            await CreateUserAsync("gwen", "Correct-Horse-1", MeterAccess.Guest);

            using var browser = await SignIn("gwen", "Correct-Horse-1");

            var before                 = meter!.Log.LastId;
            var (changing, notChanged) = await browser.Call(HttpMethod.Put, "api/v1/configuration/dns", new { enabled = false });
            var (reading,  notRead)    = await browser.Call(HttpMethod.Get, "api/v1/configuration");
            var refusals               = meter.Log.Recent(50, before, "auth").Select(entry => entry.Message).ToArray();

            Assert.Multiple(() => {

                Assert.That(changing,                          Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(notChanged?["error"]?.ToString(),  Is.EqualTo("This needs the systemadmin role."));

                // In the node's order, the viewer first.
                Assert.That(reading,                           Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(notRead?["error"]?.ToString(),     Is.EqualTo("This needs the viewer or auditor or systemadmin role."));

                Assert.That(refusals,                          Has.Some.EqualTo("'gwen' was refused dns:edit on PUT /api/v1/configuration/dns; signed in as guest."));
                Assert.That(refusals,                          Has.Some.EqualTo("'gwen' was refused configuration:read on GET /api/v1/configuration; signed in as guest."));

            });

        }

        #endregion

        #region ARoleFromTheConfigurationFile_CanBeGivenAndIsHeard()

        /// <summary>
        /// The point of the roles being data: a role the configuration file adds
        /// is one an administrator can give out, is listed with the others, and
        /// is held to exactly what the file says - here somebody who looks after
        /// the time and the readings, and nothing else.
        /// </summary>
        [Test]
        public async Task ARoleFromTheConfigurationFile_CanBeGivenAndIsHeard()
        {

            // Only the first start makes an administrator and says its password.
            var rootPassword = meter!.GeneratedPassword!;

            await RestartMeterWith(new JObject(
                                       new JProperty("timekeeper", new JArray("meter:read", "nts:read", "nts:run"))
                                   ));

            Assert.That(meter!.Roles, Is.EqualTo(new[] { "viewer", "auditor", "guest", "timekeeper", "systemadmin" }),
                        "before the administrators, as the node orders a role the file adds");

            using var administrator = await SignIn(ModbusTLSEnergyMeter.DefaultAdminUser, rootPassword);

            var (made, created) = await administrator.Call(HttpMethod.Post, "api/v1/accounts",
                                                           new { userId = "tess", role = "timekeeper" });

            Assert.That(made, Is.EqualTo(HttpStatusCode.Created), $"{created}");

            using var tess = await SignIn("tess", created?["password"]?.ToString()!);

            var me              = await tess.GetJSON("api/v1/auth/me");
            var (_, roleTable)  = await tess.Call(HttpMethod.Get, "api/v1/accounts/roles");
            var timekeeper      = roleTable?["roles"]?.FirstOrDefault(role => role["role"]?.ToString() == "timekeeper");

            Assert.Multiple(async () => {

                Assert.That(me?["role"]?.ToString(),               Is.EqualTo("timekeeper"));
                Assert.That(me?["roleTitle"]?.ToString(),          Is.EqualTo("timekeeper"),
                            "a role nobody gave a title is called by its name");
                Assert.That(me?["permissions"]?.Values<String>(),  Is.EquivalentTo(new[] { "meter:read", "nts:read", "nts:run" }));

                Assert.That(timekeeper?["permissions"]?.Values<String>(), Is.EquivalentTo(new[] { "meter:read", "nts:read", "nts:run" }),
                            "and the role table says the same");

                Assert.That(await tess.StatusOf(HttpMethod.Get, "api/v1/meter"),              Is.EqualTo(HttpStatusCode.OK));
                Assert.That(await tess.StatusOf(HttpMethod.Get, "api/v1/configuration/nts"),  Is.EqualTo(HttpStatusCode.OK));

                Assert.That(await tess.StatusOf(HttpMethod.Get, "api/v1/configuration/dns"),  Is.EqualTo(HttpStatusCode.Forbidden),
                            "what the file does not name");
                Assert.That(await tess.StatusOf(HttpMethod.Get, "api/v1/logs"),               Is.EqualTo(HttpStatusCode.Forbidden));
                Assert.That(await tess.StatusOf(HttpMethod.Put, "api/v1/configuration/nts", new { }),
                            Is.EqualTo(HttpStatusCode.Forbidden),
                            "reading the time servers and asking them is not changing them");

            });

        }

        #endregion

        #region ARoleNamingWhatTheMeterDoesNotHave_StopsTheStart()

        /// <summary>
        /// A role in the configuration file that names a resource this meter
        /// does not have stops the start, and the refusal lists the ones it has.
        /// </summary>
        /// <remarks>
        /// Otherwise a typo would be a role that quietly grants nothing, handed
        /// to somebody who then finds out on the night they need it.
        /// </remarks>
        [Test]
        public async Task ARoleNamingWhatTheMeterDoesNotHave_StopsTheStart()
        {

            await meter!.DisposeAsync();
            meter = null;

            WriteRolesIntoTheConfiguration(new JObject(
                                               new JProperty("support", new JArray("registers:edit"))
                                           ));

            var refused = Assert.Throws<InvalidOperationException>(() => NewMeter());

            Assert.That(refused?.Message, Does.Contain("'registers'").
                                          And.Contain("meter, keys, log, accounts"));

        }

        #endregion

        #region TheCertificateStore_HoldsWhatTheMeterWasStartedWith()

        /// <summary>
        /// One store for every certificate the meter shows and believes, and in
        /// it what the meter was started with: its certificate as the identity of
        /// the Modbus/TLS listener, with the intermediates it came with, and the
        /// CA its clients are issued by - which is not a root, and is a client
        /// root all the same.
        /// </summary>
        [Test]
        public async Task TheCertificateStore_HoldsWhatTheMeterWasStartedWith()
        {

            using var administrator = await SignInAsAdministrator();

            var (status, store) = await administrator.Call(HttpMethod.Get, "api/v1/certificates");

            var identity  = store?["certificates"]?["tlsIdentity"]?.FirstOrDefault(entry => entry["label"]?.ToString() == "the certificate this meter was started with");
            var clientCA  = store?["certificates"]?["clientRoot"]?. FirstOrDefault(entry => entry["label"]?.ToString() == "the CA this meter was started with");

            Assert.Multiple(() => {

                Assert.That(status,                                                               Is.EqualTo(HttpStatusCode.OK));
                Assert.That(store?["kinds"]?.Children<JProperty>().Select(kind => kind.Name),     Is.EqualTo(new[] { "tlsRoot", "clientRoot", "tlsServer", "tlsIdentity" }));
                Assert.That(store?["listeners"]?.Values<String>(),                                Is.EqualTo(new[] { "modbus", "web" }));
                Assert.That(store?["kinds"]?["tlsIdentity"]?["usages"]?.Values<String>(),         Is.EqualTo(new[] { "modbus", "web" }), "an identity is told a listener");
                Assert.That(store?["kinds"]?["tlsRoot"]?["usages"]?.Values<String>(),             Is.EqualTo(new[] { "dns", "nts" }),    "a root a service");
                Assert.That(store?["kinds"]?["clientRoot"]?["hasUsages"]?.Value<Boolean>(),       Is.False);

                Assert.That(identity,                                                             Is.Not.Null, store?.ToString());
                Assert.That(identity?["usages"]?.Values<String>(),                                Is.EqualTo(new[] { "modbus" }));
                Assert.That(identity?["hasPrivateKey"]?.Value<Boolean>(),                         Is.True);
                Assert.That(identity?["chainLength"]?.Value<Int32>(),                             Is.GreaterThan(0), "the intermediates travel with it");
                Assert.That(identity?["shownOn"]?.Values<String>(),                               Is.EqualTo(new[] { "modbus" }));
                Assert.That(store?["shown"]?["modbus"]?["current"]?.ToString(),                   Is.EqualTo(identity?["id"]?.ToString()));

                Assert.That(clientCA,                                                             Is.Not.Null, store?.ToString());
                Assert.That(clientCA?["subject"]?.ToString(),                                     Is.Not.EqualTo(clientCA?["issuer"]?.ToString()), "an issuing CA, and not its root");
                Assert.That(clientCA?["usable"]?.Value<Boolean>(),                                Is.True);

            });

        }

        #endregion

        #region ASigningRequestIsAnswered_AndTheNewerCertificateIsShown()

        /// <summary>
        /// The key is made in the meter, the request goes to a CA, and what comes
        /// back becomes an identity of the listener it was asked for - shown from
        /// the moment it is the newest valid one, without a restart, and written
        /// into the log book as the store takes it rather than at the next
        /// minute's check.
        /// </summary>
        /// <remarks>
        /// Asked without a key type: the meter's own default, which it used to
        /// refuse under its old spelling.
        /// </remarks>
        [Test]
        public async Task ASigningRequestIsAnswered_AndTheNewerCertificateIsShown()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, before)       = await administrator.Call(HttpMethod.Get, "api/v1/certificates");
            var shownBefore       = before?["shown"]?["modbus"]?["current"]?.ToString();
            var startedWith       = before?["certificates"]?["tlsIdentity"]?.First(entry => entry["id"]?.ToString() == shownBefore);
            var startedAt         = new DateTimeOffset(DateTime.SpecifyKind(startedWith!["notBefore"]!.Value<DateTime>(), DateTimeKind.Utc));

            var (made, request)   = await administrator.Call(HttpMethod.Post, "api/v1/certificates/requests",
                                                             new { listener = "modbus", subject = "CN=meter-test-001, O=Test", dnsNames = new[] { "meter-test-001.local" } });

            Assert.That(made, Is.EqualTo(HttpStatusCode.Created), $"{request}");

            var id                = request!["id"]!.ToString();
            var (downloaded, csr) = await administrator.GetText($"api/v1/certificates/requests/{id}");

            Assert.That(downloaded, Is.EqualTo(HttpStatusCode.OK), csr);

            // Signed by the device CA the meter's own certificate came from, and
            // valid from a second after that one, so that it is the newer.
            var validFrom         = startedAt.AddSeconds(1);
            var wait              = validFrom - DateTimeOffset.UtcNow;

            if (wait > TimeSpan.Zero)
                await Task.Delay(wait + TimeSpan.FromMilliseconds(250));

            using var issuer      = X509Certificate2.CreateFromPemFile(Path.Combine(workingDirectory!, "pki", "issuing-device-ca.crt"),
                                                                       Path.Combine(workingDirectory!, "pki", "issuing-device-ca.key"));

            var signing           = CertificateRequest.LoadSigningRequestPem(csr, HashAlgorithmName.SHA256, CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions);

            using var issued      = signing.Create(issuer, validFrom, validFrom.AddDays(90), [ 0x01, .. RandomNumberGenerator.GetBytes(15) ]);

            var beforeAnswer        = meter!.Log.LastId;

            var (answered, answer)  = await administrator.Call(HttpMethod.Put, $"api/v1/certificates/requests/{id}",
                                                               new { pem = issued.ExportCertificatePem() + "\n" + issuer.ExportCertificatePem() });

            // Before anything asks what is shown: what is said here was said
            // because the store changed.
            var said              = meter.Log.Recent(50, beforeAnswer, "certificates").Select(entry => entry.Message).ToArray();

            var (_, after)        = await administrator.Call(HttpMethod.Get, "api/v1/certificates");
            var (_, requests)     = await administrator.Call(HttpMethod.Get, "api/v1/certificates/requests");

            Assert.Multiple(() => {

                Assert.That(csr,                                                                         Does.StartWith("-----BEGIN CERTIFICATE REQUEST-----"));
                Assert.That(request["keyType"]?.ToString(),                                              Is.EqualTo("ecdsa-p256"));

                // The key stays in the meter: not in the file a CA is sent, and
                // not in anything the API says about the request.
                Assert.That(csr,                                                                         Does.Not.Contain("PRIVATE KEY"));
                Assert.That(request.ToString(),                                                          Does.Not.Contain("PRIVATE KEY"));
                Assert.That(requests?.ToString(),                                                        Does.Not.Contain("PRIVATE KEY"));

                Assert.That(answered,                                                                    Is.EqualTo(HttpStatusCode.OK), $"{answer}");
                Assert.That(answer?["certificate"]?["usages"]?.Values<String>(),                         Is.EqualTo(new[] { "modbus" }));
                Assert.That(answer?["certificate"]?["chainLength"]?.Value<Int32>(),                      Is.EqualTo(1), "the issuing CA came with it");

                Assert.That(after?["shown"]?["modbus"]?["current"]?.ToString(),                          Is.EqualTo(answer?["certificate"]?["id"]?.ToString()),
                            "the newer one is shown from now on");

                Assert.That(said,                                                                        Has.Some.Match("^Modbus/TLS clients are now shown '[^']*CN=meter-test-001[^']*'"),
                            $"and the log book says so as the store takes it - it said: {String.Join(" | ", said)}");

                Assert.That(requests?["requests"]?.First(one => one["id"]?.ToString() == id)?["state"]?.ToString(),
                            Is.EqualTo("answered"));

            });

        }

        #endregion

        #region WhatAListenerOrAClientNeeds_IsNotTakenAway()

        /// <summary>
        /// The only certificate a listener could show cannot be removed, switched
        /// off or given to the other listener, and the last CA Modbus/TLS clients
        /// may be issued by cannot be removed or switched off - each refused
        /// before anything is changed, while what takes nothing away is done.
        /// </summary>
        [Test]
        public async Task WhatAListenerOrAClientNeeds_IsNotTakenAway()
        {

            using var administrator = await SignInAsAdministrator();

            var (_, store)              = await administrator.Call(HttpMethod.Get, "api/v1/certificates");
            var modbus                  = store?["shown"]?["modbus"]?["current"]?.ToString();
            var clientCA                = store?["certificates"]?["clientRoot"]?.First()?["id"]?.ToString();

            var (removed,   notRemoved) = await administrator.Call(HttpMethod.Delete, $"api/v1/certificates/{modbus}");
            var (switched,  _)          = await administrator.Call(HttpMethod.Patch,  $"api/v1/certificates/{modbus}",   new { active = false });
            var (moved,     _)          = await administrator.Call(HttpMethod.Patch,  $"api/v1/certificates/{modbus}",   new { usages = new[] { "web" } });
            var (caOff,     caNotOff)   = await administrator.Call(HttpMethod.Patch,  $"api/v1/certificates/{clientCA}", new { active = false });
            var (caGone,    _)          = await administrator.Call(HttpMethod.Delete, $"api/v1/certificates/{clientCA}");
            var (renamed,   relabelled) = await administrator.Call(HttpMethod.Patch,  $"api/v1/certificates/{modbus}",   new { label = "the meter itself" });

            Assert.Multiple(() => {

                Assert.That(removed,                                 Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(notRemoved?["error"]?.ToString(),        Does.Contain("only certificate the modbus listener could show"));
                Assert.That(switched,                                Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(moved,                                   Is.EqualTo(HttpStatusCode.Conflict));

                Assert.That(caOff,                                   Is.EqualTo(HttpStatusCode.Conflict));
                Assert.That(caNotOff?["error"]?.ToString(),          Does.Contain("last CA Modbus/TLS clients may be issued by"));
                Assert.That(caGone,                                  Is.EqualTo(HttpStatusCode.Conflict));

                Assert.That(renamed,                                 Is.EqualTo(HttpStatusCode.OK), "what takes nothing away is done");
                Assert.That(relabelled?["label"]?.ToString(),        Is.EqualTo("the meter itself"));
                Assert.That(relabelled?["active"]?.Value<Boolean>(), Is.True, "and nothing else was changed on the way");

            });

        }

        #endregion

        #region TheStoreTakesItsKindsAndWhatEachIsFor()

        /// <summary>
        /// A kind the meter keeps no certificate of, an identity "for dns" and a
        /// root "for web" are each refused where they are typed, and a root for
        /// the time servers is taken.
        /// </summary>
        [Test]
        public async Task TheStoreTakesItsKindsAndWhatEachIsFor()
        {

            using var administrator = await SignInAsAdministrator();

            using var key          = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            using var identity     = new CertificateRequest("CN=somebody", key, HashAlgorithmName.SHA256).
                                         CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));

            using var rootKey      = ECDsa.Create(ECCurve.NamedCurves.nistP256);
            var rootRequest        = new CertificateRequest("CN=Some Time Server Root", rootKey, HashAlgorithmName.SHA256);
            rootRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
            using var root         = rootRequest.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(365));

            var pkcs12             = Convert.ToBase64String(identity.Export(X509ContentType.Pkcs12));
            var pem                = Convert.ToBase64String(Encoding.ASCII.GetBytes(root.ExportCertificatePem()));

            var (forDNS, dnsSaid)  = await administrator.Call(HttpMethod.Post, "api/v1/certificates", new { kind = "tlsIdentity", content = pkcs12, usages = new[] { "dns" } });
            var (forWeb, webSaid)  = await administrator.Call(HttpMethod.Post, "api/v1/certificates", new { kind = "tlsRoot",     content = pem,    usages = new[] { "web" } });
            var (v2g,    v2gSaid)  = await administrator.Call(HttpMethod.Post, "api/v1/certificates", new { kind = "v2gRoot",     content = pem });
            var (taken,  entry)    = await administrator.Call(HttpMethod.Post, "api/v1/certificates", new { kind = "tlsRoot",     content = pem,    usages = new[] { "nts" } });

            Assert.Multiple(() => {

                Assert.That(forDNS,                              Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(dnsSaid?["error"]?.ToString(),       Does.Contain("'dns' is not a listener").And.Contain("modbus, web"));

                Assert.That(forWeb,                              Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(webSaid?["error"]?.ToString(),       Does.Contain("'web' is not a usage").And.Contain("dns, nts"));

                Assert.That(v2g,                                 Is.EqualTo(HttpStatusCode.BadRequest));
                Assert.That(v2gSaid?["error"]?.ToString(),       Does.Contain("tlsRoot, clientRoot, tlsServer, tlsIdentity"));

                Assert.That(taken,                               Is.EqualTo(HttpStatusCode.Created), $"{entry}");
                Assert.That(entry?["usages"]?.Values<String>(),  Is.EqualTo(new[] { "nts" }));

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
                   ListenPort:         TestPorts.Free(),
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

            httpPort = TestPorts.Free();
            meter    = NewMeter();

            await meter.Start();

        }

        /// <summary>
        /// Stop the meter, give its configuration file the given "roles"
        /// section, and start another on the same data directory.
        /// </summary>
        private async Task RestartMeterWith(JObject Roles)
        {

            await meter!.DisposeAsync();

            WriteRolesIntoTheConfiguration(Roles);

            httpPort = TestPorts.Free();
            meter    = NewMeter();

            await meter.Start();

        }

        /// <summary>
        /// Put a "roles" section into the configuration file the next meter of
        /// this test reads, beside whatever else is in it.
        /// </summary>
        private void WriteRolesIntoTheConfiguration(JObject Roles)
        {

            var file           = Path.Combine(workingDirectory!, "configuration.json");
            var configuration  = File.Exists(file)
                                     ? JObject.Parse(File.ReadAllText(file))
                                     : new JObject();

            configuration["roles"] = Roles;

            File.WriteAllText(file, configuration.ToString());

        }

        /// <summary>
        /// Make a user in the group of the given role, or in none of this
        /// meter's groups when the role is null.
        /// </summary>
        private async Task CreateUserAsync(String      UserId,
                                           String      Password,
                                           Role?       Role)
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
                                                      Role.IsSystemAdmin
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

        private Browser NewBrowser(CookieContainer? Cookies = null)
            => new ($"http://127.0.0.1:{httpPort}/", Cookies);

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

        /// <summary>
        /// One browser: a client that keeps the cookies it was given, because
        /// what is under test is what a session is allowed to do.
        /// </summary>
        private sealed class Browser : IDisposable
        {

            private readonly HttpClient client;

            /// <summary>
            /// The cookies this browser holds: handed to another browser, they
            /// carry its sessions to the meter on another port.
            /// </summary>
            public CookieContainer Cookies { get; }

            public Browser(String            BaseAddress,
                           CookieContainer?  Cookies = null)
            {

                this.Cookies = Cookies ?? new CookieContainer();

                client = new HttpClient(new HttpClientHandler { UseCookies = true, CookieContainer = this.Cookies }) {
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

            /// <summary>
            /// What a path answers, as text: a file rather than JSON.
            /// </summary>
            public async Task<(HttpStatusCode, String)> GetText(String Path)
            {
                using var response = await client.GetAsync(Path);
                return (response.StatusCode, await response.Content.ReadAsStringAsync());
            }

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
