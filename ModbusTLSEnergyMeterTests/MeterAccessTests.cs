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

using NUnit.Framework;

using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.Tests
{

    /// <summary>
    /// What each of the meter's roles may do, now that roles are data: the
    /// same as before, permission for permission.
    /// </summary>
    /// <remarks>
    /// Asked of the meter's resources and roles as the node combines them,
    /// without a meter: this is a table, and a table does not need a port.
    /// </remarks>
    public class MeterAccessTests
    {

        #region (private static) MeterAccessControl()

        /// <summary>
        /// The meter's resources and roles as the node combines them, with no
        /// configuration file.
        /// </summary>
        private static AccessControl MeterAccessControl()
        {

            Assert.That(AccessControl.TryCombine(MeterAccess.Resources,
                                                 MeterAccess.Roles,
                                                 null,
                                                 null,
                                                 "energy meter",
                                                 out var access,
                                                 out _,
                                                 out var error),
                        Is.True,
                        error);

            return access!;

        }

        #endregion


        #region TheMeterBringsItsResourcesAndItsRoles()

        /// <summary>
        /// The node's resources and the meter's, and the node's order of roles:
        /// the viewer first - the meter's own - and the administrators last.
        /// </summary>
        [Test]
        public void TheMeterBringsItsResourcesAndItsRoles()
        {

            var access = MeterAccessControl();

            Assert.Multiple(() => {

                Assert.That(access.Resources,
                            Is.EqualTo(new[] { "configuration", "dns", "nts", "certificates", "meter", "keys", "log", "accounts" }));

                Assert.That(access.Roles.Select(role => role.Name),
                            Is.EqualTo(new[] { "viewer", "auditor", "guest", "systemadmin" }));

            });

        }

        #endregion

        #region EachRoleMayDoWhatItAlwaysMayDo(RoleName, Asked, Allowed)

        /// <summary>
        /// What each role could do before the roles were data - ReadMeter,
        /// ReadConfiguration, ChangeNetworkSettings, RunDiagnostics,
        /// WriteRegisters, ManageCertificates, ManageAccounts - it may do now,
        /// and nothing more.
        /// </summary>
        /// <remarks>
        /// The viewer is the one to watch: the node's may read everything, the
        /// meter's everything but the accounts.
        /// </remarks>
        [TestCase("viewer",       "meter:read",          true)]
        [TestCase("viewer",       "configuration:read",  true)]
        [TestCase("viewer",       "dns:read",            true)]
        [TestCase("viewer",       "nts:read",            true)]
        [TestCase("viewer",       "certificates:read",   true)]
        [TestCase("viewer",       "keys:read",           true)]
        [TestCase("viewer",       "log:read",            true)]
        [TestCase("viewer",       "accounts:read",       false)]
        [TestCase("viewer",       "nts:run",             false)]
        [TestCase("viewer",       "dns:edit",            false)]
        [TestCase("viewer",       "nts:edit",            false)]
        [TestCase("viewer",       "meter:edit",          false)]
        [TestCase("viewer",       "meter:run",           false)]
        [TestCase("viewer",       "certificates:edit",   false)]
        [TestCase("viewer",       "keys:edit",           false)]
        [TestCase("viewer",       "accounts:edit",       false)]

        [TestCase("auditor",      "meter:read",          true)]
        [TestCase("auditor",      "certificates:read",   true)]
        [TestCase("auditor",      "log:read",            true)]
        [TestCase("auditor",      "nts:run",             true)]
        [TestCase("auditor",      "accounts:read",       false)]
        [TestCase("auditor",      "dns:edit",            false)]
        [TestCase("auditor",      "nts:edit",            false)]
        [TestCase("auditor",      "meter:edit",          false)]
        [TestCase("auditor",      "meter:run",           false)]
        [TestCase("auditor",      "certificates:edit",   false)]
        [TestCase("auditor",      "keys:edit",           false)]

        [TestCase("guest",        "meter:read",          true)]
        [TestCase("guest",        "configuration:read",  false)]
        [TestCase("guest",        "nts:read",            false)]
        [TestCase("guest",        "certificates:read",   false)]
        [TestCase("guest",        "keys:read",           false)]
        [TestCase("guest",        "log:read",            false)]
        [TestCase("guest",        "meter:run",           false)]

        [TestCase("systemadmin",  "meter:edit",          true)]
        [TestCase("systemadmin",  "meter:run",           true)]
        [TestCase("systemadmin",  "dns:edit",            true)]
        [TestCase("systemadmin",  "nts:run",             true)]
        [TestCase("systemadmin",  "certificates:edit",   true)]
        [TestCase("systemadmin",  "keys:edit",           true)]
        [TestCase("systemadmin",  "accounts:edit",       true)]
        public void EachRoleMayDoWhatItAlwaysMayDo(String   RoleName,
                                                   String   Asked,
                                                   Boolean  Allowed)
        {

            Assert.That(Permission.TryParse(Asked, out var permission, out var error), Is.True, error);

            var role = MeterAccessControl().RoleNamed(RoleName);

            Assert.That(role,                                                   Is.Not.Null);
            Assert.That(role!.Allows(permission.Resource, permission.Operation), Is.EqualTo(Allowed));

        }

        #endregion

        #region TheOldNamesOfTheRoles_AreStillTaken()

        /// <summary>
        /// The roles in the organization from before the groups - IsAdmin to
        /// IsGuest - still name the role they were moved into, and nothing else
        /// does: "follows" is a label of the same enumeration and was never a
        /// role here.
        /// </summary>
        [TestCase("IsAdmin",          "systemadmin")]
        [TestCase("isadminreadonly",  "auditor")]
        [TestCase("IsMember",         "viewer")]
        [TestCase("IsGuest",          "guest")]
        [TestCase("GUEST",            "guest")]
        [TestCase("follows",          null)]
        [TestCase("0",                null)]
        public void TheOldNamesOfTheRoles_AreStillTaken(String   Text,
                                                        String?  RoleName)
        {

            var found = MeterAccess.TryParse(MeterAccessControl(), Text, out var role);

            Assert.That(found,      Is.EqualTo(RoleName is not null));
            Assert.That(role?.Name, Is.EqualTo(RoleName));

        }

        #endregion

    }

}
