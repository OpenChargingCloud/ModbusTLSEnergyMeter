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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.SunSpecModbusTLS.Common;

using cloud.charging.open.protocols.WWCP.Node.Logins;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.MeterReaders
{

    /// <summary>
    /// The SunSpec roles as login groups: what a login that reads this meter
    /// over a WebSocket or over SSH may do is the role its group is named after.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Over Modbus/TLS a client certificate carries its role. A login has no
    /// such field, and the meter already says once for many logins what they
    /// may do: by their group. So a group of each of the four roles of
    /// SunSpecTCP-22, named after it - "readonlysunspec", "gridservicesunspec",
    /// "networkadministratorsunspec", "superadministratorsunspec", as login
    /// groups are written, and "ReadOnlySunSpec" and so on on the page -, and
    /// a login is given its role by being put into the group.
    /// </para>
    /// <para>
    /// Any other group - the default one among them - is no role, and a login
    /// in it is answered with exception 01 to everything, as a certificate
    /// without a role is (SunSpecTCP-32): being let in says who it is, and
    /// nothing about what it may do.
    /// </para>
    /// </remarks>
    public static class SunSpecLoginGroups
    {

        #region GroupOf(Role) / RoleOf(GroupId)

        /// <summary>
        /// The id of the login group of the given SunSpec role: "gridservicesunspec".
        /// </summary>
        /// <param name="Role">One of <see cref="SunSpecRoles.AllMandatory"/>.</param>
        public static String GroupOf(String Role)

            => Role.ToLowerInvariant();

        /// <summary>
        /// The SunSpec role the login group of the given id stands for, or null
        /// where it is no group of a role.
        /// </summary>
        /// <param name="GroupId">The id of a login group.</param>
        public static String? RoleOf(String? GroupId)

            => GroupId is null
                   ? null
                   : SunSpecRoles.AllMandatory.FirstOrDefault(role => String.Equals(GroupOf(role), GroupId.Trim(), StringComparison.OrdinalIgnoreCase));

        #endregion

        #region EnsureIn(Logins)

        /// <summary>
        /// Make the four groups of the roles where they are not there: letting in
        /// with everything a login can sign in with, over every way the port
        /// allows. A group that is there is left as somebody made it.
        /// </summary>
        /// <param name="Logins">The WebSocket logins of the meter.</param>
        /// <returns>What could not be made, one sentence each.</returns>
        public static IEnumerable<String> EnsureIn(WebSocketLogins Logins)
        {

            var problems = new List<String>();

            foreach (var role in SunSpecRoles.AllMandatory)
            {

                if (Logins.GetGroup(GroupOf(role)) is not null)
                    continue;

                if (!Logins.TryAddOrUpdateGroup(
                        GroupOf(role),
                        role,
                        true,
                        [ AuthMethod.Basic, AuthMethod.TOTP, AuthMethod.Certificate, AuthMethod.SSHKey, AuthMethod.KeyPin ],
                        WebSocketClientAuthentications.All,
                        I18NString.Create($"Reads this meter over Modbus as {role}."),
                        out var error))
                {
                    problems.Add($"The login group of the SunSpec role {role} could not be made: {error}");
                }

            }

            return problems;

        }

        #endregion

    }

}
