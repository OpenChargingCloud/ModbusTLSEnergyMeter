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

using System.Security.Cryptography;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// Who may sign in to this meter, and as what.
    /// </summary>
    /// <remarks>
    /// The accounts are the node's - Hermod's HTTPExt API at "/ext", the first
    /// account "root" in the systemadmin group, and a role for every group of
    /// the same name. The meter's own part is the roles, <see cref="MeterRole"/>,
    /// and the accounts from before it had groups.
    /// </remarks>
    public partial class ModbusTLSEnergyMeter
    {

        #region RolesOf(User) / PermissionsOf(User)

        /// <summary>
        /// The roles this account holds on this meter: one per group of that name
        /// it is in, strongest first.
        /// </summary>
        /// <remarks>
        /// Asked of the groups every time rather than remembered at sign-in, so
        /// that taking somebody out of a group takes effect on their next request
        /// instead of at their next sign-in. A role revoked that still works
        /// until a browser is closed is not revoked.
        /// </remarks>
        public IReadOnlyList<MeterRole> RolesOf(IUser User)

            => [.. MeterRole.All.Where(role => ExtAPI.IsMember(User, role.GroupId))];

        /// <summary>
        /// Everything those roles add up to, or nothing at all when the account
        /// is in none of the groups.
        /// </summary>
        public MeterPermissions PermissionsOf(IUser User)

            => RolesOf(User).PermissionsOf();

        #endregion

        #region (protected override) OnAccountsReady()

        /// <summary>
        /// Put every account that held a role in the meter's organization, from
        /// before the meter had groups, into the group of that role - once, before
        /// anybody can sign in.
        /// </summary>
        /// <remarks>
        /// <para>
        /// The meter used to say what somebody may do with an edge from their
        /// account to its organization, "IsAdmin" to "IsGuest"; a node says it
        /// with membership of a group. An account that was here before would
        /// otherwise sign in to a meter that refuses it everything, with its
        /// administrator among them - and nobody left who may put it right.
        /// </para>
        /// <para>
        /// An account already in one of the meter's groups is left as it is: it
        /// was put there, by this or by somebody, and a role given since is not
        /// to be overruled by the edge from before. The edges stay where they
        /// are; they grant nothing any more, and removing them would be changing
        /// somebody's data for tidiness.
        /// </para>
        /// </remarks>
        protected override async Task OnAccountsReady()
        {

            foreach (var account in ExtAPI.Users.ToArray())
            {

                if (account is not User user)
                    continue;

                if (MeterRole.All.Any(role => ExtAPI.IsMember(user, role.GroupId)))
                    continue;

                // The strongest of them, where there are several: somebody made
                // both a member and an administrator was an administrator.
                var was = user.User2Organization_OutEdges.
                               Where  (edge => edge.Target.Id.ToString() == Kind.Organization).
                               Select (edge => MeterRole.Of(edge.EdgeLabel)).
                               Where  (role => role is not null).
                               OrderBy(role => MeterRole.All.ToList().IndexOf(role!)).
                               FirstOrDefault();

                if (was is null)
                    continue;

                if (!ExtAPI.TryGetUserGroup(was.GroupId, out var group) || group is not UserGroup userGroup)
                {
                    Log.Warning($"'{user.Id}' was {was.Title.ToLowerInvariant()} of this meter, and there is no {was.Name} group to put it in.", "web", "auth");
                    continue;
                }

                var joined = await ExtAPI.AddUserToUserGroup(
                                       user,
                                       was == MeterRole.SystemAdmin
                                           ? User2UserGroupEdgeLabel.IsAdmin
                                           : User2UserGroupEdgeLabel.IsMember,
                                       userGroup
                                   );

                if (joined.IsSuccess)
                    Log.Notice($"'{user.Id}' was {was.Title.ToLowerInvariant()} of this meter by its organization, and is in the {was.Name} group now.",
                               "web", "auth");

                else
                    Log.Warning($"'{user.Id}' was {was.Title.ToLowerInvariant()} of this meter, and could not be put in the {was.Name} group: " +
                                $"{joined.ErrorDescription?.FirstText() ?? "no reason was given"}",
                                "web", "auth");

            }

        }

        #endregion

        #region (internal static) GeneratePassword()

        /// <summary>
        /// A password nobody has to remember, because it is written down the
        /// moment it is shown and never needed again afterwards: for an account
        /// an administrator makes, or a password an administrator resets.
        /// </summary>
        /// <remarks>
        /// Base64 of 24 random bytes, made URL- and terminal-safe. Long enough
        /// that its strength does not depend on the character set, and made
        /// from <see cref="RandomNumberGenerator"/> rather than
        /// <see cref="Random"/> - a password drawn from something that is not
        /// secret is one that somebody who saw enough of it can tell.
        /// </remarks>
        internal static String GeneratePassword()

            => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).
                       Replace('+', '-').
                       Replace('/', '_').
                       TrimEnd('=');

        #endregion

    }

}
