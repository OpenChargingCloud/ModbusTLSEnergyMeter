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

using System.Diagnostics.CodeAnalysis;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node;
using cloud.charging.open.protocols.WWCP.Node.Web;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    /// <summary>
    /// Who may do what on this energy meter: the resources it adds to a node's,
    /// and the roles it brings.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A permission is an operation - read, edit or run - on a resource,
    /// written "meter:edit", and a role is a user group of the same name with
    /// the permissions it carries, as on every node. The node brings the
    /// administrators, who may do everything there is; the meter brings its
    /// own viewer and the roles only it has. A role the configuration file
    /// adds or redefines is heard like these.
    /// </para>
    /// <para>
    /// The meter's viewer replaces the node's, which may read everything: here
    /// that would include the accounts, and who may sign in to a meter is not
    /// something everybody who may look at it has been told.
    /// </para>
    /// <para>
    /// These are the permissions of the *web* door and have nothing to do with
    /// the SunSpec roles in a Modbus/TLS client certificate. A person signed in
    /// here and a charging station connected there are two different kinds of
    /// peer, asking two different kinds of question, and neither one's rights
    /// are expressible in the other's vocabulary.
    /// </para>
    /// </remarks>
    public static class MeterAccess
    {

        #region Resources

        /// <summary>
        /// The meter itself. Read: what it is measuring, its registers, its
        /// signed readings and its charging sessions. Edit: the commanded
        /// registers - the meter mode, and the one that clears the energy
        /// counters. Run: start and stop a charging session.
        /// </summary>
        /// <remarks>
        /// Starting a session is its own operation rather than part of
        /// editing, because it is the one thing a station operator does every
        /// day, and clearing the energy counters is the one thing here that
        /// destroys something.
        /// </remarks>
        public const String  Meter     = "meter";

        /// <summary>
        /// The keys this meter signs its readings with. Read: which there are
        /// and which is the default. Edit: make one, choose the default, take
        /// one away.
        /// </summary>
        /// <remarks>
        /// Not a certificate of the node's: a signing key is who the readings
        /// say they come from, and whoever may choose it chooses what a
        /// customer's bill can be checked against.
        /// </remarks>
        public const String  Keys      = "keys";

        /// <summary>
        /// The accounts of this meter. Read: who may sign in, and as what.
        /// Edit: make an account, give it a role, reset its password, and take
        /// it away again.
        /// </summary>
        /// <remarks>
        /// Whoever may edit them may make an administrator, which is every other
        /// permission here by a longer route.
        /// </remarks>
        public const String  Accounts  = "accounts";

        /// <summary>
        /// The log, the log book beside it, and the event stream that follows
        /// them. Read only: nobody edits evidence.
        /// </summary>
        /// <remarks>
        /// Open to anybody signed in on a node, and not here: every Modbus
        /// request is in it, and so is who signed in when, which is more than
        /// somebody who was given a look at the readings was given.
        /// </remarks>
        public const String  Log       = "log";

        /// <summary>
        /// What this meter adds to the node's resources - configuration, dns,
        /// nts and certificates - in the order a permission list is read in.
        /// </summary>
        public static readonly IReadOnlyList<String>  Resources  = [ Meter, Keys, Log, Accounts ];

        #endregion

        #region Roles

        /// <summary>
        /// Everything there is to read, but the accounts.
        /// </summary>
        private static readonly IReadOnlyList<Permission>  readingAllButTheAccounts  = [
                                                                                          Permission.Read(Meter),
                                                                                          Permission.Read(NodeResources.Configuration),
                                                                                          Permission.Read(NodeResources.DNS),
                                                                                          Permission.Read(NodeResources.NTS),
                                                                                          Permission.Read(NodeResources.Certificates),
                                                                                          Permission.Read(Keys),
                                                                                          Permission.Read(Log)
                                                                                      ];

        /// <summary>
        /// Sees the readings and how this meter is configured.
        /// </summary>
        /// <remarks>
        /// The name every node gives the role that may look and nothing else -
        /// narrower here than the node's, by the accounts.
        /// </remarks>
        public static readonly Role  Viewer   = new ("viewer",
                                                     readingAllButTheAccounts,
                                                     "Sees the readings and how this meter is configured. Changes nothing and sends " +
                                                     "nothing from it.");

        /// <summary>
        /// Sees everything but the accounts, may ask a time server whether it
        /// answers, and changes nothing.
        /// </summary>
        public static readonly Role  Auditor  = new ("auditor",
                                                     [ .. readingAllButTheAccounts,
                                                       Permission.Run(NodeResources.NTS) ],
                                                     "Sees the readings, the whole configuration and the certificates, and may ask a " +
                                                     "time server whether it answers. Changes nothing, and does not see these accounts.");

        /// <summary>
        /// Sees the readings and nothing else.
        /// </summary>
        public static readonly Role  Guest    = new ("guest",
                                                     [ Permission.Read(Meter) ],
                                                     "Sees the readings and nothing else - for somebody who was given a look at a " +
                                                     "meter without being given the site it stands on.");

        /// <summary>
        /// The roles this meter brings. The administrators are the node's, and
        /// so is the order: the viewer first, the administrators last.
        /// </summary>
        public static readonly IReadOnlyList<Role>  Roles  = [ Viewer, Auditor, Guest ];

        /// <summary>
        /// What the administrators may do, in the words somebody would use
        /// about it: "may do everything" is what the node says, and it is true,
        /// but it does not tell anybody what everything is on a meter.
        /// </summary>
        public const String  SystemAdminDescription  = "Everything: the readings, the configuration, the meter mode and the energy " +
                                                       "counters, the certificates this meter shows and the CAs it accepts, the " +
                                                       "signing keys, and these accounts.";

        #endregion

        #region From before the groups

        /// <summary>
        /// The role in the meter's organization every role was before there
        /// were groups, strongest first.
        /// </summary>
        private static readonly (User2OrganizationEdgeLabel Was, String Role)[]  organizationRoles  = [
                                                                                                          (User2OrganizationEdgeLabel.IsAdmin,          WWCPNode.AdminRole),
                                                                                                          (User2OrganizationEdgeLabel.IsAdminReadOnly,  "auditor"),
                                                                                                          (User2OrganizationEdgeLabel.IsMember,         "viewer"),
                                                                                                          (User2OrganizationEdgeLabel.IsGuest,          "guest")
                                                                                                      ];

        /// <summary>
        /// The name of the role an account held as a role in the meter's
        /// organization, or null for an edge that never meant one.
        /// </summary>
        public static String? RoleNameOf(User2OrganizationEdgeLabel OrganizationRole)

            => organizationRoles.FirstOrDefault(role => role.Was == OrganizationRole).Role;

        /// <summary>
        /// Where the organization role an account held stands among the others:
        /// 0 for the strongest, and past the end for an edge that never meant one.
        /// </summary>
        public static Int32 RankOf(User2OrganizationEdgeLabel OrganizationRole)
        {

            var index = Array.FindIndex(organizationRoles, role => role.Was == OrganizationRole);

            return index < 0
                       ? organizationRoles.Length
                       : index;

        }

        #endregion


        #region TryParse(Access, Text, out Role)

        /// <summary>
        /// A role of this meter by its name, in any case - or by the organization
        /// role it used to be, so that a script written against the meter before
        /// it had groups still names a role that exists.
        /// </summary>
        /// <param name="Access">The meter's roles: its own, the node's and the configuration file's.</param>
        /// <param name="Text">What was asked for.</param>
        /// <param name="Role">The role.</param>
        public static Boolean TryParse(AccessControl                  Access,
                                       String?                        Text,
                                       [NotNullWhen(true)] out Role?  Role)
        {

            var text = Text?.Trim();

            Role = Access.RoleNamed(text);

            if (Role is null)
                foreach (var (was, name) in organizationRoles)
                    if (String.Equals(was.ToString(), text, StringComparison.OrdinalIgnoreCase))
                        Role = Access.RoleNamed(name);

            return Role is not null;

        }

        #endregion

        #region TitleOf(Role) / DescriptionOf(Role)

        /// <summary>
        /// What a person calls a role: "Administrator" rather than "systemadmin",
        /// and a role the configuration file adds by its own name.
        /// </summary>
        public static String TitleOf(Role Role)

            => Role.Name.ToLowerInvariant() switch {
                   WWCPNode.AdminRole  => "Administrator",
                   "auditor"           => "Auditor",
                   "viewer"            => "Viewer",
                   "guest"             => "Guest",
                   _                   => Role.Name
               };

        /// <summary>
        /// What holding a role means, in the words somebody would use about it,
        /// or null for a role the configuration file adds without saying.
        /// </summary>
        public static String? DescriptionOf(Role Role)

            => Role.IsSystemAdmin
                   ? SystemAdminDescription
                   : Role.Description;

        #endregion

        #region Strongest(Access, Roles)

        /// <summary>
        /// The one of the given roles that grants the most - the one a page names
        /// somebody by - or null for none at all.
        /// </summary>
        /// <remarks>
        /// Counted rather than looked up in an order, because a role from the
        /// configuration file has no place in any order this meter could know,
        /// and the node's order puts the viewer first and not the strongest.
        /// </remarks>
        public static Role? Strongest(AccessControl      Access,
                                      IEnumerable<Role>  Roles)

            => Roles.OrderByDescending(role => Access.PermissionsOf([ role ]).Count).
                     FirstOrDefault();

        #endregion

    }

}
