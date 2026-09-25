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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

using cloud.charging.open.protocols.WWCP.Node;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// What somebody signed in to this energy meter is allowed to do.
    /// </summary>
    /// <remarks>
    /// Flags rather than a list, because a permission is asked about one at a
    /// time and answered by a single test - and because the set a role grants
    /// is then a constant instead of a collection to be built and searched.
    ///
    /// Only what this meter actually enforces is named here. A permission with
    /// nothing behind it is a promise made to whoever reads the role table and
    /// not kept.
    ///
    /// These are the permissions of the *web* door and have nothing to do with
    /// the SunSpec roles in a Modbus/TLS client certificate. A person signed in
    /// here and a charging station connected there are two different kinds of
    /// peer, asking two different kinds of question, and neither one's rights
    /// are expressible in the other's vocabulary.
    /// </remarks>
    [Flags]
    public enum MeterPermissions : UInt32
    {

        /// <summary>
        /// Nothing at all. What a role this meter does not know would grant.
        /// </summary>
        None                   = 0,

        /// <summary>
        /// See what the meter is measuring, and read its registers.
        /// </summary>
        ReadMeter              = 1,

        /// <summary>
        /// See how this meter is configured: its name resolution, its time
        /// source and the certificates it was started with.
        /// </summary>
        ReadConfiguration      = 2,

        /// <summary>
        /// Change how this meter reaches the network: its name resolution and
        /// where it reads the time.
        /// </summary>
        ChangeNetworkSettings  = 4,

        /// <summary>
        /// Make this meter ask a time server something, to find out whether it
        /// can.
        /// </summary>
        /// <remarks>
        /// Its own permission and not part of reading: a diagnostic sends
        /// traffic from this meter to a host somebody named, which is more than
        /// it sounds like to hand to everybody who may look at a page.
        /// </remarks>
        RunDiagnostics         = 8,

        /// <summary>
        /// Write the commanded registers: the meter mode, and the one that
        /// clears the energy counters.
        /// </summary>
        /// <remarks>
        /// Clearing a meter's energy counters is the one thing here that
        /// destroys something, which is why it is not folded into changing
        /// settings.
        /// </remarks>
        WriteRegisters         = 16,

        /// <summary>
        /// Ask for a new certificate, put one in, and say which CAs a
        /// Modbus/TLS client may chain to.
        /// </summary>
        /// <remarks>
        /// Its own permission rather than part of changing network settings,
        /// because it is a bigger thing than any of those: which certificate
        /// this meter shows is who it says it is, and which CAs it trusts is
        /// who may talk to it at all. Somebody who may repoint a name server
        /// has not thereby been handed the identity of the device.
        /// </remarks>
        ManageCertificates     = 32,

        /// <summary>
        /// Make accounts for this meter, say what each of them may do, and take
        /// them away again.
        /// </summary>
        /// <remarks>
        /// The largest of them, and therefore its own: everything else on this
        /// list is something a person does to the meter, and this is the one
        /// that decides who the people are. Somebody who may hand out accounts
        /// may hand out an administrator's account, which is every other
        /// permission here by a longer route.
        /// </remarks>
        ManageAccounts         = 64

    }


    /// <summary>
    /// A role somebody signs in to this meter as: the user group that carries
    /// it, what it is called, and what it lets them do.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Each role is a user group of the same name, as it is on every node -
    /// the vehicle's, the charging station's - and membership of that group
    /// is what carries the permissions here. The meter used to say it with an
    /// edge to its organization instead, "IsAdmin" to "IsGuest"; an account
    /// from then is put in the group of the role it had, once, at a start - see
    /// <see cref="ModbusTLSEnergyMeter"/>'s OnAccountsReady - and
    /// <see cref="WasOrganizationRole"/> says which that is.
    /// </para>
    /// <para>
    /// A closed set: a group this meter has never heard of grants nothing,
    /// rather than quietly granting something. Three of the four change
    /// nothing, and that is the point of them: somebody who has to watch what
    /// a meter is doing - an operator on a night shift, a technician on the
    /// phone, an auditor - should not have to be given the account that can
    /// also clear the energy counters or replace the certificate.
    /// </para>
    /// </remarks>
    /// <param name="Name">The role, and the name of the user group that carries it.</param>
    /// <param name="Title">What it is called in a sentence.</param>
    /// <param name="Permissions">What it grants.</param>
    /// <param name="Description">What somebody holding it may do, in the words they would use about it.</param>
    /// <param name="WasOrganizationRole">The role in the meter's organization it was before there were groups.</param>
    public sealed record MeterRole(String                      Name,
                                   String                      Title,
                                   MeterPermissions            Permissions,
                                   String                      Description,
                                   User2OrganizationEdgeLabel  WasOrganizationRole)
    {

        #region Properties

        /// <summary>
        /// The user group whose members hold this role.
        /// </summary>
        public UserGroup_Id  GroupId
            => UserGroup_Id.Parse(Name);

        #endregion

        #region Data

        /// <summary>
        /// Everything: the readings, the configuration, the meter mode and the
        /// energy counters, the certificates, and the accounts. The group every
        /// node names its administrators by, so that an account shared with the
        /// other programs is an administrator of this meter too.
        /// </summary>
        public static readonly MeterRole  SystemAdmin  = new (
                                                             WWCPNode.AdminRole,
                                                             "Administrator",
                                                             MeterPermissions.ReadMeter             |
                                                             MeterPermissions.ReadConfiguration     |
                                                             MeterPermissions.ChangeNetworkSettings |
                                                             MeterPermissions.RunDiagnostics        |
                                                             MeterPermissions.WriteRegisters        |
                                                             MeterPermissions.ManageCertificates    |
                                                             MeterPermissions.ManageAccounts,
                                                             "Everything: the readings, the configuration, the meter mode and the energy " +
                                                             "counters, the certificates this meter shows and the CAs it accepts, and these " +
                                                             "accounts.",
                                                             User2OrganizationEdgeLabel.IsAdmin
                                                         );

        /// <summary>
        /// Sees everything but the accounts, may ask a time server whether it
        /// answers, and changes nothing.
        /// </summary>
        public static readonly MeterRole  Auditor      = new (
                                                             "auditor",
                                                             "Auditor",
                                                             MeterPermissions.ReadMeter             |
                                                             MeterPermissions.ReadConfiguration     |
                                                             MeterPermissions.RunDiagnostics,
                                                             "Sees the readings, the whole configuration and the certificates, and may ask a " +
                                                             "time server whether it answers. Changes nothing, and does not see these accounts.",
                                                             User2OrganizationEdgeLabel.IsAdminReadOnly
                                                         );

        /// <summary>
        /// Sees the readings and how this meter is configured.
        /// </summary>
        /// <remarks>
        /// The name every node gives the role that may look and nothing else.
        /// </remarks>
        public static readonly MeterRole  Viewer       = new (
                                                             "viewer",
                                                             "Viewer",
                                                             MeterPermissions.ReadMeter             |
                                                             MeterPermissions.ReadConfiguration,
                                                             "Sees the readings and how this meter is configured. Changes nothing and sends " +
                                                             "nothing from it.",
                                                             User2OrganizationEdgeLabel.IsMember
                                                         );

        /// <summary>
        /// Sees the readings and nothing else.
        /// </summary>
        public static readonly MeterRole  Guest        = new (
                                                             "guest",
                                                             "Guest",
                                                             MeterPermissions.ReadMeter,
                                                             "Sees the readings and nothing else - for somebody who was given a look at a " +
                                                             "meter without being given the site it stands on.",
                                                             User2OrganizationEdgeLabel.IsGuest
                                                         );

        /// <summary>
        /// Every role this meter hands out, strongest first - which is the order
        /// a list of them should be shown in, so that the one that grants the
        /// most is not the one somebody picks by accident at the top of a
        /// dropdown.
        /// </summary>
        public static readonly IReadOnlyList<MeterRole>  All  = [ SystemAdmin, Auditor, Viewer, Guest ];

        #endregion


        #region (static) TryParse(Text, out Role)

        /// <summary>
        /// A role by the name of its group, in any case - or by the organization
        /// role it used to be, so that a script written against the meter before
        /// it had groups still names a role that exists.
        /// </summary>
        public static Boolean TryParse(String?                             Text,
                                       [NotNullWhen(true)] out MeterRole?  Role)
        {

            var text = Text?.Trim();

            Role = All.FirstOrDefault(role => String.Equals(role.Name,                           text, StringComparison.OrdinalIgnoreCase) ||
                                              String.Equals(role.WasOrganizationRole.ToString(), text, StringComparison.OrdinalIgnoreCase));

            return Role is not null;

        }

        #endregion

        #region (static) Of(OrganizationRole)

        /// <summary>
        /// The role an account held as a role in the meter's organization, or
        /// null for an edge that never meant one.
        /// </summary>
        public static MeterRole? Of(User2OrganizationEdgeLabel OrganizationRole)

            => All.FirstOrDefault(role => role.WasOrganizationRole == OrganizationRole);

        #endregion

        #region ToJSON()

        /// <summary>
        /// A role as a page needs it: what it is called, what it does, and the
        /// permissions behind the words.
        /// </summary>
        public JObject ToJSON()

            => new (
                   new JProperty("role",         Name),
                   new JProperty("title",        Title),
                   new JProperty("description",  Description),
                   new JProperty("permissions",  new JArray(Permissions.Names()))
               );

        #endregion

        #region (override) ToString()

        public override String ToString()
            => Name;

        #endregion

    }


    /// <summary>
    /// What a set of roles adds up to, and what it is called.
    /// </summary>
    public static class MeterPermissionsExtensions
    {

        #region PermissionsOf(this Roles)

        /// <summary>
        /// Everything the given roles grant together.
        /// </summary>
        public static MeterPermissions PermissionsOf(this IEnumerable<MeterRole> Roles)
        {

            var permissions = MeterPermissions.None;

            foreach (var role in Roles)
                permissions |= role.Permissions;

            return permissions;

        }

        #endregion

        #region Names(this Permissions)

        /// <summary>
        /// The permissions, one name each, for a page that wants to grey out
        /// what this person may not do.
        /// </summary>
        public static IEnumerable<String> Names(this MeterPermissions Permissions)
        {

            foreach (var permission in Enum.GetValues<MeterPermissions>())
                if (permission != MeterPermissions.None && Permissions.HasFlag(permission))
                    yield return permission.ToString();

        }

        #endregion

    }

}
