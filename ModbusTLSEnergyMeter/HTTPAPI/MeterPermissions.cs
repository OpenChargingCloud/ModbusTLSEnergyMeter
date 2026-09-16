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

using Newtonsoft.Json.Linq;

using org.GraphDefined.Vanaheimr.Hermod.HTTP;

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
    /// Which permissions a role in the meter's organization carries.
    /// </summary>
    public static class MeterPermissionsExtensions
    {

        /// <summary>
        /// What the given organization role grants.
        /// </summary>
        /// <remarks>
        /// A closed set: a label this meter has never heard of grants nothing,
        /// rather than being taken for a known one because it looks similar.
        ///
        /// A guest sees the readings and nothing else - which is the useful
        /// half for somebody who was given a look at a meter without being
        /// given the site it stands on.
        /// </remarks>
        public static MeterPermissions PermissionsOf(this User2OrganizationEdgeLabel Role)

            => Role switch {

                   User2OrganizationEdgeLabel.IsAdmin           => MeterPermissions.ReadMeter             |
                                                                   MeterPermissions.ReadConfiguration     |
                                                                   MeterPermissions.ChangeNetworkSettings |
                                                                   MeterPermissions.RunDiagnostics        |
                                                                   MeterPermissions.WriteRegisters        |
                                                                   MeterPermissions.ManageCertificates    |
                                                                   MeterPermissions.ManageAccounts,

                   User2OrganizationEdgeLabel.IsAdminReadOnly   => MeterPermissions.ReadMeter             |
                                                                   MeterPermissions.ReadConfiguration     |
                                                                   MeterPermissions.RunDiagnostics,

                   User2OrganizationEdgeLabel.IsMember          => MeterPermissions.ReadMeter             |
                                                                   MeterPermissions.ReadConfiguration,

                   User2OrganizationEdgeLabel.IsGuest           => MeterPermissions.ReadMeter,

                   _                                            => MeterPermissions.None

               };

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

    }


    /// <summary>
    /// The roles this meter hands out, and what each of them is called when a
    /// person has to choose one.
    /// </summary>
    /// <remarks>
    /// Four of Hermod's edge labels and not all of them: "follows" and
    /// "IsFollowedBy" are about a social graph this meter does not have, and an
    /// account given one of those would hold a role that grants nothing while
    /// looking like it grants something.
    ///
    /// Three of the four change nothing. That is the point of them: somebody
    /// who has to watch what a meter is doing - an operator on a night shift, a
    /// technician on the phone, an auditor - should not have to be given the
    /// account that can also clear the energy counters or replace the
    /// certificate.
    /// </remarks>
    public static class MeterRoles
    {

        /// <summary>
        /// The roles that can be given out here, strongest first - which is the
        /// order a list of them should be shown in, so that the one that grants
        /// the most is the one nobody picks by accident at the top of a
        /// dropdown.
        /// </summary>
        public static readonly IReadOnlyList<User2OrganizationEdgeLabel> Assignable = [
            User2OrganizationEdgeLabel.IsAdmin,
            User2OrganizationEdgeLabel.IsAdminReadOnly,
            User2OrganizationEdgeLabel.IsMember,
            User2OrganizationEdgeLabel.IsGuest
        ];

        /// <summary>
        /// What this role is called in a sentence.
        /// </summary>
        public static String AsText(this User2OrganizationEdgeLabel Role)

            => Role switch {
                   User2OrganizationEdgeLabel.IsAdmin          => "Administrator",
                   User2OrganizationEdgeLabel.IsAdminReadOnly  => "Read-only administrator",
                   User2OrganizationEdgeLabel.IsMember         => "Member",
                   User2OrganizationEdgeLabel.IsGuest          => "Guest",
                   _                                           => Role.ToString()
               };

        /// <summary>
        /// What somebody holding it may do, in the words they would use about
        /// it rather than the names of the flags.
        /// </summary>
        public static String Description(this User2OrganizationEdgeLabel Role)

            => Role switch {

                   User2OrganizationEdgeLabel.IsAdmin
                       => "Everything: the readings, the configuration, the meter mode and the energy " +
                          "counters, the certificates this meter shows and the CAs it accepts, and these " +
                          "accounts.",

                   User2OrganizationEdgeLabel.IsAdminReadOnly
                       => "Sees the readings, the whole configuration and the certificates, and may ask a " +
                          "time server whether it answers. Changes nothing, and does not see these accounts.",

                   User2OrganizationEdgeLabel.IsMember
                       => "Sees the readings and how this meter is configured. Changes nothing and sends " +
                          "nothing from it.",

                   User2OrganizationEdgeLabel.IsGuest
                       => "Sees the readings and nothing else - for somebody who was given a look at a " +
                          "meter without being given the site it stands on.",

                   _   => "A role this meter does not know, which grants nothing."

               };

        /// <summary>
        /// The role a request named, when this meter hands that one out.
        /// </summary>
        /// <remarks>
        /// Only the assignable four, so that a request naming "follows" is
        /// refused rather than quietly making an account with no rights that
        /// somebody will later have to work out the reason for.
        /// </remarks>
        public static Boolean TryParse(String? Text, out User2OrganizationEdgeLabel Role)
        {

            foreach (var candidate in Assignable)
            {
                if (String.Equals(candidate.ToString(), Text?.Trim(), StringComparison.OrdinalIgnoreCase))
                {
                    Role = candidate;
                    return true;
                }
            }

            Role = User2OrganizationEdgeLabel.IsGuest;
            return false;

        }

        /// <summary>
        /// A role as a page needs it: what it is called, what it does, and the
        /// permissions behind the words.
        /// </summary>
        public static JObject ToJSON(this User2OrganizationEdgeLabel Role)

            => new (
                   new JProperty("role",         Role.ToString()),
                   new JProperty("title",        Role.AsText()),
                   new JProperty("description",  Role.Description()),
                   new JProperty("permissions",  new JArray(Role.PermissionsOf().Names()))
               );

    }

}
