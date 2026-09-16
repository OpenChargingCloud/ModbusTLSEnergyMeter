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
        WriteRegisters         = 16

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
                                                                   MeterPermissions.WriteRegisters,

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

}
