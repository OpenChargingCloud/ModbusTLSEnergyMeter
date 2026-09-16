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

using Microsoft.Extensions.Logging;

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS
{

    public partial class ModbusTLSEnergyMeter
    {

        #region Data

        /// <summary>
        /// The account this meter makes for itself when it has no accounts at
        /// all, so that somebody can sign in for the first time.
        /// </summary>
        public const String  DefaultAdminUserId    = "admin";

        /// <summary>
        /// The organization every account of this meter belongs to.
        /// </summary>
        /// <remarks>
        /// One organization, because a meter is one thing that one group of
        /// people looks after. The role somebody holds *in* it - administrator,
        /// read-only administrator, member, guest - is what separates who may
        /// change this meter from who may only watch it.
        /// </remarks>
        public const String  MeterOrganizationId   = "EnergyMeter";

        #endregion

        #region Properties

        /// <summary>
        /// Where the accounts of this meter, and the log of what they did, are
        /// written.
        /// </summary>
        public String  DataPath   { get; }

        #endregion


        #region (private) EnsureFirstAdministratorAsync()

        /// <summary>
        /// Make sure somebody can sign in: an organization for this meter, and
        /// on a first start an administrator in it whose password is shown once.
        /// </summary>
        /// <remarks>
        /// A meter with a web interface nobody can open is not safer, it is
        /// just unusable - and the alternative, an unauthenticated setup page
        /// that makes the first account, is a door of its own standing open
        /// for exactly as long as nobody has walked through it yet. So the
        /// first password is made here, shown to whoever started the process,
        /// and kept nowhere but in its hash.
        ///
        /// This runs on every start and does nothing at all once there is an
        /// account, so a meter whose administrator locked themselves out does
        /// not quietly grow a second way in.
        /// </remarks>
        private async Task EnsureFirstAdministratorAsync()
        {

            var organization = await HTTPExtAPI.CreateOrganizationIfNotExists(
                                         Organization_Id.Parse(MeterOrganizationId),
                                         I18NString.Create($"Energy meter {SerialNumber}"),
                                         I18NString.Create($"Everybody who looks after the SunSpec Modbus/TLS energy meter {SerialNumber}."),
                                         CurrentUserId: HTTPExtAPI.Robot?.Id
                                     );

            // That helper hands back an organization only when it actually made
            // one: an organization that was already there comes back as null,
            // which is the "if not exists" doing its job and not a failure. So
            // the second start has to go and look for what the first one made.
            if (organization is null)
                HTTPExtAPI.TryGetOrganization(
                    Organization_Id.Parse(MeterOrganizationId),
                    out organization
                );

            if (organization is null)
            {
                logger.LogError("the organization '{Organization}' is neither there nor could be created", MeterOrganizationId);
                return;
            }

            if (HTTPExtAPI.Users.Any())
                return;

            var password     = GeneratePassword();

            var newUser      = new User(
                                   User_Id.Parse(DefaultAdminUserId),
                                   I18NString.Create("Administrator"),
                                   SimpleEMailAddress.Parse($"{DefaultAdminUserId}@{SerialNumber.ToLowerInvariant()}.local"),

                                   // Nobody is going to answer a confirmation mail
                                   // from a meter in a car park, and an account that
                                   // cannot sign in until they do is a first start
                                   // that never finishes.
                                   IsAuthenticated:  true,

                                   DataSource:       "first start"
                               );

            // The overload that takes the role and the organization, so that the
            // account and what it may do are one step: a user added first and
            // given a role second is, in between, an account with no rights that
            // a crash would leave behind for good.
            var addedUser    = await HTTPExtAPI.AddUser(
                                         newUser,
                                         User2OrganizationEdgeLabel.IsAdmin,
                                         organization,
                                         SkipNewUserEMail:          true,
                                         SkipNewUserNotifications:  true,
                                         CurrentUserId:             HTTPExtAPI.Robot?.Id
                                     );

            if (addedUser.Result != CommandResult.Success)
            {
                logger.LogError(
                    "the first administrator could not be created ({Result}): {Reason}",
                    addedUser.Result,
                    addedUser.Description?.FirstText() ?? "no reason given"
                );
                return;
            }

            var changedPassword = await HTTPExtAPI.ChangePassword(
                                            newUser,
                                            password,
                                            SuppressNotifications:  true,
                                            CurrentUserId:          HTTPExtAPI.Robot?.Id
                                        );

            if (changedPassword.Result != CommandResult.Success)
            {
                logger.LogError(
                    "the first administrator was created, but has no password ({Result}) - use the password reset",
                    changedPassword.Result
                );
                return;
            }

            GeneratedUserId    = DefaultAdminUserId;
            GeneratedPassword  = password;

            logger.LogInformation(
                "no accounts yet, so '{UserId}' was made an administrator of '{Organization}'",
                DefaultAdminUserId,
                MeterOrganizationId
            );

        }

        #endregion

        #region (internal static) GeneratePassword()

        /// <summary>
        /// A password nobody has to remember, because it is written down the
        /// moment it is shown and never needed again afterwards.
        /// </summary>
        /// <remarks>
        /// Base64 of 24 random bytes, made URL- and terminal-safe. Long enough
        /// that its strength does not depend on the character set, and made
        /// from <see cref="RandomNumberGenerator"/> rather than
        /// <see cref="Random"/> - a password seeded from the clock is one that
        /// somebody who knows roughly when the meter started can search.
        /// </remarks>
        internal static String GeneratePassword()

            => Convert.ToBase64String(RandomNumberGenerator.GetBytes(24)).
                       Replace('+', '-').
                       Replace('/', '_').
                       TrimEnd('=');

        #endregion

    }

}
