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

using org.GraphDefined.Vanaheimr.Illias;
using org.GraphDefined.Vanaheimr.Hermod.HTTP;
using org.GraphDefined.Vanaheimr.Hermod.Mail;

#endregion

namespace cloud.charging.open.EnergyMeters.ModbusTLS.HTTPAPI
{

    /// <summary>
    /// Who may sign in to this meter's web interface, and as what.
    /// </summary>
    /// <remarks>
    /// An account is a person and a role, and the role is the whole of what
    /// they may do: this meter has no per-resource rights and does not want
    /// any. A role is a user group of the same name, as on every node, and
    /// three of the four change nothing at all, which is the reason this
    /// exists - watching a meter should not require the account that can also
    /// replace its certificate.
    ///
    /// Changing your own password is not here. Hermod answers that at
    /// "/ext/auth/password", where the current password is asked for before
    /// the new one is taken and every other session of the account is ended.
    /// An administrator resetting somebody else's password is a different act
    /// with a different rule, and that one is below.
    /// </remarks>
    public partial class MeterHTTPAPI
    {

        #region (private) RegisterAccountTemplates()

        private void RegisterAccountTemplates()
        {

            AddHandler(HTTPPath.Root + "v1/accounts",                GetAccounts,         HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/accounts",                PostAccount,         HTTPMethod.POST);
            AddHandler(HTTPPath.Root + "v1/accounts/roles",          GetRoles,            HTTPMethod.GET);
            AddHandler(HTTPPath.Root + "v1/accounts/{id}",           DeleteAccount,       HTTPMethod.DELETE);
            AddHandler(HTTPPath.Root + "v1/accounts/{id}/role",      PutAccountRole,      HTTPMethod.PUT);
            AddHandler(HTTPPath.Root + "v1/accounts/{id}/password",  PutAccountPassword,  HTTPMethod.PUT);

        }

        #endregion


        #region (private) GetAccounts       (Request)

        /// <summary>
        /// GET /api/v1/accounts: every account of this meter with the role it
        /// holds, and the table of roles that can be given out.
        /// </summary>
        /// <remarks>
        /// Both in one answer, because a page that lets somebody choose a role
        /// has to show what the roles mean, and asking twice for something that
        /// never changes is two requests where one would do.
        ///
        /// Administrators only. The list of who can get into a device is the
        /// most useful thing on it to somebody who should not be there.
        /// </remarks>
        private Task<HTTPResponse> GetAccounts(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageAccounts, false, out var user, out var refused))
                return Task.FromResult(refused);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(
                               new JProperty("accounts",  new JArray(accounts.Users.
                                                                              OrderBy(account => account.Id.ToString()).
                                                                              Select (account => AccountJSON(account, user)))),
                               new JProperty("roles",     RolesJSON())
                           ))
                   );

        }

        #endregion

        #region (private) GetRoles          (Request)

        /// <summary>
        /// GET /api/v1/accounts/roles: what each role is called and what it
        /// grants.
        /// </summary>
        /// <remarks>
        /// Readable by anybody signed in, unlike the accounts themselves: this
        /// says what a role means, which is what somebody who has been given
        /// one wants to know about their own, and it names nobody.
        /// </remarks>
        private Task<HTTPResponse> GetRoles(HTTPRequest Request)
        {

            if (!TryGetUser(Request, out _, out var unauthorized))
                return Task.FromResult(unauthorized);

            return Task.FromResult(
                       JSONResponse(Request, HTTPStatusCode.OK,
                           new JObject(new JProperty("roles", RolesJSON())))
                   );

        }

        #endregion

        #region (private) PostAccount       (Request)

        /// <summary>
        /// POST /api/v1/accounts with {"userId": "...", "role": "viewer",
        /// "name": "...", "email": "...", "password": "..."}.
        /// </summary>
        /// <remarks>
        /// The password may be left out, and usually should be: what comes back
        /// then is one this meter made, shown once and never again, which is
        /// better than one somebody thought of while standing in front of a
        /// charging station.
        ///
        /// The account is made in the meter's organization, which is what
        /// signing in asks of it, and put in the group of its role. A failure in
        /// between takes the account back out, rather than leave one behind that
        /// can sign in and do nothing.
        /// </remarks>
        private async Task<HTTPResponse> PostAccount(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageAccounts, true, out var user, out var refused))
                return refused;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            #region The name it signs in with

            var userIdText = json["userId"]?.Value<String>()?.Trim();

            if (String.IsNullOrEmpty(userIdText))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, "A 'userId' is required.");

            if (!User_Id.TryParse(userIdText, out var userId))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'{userIdText}' is not a usable user identification.");

            if (accounts.TryGetUser(userId, out _))
                return ErrorJSON(Request, HTTPStatusCode.Conflict, $"There is already an account called '{userId}'.");

            #endregion

            #region What it may do

            if (!MeterRole.TryParse(json["role"]?.Value<String>(), out var role))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 $"A 'role' is required, one of: {String.Join(", ", MeterRole.All.Select(one => one.Name))}.");

            if (!TryGetGroup(role, out var group))
                return ErrorJSON(Request, HTTPStatusCode.InternalServerError, $"The {role.Name} group is missing.");

            #endregion

            #region The password, given or made here

            var givenPassword  = json["password"]?.Value<String>();
            var generated      = String.IsNullOrEmpty(givenPassword);
            var password       = generated
                                     ? ModbusTLSEnergyMeter.GeneratePassword()
                                     : givenPassword!;

            if (!generated && accounts.ValidatePassword(password) is String weak)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, weak);

            #endregion

            #region An address, whether or not anybody ever reads it

            // A meter in a car park sends no mail and nobody answers what it
            // would send, but Hermod's users have an address, so one is made up
            // from the serial number.
            var emailText = json["email"]?.Value<String>()?.Trim();

            if (String.IsNullOrEmpty(emailText))
                emailText = $"{userId}@{meter.SerialNumber.ToLowerInvariant()}.local";

            if (!SimpleEMailAddress.TryParse(emailText, out var email))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, $"'{emailText}' is not an e-mail address.");

            #endregion

            if (!TryGetMeterOrganization(out var organization))
                return ErrorJSON(Request, HTTPStatusCode.InternalServerError,
                                 $"The organization '{meter.Kind.Organization}' is missing.");

            var name     = json["name"]?.Value<String>()?.Trim();

            var newUser  = new User(
                               userId,
                               I18NString.Create(String.IsNullOrEmpty(name) ? userId.ToString() : name),
                               email,

                               // Nobody is going to answer a confirmation mail from
                               // a meter, and an account that cannot sign in until
                               // they do is one that never starts.
                               IsAuthenticated:  true,

                               DataSource:       $"added by {user.Id}"
                           );

            var added    = await accounts.AddUser(
                                     newUser,
                                     User2OrganizationEdgeLabel.IsMember,
                                     organization,
                                     SkipNewUserEMail:          true,
                                     SkipNewUserNotifications:  true,
                                     CurrentUserId:             user.Id
                                 );

            if (added.Result != CommandResult.Success)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 $"'{userId}' could not be created: {added.Description?.FirstText() ?? added.Result.ToString()}");

            var changed  = await accounts.ChangePassword(
                                     newUser,
                                     password,
                                     SuppressNotifications:  true,
                                     CurrentUserId:          user.Id
                                 );

            var joined   = changed.Result == CommandResult.Success
                               ? await accounts.AddUserToUserGroup(newUser, EdgeLabelOf(role), group, CurrentUserId: user.Id)
                               : null;

            if (changed.Result != CommandResult.Success || joined?.IsSuccess != true)
            {

                // An account that exists and cannot sign in, or signs in and may
                // do nothing, is worse than no account: it is in the list, and
                // nobody can use it. Take it back out rather than leave that
                // behind.
                await Remove(newUser, user);

                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 changed.Result != CommandResult.Success
                                     ? $"'{userId}' could not be given a password: {changed.Description?.FirstText() ?? changed.Result.ToString()}"
                                     : $"'{userId}' could not be put in the {role.Name} group: {joined?.ErrorDescription?.FirstText() ?? "no reason was given"}");

            }

            meter.Log.Notice(
                $"'{user.Id}' made the account '{userId}' {Article(role)} {role.Title.ToLowerInvariant()}.",
                "accounts", "web"
            );

            return JSONResponse(Request, HTTPStatusCode.Created,
                       new JObject(

                           new JProperty("account",   AccountJSON(
                                                          accounts.TryGetUser(userId, out var stored) && stored is not null
                                                              ? stored
                                                              : newUser,
                                                          user
                                                      )),

                           // Once. It is kept nowhere it could be read back, so
                           // a page that loses it has lost it.
                           generated
                               ? new JProperty("password", password)
                               : new JProperty("password", JValue.CreateNull())

                       ));

        }

        #endregion

        #region (private) PutAccountRole    (Request)

        /// <summary>
        /// PUT /api/v1/accounts/{id}/role with {"role": "guest"}.
        /// </summary>
        /// <remarks>
        /// The account is taken out of every group of this meter's roles and put
        /// in the new one, so that a role is a role and not the strongest of
        /// several that accumulated.
        /// </remarks>
        private async Task<HTTPResponse> PutAccountRole(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageAccounts, true, out var user, out var refused))
                return refused;

            if (!TryGetAccount(Request, out var account, out var unknown))
                return unknown;

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            if (!MeterRole.TryParse(json["role"]?.Value<String>(), out var role))
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 $"A 'role' is required, one of: {String.Join(", ", MeterRole.All.Select(one => one.Name))}.");

            var held = meter.RolesOf(account);
            var was  = held.FirstOrDefault();

            if (held.Count == 1 && was == role)
                return JSONResponse(Request, HTTPStatusCode.OK, AccountJSON(account, user));

            if (role != MeterRole.SystemAdmin &&
                WouldLeaveNoAdministrator(account))
                return ErrorJSON(Request, HTTPStatusCode.Conflict, OnlyAdministrator(account));

            if (account is not User person || !TryGetGroup(role, out var group))
                return ErrorJSON(Request, HTTPStatusCode.InternalServerError, $"'{account.Id}' or the {role.Name} group cannot be changed here.");

            foreach (var old in held)
                if (TryGetGroup(old, out var oldGroup))
                    await accounts.RemoveUserFromUserGroup(person, oldGroup, CurrentUserId: user.Id);

            var result = await accounts.AddUserToUserGroup(person, EdgeLabelOf(role), group, CurrentUserId: user.Id);

            if (!result.IsSuccess)
            {

                // The old roles were taken away a moment ago, so failing here
                // would leave an account that can sign in and do nothing. Put
                // back what was there rather than leave that behind.
                foreach (var old in held)
                    if (TryGetGroup(old, out var oldGroup))
                        await accounts.AddUserToUserGroup(person, EdgeLabelOf(old), oldGroup, CurrentUserId: user.Id);

                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 $"'{account.Id}' could not be made {Article(role)} {role.Title.ToLowerInvariant()}: " +
                                 $"{result.ErrorDescription?.FirstText() ?? "no reason given"}");

            }

            // What they may do has changed under them, and a browser holding the
            // old answer of /me would go on showing buttons that now answer 403.
            // Signing them out is the honest way to say so.
            accounts.Sessions.RemoveAllForUser(account.Id);

            meter.Log.Notice(
                $"'{user.Id}' made '{account.Id}' {Article(role)} {role.Title.ToLowerInvariant()}" +
                (was is not null ? $", who was {Article(was)} {was.Title.ToLowerInvariant()}." : "."),
                "accounts", "web"
            );

            return JSONResponse(Request, HTTPStatusCode.OK,
                       AccountJSON(
                           accounts.TryGetUser(account.Id, out var stored) && stored is not null
                               ? stored
                               : account,
                           user
                       ));

        }

        #endregion

        #region (private) PutAccountPassword(Request)

        /// <summary>
        /// PUT /api/v1/accounts/{id}/password with an optional
        /// {"password": "..."}: a new password for somebody who has lost theirs.
        /// </summary>
        /// <remarks>
        /// Not for your own account. Changing your own password is done where
        /// the current one is asked for first - which is what stops somebody
        /// who finds an unlocked browser from taking the account over - and
        /// this route asks for nothing, because an administrator resetting a
        /// password does not know the old one.
        ///
        /// Every session of that account ends. A password reset that leaves the
        /// old session alive has not taken the account back.
        /// </remarks>
        private async Task<HTTPResponse> PutAccountPassword(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageAccounts, true, out var user, out var refused))
                return refused;

            if (!TryGetAccount(Request, out var account, out var unknown))
                return unknown;

            if (account.Id == user.Id)
                return ErrorJSON(Request, HTTPStatusCode.Conflict,
                                 "This is your own account. Change your own password where the current one is asked " +
                                 "for, so that a browser somebody walks up to cannot take it over.");

            if (!TryParseJSONObject(Request, out var json, out var errorResponse))
                return errorResponse;

            var givenPassword  = json["password"]?.Value<String>();
            var generated      = String.IsNullOrEmpty(givenPassword);
            var password       = generated
                                     ? ModbusTLSEnergyMeter.GeneratePassword()
                                     : givenPassword!;

            if (!generated && accounts.ValidatePassword(password) is String weak)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest, weak);

            // The overload taking a list, because the single-user one refuses
            // to change a password that already exists unless the current one
            // is handed to it - which an administrator resetting somebody
            // else's does not have.
            var changed = await accounts.ChangePassword(
                                    [ account ],
                                    password,
                                    SuppressNotifications:  true,
                                    CurrentUserId:          user.Id
                                );

            if (changed.Result != CommandResult.Success)
                return ErrorJSON(Request, HTTPStatusCode.BadRequest,
                                 $"The password of '{account.Id}' could not be changed: " +
                                 $"{changed.Description?.FirstText() ?? changed.Result.ToString()}");

            accounts.Sessions.RemoveAllForUser(account.Id);

            meter.Log.Notice(
                $"'{user.Id}' gave '{account.Id}' a new password and ended its sessions.",
                "accounts", "web"
            );

            return JSONResponse(Request, HTTPStatusCode.OK,
                       new JObject(
                           new JProperty("account",   AccountJSON(account, user)),
                           generated
                               ? new JProperty("password", password)
                               : new JProperty("password", JValue.CreateNull())
                       ));

        }

        #endregion

        #region (private) DeleteAccount     (Request)

        /// <summary>
        /// DELETE /api/v1/accounts/{id}
        /// </summary>
        private async Task<HTTPResponse> DeleteAccount(HTTPRequest Request)
        {

            if (!TryAuthorize(Request, MeterPermissions.ManageAccounts, true, out var user, out var refused))
                return refused;

            if (!TryGetAccount(Request, out var account, out var unknown))
                return unknown;

            if (WouldLeaveNoAdministrator(account))
                return ErrorJSON(Request, HTTPStatusCode.Conflict, OnlyAdministrator(account));

            if (!await Remove(account, user))
                return ErrorJSON(Request, HTTPStatusCode.InternalServerError,
                                 $"'{account.Id}' could not be removed. Its roles on this meter have already been taken away, " +
                                  "so it can sign in and do nothing until it is either removed or given a role again.");

            accounts.Sessions.RemoveAllForUser(account.Id);

            meter.Log.Notice(
                $"'{user.Id}' removed the account '{account.Id}'" +
                (account.Id == user.Id ? " - their own." : "."),
                "accounts", "web"
            );

            return JSONResponse(Request, HTTPStatusCode.OK,
                       new JObject(

                           new JProperty("removed",  account.Id.ToString()),

                           // So that a page which has just removed the account it
                           // is signed in as stops, rather than carrying on with
                           // a session that belongs to nobody.
                           new JProperty("wasYou",   account.Id == user.Id)

                       ));

        }

        #endregion


        #region (private) Remove(Account, By)

        /// <summary>
        /// Take an account out of every organization it is in, and then away.
        /// </summary>
        /// <remarks>
        /// Hermod will not delete a user who is still a member of an
        /// organization, so those memberships go first - every one of them and
        /// not only this meter's: an edge to something else would otherwise
        /// leave an account that cannot be removed for a reason nothing here
        /// says. Its groups and its password go with it in Hermod itself, since
        /// ce716a40; before that, an account made again under the same name
        /// found both.
        /// </remarks>
        private async Task<Boolean> Remove(IUser  Account,
                                           IUser  By)
        {

            foreach (var edge in Account.User2Organization_OutEdges.ToArray())
                await accounts.RemoveUserFromOrganization(Account, edge.EdgeLabel, edge.Target, CurrentUserId: By.Id);

            var result = await accounts.DeleteUser(
                                   Account,
                                   SkipUserDeletedNotifications:  true,
                                   CurrentUserId:                 By.Id
                               );

            return result.Result == CommandResult.Success;

        }

        #endregion

        #region (private) TryGetAccount(Request, out Account, out Unknown)

        /// <summary>
        /// The account the path names, or the 404 saying there is none.
        /// </summary>
        private Boolean TryGetAccount(HTTPRequest                             Request,
                                      [NotNullWhen(true)]  out IUser?         Account,
                                      [NotNullWhen(false)] out HTTPResponse?  Unknown)
        {

            var id = Request.ParsedURLParameters.Length > 0 ? Request.ParsedURLParameters[0] : "";

            if (User_Id.TryParse(id, out var userId) &&
                accounts.TryGetUser(userId, out var account) &&
                account is not null)
            {
                Account  = account;
                Unknown  = null;
                return true;
            }

            Account  = null;
            Unknown  = ErrorJSON(Request, HTTPStatusCode.NotFound, $"There is no account called '{id}'.");
            return false;

        }

        #endregion

        #region (private) TryGetGroup(Role, out Group) / EdgeLabelOf(Role)

        /// <summary>
        /// The user group that carries a role - which the node makes at every
        /// start, so that it is there unless somebody took it away since.
        /// </summary>
        private Boolean TryGetGroup(MeterRole                           Role,
                                    [NotNullWhen(true)] out UserGroup?  Group)
        {

            if (accounts.TryGetUserGroup(Role.GroupId, out var group) && group is UserGroup userGroup)
            {
                Group = userGroup;
                return true;
            }

            Group = null;
            return false;

        }

        /// <summary>
        /// How an account is in a role's group: as one of its administrators in
        /// the systemadmin group, which is how the node puts its first account
        /// there, and as a member everywhere else.
        /// </summary>
        private static User2UserGroupEdgeLabel EdgeLabelOf(MeterRole Role)

            => Role == MeterRole.SystemAdmin
                   ? User2UserGroupEdgeLabel.IsAdmin
                   : User2UserGroupEdgeLabel.IsMember;

        #endregion

        #region (private) WouldLeaveNoAdministrator(Account) / OnlyAdministrator(Account)

        /// <summary>
        /// Whether taking this account's administrator role away would leave the
        /// meter without one.
        /// </summary>
        /// <remarks>
        /// The one rule here that is not about tidiness. A meter whose last
        /// administrator has been removed or demoted cannot be given another
        /// one from a browser, cannot be given a new certificate and cannot be
        /// told which CAs to accept - and the only way back is a text editor on
        /// its disk.
        ///
        /// Demoting or removing yourself is allowed as long as somebody else is
        /// an administrator, because then it is an ordinary thing to want: the
        /// person who set a meter up hands it over and takes their own account
        /// off it.
        /// </remarks>
        private Boolean WouldLeaveNoAdministrator(IUser Account)

            => accounts.IsMember(Account, MeterRole.SystemAdmin.GroupId) &&
               accounts.Users.Count(candidate => accounts.IsMember(candidate, MeterRole.SystemAdmin.GroupId)) <= 1;

        private static String OnlyAdministrator(IUser Account)

            => $"'{Account.Id}' is the only administrator of this meter. Make somebody else one first - otherwise " +
                "nobody could manage its certificates or its accounts again, and the only way back would be its disk.";

        #endregion

        #region (private) TryGetMeterOrganization(out Organization)

        private Boolean TryGetMeterOrganization([NotNullWhen(true)] out IOrganization? Organization)
        {

            if (Organization_Id.TryParse(meter.Kind.Organization, out var organizationId) &&
                accounts.TryGetOrganization(organizationId, out var organization) &&
                organization is not null)
            {
                Organization = organization;
                return true;
            }

            Organization = null;
            return false;

        }

        #endregion

        #region (private) AccountJSON(Account, CurrentUser) / RolesJSON() / Article(Role)

        /// <summary>
        /// One account as a page shows it.
        /// </summary>
        /// <remarks>
        /// The strongest of its roles as "role", which is what the page's list
        /// shows and changes, and every one of them as "roles" beside it - an
        /// account put in a second group by some other way is not to be
        /// described as having one.
        /// </remarks>
        private JObject AccountJSON(IUser Account, IUser CurrentUser)
        {

            var roles = meter.RolesOf(Account);
            var role  = roles.FirstOrDefault();

            return new JObject(

                       new JProperty("userId",       Account.Id.ToString()),
                       new JProperty("name",         Account.Name.FirstText()),
                       new JProperty("email",        Account.EMail.Address.ToString()),

                       role is not null
                           ? new JProperty("role",   role.Name)
                           : new JProperty("role",   JValue.CreateNull()),

                       new JProperty("roles",        new JArray(roles.Select(one => one.Name))),
                       new JProperty("roleTitle",    role?.Title ?? "No role on this meter"),
                       new JProperty("permissions",  new JArray(roles.PermissionsOf().Names())),

                       // So that a page can say "you" rather than leaving somebody
                       // to recognise their own user name in a list.
                       new JProperty("isYou",        Account.Id == CurrentUser.Id)

                   );

        }

        private static JArray RolesJSON()

            => new (MeterRole.All.Select(role => role.ToJSON()));

        private static String Article(MeterRole Role)

            => "aeiou".Contains(Char.ToLowerInvariant(Role.Title[0]))
                   ? "an"
                   : "a";

        #endregion

    }

}
