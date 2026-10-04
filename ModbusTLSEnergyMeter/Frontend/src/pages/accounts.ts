import { api, type Account, type RoleInfo } from '../api/client';
import { auth } from '../auth';
import { html as stringHTML, must } from '@node/html';
import type { Page } from '@node/router';
import { mayButNot, shell } from '@node/shell';
import { errorMessage, field } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, live, nothing, render, repeat, type TemplateResult } from '@node/view';

/**
 * Who may sign in to this meter, and as what.
 *
 * Two pages in one, because which of them you see depends on what you are:
 * everybody signed in gets their own account and can change their own
 * password, and an administrator also gets the list of everybody else.
 *
 * The reason the list exists at all is the roles below it that change nothing.
 * Watching what a meter is doing - on a night shift, on the phone, for an
 * audit - should not require the account that can also clear the energy
 * counters or replace the certificate, and until there was a page for it the
 * only account a meter had was the one that could do everything.
 *
 * Drawn by view.ts: a draw changes only what differs, so that a password or an
 * account half typed - and its focus - outlives a role being changed or a
 * password reset beside it.
 */
export const accountsPage: Page = {

    title: 'Accounts',

    render({ root, navigate }) {

        const content = shell(root, {
            active:    '/configuration/accounts',
            title:     'Accounts',
            subtitle:  'Who may sign in to this meter, and as what.',
            actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws a password or an account half typed away as
        // thoroughly as leaving the page does, so it asks first.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
            if (unsaved.mayBeLost())
                void reload();
        });

        // Seeing the accounts and changing them are two permissions: a role the
        // configuration file adds may be given the one without the other.
        const maySee    = auth.can('accounts', 'read');
        const mayManage = maySee && auth.can('accounts', 'edit');

        let cancelled  = false;
        let accounts: Account[] | null = null;
        let roles:    RoleInfo[]       = [];

        // A password the meter has just made. Shown once, kept nowhere it could
        // be read back, and left on the page until it is dismissed rather than
        // cleared by the next redraw - somebody who loses it has lost it.
        let issued: { userId: string; password: string; why: string } | null = null;

        /**
         * The role chosen for a new account, whose description the form shows
         * - or undefined while it is the one drawn as chosen.
         */
        let roleChosen: string | undefined;


        function roleOf(name: string | null): RoleInfo | undefined {
            return roles.find(role => role.role === name);
        }


        function draw(): void {

            const me = auth.user;

            render(content, html`

                ${issued === null ? nothing : html`
                    <section class="card issued">

                        <h2><i class="fa-solid fa-key"></i> The password of '${issued.userId}'</h2>

                        <p>${issued.why} Write it down or hand it over now: it is kept nowhere it
                           could be read back, so closing this is the end of it.</p>

                        <div class="form-actions">
                            <input type="text" class="mono grow" id="issued-password" readonly .value=${issued.password} />
                            <button type="button" class="btn small" id="copy-password" @click=${copyPassword}>Copy</button>
                            <button type="button" class="btn small primary" id="dismiss-password" @click=${putAway}>Done</button>
                            <span id="copy-note" class="form-notice" role="status"></span>
                        </div>

                    </section>
                `}

                <section class="card">

                    <h2><i class="fa-solid fa-user"></i> Your account</h2>

                    <div class="table-scroll">
                        <table class="kv">
                            <tr><td>Signed in as</td><td><code>${me?.username ?? '-'}</code></td></tr>
                            <tr><td>Role</td><td>${me?.roleTitle ?? 'none'}</td></tr>
                        </table>
                    </div>

                    ${me?.roleDescription === null || me?.roleDescription === undefined ? nothing : html`
                        <p class="hint">${me.roleDescription}</p>
                    `}

                    <form id="password-form" class="form-stack" @submit=${changeOwnPassword}>

                        <label>Your current password
                            <input type="password" name="currentPassword" autocomplete="current-password" required />
                        </label>

                        <label>A new one
                            <input type="password" name="newPassword" autocomplete="new-password" required minlength="8" />
                        </label>

                        <label>The new one again
                            <input type="password" name="repeated" autocomplete="new-password" required minlength="8" />
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary">Change it</button>
                            <span id="password-note"  class="form-notice" role="status"></span>
                            <span id="password-error" class="form-error"  role="alert"></span>
                        </div>

                        <span class="hint">
                            The current one is asked for so that a browser somebody walks up to cannot
                            take the account over. Every other session of yours ends.
                        </span>

                    </form>

                </section>

                ${maySee ? html`

                    <h2 class="section-heading">Everybody else</h2>

                    <div class="accounts">
                        ${repeat(accounts ?? [], account => account.userId, card)}
                    </div>

                    ${mayManage ? html`<section class="card">

                        <h2><i class="fa-solid fa-user-plus"></i> Add an account</h2>

                        <form id="add-form" class="form-stack" @submit=${add}>

                            <label>Name to sign in with
                                <input type="text" name="userId" required placeholder="rory" autocomplete="off" />
                            </label>

                            <label>Shown name <span class="muted small">(optional)</span>
                                <input type="text" name="name" placeholder="Rory" autocomplete="off" />
                            </label>

                            <label>Role
                                <select name="role" id="role-choice"
                                        @change=${(event: Event) => { roleChosen = (event.target as HTMLSelectElement).value; draw(); }}>
                                    ${roles.map(role => html`
                                        <option value="${role.role}" ?selected=${role.role === 'viewer'}>
                                            ${role.title}
                                        </option>
                                    `)}
                                </select>
                            </label>

                            <p class="hint" id="role-description">${roleOf(roleChosen ?? 'viewer')?.description ?? ''}</p>

                            <div class="form-actions">
                                <button type="submit" class="btn primary">Add it</button>
                                <span id="add-note"  class="form-notice" role="status"></span>
                                <span id="add-error" class="form-error"  role="alert"></span>
                            </div>

                            <span class="hint">
                                No password is asked for: this meter makes one and shows it once. A password
                                thought up in front of a charging station is the one thing here nobody
                                should have to invent.
                            </span>

                        </form>

                    </section>` : nothing}

                ` : html`
                    <div class="notice">
                        ${mayButNot('change its own password', 'see or hand out accounts')}
                    </div>
                `}
            `);

        }


        function card(account: Account): TemplateResult {

            const description = roleOf(account.role)?.description;

            return html`
                <section class="card account ${account.role === null ? 'expired' : ''}">

                    <h2>
                        <i class="fa-solid fa-user"></i> ${account.userId}
                        ${account.isYou ? html`<span class="chip ok">you</span>` : nothing}
                    </h2>

                    <div class="table-scroll">
                        <table class="kv">
                            <tr><td>Name</td><td>${account.name ?? account.userId}</td></tr>
                            <tr><td>E-mail</td><td class="wrap">${account.email}</td></tr>
                            <tr><td>Role</td>
                                <td>
                                    ${mayManage ? html`<select data-role-for="${account.userId}"
                                                               .value=${live(account.role ?? '')}
                                                               @change=${(event: Event) => setRole(account.userId, (event.target as HTMLSelectElement).value)}>
                                        ${roles.map(role => html`
                                            <option value="${role.role}" ?selected=${role.role === account.role}>
                                                ${role.title}
                                            </option>
                                        `)}
                                        ${account.role === null
                                              ? html`<option value="" selected>No role in this meter</option>`
                                              : nothing}
                                    </select>` : account.roleTitle}
                                </td></tr>
                        </table>
                    </div>

                    ${description ? html`
                        <p class="hint">${description}</p>
                    ` : nothing}

                    ${mayManage ? html`
                        <div class="form-actions">
                            ${account.isYou ? nothing : html`
                                <button type="button" class="btn small" data-reset="${account.userId}" @click=${() => resetPassword(account.userId)}>Reset the password</button>
                            `}
                            <button type="button" class="btn small danger" data-remove="${account.userId}" @click=${() => remove(account.userId)}>Remove</button>
                        </div>
                    ` : nothing}

                    ${account.isYou ? html`
                        <span class="hint">
                            Your own password is changed above, where the current one is asked for.
                        </span>
                    ` : nothing}

                </section>
            `;

        }


        function copyPassword(): void {

            const input = must<HTMLInputElement>(content, '#issued-password');
            const note  = must<HTMLElement>(content, '#copy-note');

            void (async () => {

                // The clipboard is only there on a secure origin, and a meter
                // on a LAN address over plain HTTP is not one. Saying so beats
                // a button that does nothing.
                try
                {
                    await navigator.clipboard.writeText(input.value);
                    note.textContent = 'Copied.';
                }
                catch
                {
                    input.select();
                    note.textContent = 'Selected - copy it with Ctrl+C.';
                }

            })();

        }

        function putAway(): void {
            issued = null;
            draw();
        }


        function changeOwnPassword(event: SubmitEvent): void {

            event.preventDefault();

            const note  = must<HTMLElement>(content, '#password-note');
            const error = must<HTMLElement>(content, '#password-error');
            const form  = event.currentTarget as HTMLFormElement;

            note.textContent  = '';
            error.textContent = '';

            if (field(form, 'newPassword', false) !== field(form, 'repeated', false)) {
                error.textContent = 'The two new passwords are not the same.';
                return;
            }

            void (async () => {
                try
                {

                    await api.auth.changePassword(
                              field(form, 'currentPassword', false),
                              field(form, 'newPassword',     false)
                          );

                    form.reset();
                    note.textContent = 'Changed. Every other session of yours has ended.';

                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                }
            })();

        }


        function add(event: SubmitEvent): void {

            event.preventDefault();

            const note   = must<HTMLElement>(content, '#add-note');
            const error  = must<HTMLElement>(content, '#add-error');
            const form   = event.currentTarget as HTMLFormElement;
            const name   = field(form, 'name');

            note.textContent  = '';
            error.textContent = '';

            void (async () => {
                try
                {

                    const created = await api.accounts.create({
                                              userId:  field(form, 'userId'),
                                              role:    field(form, 'role'),
                                              ...(name.length > 0 ? { name } : {})
                                          });

                    if (created.password !== null)
                        issued = {
                            userId:    created.account.userId,
                            password:  created.password,
                            why:       `'${created.account.userId}' was added as ` +
                                       `${created.account.roleTitle.toLowerCase()}, with this password.`
                        };

                    roleChosen = undefined;

                    await load();

                    // A draw leaves a form as it is typed into; this one was
                    // made into an account, so it goes back to what it starts
                    // with.
                    form.reset();

                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                }
            })();

        }


        /**
         * A role chosen beside an account, set as it is chosen. Asked first,
         * and what is not set - asked no, or refused - goes back to the role
         * the meter has.
         */
        function setRole(userId: string, role: string): void {

            if (!confirm(`Make '${userId}' ${roleOf(role)?.title.toLowerCase() ?? role}?` +
                         `\n\n${roleOf(role)?.description ?? ''}` +
                         `\n\nEvery session of that account ends, so they will have to sign in again.`)) {
                draw();
                return;
            }

            void (async () => {
                try
                {

                    await api.accounts.setRole(userId, role);

                    // Demoting yourself takes away what this page needs to
                    // draw itself, so there is nothing to come back to.
                    if (userId === auth.user?.username) {
                        await auth.refresh();
                        navigate('/meter');
                        return;
                    }

                    await load();

                }
                catch (problem)
                {
                    draw();
                    alert(errorMessage(problem));
                }
            })();

        }


        function resetPassword(userId: string): void {

            if (!confirm(`Give '${userId}' a new password?` +
                         `\n\nEvery session of that account ends, and whatever they knew stops working.`))
                return;

            void (async () => {
                try
                {

                    const reset = await api.accounts.resetPassword(userId);

                    if (reset.password !== null)
                        issued = {
                            userId:    userId,
                            password:  reset.password,
                            why:       `'${userId}' has a new password and every session of that ` +
                                        'account has ended.'
                        };

                    await load();

                }
                catch (problem)
                {
                    alert(errorMessage(problem));
                }
            })();

        }


        function remove(userId: string): void {

            const isYou = userId === auth.user?.username;

            if (!confirm(isYou
                             ? `Remove your own account, '${userId}'?\n\nYou will be signed out and ` +
                                'will not be able to sign in again.'
                             : `Remove the account '${userId}'?\n\nThis cannot be undone.`))
                return;

            void (async () => {
                try
                {

                    const removed = await api.accounts.remove(userId);

                    if (removed.wasYou) {
                        auth.set(null);
                        navigate('/login');
                        return;
                    }

                    await load();

                }
                catch (problem)
                {
                    alert(errorMessage(problem));
                }
            })();

        }


        /**
         * The accounts as the meter has them now, drawn over the page as it
         * is: what is typed into its forms stays, with its focus.
         */
        async function load(): Promise<void> {

            try
            {

                // Somebody who may see the accounts gets both in one request;
                // everybody else may read what the roles mean but not who holds
                // them.
                if (maySee)
                {
                    const list = await api.accounts.list();

                    if (cancelled)
                        return;

                    accounts = list.accounts;
                    roles    = list.roles;
                }

                else
                {
                    const answer = await api.accounts.roles();

                    if (cancelled)
                        return;

                    accounts = null;
                    roles    = answer.roles;
                }

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }

        /** Reload: the accounts as the meter has them, and the forms as they start. */
        async function reload(): Promise<void> {

            roleChosen = undefined;

            await load();

            content.querySelectorAll('form').forEach(form => form.reset());

        }

        // A new password and a new account are in their forms alone until they
        // are sent. The role beside an account is no draft: it is set the
        // moment it is chosen, and it is outside every form.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
