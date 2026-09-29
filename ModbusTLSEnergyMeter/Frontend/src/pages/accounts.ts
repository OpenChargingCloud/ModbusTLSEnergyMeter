import { api, type Account, type RoleInfo } from '../api/client';
import { auth } from '../auth';
import { keepDrafts } from '@node/drafts';
import { html, must, render, type HTMLFragment } from '@node/html';
import type { Page } from '@node/router';
import { mayButNot, shell } from '@node/shell';
import { errorMessage, field } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';

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
 */
export const accountsPage: Page = {

    title: 'Accounts',

    render({ root, navigate }) {

        const content = shell(root, {
            active:    '/configuration/accounts',
            title:     'Accounts',
            subtitle:  'Who may sign in to this meter, and as what.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws a password or an account half typed away as
        // thoroughly as leaving the page does, so it asks first.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
            if (unsaved.mayBeLost())
                void load();
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


        function roleOf(name: string | null): RoleInfo | undefined {
            return roles.find(role => role.role === name);
        }


        function draw(): void {

            const me = auth.user;

            render(content, html`

                ${issued === null ? '' : html`
                    <section class="card issued">

                        <h2><i class="fa-solid fa-key"></i> The password of '${issued.userId}'</h2>

                        <p>${issued.why} Write it down or hand it over now: it is kept nowhere it
                           could be read back, so closing this is the end of it.</p>

                        <div class="form-actions">
                            <input type="text" class="mono grow" id="issued-password" readonly value="${issued.password}" />
                            <button type="button" class="btn small" id="copy-password">Copy</button>
                            <button type="button" class="btn small primary" id="dismiss-password">Done</button>
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

                    ${me?.roleDescription === null || me?.roleDescription === undefined ? '' : html`
                        <p class="hint">${me.roleDescription}</p>
                    `}

                    <form id="password-form" class="form-stack">

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
                        ${(accounts ?? []).map(card)}
                    </div>

                    ${mayManage ? html`<section class="card">

                        <h2><i class="fa-solid fa-user-plus"></i> Add an account</h2>

                        <form id="add-form" class="form-stack">

                            <label>Name to sign in with
                                <input type="text" name="userId" required placeholder="rory" autocomplete="off" />
                            </label>

                            <label>Shown name <span class="muted small">(optional)</span>
                                <input type="text" name="name" placeholder="Rory" autocomplete="off" />
                            </label>

                            <label>Role
                                <select name="role" id="role-choice">
                                    ${roles.map(role => html`
                                        <option value="${role.role}" ${role.role === 'viewer' ? html`selected` : ''}>
                                            ${role.title}
                                        </option>
                                    `)}
                                </select>
                            </label>

                            <p class="hint" id="role-description">${roleOf('viewer')?.description ?? ''}</p>

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

                    </section>` : ''}

                ` : html`
                    <div class="notice">
                        ${mayButNot('change its own password', 'see or hand out accounts')}
                    </div>
                `}
            `);

            wire();

        }


        function card(account: Account): HTMLFragment {

            const description = roleOf(account.role)?.description;

            return html`
                <section class="card account ${account.role === null ? 'expired' : ''}">

                    <h2>
                        <i class="fa-solid fa-user"></i> ${account.userId}
                        ${account.isYou ? html`<span class="chip ok">you</span>` : ''}
                    </h2>

                    <div class="table-scroll">
                        <table class="kv">
                            <tr><td>Name</td><td>${account.name ?? account.userId}</td></tr>
                            <tr><td>E-mail</td><td class="wrap">${account.email}</td></tr>
                            <tr><td>Role</td>
                                <td>
                                    ${mayManage ? html`<select data-role-for="${account.userId}">
                                        ${roles.map(role => html`
                                            <option value="${role.role}" ${role.role === account.role ? html`selected` : ''}>
                                                ${role.title}
                                            </option>
                                        `)}
                                        ${account.role === null
                                              ? html`<option value="" selected>No role in this meter</option>`
                                              : ''}
                                    </select>` : account.roleTitle}
                                </td></tr>
                        </table>
                    </div>

                    ${description ? html`
                        <p class="hint">${description}</p>
                    ` : ''}

                    ${mayManage ? html`
                        <div class="form-actions">
                            ${account.isYou ? '' : html`
                                <button type="button" class="btn small" data-reset="${account.userId}">Reset the password</button>
                            `}
                            <button type="button" class="btn small danger" data-remove="${account.userId}">Remove</button>
                        </div>
                    ` : ''}

                    ${account.isYou ? html`
                        <span class="hint">
                            Your own password is changed above, where the current one is asked for.
                        </span>
                    ` : ''}

                </section>
            `;

        }


        function wire(): void {

            wireIssued();
            wireOwnPassword();

            if (!mayManage)
                return;

            wireAddForm();
            wireRoleChanges();
            wireResets();
            wireRemovals();

        }

        function wireIssued(): void {

            if (issued === null)
                return;

            const input = must<HTMLInputElement>(content, '#issued-password');
            const note  = must<HTMLElement>(content, '#copy-note');

            must<HTMLButtonElement>(content, '#copy-password').addEventListener('click', () => {
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
            });

            must<HTMLButtonElement>(content, '#dismiss-password').addEventListener('click', () => {
                issued = null;
                drawAgain(null);
            });

        }

        function wireOwnPassword(): void {

            const note  = must<HTMLElement>(content, '#password-note');
            const error = must<HTMLElement>(content, '#password-error');

            must<HTMLFormElement>(content, '#password-form').addEventListener('submit', event => {

                event.preventDefault();
                note.textContent  = '';
                error.textContent = '';

                const form = event.target as HTMLFormElement;

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

            });

        }

        function wireAddForm(): void {

            const note   = must<HTMLElement>(content, '#add-note');
            const error  = must<HTMLElement>(content, '#add-error');

            must<HTMLSelectElement>(content, '#role-choice').addEventListener('change', sayWhatTheRoleGrants);

            must<HTMLFormElement>(content, '#add-form').addEventListener('submit', event => {

                event.preventDefault();
                note.textContent  = '';
                error.textContent = '';

                const form = event.target as HTMLFormElement;
                const name = field(form, 'name');

                void (async () => {
                    try
                    {

                        const created = await api.accounts.create({
                                                  userId:  field(form, 'userId'),
                                                  role:    field(form, 'role'),
                                                  ...(name.length > 0 ? { name } : {})
                                              });

                        form.reset();

                        if (created.password !== null)
                            issued = {
                                userId:    created.account.userId,
                                password:  created.password,
                                why:       `'${created.account.userId}' was added as ` +
                                           `${created.account.roleTitle.toLowerCase()}, with this password.`
                            };

                        await load('add-form');

                    }
                    catch (problem)
                    {
                        error.textContent = errorMessage(problem);
                    }
                })();

            });

        }

        function wireRoleChanges(): void {

            for (const select of content.querySelectorAll<HTMLSelectElement>('[data-role-for]')) {

                const userId = select.dataset['roleFor'] ?? '';
                const was    = select.value;

                select.addEventListener('change', () => {

                    const role = select.value;

                    if (!confirm(`Make '${userId}' ${roleOf(role)?.title.toLowerCase() ?? role}?` +
                                 `\n\n${roleOf(role)?.description ?? ''}` +
                                 `\n\nEvery session of that account ends, so they will have to sign in again.`)) {
                        select.value = was;
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

                            await load(null);

                        }
                        catch (problem)
                        {
                            select.value = was;
                            alert(errorMessage(problem));
                        }
                    })();

                });

            }

        }

        function wireResets(): void {

            for (const button of content.querySelectorAll<HTMLElement>('[data-reset]')) {

                const userId = button.dataset['reset'] ?? '';

                button.addEventListener('click', () => {

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

                            await load(null);

                        }
                        catch (problem)
                        {
                            alert(errorMessage(problem));
                        }
                    })();

                });

            }

        }

        function wireRemovals(): void {

            for (const button of content.querySelectorAll<HTMLElement>('[data-remove]')) {

                const userId = button.dataset['remove'] ?? '';
                const isYou  = userId === auth.user?.username;

                button.addEventListener('click', () => {

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

                            await load(null);

                        }
                        catch (problem)
                        {
                            alert(errorMessage(problem));
                        }
                    })();

                });

            }

        }


        /**
         * What the role chosen for a new account grants, said where it is
         * chosen rather than on a page somebody would have to go and look for:
         * as it is chosen, and again once the page is drawn anew with the
         * choice put back, which keepDrafts does without telling the page.
         */
        function sayWhatTheRoleGrants(): void {

            const choice       = content.querySelector<HTMLSelectElement>('#role-choice');
            const description  = content.querySelector<HTMLElement>('#role-description');

            if (choice !== null && description !== null)
                description.textContent = roleOf(choice.value)?.description ?? '';

        }

        /**
         * The page drawn anew after something was done on it, over the page as
         * it is: what is typed into its forms is kept, but for the form whose
         * save this follows - saved, or null where none was - which is drawn
         * as the meter has it now.
         */
        function drawAgain(saved: string | null): void {

            keepDrafts(content, saved, draw);

            sayWhatTheRoleGrants();

        }


        /**
         * The accounts as the meter has them now: drawn from nothing the first
         * time and on Reload, and after something was done on the page drawn
         * anew over it, keeping what is typed - saved is the form whose save
         * it follows, or null.
         */
        async function load(saved?: string | null): Promise<void> {

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

                if (saved === undefined)
                    draw();
                else
                    drawAgain(saved);

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }

        // A new password and a new account are in their forms alone until they
        // are sent. The role beside an account is no draft: it is set the
        // moment it is chosen, and it is outside every form.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
