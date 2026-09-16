import { auth } from '../auth';
import { config } from '../config';
import { html, must, render } from '../html';
import type { Page } from '../router';
import { errorMessage, field, safeNext } from '../ui';

export const loginPage: Page = {

    title: 'Sign in',

    render({ root, url, navigate }) {

        const next = safeNext(url.searchParams.get('next')) ?? '/meter';

        if (auth.user) {
            navigate(next, true);
            return;
        }

        render(root, html`
            <section class="login">

                <h1><i class="fa-solid fa-gauge-high"></i> Energy Meter</h1>
                <p class="muted">Sign in to look after this meter.</p>

                <form id="login-form" class="form-stack">
                    <label>User
                        <input name="login" required autocomplete="username" autofocus />
                    </label>
                    <label>Password
                        <input name="password" type="password" required autocomplete="current-password" />
                    </label>
                    <div class="form-actions">
                        <button type="submit" class="btn primary">Sign in</button>
                        <span id="form-error" class="form-error" role="alert"></span>
                    </div>
                </form>

                <p class="small muted login-hint">
                    The first administrator and its password are printed on the console
                    the first time this meter starts.
                </p>

                <p class="small muted">meter ${config.serverVersion} &middot; web ${config.frontendVersion}</p>

            </section>
        `);

        const form    = must<HTMLFormElement>(root, '#login-form');
        const error   = must<HTMLElement>(root, '#form-error');
        const button  = must<HTMLButtonElement>(form, 'button[type="submit"]');

        form.addEventListener('submit', event => {

            event.preventDefault();
            error.textContent = '';
            button.disabled   = true;

            void (async () => {
                try
                {
                    // The password is read untrimmed: a space at either end is
                    // part of it, and quietly dropping one would turn a right
                    // password into a wrong one.
                    await auth.signIn(field(form, 'login'), field(form, 'password', false));

                    if (auth.user === null)
                        throw new Error('Signed in, but this meter does not say who that is.');

                    navigate(next, true);
                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                    button.disabled   = false;
                }
            })();

        });

    }

};
