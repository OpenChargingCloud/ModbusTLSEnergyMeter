import { auth } from '../auth';
import { html, render } from '../html';
import type { Page } from '../router';
import { shell, visibleMenu } from '../shell';

export const notFoundPage: Page = {

    title: 'Not found',

    render({ root, url }) {

        // Signed out, this page is all there is - no menu to put it in, and
        // nothing to list either, because what a person may see is what their
        // role says and nobody has one yet.
        const content = auth.user
                            ? shell(root, { active: '', title: 'Not found' })
                            : root;

        const pages = auth.user ? visibleMenu() : [];

        render(content, html`
            <section class="not-found">
                <p>There is no page at <code>${url.pathname}</code>.</p>
                <p class="muted">
                    ${pages.length > 0
                          ? html`This meter has
                                 ${pages.map((entry, index) => html`${index > 0 ? ' and ' : ''}<a href="${entry.path}">${entry.label}</a>`)}.`
                          : html`<a href="/login">Sign in</a> to see what this meter has.`}
                </p>
            </section>
        `);

    }

};
