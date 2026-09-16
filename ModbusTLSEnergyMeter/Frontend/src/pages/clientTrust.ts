import { api, type ClientTrust, type TrustedChain } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage, field } from '../ui';

/**
 * Which CAs a Modbus/TLS client certificate may chain to - which is who may
 * talk to this meter at all.
 *
 * More than one on purpose. A meter in the field is reached by peers whose
 * certificates were issued by different people, and even with a single issuer,
 * replacing it is a thing that happens while both the old and the new one still
 * have to work. One pinned CA makes that a flag day.
 *
 * This is only about Modbus/TLS. The web interface authenticates nobody by
 * certificate; there a person signs in with an account.
 */
export const clientTrustPage: Page = {

    title: 'Client trust',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/certificates/clients',
            title:     'Client trust',
            subtitle:  'Which CAs a Modbus/TLS client certificate may chain to.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayManage = auth.can('ManageCertificates');

        let cancelled = false;
        let trust: ClientTrust | null = null;
        let roles: string[] = [];


        function draw(): void {

            if (trust === null)
                return;

            const accepted = trust.chains.filter(chain => chain.enabled).length;

            render(content, html`

                ${mayManage ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.roleTitle ?? 'somebody'}, which may look at the accepted CAs
                        but not change them.
                    </div>
                `}

                ${accepted === 0 ? html`
                    <div class="notice">
                        No CA is accepted at the moment, so every Modbus/TLS client is refused at the
                        handshake. The web interface is unaffected - which is why this page can still
                        be reached to put that right.
                    </div>
                ` : ''}

                <div class="certificates">
                    ${trust.chains.length === 0
                          ? html`<p class="muted">No CA has been added.</p>`
                          : trust.chains.map(card)}
                </div>

                ${mayManage ? html`
                    <section class="card">

                        <h2><i class="fa-solid fa-plus"></i> Accept another CA</h2>

                        <form id="add-form" class="form-stack">

                            <label>Name
                                <input type="text" name="name" placeholder="the operator's PKI" />
                            </label>

                            <label>The CA certificate, PEM encoded. Intermediates may come with it.
                                <textarea class="mono" rows="8" name="pem" required
                                          placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary">Accept it</button>
                                <span id="form-note"  class="form-notice" role="status"></span>
                                <span id="form-error" class="form-error"  role="alert"></span>
                            </div>

                            <span class="hint">
                                What belongs here is the CA that signs your clients, not a client. Adding one
                                takes effect at the next handshake; connections already open are not touched.
                            </span>

                        </form>

                    </section>
                ` : ''}

                <section class="card">

                    <h2><i class="fa-solid fa-user-shield"></i> SunSpec roles</h2>

                    <p class="muted small">
                        Being let in is not being allowed to do anything. What a client may do once its
                        certificate has chained to one of the CAs above is decided by the SunSpec role
                        inside that certificate, and not by anything on this page.
                    </p>

                    <table class="kv">
                        ${roles.map(role => html`<tr><td colspan="2"><code>${role}</code></td></tr>`)}
                    </table>

                </section>
            `);

            wire();

        }

        function card(chain: TrustedChain): HTMLFragment {

            return html`
                <section class="card certificate ${chain.enabled ? '' : 'expired'}">

                    <h2>
                        <i class="fa-solid fa-certificate"></i> ${chain.name}
                        <span class="chip ${chain.enabled ? 'on' : 'off'}">${chain.enabled ? 'accepted' : 'switched off'}</span>
                    </h2>

                    ${chain.certificates.map(certificate => html`
                        <table class="kv">
                            <tr><td>Subject</td><td>${certificate.subject}</td></tr>
                            <tr><td>Issuer</td><td>${certificate.isRoot ? 'itself (a root)' : certificate.issuer}</td></tr>
                            <tr><td>Valid until</td>
                                <td class="${certificate.expired ? 'form-error' : ''}">
                                    ${new Date(certificate.notAfter).toLocaleDateString()}${certificate.expired ? ' - expired' : ''}
                                </td></tr>
                            <tr><td>Thumbprint</td><td class="wrap"><code>${certificate.thumbprint}</code></td></tr>
                        </table>
                    `)}

                    <table class="kv">
                        <tr><td>Added</td><td>${new Date(chain.addedAt).toLocaleString()}</td></tr>
                    </table>

                    ${mayManage ? html`
                        <div class="form-actions">
                            <button type="button" class="btn small" data-toggle="${chain.id}">
                                ${chain.enabled ? 'Stop accepting' : 'Accept again'}
                            </button>
                            <button type="button" class="btn small danger" data-remove="${chain.id}">Remove</button>
                        </div>
                    ` : ''}

                </section>
            `;

        }

        function wire(): void {

            if (!mayManage)
                return;

            const note  = must<HTMLElement>(content, '#form-note');
            const error = must<HTMLElement>(content, '#form-error');

            must<HTMLFormElement>(content, '#add-form').addEventListener('submit', event => {

                event.preventDefault();
                note.textContent  = '';
                error.textContent = '';

                const form = event.target as HTMLFormElement;

                void (async () => {
                    try
                    {
                        await api.trust.add(field(form, 'name'), field(form, 'pem', false));
                        await load();
                    }
                    catch (problem)
                    {
                        error.textContent = errorMessage(problem);
                    }
                })();

            });

            for (const button of content.querySelectorAll<HTMLElement>('[data-toggle]')) {

                const id = button.dataset['toggle'] ?? '';

                button.addEventListener('click', () => {
                    void (async () => {
                        try
                        {
                            const chain = trust?.chains.find(candidate => candidate.id === id);
                            await api.trust.setEnabled(id, !(chain?.enabled ?? true));
                            await load();
                        }
                        catch (problem)
                        {
                            alert(errorMessage(problem));
                        }
                    })();
                });

            }

            for (const button of content.querySelectorAll<HTMLElement>('[data-remove]')) {

                const id = button.dataset['remove'] ?? '';

                button.addEventListener('click', () => {

                    if (!confirm('Stop accepting clients from this CA, and remove it?'))
                        return;

                    void (async () => {
                        try
                        {
                            await api.trust.remove(id);
                            await load();
                        }
                        catch (problem)
                        {
                            alert(errorMessage(problem));
                        }
                    })();

                });

            }

        }

        async function load(): Promise<void> {

            try
            {

                const [next, certificates] = await Promise.all([api.trust.get(), api.certificates()]);

                if (cancelled)
                    return;

                trust = next;
                roles = certificates.sunSpecRoles;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }

        void load();

        return () => { cancelled = true; };

    }

};
