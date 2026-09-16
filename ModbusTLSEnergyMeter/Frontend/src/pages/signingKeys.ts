import { api, type SigningKey, type SigningKeys } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { copyText, errorMessage, field } from '../ui';

/**
 * The keys this meter puts its name to a reading with.
 *
 * Not the TLS certificates and deliberately not kept with them. A TLS key says
 * "this listener is this host" for the length of a connection and is replaced
 * whenever a CA issues a new certificate; these say "this meter measured this",
 * and have to go on meaning it for as long as anybody may want to check a
 * reading - years after the connection, and after the certificate it was taken
 * under has expired.
 *
 * There is more than one because the data formats disagree about cryptography
 * and cannot be talked out of it.
 */
export const signingKeysPage: Page = {

    title: 'Signing keys',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/keys',
            title:     'Signing keys',
            subtitle:  'What this meter puts its name to a reading with.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayManage = auth.can('ManageCertificates');

        let cancelled = false;
        let store: SigningKeys | null = null;


        /** What an algorithm is good for here, said where it is chosen. */
        function purposeOf(algorithm: string): string {

            if (store === null)
                return '';

            if (algorithm === store.alfenAlgorithm)
                return 'Alfen only - 192 bits, which nothing new should use, and the one curve that format parses.';

            return store.ocmfAlgorithms.includes(algorithm)
                       ? 'OCMF and Alfen-shaped records.'
                       : 'Signing, but no document format here can say it was signed with this.';

        }


        function draw(): void {

            if (store === null)
                return;

            const usable = store.algorithms.filter(algorithm => store!.ocmfAlgorithms.includes(algorithm) ||
                                                                algorithm === store!.alfenAlgorithm);

            render(content, html`

                ${mayManage ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.role ?? 'somebody'}, which may look at the signing keys
                        but not make or remove one.
                    </div>
                `}

                ${store.error === null ? '' : html`
                    <div class="error-box">${store.error}</div>
                `}

                ${store.keys.length === 0 ? html`
                    <div class="notice">
                        This meter has no signing key, so nothing it measures can be shown to have come
                        from it.
                    </div>
                ` : ''}

                <div class="keys">
                    ${store.keys.map(card)}
                </div>

                ${mayManage ? html`
                    <section class="card">

                        <h2><i class="fa-solid fa-plus"></i> Make another key</h2>

                        <form id="add-form" class="form-stack">

                            <label>Algorithm
                                <select name="algorithm" id="algorithm">
                                    ${usable.map(algorithm => html`
                                        <option value="${algorithm}">${algorithm}</option>
                                    `)}
                                </select>
                            </label>

                            <p class="hint" id="algorithm-purpose">${purposeOf(usable[0] ?? '')}</p>

                            <label>What it is for <span class="muted small">(optional)</span>
                                <input type="text" name="note" placeholder="for the Alfen receipts" autocomplete="off" />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary">Make it</button>
                                <span id="add-error" class="form-error" role="alert"></span>
                            </div>

                            <span class="hint">
                                A new key signs nothing by itself. It becomes the one this meter signs with when
                                it is made the identity, and until then it is there for whoever names it.
                            </span>

                        </form>

                    </section>
                ` : ''}

                <section class="card">

                    <h2><i class="fa-solid fa-circle-info"></i> Why there is more than one</h2>

                    <p class="muted small">
                        The formats disagree about cryptography and cannot be talked out of it. OCMF's own
                        algorithm is ECDSA over secp256r1; the Alfen format carries a 25 byte compressed point
                        and parses secp192r1 and nothing else; anybody who wants a signature that outlives a
                        quantum computer wants ML-DSA. A meter that held one key could speak one of those.
                    </p>

                    <p class="muted small">
                        These are not certificates and no CA issues them. What a peer needs in order to check a
                        reading is the public key, which travels with every document this meter hands out.
                    </p>

                </section>
            `);

            wire();

        }


        function card(key: SigningKey): HTMLFragment {

            return html`
                <section class="card signing-key ${key.isDefault ? 'in-use' : ''}">

                    <h2>
                        <i class="fa-solid fa-key"></i> ${key.algorithm}
                        ${key.isDefault ? html`<span class="chip on">the identity</span>` : ''}
                    </h2>

                    <table class="kv">
                        <tr><td>Id</td><td><code>${key.id}</code></td></tr>
                        <tr><td>Fingerprint</td><td><code>${key.fingerprint}</code></td></tr>
                        <tr><td>Made</td><td>${new Date(key.createdAt).toLocaleString()}</td></tr>
                        <tr><td>Good for</td><td>${purposeOf(key.algorithm)}</td></tr>
                        ${key.note === null ? '' : html`<tr><td>Note</td><td>${key.note}</td></tr>`}
                    </table>

                    <label class="stacked">The public key
                        <textarea class="mono" rows="3" readonly data-key="${key.id}">${key.publicKey}</textarea>
                    </label>

                    <div class="form-actions">

                        <button type="button" class="btn small" data-copy="${key.id}">Copy</button>

                        ${mayManage && !key.isDefault ? html`
                            <button type="button" class="btn small" data-default="${key.id}">Sign with this one</button>
                        ` : ''}

                        ${mayManage ? html`
                            <button type="button" class="btn small danger" data-remove="${key.id}">Remove</button>
                        ` : ''}

                        <span class="form-notice" data-note="${key.id}" role="status"></span>

                    </div>

                </section>
            `;

        }


        function wire(): void {

            for (const button of content.querySelectorAll<HTMLElement>('[data-copy]')) {

                const id = button.dataset['copy'] ?? '';

                button.addEventListener('click', () => {

                    const area = content.querySelector<HTMLTextAreaElement>(`[data-key="${id}"]`);
                    const note = content.querySelector<HTMLElement>(`[data-note="${id}"]`);

                    if (area && note)
                        void copyText(area.value, area).then(said => { note.textContent = said; });

                });

            }

            if (!mayManage)
                return;

            const select  = content.querySelector<HTMLSelectElement>('#algorithm');
            const purpose = content.querySelector<HTMLElement>('#algorithm-purpose');

            select?.addEventListener('change', () => {
                if (purpose)
                    purpose.textContent = purposeOf(select.value);
            });

            content.querySelector<HTMLFormElement>('#add-form')?.addEventListener('submit', event => {

                event.preventDefault();

                const error = must<HTMLElement>(content, '#add-error');
                const form  = event.target as HTMLFormElement;
                const note  = field(form, 'note');

                error.textContent = '';

                void (async () => {
                    try
                    {
                        await api.keys.create(field(form, 'algorithm'), note.length > 0 ? note : undefined);
                        await load();
                    }
                    catch (problem)
                    {
                        error.textContent = errorMessage(problem);
                    }
                })();

            });

            for (const button of content.querySelectorAll<HTMLElement>('[data-default]')) {

                const id = button.dataset['default'] ?? '';

                button.addEventListener('click', () => {

                    if (!confirm(`Sign new readings with '${id}' from now on?` +
                                 '\n\nNothing already signed changes: every document says which algorithm it ' +
                                 'was signed with and is checked against the key that signed it.'))
                        return;

                    void (async () => {
                        try   { await api.keys.setDefault(id); await load(); }
                        catch (problem) { alert(errorMessage(problem)); }
                    })();

                });

            }

            for (const button of content.querySelectorAll<HTMLElement>('[data-remove]')) {

                const id = button.dataset['remove'] ?? '';

                button.addEventListener('click', () => {

                    if (!confirm(`Remove the signing key '${id}'?` +
                                 '\n\nEverything it ever signed stops being checkable against this meter. ' +
                                 'This cannot be undone.'))
                        return;

                    void (async () => {
                        try   { await api.keys.remove(id); await load(); }
                        catch (problem) { alert(errorMessage(problem)); }
                    })();

                });

            }

        }


        async function load(): Promise<void> {

            try
            {

                const next = await api.keys.list();

                if (cancelled)
                    return;

                store = next;
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
