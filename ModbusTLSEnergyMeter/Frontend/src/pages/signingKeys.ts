import { api, type SigningKey, type SigningKeys } from '../api/client';
import { auth } from '../auth';
import { html as stringHTML, must } from '@node/html';
import type { Page } from '@node/router';
import { mayButNot, shell } from '@node/shell';
import { copyText, errorMessage, field } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, repeat, type TemplateResult } from '@node/view';

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
 *
 * Drawn by view.ts: a draw changes only what differs, so that a note typed for
 * a new key - and its focus - outlives another key being made the identity or
 * removed beside it.
 */
export const signingKeysPage: Page = {

    title: 'Signing keys',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/keys',
            title:     'Signing keys',
            subtitle:  'What this meter puts its name to a reading with.',
            actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws a key half asked for away as thoroughly as leaving
        // the page does, so it asks first.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
            if (unsaved.mayBeLost())
                void reload();
        });

        const mayManage = auth.can('keys', 'edit');

        let cancelled = false;
        let store: SigningKeys | null = null;

        /**
         * The algorithm chosen for a new key, whose purpose the form says - or
         * undefined while it is the one drawn as chosen.
         */
        let algorithmChosen: string | undefined;


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

                ${mayManage ? nothing : html`
                    <div class="notice">
                        ${mayButNot('look at the signing keys', 'make or remove one')}
                    </div>
                `}

                ${store.error === null ? nothing : html`
                    <div class="error-box">${store.error}</div>
                `}

                ${store.keys.length === 0 ? html`
                    <div class="notice">
                        This meter has no signing key, so nothing it measures can be shown to have come
                        from it.
                    </div>
                ` : nothing}

                <div class="keys">
                    ${repeat(store.keys, key => key.id, card)}
                </div>

                ${mayManage ? html`
                    <section class="card">

                        <h2><i class="fa-solid fa-plus"></i> Make another key</h2>

                        <form id="add-form" class="form-stack" @submit=${make}>

                            <label>Algorithm
                                <select name="algorithm" id="algorithm"
                                        @change=${(event: Event) => { algorithmChosen = (event.target as HTMLSelectElement).value; draw(); }}>
                                    ${usable.map(algorithm => html`
                                        <option value="${algorithm}" ?selected=${algorithm === usable[0]}>${algorithm}</option>
                                    `)}
                                </select>
                            </label>

                            <p class="hint" id="algorithm-purpose">${purposeOf(algorithmChosen ?? usable[0] ?? '')}</p>

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
                ` : nothing}

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

        }


        function card(key: SigningKey): TemplateResult {

            return html`
                <section class="card signing-key ${key.isDefault ? 'in-use' : ''}">

                    <h2>
                        <i class="fa-solid fa-key"></i> ${key.algorithm}
                        ${key.isDefault ? html`<span class="chip ok">the identity</span>` : nothing}
                    </h2>

                    <div class="table-scroll">
                        <table class="kv">
                            <tr><td>Id</td><td><code>${key.id}</code></td></tr>
                            <tr><td>Fingerprint</td><td><code>${key.fingerprint}</code></td></tr>
                            <tr><td>Made</td><td>${new Date(key.createdAt).toLocaleString()}</td></tr>
                            <tr><td>Good for</td><td>${purposeOf(key.algorithm)}</td></tr>
                            ${key.note === null ? nothing : html`<tr><td>Note</td><td>${key.note}</td></tr>`}
                        </table>
                    </div>

                    <label class="stacked">The public key
                        <textarea class="mono" rows="3" readonly data-key="${key.id}" .defaultValue=${key.publicKey}></textarea>
                    </label>

                    <div class="form-actions">

                        <button type="button" class="btn small" data-copy="${key.id}" @click=${() => copy(key.id)}>Copy</button>

                        ${mayManage && !key.isDefault ? html`
                            <button type="button" class="btn small" data-default="${key.id}" @click=${() => makeTheIdentity(key.id)}>Sign with this one</button>
                        ` : nothing}

                        ${mayManage ? html`
                            <button type="button" class="btn small danger" data-remove="${key.id}" @click=${() => remove(key.id)}>Remove</button>
                        ` : nothing}

                        <span class="form-notice" data-note="${key.id}" role="status"></span>

                    </div>

                </section>
            `;

        }


        function copy(id: string): void {

            const area = content.querySelector<HTMLTextAreaElement>(`[data-key="${id}"]`);
            const note = content.querySelector<HTMLElement>(`[data-note="${id}"]`);

            if (area && note)
                void copyText(area.value, area).then(said => { note.textContent = said; });

        }


        function make(event: SubmitEvent): void {

            event.preventDefault();

            const error = must<HTMLElement>(content, '#add-error');
            const form  = event.currentTarget as HTMLFormElement;
            const note  = field(form, 'note');

            error.textContent = '';

            void (async () => {
                try
                {
                    await api.keys.create(field(form, 'algorithm'), note.length > 0 ? note : undefined);

                    algorithmChosen = undefined;
                    await load();

                    // A draw leaves a form as it is typed into; this one was
                    // made into a key, so it goes back to what it starts with.
                    form.reset();
                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                }
            })();

        }


        function makeTheIdentity(id: string): void {

            if (!confirm(`Sign new readings with '${id}' from now on?` +
                         '\n\nNothing already signed changes: every document says which algorithm it ' +
                         'was signed with and is checked against the key that signed it.'))
                return;

            void (async () => {
                try   { await api.keys.setDefault(id); await load(); }
                catch (problem) { alert(errorMessage(problem)); }
            })();

        }


        function remove(id: string): void {

            if (!confirm(`Remove the signing key '${id}'?` +
                         '\n\nEverything it ever signed stops being checkable against this meter. ' +
                         'This cannot be undone.'))
                return;

            void (async () => {
                try   { await api.keys.remove(id); await load(); }
                catch (problem) { alert(errorMessage(problem)); }
            })();

        }


        /**
         * The keys as the meter has them now, drawn over the page as it is:
         * what is typed into its form stays, with its focus.
         */
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

        /** Reload: the keys as the meter has them, and the form as it starts. */
        async function reload(): Promise<void> {

            algorithmChosen = undefined;

            await load();

            content.querySelectorAll('form').forEach(form => form.reset());

        }

        // A key asked for and not made yet is in the form alone. The first
        // algorithm is drawn as chosen, as the browser shows it anyway, so
        // that an untouched form is not taken for one somebody began.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
