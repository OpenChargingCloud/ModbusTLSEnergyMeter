import { api, type PublicKeyOut, type SessionState, type SignedMeterValue } from '../api/client';
import { auth } from '../auth';
import { html as stringHTML, must } from '@node/html';
import type { Page } from '@node/router';
import { mayButNot, shell } from '@node/shell';
import { copyText, errorMessage, field, formatSince } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, type TemplateResult } from '@node/view';

/**
 * Charging sessions, and readings this meter has put its name to.
 *
 * A reading on the Meter page is a number this meter says it measured. One from
 * here is a number somebody can still check in a year, against a key that was
 * this meter's before the reading was taken - so this page is mostly about
 * getting two things into the right hands at the right time: the public key
 * before the session, and the document after it.
 *
 * Nothing here is stored for later. A document that is not written down when it
 * is shown is gone, which is the same rule the meter itself works by and the
 * reason the copy button is next to every one of them.
 *
 * Drawn by view.ts: a draw changes only what differs, so that who is charging,
 * typed and not started yet, outlives a reading being signed or put away
 * beside it - its focus too.
 */
export const sessionsPage: Page = {

    title: 'Sessions',

    render({ root }) {

        const content = shell(root, {
            active:    '/sessions',
            title:     'Sessions',
            subtitle:  'Charging sessions, and readings this meter has signed.',
            actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws a session half started away as thoroughly as leaving
        // the page does, so it asks first.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
            if (unsaved.mayBeLost())
                void reload();
        });

        const mayDrive = auth.can('meter', 'run');

        let cancelled = false;
        let state: SessionState | null = null;

        // The last thing this page was handed and will not be handed again: the
        // public key when a session starts, the signed document when one stops
        // or when a reading is signed on its own. Held here rather than fetched
        // again because a document cannot be fetched again - nothing on the
        // meter keeps it, and asking a second time signs a second reading at a
        // second moment.
        let shown: { title: string; key: PublicKeyOut; text?: string; note?: string } | null = null;


        function draw(): void {

            if (state === null)
                return;

            const session = state.session;

            render(content, html`

                ${mayDrive ? nothing : html`
                    <div class="notice">
                        ${mayButNot('watch a charging session', 'start or stop one, or ask for a signed reading')}
                    </div>
                `}

                <section class="card ${session ? 'running' : ''}">

                    <h2>
                        <i class="fa-solid fa-plug-circle-bolt"></i> Charging session
                        <span class="chip ${session ? 'ok' : 'off'}">${session ? 'running' : 'none'}</span>
                    </h2>

                    ${session ? html`

                        <div class="table-scroll">
                            <table class="kv">
                                <tr><td>Started</td><td>${new Date(session.startedAt).toLocaleString()} (${formatSince(session.startedAt)})</td></tr>
                                <tr><td>At</td><td>${session.startValue} ${session.unit}</td></tr>
                                <tr><td>Session</td><td><code>${session.sessionId}</code></td></tr>
                                <tr><td>Signed with</td><td><code>${session.keyId}</code></td></tr>
                                ${session.identification === null ? nothing : html`
                                    <tr><td>Started by</td><td><code>${session.identification}</code></td></tr>
                                `}
                            </table>
                        </div>

                        <p class="hint">
                            The reading it started at stays here until it stops. A start reading handed out on
                            its own is a number saying a meter stood somewhere at some moment, which is not
                            evidence of anything - what comes back at the end is one document holding both.
                        </p>

                        ${mayDrive ? html`
                            <div class="form-actions">
                                <button type="button" class="btn primary" id="stop" @click=${stop}>Stop it</button>
                                <span id="session-error" class="form-error" role="alert"></span>
                            </div>
                        ` : nothing}

                    ` : html`

                        <p class="muted small">
                            No session is running. Starting one takes the reading this meter stands at now and
                            answers with the public key, so that whoever checks the document afterwards was
                            given the key before the session began.
                        </p>

                        ${mayDrive ? html`
                            <form id="start-form" class="form-stack" @submit=${start}>

                                <label>Who is charging <span class="muted small">(optional)</span>
                                    <input type="text" name="identification" placeholder="DEADBEEF01" autocomplete="off" />
                                </label>

                                <label>How they were identified <span class="muted small">(optional)</span>
                                    <select name="identificationType">
                                        <option value="" selected>not stated</option>
                                        <option value="ISO14443">ISO14443 - an RFID card</option>
                                        <option value="ISO15693">ISO15693 - an RFID tag</option>
                                        <option value="EVCCID">EVCCID - the vehicle itself</option>
                                        <option value="CENTRAL">CENTRAL - a backend said so</option>
                                        <option value="UNDEFINED">UNDEFINED</option>
                                    </select>
                                </label>

                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Start a session</button>
                                    <span id="session-error" class="form-error" role="alert"></span>
                                </div>

                                <span class="hint">
                                    One at a time: this meter is one measuring point, and a second session would
                                    have to share the same energy counter with the first.
                                </span>

                            </form>
                        ` : nothing}

                    `}

                </section>

                ${shown === null ? nothing : documentCard(shown)}

                <section class="card">

                    <h2><i class="fa-solid fa-file-signature"></i> A reading on its own</h2>

                    <p class="muted small">
                        One signed reading belonging to no charging session - what OCMF calls a fiscal reading
                        and counts in a sequence of its own.
                    </p>

                    ${mayDrive ? html`
                        <div class="form-actions">
                            <button type="button" class="btn" data-value="ocmf" @click=${() => sign('ocmf')}>Sign one as OCMF</button>
                            <button type="button" class="btn" data-value="alfen" @click=${() => sign('alfen')}>... or as Alfen</button>
                            <span id="value-error" class="form-error" role="alert"></span>
                        </div>
                    ` : html`
                        <p class="muted small">Signing one sends this meter to work, so it needs more than reading.</p>
                    `}

                </section>
            `);

        }


        function documentCard(shown: { title: string; key: PublicKeyOut; text?: string; note?: string }): TemplateResult {

            return html`
                <section class="card signed">

                    <h2><i class="fa-solid fa-stamp"></i> ${shown.title}</h2>

                    ${shown.note === undefined ? nothing : html`<p class="hint">${shown.note}</p>`}

                    ${shown.text === undefined ? nothing : html`
                        <label class="stacked">The document
                            <textarea class="mono" rows="7" id="document" readonly .defaultValue=${shown.text}></textarea>
                        </label>
                    `}

                    <label class="stacked">
                        The public key to check it with - ${shown.key.encoding}, ${shown.key.format}
                        <textarea class="mono" rows="3" id="document-key" readonly .defaultValue=${shown.key.publicKey}></textarea>
                    </label>

                    <div class="table-scroll">
                        <table class="kv">
                            <tr><td>Key</td><td><code>${shown.key.keyId}</code> (${shown.key.algorithm})</td></tr>
                            <tr><td>Fingerprint</td><td><code>${shown.key.fingerprint}</code></td></tr>
                            ${shown.key.ocmfAlgorithm === null ? nothing : html`
                                <tr><td>Named in OCMF as</td><td><code>${shown.key.ocmfAlgorithm}</code></td></tr>
                            `}
                        </table>
                    </div>

                    <div class="form-actions">
                        ${shown.text === undefined ? nothing : html`
                            <button type="button" class="btn small" id="copy-document" @click=${() => copy('#document')}>Copy the document</button>
                        `}
                        <button type="button" class="btn small" id="copy-key" @click=${() => copy('#document-key')}>Copy the key</button>
                        <button type="button" class="btn small" id="dismiss-document" @click=${putAway}>Done</button>
                        <span id="copy-note" class="form-notice" role="status"></span>
                    </div>

                    <span class="hint">
                        ${shown.text === undefined
                              ? html`The key does not change and can be read again on the Signing keys page. What
                                     cannot be had twice is the document at the end of this session.`
                              : html`Nothing here keeps this. Write it down or hand it over now; asking again signs
                                     a different reading at a different moment.`}
                    </span>

                </section>
            `;

        }


        /** The document or the key shown put away: written down, or not wanted. */
        function putAway(): void {
            shown = null;
            draw();
        }


        /** What a text area holds, copied - and said beside the buttons. */
        function copy(area: string): void {

            const text = content.querySelector<HTMLTextAreaElement>(area);
            const note = must<HTMLElement>(content, '#copy-note');

            if (text)
                void copyText(text.value, text).then(said => { note.textContent = said; });

        }


        function start(event: SubmitEvent): void {

            event.preventDefault();

            const error = must<HTMLElement>(content, '#session-error');
            const form  = event.currentTarget as HTMLFormElement;

            error.textContent = '';

            void (async () => {
                try
                {

                    const started = await api.signing.start(
                                              field(form, 'identification')     || undefined,
                                              field(form, 'identificationType') || undefined
                                          );

                    shown = {
                        title:  `The public key of session ${started.sessionId}`,
                        key:    started.publicKey,
                        note:   `Started at ${started.startValue} ${started.unit}. This key is what the ` +
                                 'document at the end has to be checked against, and you have it before ' +
                                 'the session rather than after it.'
                    };

                    // The session runs: the form it was started with is no
                    // longer on the page, and the one drawn when it stops is
                    // a new one, empty.
                    await load();

                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                }
            })();

        }


        function stop(): void {

            const error = must<HTMLElement>(content, '#session-error');

            error.textContent = '';

            void (async () => {
                try
                {

                    const stopped = await api.signing.stop();

                    shown = {
                        title:  `Session ${stopped.sessionId}, signed`,
                        text:   stopped.ocmf,
                        key:    stopped.publicKey,
                        note:   `${stopped.startValue} to ${stopped.stopValue} ${stopped.unit} - ` +
                                `${stopped.energy_kWh} kWh in all. Both readings are inside one document, ` +
                                 'so the subtraction is part of what was signed rather than something ' +
                                 'somebody has to be trusted to have done correctly.'
                    };

                    await load();

                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                }
            })();

        }


        function sign(format: 'ocmf' | 'alfen'): void {

            const valueError = must<HTMLElement>(content, '#value-error');

            valueError.textContent = '';

            void (async () => {
                try
                {

                    const signed: SignedMeterValue = await api.signing.value(format);

                    shown = {
                        title:  `A signed reading, ${signed.format}`,
                        text:   signed.ocmf ?? signed.alfen ?? '',
                        key:    signed.publicKey,
                        ...(signed.note !== undefined ? { note: signed.note } : {})
                    };

                    draw();

                }
                catch (problem)
                {
                    valueError.textContent = errorMessage(problem);
                }
            })();

        }


        /**
         * The session as the meter has it now, drawn over the page as it is:
         * what is typed into its form stays, with its focus.
         */
        async function load(): Promise<void> {

            try
            {

                const next = await api.signing.session();

                if (cancelled)
                    return;

                state = next;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }

        /** Reload: the session as the meter has it, and the form as it starts. */
        async function reload(): Promise<void> {

            await load();

            content.querySelectorAll('form').forEach(form => form.reset());

        }

        // Who is charging, typed and not started yet, is in the form alone.
        // "not stated" is drawn as chosen, as the browser shows it anyway, so
        // that an untouched form is not taken for one somebody began.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};
