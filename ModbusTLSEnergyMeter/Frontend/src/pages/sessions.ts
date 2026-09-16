import { api, type PublicKeyOut, type SessionState, type SignedMeterValue } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { copyText, errorMessage, field, formatSince } from '../ui';

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
 */
export const sessionsPage: Page = {

    title: 'Sessions',

    render({ root }) {

        const content = shell(root, {
            active:    '/sessions',
            title:     'Sessions',
            subtitle:  'Charging sessions, and readings this meter has signed.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayDrive = auth.can('WriteRegisters');

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

                ${mayDrive ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.roleTitle ?? 'somebody'}, which may watch a charging session
                        but not start or stop one, and may not ask for a signed reading.
                    </div>
                `}

                <section class="card ${session ? 'running' : ''}">

                    <h2>
                        <i class="fa-solid fa-plug-circle-bolt"></i> Charging session
                        <span class="chip ${session ? 'on' : 'off'}">${session ? 'running' : 'none'}</span>
                    </h2>

                    ${session ? html`

                        <table class="kv">
                            <tr><td>Started</td><td>${new Date(session.startedAt).toLocaleString()} (${formatSince(session.startedAt)})</td></tr>
                            <tr><td>At</td><td>${session.startValue} ${session.unit}</td></tr>
                            <tr><td>Session</td><td><code>${session.sessionId}</code></td></tr>
                            <tr><td>Signed with</td><td><code>${session.keyId}</code></td></tr>
                            ${session.identification === null ? '' : html`
                                <tr><td>Started by</td><td><code>${session.identification}</code></td></tr>
                            `}
                        </table>

                        <p class="hint">
                            The reading it started at stays here until it stops. A start reading handed out on
                            its own is a number saying a meter stood somewhere at some moment, which is not
                            evidence of anything - what comes back at the end is one document holding both.
                        </p>

                        ${mayDrive ? html`
                            <div class="form-actions">
                                <button type="button" class="btn primary" id="stop">Stop it</button>
                                <span id="session-error" class="form-error" role="alert"></span>
                            </div>
                        ` : ''}

                    ` : html`

                        <p class="muted small">
                            No session is running. Starting one takes the reading this meter stands at now and
                            answers with the public key, so that whoever checks the document afterwards was
                            given the key before the session began.
                        </p>

                        ${mayDrive ? html`
                            <form id="start-form" class="form-stack">

                                <label>Who is charging <span class="muted small">(optional)</span>
                                    <input type="text" name="identification" placeholder="DEADBEEF01" autocomplete="off" />
                                </label>

                                <label>How they were identified <span class="muted small">(optional)</span>
                                    <select name="identificationType">
                                        <option value="">not stated</option>
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
                        ` : ''}

                    `}

                </section>

                ${shown === null ? '' : documentCard(shown)}

                <section class="card">

                    <h2><i class="fa-solid fa-file-signature"></i> A reading on its own</h2>

                    <p class="muted small">
                        One signed reading belonging to no charging session - what OCMF calls a fiscal reading
                        and counts in a sequence of its own.
                    </p>

                    ${mayDrive ? html`
                        <div class="form-actions">
                            <button type="button" class="btn" data-value="ocmf">Sign one as OCMF</button>
                            <button type="button" class="btn" data-value="alfen">... or as Alfen</button>
                            <span id="value-error" class="form-error" role="alert"></span>
                        </div>
                    ` : html`
                        <p class="muted small">Signing one sends this meter to work, so it needs more than reading.</p>
                    `}

                </section>
            `);

            wire();

        }


        function documentCard(shown: { title: string; key: PublicKeyOut; text?: string; note?: string }): HTMLFragment {

            return html`
                <section class="card signed">

                    <h2><i class="fa-solid fa-stamp"></i> ${shown.title}</h2>

                    ${shown.note === undefined ? '' : html`<p class="hint">${shown.note}</p>`}

                    ${shown.text === undefined ? '' : html`
                        <label class="stacked">The document
                            <textarea class="mono" rows="7" id="document" readonly>${shown.text}</textarea>
                        </label>
                    `}

                    <label class="stacked">
                        The public key to check it with - ${shown.key.encoding}, ${shown.key.format}
                        <textarea class="mono" rows="3" id="document-key" readonly>${shown.key.publicKey}</textarea>
                    </label>

                    <table class="kv">
                        <tr><td>Key</td><td><code>${shown.key.keyId}</code> (${shown.key.algorithm})</td></tr>
                        <tr><td>Fingerprint</td><td><code>${shown.key.fingerprint}</code></td></tr>
                        ${shown.key.ocmfAlgorithm === null ? '' : html`
                            <tr><td>Named in OCMF as</td><td><code>${shown.key.ocmfAlgorithm}</code></td></tr>
                        `}
                    </table>

                    <div class="form-actions">
                        ${shown.text === undefined ? '' : html`
                            <button type="button" class="btn small" id="copy-document">Copy the document</button>
                        `}
                        <button type="button" class="btn small" id="copy-key">Copy the key</button>
                        <button type="button" class="btn small" id="dismiss-document">Done</button>
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


        function wire(): void {

            wireDocument();

            if (!mayDrive)
                return;

            const error = must<HTMLElement>(content, '#session-error');

            content.querySelector<HTMLFormElement>('#start-form')?.addEventListener('submit', event => {

                event.preventDefault();
                error.textContent = '';

                const form = event.target as HTMLFormElement;

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

                        await load();

                    }
                    catch (problem)
                    {
                        error.textContent = errorMessage(problem);
                    }
                })();

            });

            content.querySelector<HTMLButtonElement>('#stop')?.addEventListener('click', () => {

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

            });

            const valueError = must<HTMLElement>(content, '#value-error');

            for (const button of content.querySelectorAll<HTMLElement>('[data-value]')) {

                const format = (button.dataset['value'] ?? 'ocmf') as 'ocmf' | 'alfen';

                button.addEventListener('click', () => {

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

                });

            }

        }

        function wireDocument(): void {

            if (shown === null)
                return;

            const note      = must<HTMLElement>(content, '#copy-note');
            const keyArea   = must<HTMLTextAreaElement>(content, '#document-key');
            const documentA = content.querySelector<HTMLTextAreaElement>('#document');

            content.querySelector<HTMLButtonElement>('#copy-document')?.addEventListener('click', () => {
                if (documentA)
                    void copyText(documentA.value, documentA).then(said => { note.textContent = said; });
            });

            must<HTMLButtonElement>(content, '#copy-key').addEventListener('click', () => {
                void copyText(keyArea.value, keyArea).then(said => { note.textContent = said; });
            });

            must<HTMLButtonElement>(content, '#dismiss-document').addEventListener('click', () => {
                shown = null;
                draw();
            });

        }


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

        void load();

        return () => { cancelled = true; };

    }

};
