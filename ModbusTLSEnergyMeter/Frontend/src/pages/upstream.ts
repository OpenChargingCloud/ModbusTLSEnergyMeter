import { api, type UpstreamPage, type UpstreamUpdate } from '../api/client';
import { auth } from '../auth';
import { must } from '@node/html';
import { asShown, draftOf, withPins, type StoreOffers } from '@node/pages/pins';
import { certificateVerdictView, judgementView, pinsFieldset, readPinsFieldset, storeOffers } from '@node/pages/pinViews';
import type { Page } from '@node/router';
import { mayButNot, reloadButton, shell } from '@node/shell';
import { errorMessage, field, formatTimestamp, numberField, whileSaving } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render, type TemplateResult } from '@node/view';

/**
 * The meter in front of which this one stands: where it is reached, over
 * plain Modbus/TCP or over Modbus/TLS, whom this meter is to it and whom it
 * is believed to be - and how reaching it goes.
 *
 * Without one, this meter measures with its own simulation. With one, every
 * request a client asks is passed on to it, and the charging sessions this
 * meter signs are signed with what that meter counted. That is what makes
 * this meter a wrapper around any Modbus device.
 *
 * Whom it is believed to be, over TLS, is said as a time server's is, with
 * the node's own fields: the certificates it may show and the roots its chain
 * may end at, what showing another comes to, and what is learned the first
 * time it is believed. Whom this meter is to it is a TLS identity of the
 * certificate store whose certificate carries a SunSpec role.
 */
export const upstreamPage: Page = {

    title: 'Upstream',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/upstream',
            title:     'Upstream',
            subtitle:  'The meter in front of which this one stands, and measures with - or none, and it measures with its own simulation.',
            actions:   reloadButton(() => reload())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        const mayChange = auth.can('meter', 'edit');

        let cancelled = false;
        let current:  UpstreamPage | null = null;
        let offers:   StoreOffers | null  = null;


        function draw(): void {

            if (current === null)
                return;

            const page = current;

            render(content, html`

                ${mayChange ? nothing : html`
                    <div class="notice">${mayButNot('look at what this meter stands in front of', 'change it')}</div>
                `}

                <div class="cards">
                    ${linkCard(page)}
                    ${stateCard(page)}
                </div>

            `);

        }


        /** Where it is reached, how, and whom it is believed to be. */
        function linkCard(page: UpstreamPage): TemplateResult {

            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-link"></i> The meter behind</h2>

                    <form id="upstream-form" class="form-stack" @submit=${save}>

                        <label>Host
                            <input type="text" name="host" value="${page.host ?? ''}" ?disabled=${!mayChange}
                                   placeholder="where it is reached - empty for none" spellcheck="false" autocomplete="off" />
                            <span class="hint">
                                Its name or its address. Over Modbus/TLS its certificate has to be issued for it.
                            </span>
                        </label>

                        <label class="checkbox">
                            <input type="checkbox" name="tls" ?checked=${page.tls} ?disabled=${!mayChange} />
                            Modbus/TLS
                            <span class="hint">Rather than plain Modbus/TCP: shown an identity, and held to a certificate.</span>
                        </label>

                        <label>Port
                            <input type="number" name="port" min="1" max="65535" value="${page.port ?? ''}" ?disabled=${!mayChange}
                                   placeholder="${page.defaults.tcpPort} for Modbus/TCP, ${page.defaults.tlsPort} for Modbus/TLS" />
                        </label>

                        <label>Unit
                            <input type="number" name="unit" min="0" max="255" value="${page.unit ?? ''}" ?disabled=${!mayChange}
                                   placeholder="${page.defaults.unit}" />
                        </label>

                        <label>Shown, over Modbus/TLS
                            <select name="identity" ?disabled=${!mayChange}>
                                <option value="" ?selected=${page.identity === null}>the identity with the least role that may read</option>
                                ${page.identities.map(identity => html`
                                    <option value="${identity.id}" ?selected=${page.identity === identity.id}>${identity.label} (${identity.role})</option>
                                `)}
                                ${page.identity !== null && !page.identities.some(identity => identity.id === page.identity)
                                      ? html`<option value="${page.identity}" selected>${page.identity} - not in the store</option>`
                                      : nothing}
                            </select>
                            <span class="hint">
                                TLS identities of the certificate store whose certificate carries a SunSpec role: the
                                meter behind decides by it what this one may do.
                                ${page.identities.length === 0 ? html`<strong>There is none yet.</strong>` : nothing}
                            </span>
                        </label>

                        ${pinsFieldset(draftOf(page.heldTo), {
                              service:   page.usage,
                              what:      'meter',
                              evidence:  true,
                              shown:     page.server === null || !page.tls
                                             ? null
                                             : { name:         page.server,
                                                 certificate:  page.judgement?.certificate ?? page.known?.certificate ?? null,
                                                 root:         page.judgement?.root        ?? page.known?.root        ?? null },
                              offers
                          })}

                        <p class="muted small">
                            Over Modbus/TLS, beyond that, its certificate has to chain to a root this machine trusts or a
                            TLS root of the store for <code>${page.usage}</code>.
                        </p>

                        ${mayChange
                              ? html`
                                  <div class="form-actions">
                                      <button type="submit" class="btn primary">Save</button>
                                      <span class="form-notice" role="status"></span>
                                      <span class="form-error"  role="alert"></span>
                                  </div>
                                  <p class="muted small">
                                      Saved to ${page.file}, and measured with at once.
                                  </p>
                                `
                              : nothing}

                    </form>

                </section>
            `;

        }


        /** How reaching it goes, and what its certificate was last judged. */
        function stateCard(page: UpstreamPage): TemplateResult {

            const state = page.state;

            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-plug-circle-check"></i> How it goes</h2>

                    ${!page.upstream || state === null
                          ? html`<p class="muted small upstream-none">This meter stands in front of no meter: it measures with its own simulation.</p>`
                          : html`
                              <div class="kv-list">
                                  <div class="kv"><span class="k">State</span><span class="v upstream-state">${state.state}, since ${formatTimestamp(state.since)}</span></div>
                                  <div class="kv"><span class="k">Over</span><span class="v">${state.tls ? 'Modbus/TLS' : 'Modbus/TCP'}${state.protocol ? html`, ${state.protocol}, <code>${state.cipherSuite}</code>` : nothing}</span></div>
                                  ${state.identity ? html`<div class="kv"><span class="k">Shown</span><span class="v">${state.identity.label} (${state.identity.role})</span></div>` : nothing}
                              </div>
                              ${state.error ? html`<p class="form-error upstream-error">${state.error}</p>` : nothing}
                            `}

                    ${page.upstream && page.tls
                          ? html`
                              <h3>Its certificate</h3>
                              <p>${certificateVerdictView(page.judgement, page.known)}</p>
                              ${page.judgement ? judgementView(page.judgement) : nothing}
                            `
                          : nothing}

                </section>
            `;

        }


        async function save(event: SubmitEvent): Promise<void> {

            event.preventDefault();

            if (current === null)
                return;

            const form  = event.currentTarget as HTMLFormElement;
            const note  = must<HTMLElement>(form, '.form-notice');
            const error = must<HTMLElement>(form, '.form-error');

            note.textContent  = '';
            error.textContent = '';

            const pins = readPinsFieldset(form);

            if (pins.error !== undefined) {
                error.textContent = pins.error;
                return;
            }

            // Read before whileSaving switches the form off - FormData leaves a
            // switched-off control out.
            const update = withPins<UpstreamUpdate>({
                               host:         field(form, 'host'),
                               port:         numberOrNull(numberField(form, 'port')),
                               unit:         numberOrNull(numberField(form, 'unit')),
                               tls:          must<HTMLInputElement>(form, 'input[name="tls"]').checked,
                               identity:     field(form, 'identity') || null,
                               pinsAsShown:  asShown(current.heldTo)
                           }, pins.draft);

            try
            {

                current = await whileSaving(content, note, () => api.upstream.save(update));

                if (cancelled)
                    return;

                draw();
                form.reset();

                note.textContent = 'Saved.';

            }
            catch (problem)
            {
                if (!cancelled)
                    error.textContent = errorMessage(problem);
            }

        }


        async function load(): Promise<void> {

            try
            {

                const [ loaded, kept ] = await Promise.all([ api.upstream.get(), storeOffers('upstream') ]);

                if (cancelled)
                    return;

                current = loaded;
                offers  = kept;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">What this meter stands in front of could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        async function reload(): Promise<void> {
            await load();
            if (!cancelled)
                content.querySelector<HTMLFormElement>('#upstream-form')?.reset();
        }

        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};


/** A number not typed is none: the meter takes its default. */
function numberOrNull(Value: number): number | null {
    return Number.isNaN(Value) ? null : Value;
}
