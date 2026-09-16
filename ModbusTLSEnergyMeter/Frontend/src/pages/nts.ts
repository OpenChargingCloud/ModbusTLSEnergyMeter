import { api, type Clock, type NTSConfiguration } from '../api/client';
import { auth } from '../auth';
import { html, must, render } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { checked, errorMessage, field, formatNumber, numberField } from '../ui';

/**
 * Where this meter reads the time, and what that is worth.
 *
 * Two forms, because they are two different statements. The first says which
 * server to ask and how often. The second says whose answer counts as legal
 * time - which no meter can work out by itself: naming an authority is the
 * operator vouching for one, and it is what makes the question mean anything
 * at all.
 */
export const ntsPage: Page = {

    title: 'NTS client',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/nts',
            title:     'NTS client',
            subtitle:  'Where this meter reads the time, and how it knows the answer is real.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayChange = auth.can('ChangeNetworkSettings');
        const mayTest   = auth.can('RunDiagnostics');

        let cancelled = false;
        let settings: NTSConfiguration | null = null;
        let clock:    Clock | null            = null;


        function draw(): void {

            if (settings === null || clock === null)
                return;

            const nts  = settings;
            const time = clock;

            render(content, html`

                ${mayChange ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.role ?? 'somebody'}, which may look at the time
                        client but not change it.
                    </div>
                `}

                <div class="cards">

                    <section class="card">

                        <h2>
                            <i class="fa-solid fa-clock"></i> Time server
                            <span class="chip ${time.ntsEnabled ? 'on' : 'off'}">${time.ntsEnabled ? 'on' : 'off'}</span>
                        </h2>

                        <form id="nts-form" class="form-stack">

                            <label class="switch">
                                <input type="checkbox" name="enabled" ${time.ntsEnabled ? html`checked` : ''} ${mayChange ? '' : html`disabled`} />
                                <span>Ask the time server</span>
                            </label>

                            <label>Host name
                                <input type="text" name="hostname" value="${nts.hostname ?? time.server}"
                                       placeholder="ptbtime1.ptb.de" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>NTS-KE port
                                <input type="number" name="ntsKEPort" min="1" max="65535"
                                       value="${nts.ntsKEPort ?? 4460}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>NTP port
                                <input type="number" name="ntpPort" min="1" max="65535"
                                       value="${nts.ntpPort ?? 123}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>Timeout in seconds
                                <input type="number" name="timeoutSeconds" min="0.1" max="120" step="0.1"
                                       value="${nts.timeoutSeconds ?? 10}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>Check every ... seconds
                                <input type="number" name="checkEverySeconds" min="10" max="86400"
                                       value="${time.checkEvery_s}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary" ${mayChange ? '' : html`disabled`}>Save</button>
                                ${mayTest ? html`<button type="button" class="btn" id="sync-now">Check the clock now</button>` : ''}
                                <span id="nts-note"  class="form-notice" role="status"></span>
                                <span id="nts-error" class="form-error"  role="alert"></span>
                            </div>

                            <span class="hint">
                                Changing the server builds a new client: the cookies of the old one
                                belonged to that host and to no other.
                            </span>

                        </form>

                    </section>

                    <section class="card">

                        <h2>
                            <i class="fa-solid fa-hourglass-half"></i> This meter's clock
                            <span class="chip ${time.isLegalTime ? 'on' : 'alert'}">${time.isLegalTime ? 'legal time' : 'unverified'}</span>
                        </h2>

                        <table class="kv">
                            <tr><td>Now</td><td>${new Date(time.now).toLocaleString()}</td></tr>
                            <tr><td>Server</td><td>${time.server}</td></tr>
                            <tr><td>Last check</td><td>${time.lastCheck ? new Date(time.lastCheck).toLocaleString() : 'never'}</td></tr>
                            <tr><td>Offset</td><td>${time.lastCheckOffset_ms === null ? '-' : `${formatNumber(time.lastCheckOffset_ms, 1)} ms`}</td></tr>
                            <tr><td>Authority</td><td>${time.legalAuthority ?? 'none configured'}</td></tr>
                            <tr><td>Tolerance</td><td>${formatNumber(time.legalTolerance_ms, 0)} ms</td></tr>
                            <tr><td>Max age of a check</td><td>${Math.round(time.legalMaxAge_s / 60)} min</td></tr>
                        </table>

                        <p class="hint">${time.why}.</p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-scale-balanced"></i> What counts as legal time</h2>

                        <form id="legal-form" class="form-stack">

                            <label>Authority
                                <input type="text" name="legalTimeAuthority" value="${time.legalAuthority ?? ''}"
                                       placeholder="PTB" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>Tolerance in seconds
                                <input type="number" name="legalTimeToleranceSeconds" min="0.001" max="60" step="0.001"
                                       value="${time.legalTolerance_ms / 1000}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>Max age of a check in seconds
                                <input type="number" name="legalTimeMaxAgeSeconds" min="10" max="86400"
                                       value="${time.legalMaxAge_s}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary" ${mayChange ? '' : html`disabled`}>Save</button>
                                <span id="legal-note"  class="form-notice" role="status"></span>
                                <span id="legal-error" class="form-error"  role="alert"></span>
                            </div>

                            <span class="hint">
                                This meter cannot find out by itself who stands behind a time server.
                                Naming one is the operator saying so, and it is what makes the
                                question "is this legal time" mean anything at all.
                            </span>

                        </form>

                    </section>

                </div>
            `);

            wire();

        }

        function wire(): void {

            if (mayTest) {

                const sync = must<HTMLButtonElement>(content, '#sync-now');

                sync.addEventListener('click', () => {

                    sync.disabled    = true;
                    sync.textContent = 'Asking ...';

                    void (async () => {
                        try
                        {
                            await api.nts.sync();
                        }
                        catch (problem)
                        {
                            must<HTMLElement>(content, '#nts-error').textContent = errorMessage(problem);
                        }
                        finally
                        {
                            await load();
                        }
                    })();

                });

            }

            if (!mayChange)
                return;

            save('#nts-form', '#nts-note', '#nts-error', form => ({
                enabled:            checked(form, 'enabled'),
                hostname:           field(form, 'hostname'),
                ntsKEPort:          numberField(form, 'ntsKEPort'),
                ntpPort:            numberField(form, 'ntpPort'),
                timeoutSeconds:     numberField(form, 'timeoutSeconds'),
                checkEverySeconds:  numberField(form, 'checkEverySeconds')
            }));

            save('#legal-form', '#legal-note', '#legal-error', form => {

                const authority = field(form, 'legalTimeAuthority');

                return {
                    // An empty field takes the authority away rather than
                    // naming one called "".
                    legalTimeAuthority:         authority.length > 0 ? authority : null,
                    legalTimeToleranceSeconds:  numberField(form, 'legalTimeToleranceSeconds'),
                    legalTimeMaxAgeSeconds:     numberField(form, 'legalTimeMaxAgeSeconds')
                };

            });

        }

        /** Both forms send to the same place; only what they carry differs. */
        function save(formSelector:   string,
                      noteSelector:   string,
                      errorSelector:  string,
                      body:           (form: HTMLFormElement) => Parameters<typeof api.nts.save>[0]): void {

            const form = must<HTMLFormElement>(content, formSelector);

            form.addEventListener('submit', event => {

                event.preventDefault();

                must<HTMLElement>(content, noteSelector).textContent  = '';
                must<HTMLElement>(content, errorSelector).textContent = '';

                void (async () => {
                    try
                    {
                        await api.nts.save(body(form));
                        await load();
                        must<HTMLElement>(content, noteSelector).textContent = 'Saved.';
                    }
                    catch (problem)
                    {
                        must<HTMLElement>(content, errorSelector).textContent = errorMessage(problem);
                    }
                })();

            });

        }

        async function load(): Promise<void> {

            try
            {

                const [nextSettings, nextClock] = await Promise.all([api.nts.get(), api.clock()]);

                if (cancelled)
                    return;

                settings  = nextSettings;
                clock     = nextClock;

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
