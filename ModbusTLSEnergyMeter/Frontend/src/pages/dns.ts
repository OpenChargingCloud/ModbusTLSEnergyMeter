import { api, type DNSConfiguration, type DNSServer } from '../api/client';
import { auth } from '../auth';
import { html, must, render } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { checked, errorMessage, numberField } from '../ui';

const transports = ['UDP', 'TCP', 'TLS', 'HTTPS'];

/**
 * How this meter resolves names.
 *
 * The list of servers is edited here and sent whole, because a name server is
 * one value: merging an old list into a new one by position is how a removed
 * server comes back.
 */
export const dnsPage: Page = {

    title: 'DNS client',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/dns',
            title:     'DNS client',
            subtitle:  'How this meter resolves names.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayChange = auth.can('ChangeNetworkSettings');

        let cancelled = false;
        let current: DNSConfiguration | null = null;

        // The servers being edited, which is a copy: nothing is changed on the
        // meter until Save, and Reload has to be able to throw this away.
        let servers: DNSServer[] = [];


        function draw(): void {

            if (current === null)
                return;

            const configuration = current;

            render(content, html`

                ${mayChange ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.role ?? 'somebody'}, which may look at the name
                        servers but not change them.
                    </div>
                `}

                <div class="cards">

                    <section class="card wide">

                        <h2>
                            <i class="fa-solid fa-magnifying-glass-location"></i> Name servers
                            <span class="chip ${configuration.enabled ? 'on' : 'off'}">${configuration.enabled ? 'on' : 'off'}</span>
                        </h2>

                        <div class="server-list" id="servers"></div>

                        <div class="form-actions">
                            <button type="button" class="btn" id="add-server" ${mayChange ? '' : html`disabled`}>
                                Add a name server
                            </button>
                        </div>

                        <p class="hint">
                            Switching name resolution off takes the servers away from the client,
                            which is what being switched off means for everything holding it.
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-sliders"></i> How it asks</h2>

                        <form id="dns-form" class="form-stack">

                            <label class="switch">
                                <input type="checkbox" name="enabled" ${configuration.enabled ? html`checked` : ''} ${mayChange ? '' : html`disabled`} />
                                <span>Name resolution on</span>
                            </label>

                            <label class="switch">
                                <input type="checkbox" name="recursionDesired" ${configuration.recursionDesired ? html`checked` : ''} ${mayChange ? '' : html`disabled`} />
                                <span>Recursion desired</span>
                            </label>

                            <label class="switch">
                                <input type="checkbox" name="useCache" ${configuration.useCache ? html`checked` : ''} ${mayChange ? '' : html`disabled`} />
                                <span>Use the cache</span>
                            </label>

                            <label class="switch">
                                <input type="checkbox" name="dnssecOK" ${configuration.dnssecOK ? html`checked` : ''} ${mayChange ? '' : html`disabled`} />
                                <span>DNSSEC OK</span>
                            </label>

                            <label class="switch">
                                <input type="checkbox" name="followCNAMEs" ${configuration.followCNAMEs ? html`checked` : ''} ${mayChange ? '' : html`disabled`} />
                                <span>Follow CNAMEs</span>
                            </label>

                            <label>Query timeout in seconds
                                <input type="number" name="queryTimeoutSeconds" min="0.1" max="60" step="0.1"
                                       value="${configuration.queryTimeoutSeconds}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>Max CNAME follows
                                <input type="number" name="maxCNAMEFollows" min="0" max="255"
                                       value="${configuration.maxCNAMEFollows}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <label>Max retries
                                <input type="number" name="maxRetries" min="0" max="255"
                                       value="${configuration.maxRetries}" ${mayChange ? '' : html`disabled`} />
                            </label>

                            <div class="form-actions">
                                <button type="submit" class="btn primary" ${mayChange ? '' : html`disabled`}>Save</button>
                                <span id="form-note"  class="form-notice" role="status"></span>
                                <span id="form-error" class="form-error"  role="alert"></span>
                            </div>

                            <span class="hint">
                                Saved to ${configuration.file ?? 'the configuration file'}, and in effect at once.
                            </span>

                        </form>

                    </section>

                </div>
            `);

            drawServers();
            wire();

        }

        function drawServers(): void {

            const list = must<HTMLElement>(content, '#servers');

            if (servers.length === 0) {
                render(list, html`<p class="muted small">No name server: this meter resolves nothing.</p>`);
                return;
            }

            render(list, html`
                ${servers.map((server, index) => html`
                    <div class="server-row">
                        <input type="text" data-field="address" data-index="${index}" value="${server.address}"
                               placeholder="192.168.1.1" ${mayChange ? '' : html`disabled`} />
                        <input type="number" data-field="port" data-index="${index}" value="${server.port}"
                               min="1" max="65535" ${mayChange ? '' : html`disabled`} />
                        <select data-field="transport" data-index="${index}" ${mayChange ? '' : html`disabled`}>
                            ${transports.map(transport => html`
                                <option ${server.transport === transport ? html`selected` : ''}>${transport}</option>
                            `)}
                        </select>
                        <button type="button" class="btn small danger" data-remove="${index}" ${mayChange ? '' : html`disabled`}>
                            Remove
                        </button>
                    </div>
                `)}
            `);

        }

        function wire(): void {

            const list = must<HTMLElement>(content, '#servers');

            // Delegated, because the rows are redrawn whenever one is added or
            // taken away and listeners on them would go with them.
            const edit = (event: Event): void => {

                const element = event.target as HTMLInputElement | HTMLSelectElement;
                const name    = element.dataset['field'];
                const index   = Number(element.dataset['index']);

                if (name === undefined || !Number.isInteger(index))
                    return;

                const server = servers[index];

                if (server === undefined)
                    return;

                if (name === 'port')            server.port      = Number(element.value);
                else if (name === 'address')    server.address   = element.value;
                else if (name === 'transport')  server.transport = element.value;

            };

            list.addEventListener('input',  edit);
            list.addEventListener('change', edit);

            list.addEventListener('click', event => {

                const button = (event.target as Element | null)?.closest<HTMLElement>('[data-remove]');

                if (!button)
                    return;

                servers.splice(Number(button.dataset['remove']), 1);
                drawServers();

            });

            if (!mayChange)
                return;

            must<HTMLButtonElement>(content, '#add-server').addEventListener('click', () => {
                servers.push({ address: '', port: 53, transport: 'UDP' });
                drawServers();
            });

            const form  = must<HTMLFormElement>(content, '#dns-form');
            const note  = must<HTMLElement>(content, '#form-note');
            const error = must<HTMLElement>(content, '#form-error');

            form.addEventListener('submit', event => {

                event.preventDefault();
                note.textContent  = '';
                error.textContent = '';

                void (async () => {
                    try
                    {

                        current = await api.dns.save({
                            enabled:              checked(form, 'enabled'),
                            recursionDesired:     checked(form, 'recursionDesired'),
                            useCache:             checked(form, 'useCache'),
                            dnssecOK:             checked(form, 'dnssecOK'),
                            followCNAMEs:         checked(form, 'followCNAMEs'),
                            queryTimeoutSeconds:  numberField(form, 'queryTimeoutSeconds'),
                            maxCNAMEFollows:      numberField(form, 'maxCNAMEFollows'),
                            maxRetries:           numberField(form, 'maxRetries'),
                            servers:              servers.filter(server => server.address.trim().length > 0)
                        });

                        servers = current.servers.map(server => ({ ...server }));

                        draw();
                        must<HTMLElement>(content, '#form-note').textContent = 'Saved.';

                    }
                    catch (problem)
                    {
                        error.textContent = errorMessage(problem);
                    }
                })();

            });

        }

        async function load(): Promise<void> {

            try
            {

                const configuration = await api.dns.get();

                if (cancelled)
                    return;

                current  = configuration;
                servers  = configuration.servers.map(server => ({ ...server }));

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
