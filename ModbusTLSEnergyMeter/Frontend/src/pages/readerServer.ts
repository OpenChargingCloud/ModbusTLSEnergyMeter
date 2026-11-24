import { readerServerAPI as api, type ReaderServer } from '../api/client';
import { toURL } from '@node/basePath';
import type { Page } from '@node/router';
import { reloadButton, shell } from '@node/shell';
import { errorMessage } from '@node/ui';
import { html, render, repeat, type TemplateResult } from '@node/view';

/** How a client may authenticate, in a few words. */
const IN_WORDS: Record<string, string> = {
    httpAuthWithoutTLS:    'a password, without TLS',
    httpAuthOverTLS:       'a password, over TLS',
    tlsClientCertificate:  'a TLS client certificate'
};

/**
 * The server what reads this meter without Modbus/TLS connects to - over a
 * WebSocket or SSH - as it is: whether it listens, how one may sign in, who
 * is connected now, and the SunSpec role each login reads as.
 *
 * Read-only: the server is changed in the "webSocketServer" section of the
 * file, and the meter started again. Who may connect, and as which role, is
 * changed on the pages below it - the logins and their groups, the accepted
 * chains and the connections, which are every WebSocket server's pages.
 */
export const readerServerPage: Page = {

    title: 'Meter readers',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/reader-server',
            title:     'Meter readers',
            subtitle:  'the server they connect to, who is connected, and as which SunSpec role each reads.',
            actions:   reloadButton(() => load())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        let cancelled = false;


        function draw(server: ReaderServer): void {

            const configuration  = server.configuration;
            const roles          = Object.entries(server.roles);

            render(content, html`

                <div class="cards">

                    <section class="card">

                        <h2><i class="fa-solid fa-server"></i> The server</h2>

                        <div class="kv">
                            <span class="k">WebSocket</span>
                            <span class="v" id="reader-websocket">
                                ${server.state.running
                                      ? html`<span class="badge ok">listening</span> on port ${configuration.port ?? '-'}${server.state.tls ? ', over TLS' : ', without TLS'}`
                                      : configuration.enabled === true
                                            ? html`<span class="badge warn">switched on, not listening</span>`
                                            : html`<span class="badge">switched off</span>`}
                            </span>
                            <span class="k">SSH</span>
                            <span class="v" id="reader-ssh">
                                ${server.state.ssh
                                      ? html`<span class="badge ok">served</span> on port ${server.state.sshPort ?? '-'}, as the subsystem <code>modbus@open.charging.cloud</code>`
                                      : html`<span class="badge">not served</span>`}
                            </span>
                            <span class="k">Signing in</span>
                            <span class="v">${(configuration.clientAuthentication ?? []).map(way => IN_WORDS[way] ?? way).join(', ') || '-'}</span>
                            <span class="k">Revocation</span>
                            <span class="v">${configuration.checkCertificateRevocation ? 'a client certificate is checked against its CRL' : 'not checked'}</span>
                        </div>

                        <p class="hint">
                            Changed in the <code>webSocketServer</code> section of the file, and the meter started again.
                            Who may connect: the <a href="${toURL('/configuration/reader-server/logins')}">logins</a>,
                            the <a href="${toURL('/configuration/reader-server/trust')}">accepted chains</a> and the
                            <a href="${toURL('/configuration/connections')}">connections</a> - a reader is written down
                            as both, a connection of the type "MeterReader" that lets it in and a login it signs in with.
                            What it may do is the SunSpec role its login's group is named after.
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-plug"></i> Connected now</h2>

                        ${server.connected.length === 0
                              ? html`<p class="muted" id="reader-connected">No meter reader is connected.</p>`
                              : html`<ul id="reader-connected">${repeat(server.connected, login => login, login => html`<li><code>${login}</code></li>`)}</ul>`}

                    </section>

                    <section class="card wide">

                        <h2><i class="fa-solid fa-user-tag"></i> As which role they read</h2>

                        ${roles.length === 0
                              ? html`<p class="muted" id="reader-roles">No meter reader has a login yet.</p>`
                              : rolesTable(roles)}

                    </section>

                </div>
            `);

        }


        function rolesTable(roles: [string, string | null][]): TemplateResult {

            return html`
                <div class="table-scroll">
                    <table class="table" id="reader-roles">
                        <thead>
                            <tr>
                                <th>Login</th>
                                <th>SunSpec role</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${repeat(roles, ([login]) => login, ([login, role]) => html`
                                <tr>
                                    <td><code>${login}</code></td>
                                    <td>${role ?? html`<span class="muted">none - every request is refused</span>`}</td>
                                </tr>
                            `)}
                        </tbody>
                    </table>
                </div>
            `;

        }


        async function load(): Promise<void> {

            try
            {

                const server = await api.get();

                if (!cancelled)
                    draw(server);

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
