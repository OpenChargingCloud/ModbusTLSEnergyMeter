import { api, type ModbusConnection } from '../api/client';
import type { Page } from '@node/router';
import { reloadButton, shell } from '@node/shell';
import { errorMessage, formatSince, formatTime } from '@node/ui';
import { html, nothing, render, repeat, type TemplateResult } from '@node/view';

/**
 * Who is connected to this meter over Modbus/TLS now.
 *
 * The log says every request, and from whom - afterwards. This is the moment:
 * each connection that is open, from the instant its TLS handshake held, with
 * where it comes from, whose certificate its client showed and the SunSpec
 * role in it - which is what decides what it may read and write - and how
 * much it has asked, refused requests among them.
 *
 * What 'showConnections' says at the command line, and for the same accounts:
 * whoever may read the log.
 *
 * As it was when the page was opened or reloaded: a connection that came or
 * went since is not here until then, which the page says.
 */
export const connectionsPage: Page = {

    title: 'Connections',

    render({ root }) {

        const content = shell(root, {
            active:    '/connections',
            title:     'Connections',
            subtitle:  'Who is connected to this meter over Modbus/TLS now.',
            actions:   reloadButton(() => reload())
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        let cancelled = false;

        async function reload(): Promise<void> {

            try
            {

                const { connections } = await api.meter.connections();

                if (cancelled)
                    return;

                render(content, html`

                    <section class="card" id="connections">

                        <h2>
                            <i class="fa-solid fa-plug"></i> Modbus/TLS
                            <span class="chip ${connections.length > 0 ? 'ok' : 'off'}" id="count">${
                                connections.length === 0 ? 'nobody'
                              : connections.length === 1 ? '1 connection'
                              :                            `${connections.length} connections`}</span>
                        </h2>

                        ${connections.length === 0

                            ? html`<p class="muted small" id="nobody">Nobody is connected to this meter over Modbus/TLS.</p>`

                            : html`
                                <div class="table-scroll">
                                    <table class="list">
                                        <thead>
                                            <tr>
                                                <th>#</th><th>Role</th><th>From</th><th>Since</th><th>Requests</th><th>Certificate</th>
                                            </tr>
                                        </thead>
                                        <tbody>${repeat(connections, connection => connection.id, row)}</tbody>
                                    </table>
                                </div>
                              `}

                        <p class="hint">
                            As it was when this page was opened or reloaded. A connection is listed once its
                            TLS handshake held, whether it has asked anything or not; the number is the one
                            its requests have in the log.
                        </p>

                    </section>

                `);

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);
            }

        }

        void reload();

        return () => { cancelled = true; };

    }

};


/** One connection. */
function row(connection: ModbusConnection): TemplateResult {

    return html`
        <tr data-connection="${connection.id}">
            <td>${connection.id}</td>
            <td>${connection.role !== null
                      ? html`<span class="chip">${connection.role}</span>`
                      : html`<span class="chip bad" title="A certificate without a SunSpec role may do nothing.">no role</span>`}</td>
            <td><code>${connection.peer ?? 'unknown'}</code></td>
            <td title="${new Date(connection.since).toLocaleString()}">${formatSince(connection.since)}</td>
            <td>${connection.requests}${connection.refused > 0
                      ? html` <span class="chip bad">${connection.refused} refused</span>`
                      : nothing}${connection.lastRequest !== null
                      ? html` <span class="muted small">last ${formatTime(connection.lastRequest)}</span>`
                      : nothing}</td>
            <td class="wrap" title="SHA-256 ${connection.clientFingerprint}">${connection.clientSubject}
                <span class="muted small">${connection.protocol}</span></td>
        </tr>
    `;

}
