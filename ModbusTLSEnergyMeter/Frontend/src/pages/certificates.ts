import { api, type Certificate } from '../api/client';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage } from '../ui';

/**
 * What this meter shows to its Modbus/TLS clients, and who it lets in.
 *
 * Nothing here can be changed from a browser: a meter's certificate and the CA
 * it trusts are decided when the meter is set up, and swapping either of them
 * from a web page would mean the page could lock every client out.
 */
export const certificatesPage: Page = {

    title: 'Certificates',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/certificates',
            title:     'Certificates',
            subtitle:  'What this meter shows, and who it lets in.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        let cancelled = false;

        async function load(): Promise<void> {

            try
            {

                const certificates = await api.certificates();

                if (cancelled)
                    return;

                render(content, html`
                    <div class="cards">

                        ${card('Meter certificate', certificates.meter)}
                        ${card('Client CA',         certificates.clientCA)}

                        <section class="card">

                            <h2><i class="fa-solid fa-user-shield"></i> SunSpec roles</h2>

                            <p class="muted small">
                                What a Modbus/TLS client may do is decided by the role in its
                                certificate, and not by an account here.
                            </p>

                            <table class="kv">
                                ${certificates.sunSpecRoles.map(role => html`
                                    <tr><td colspan="2"><code>${role}</code></td></tr>
                                `)}
                            </table>

                        </section>

                    </div>
                `);

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


function card(title: string, certificate: Certificate): HTMLFragment {

    return html`
        <section class="card">

            <h2><i class="fa-solid fa-certificate"></i> ${title}</h2>

            <table class="kv">
                <tr><td>Subject</td><td>${certificate.subject}</td></tr>
                <tr><td>Issuer</td><td>${certificate.issuer}</td></tr>
                <tr><td>Valid from</td><td>${new Date(certificate.notBefore).toLocaleDateString()}</td></tr>
                <tr><td>Valid until</td><td>${new Date(certificate.notAfter).toLocaleDateString()}</td></tr>
                <tr><td>Thumbprint</td><td class="wrap"><code>${certificate.thumbprint}</code></td></tr>
            </table>

        </section>
    `;

}
