import { api, type CertificateEntry, type CertificatePurpose, type CertificateRequestBody, type CertificateStore } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage, field } from '../ui';

/**
 * The certificates one listener of this meter can show.
 *
 * There are two of these pages and they are deliberately not one. The
 * certificate a meter shows a charging station says "I am this device", is
 * issued by a device PKI and is checked by a machine that has pinned that PKI.
 * The certificate it shows a browser says "I am this administrative web
 * server", comes from wherever the operator's web certificates come from, and
 * is checked against a trust store this meter has no say in. One certificate
 * would have to be accepted by both, and nothing issues such a thing.
 *
 * The private key is made in the meter and never leaves it: what goes out is a
 * signing request, and the only thing that has to come back is a certificate.
 *
 * Rolling over is not a button. Both listeners ask the store at every
 * handshake, and the answer is whichever valid certificate began last - so one
 * uploaded today that becomes valid in two days is simply not the answer until
 * then, and is the answer from the second it is.
 */
export function serverCertificatesPage(purpose: CertificatePurpose): Page {

    const what = purpose === 'modbus'
                     ? {
                           title:     'Modbus/TLS certificate',
                           subtitle:  'What this meter shows a charging station or a controller that connects to it.',
                           icon:      'fa-plug-circle-bolt',
                           menu:      '/configuration/certificates/modbus',
                           hint:      'Checked by a machine that has pinned the CA that issued it. A certificate from anywhere else will be refused by the peers, however valid it looks here.'
                       }
                     : {
                           title:     'Web certificate',
                           subtitle:  'What this meter shows a browser that opens this page.',
                           icon:      'fa-globe',
                           menu:      '/configuration/certificates/web',
                           hint:      'Checked against the browser’s own trust store. The one this meter signed for itself at the first start works, and a browser will say it does not know who signed it - because it does not.'
                       };

    return {

        title: what.title,

        render({ root }) {

            const content = shell(root, {
                active:    what.menu,
                title:     what.title,
                subtitle:  what.subtitle,
                actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
            });

            render(content, html`<div class="loading">Loading ...</div>`);

            must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

            const mayManage = auth.can('ManageCertificates');

            let cancelled = false;
            let store: CertificateStore | null = null;


            function draw(): void {

                if (store === null)
                    return;

                const current = store;

                render(content, html`

                    ${mayManage ? '' : html`
                        <div class="notice">
                            Signed in as ${auth.user?.roleTitle ?? 'somebody'}, which may look at the certificates but
                            not ask for or put in a new one.
                        </div>
                    `}

                    ${current.nextAt ? html`
                        <div class="notice">
                            A newer certificate is waiting and takes over on
                            ${new Date(current.nextAt).toLocaleString()}. Nothing has to be done for that
                            to happen, and nothing restarts.
                        </div>
                    ` : ''}

                    <div class="certificates">
                        ${current.entries.length === 0
                              ? html`<p class="muted">Nothing in this store yet.</p>`
                              : current.entries.map(entry => card(entry, current))}
                    </div>

                    ${mayManage ? html`
                        <section class="card">

                            <h2><i class="fa-solid fa-file-signature"></i> Ask for a new certificate</h2>

                            <form id="request-form" class="form-stack">

                                <label>Subject
                                    <input type="text" name="subject" required
                                           placeholder="CN=${purpose === 'modbus' ? 'meter7.lan, O=Acme' : 'meter7.example.org, O=Acme'}" />
                                </label>

                                <label>DNS names, separated by commas
                                    <input type="text" name="dnsNames" placeholder="meter7.lan, meter7" />
                                </label>

                                <label>IP addresses, separated by commas
                                    <input type="text" name="ipAddresses" placeholder="192.168.7.20" />
                                </label>

                                <label>Key
                                    <select name="keyType" id="key-type">
                                        <optgroup label="This listener can show these">
                                            <option value="ec256" selected>ECDSA P-256</option>
                                            <option value="ec384">ECDSA P-384</option>
                                            <option value="ec521">ECDSA P-521</option>
                                            <option value="rsa2048">RSA 2048</option>
                                            <option value="rsa3072">RSA 3072</option>
                                            <option value="rsa4096">RSA 4096</option>
                                        </optgroup>
                                        <optgroup label="For a certificate used elsewhere">
                                            <option value="ed25519">Ed25519</option>
                                            <option value="ed448">Ed448</option>
                                            <option value="mldsa44">ML-DSA-44</option>
                                            <option value="mldsa65">ML-DSA-65</option>
                                            <option value="mldsa87">ML-DSA-87</option>
                                        </optgroup>
                                    </select>
                                </label>

                                <p class="hint" id="key-type-note"></p>

                                <label>Note
                                    <input type="text" name="note" placeholder="what this is for" />
                                </label>

                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Make a key and a request</button>
                                    <span id="form-note"  class="form-notice" role="status"></span>
                                    <span id="form-error" class="form-error"  role="alert"></span>
                                </div>

                                <span class="hint">
                                    The key is made here and stays here. What you get back is the request to
                                    hand to whoever signs it; bring the certificate back to this page.
                                    ${what.hint}
                                </span>

                            </form>

                        </section>
                    ` : ''}
                `);

                wire();

            }

            /** One entry: what it is, what state it is in, and what can be done with it. */
            function card(entry: CertificateEntry, store: CertificateStore): HTMLFragment {

                const inUse  = entry.id === store.currentId;
                const next   = entry.id === store.nextId;

                return html`
                    <section class="card certificate ${inUse ? 'in-use' : ''} ${entry.state === 'expired' ? 'expired' : ''}">

                        <h2>
                            <i class="fa-solid ${what.icon}"></i>
                            ${entry.certificate ? entry.certificate.subject : entry.subject}
                            ${inUse ? html`<span class="chip on">in use</span>`
                                    : next  ? html`<span class="chip">next</span>`
                                            : html`<span class="chip ${entry.state === 'expired' ? 'alert' : ''}">${entry.state}</span>`}
                        </h2>

                        <table class="kv">
                            ${entry.certificate ? html`
                                <tr><td>Issuer</td><td>${entry.certificate.issuer}</td></tr>
                                <tr><td>Valid from</td><td>${new Date(entry.certificate.notBefore).toLocaleString()}</td></tr>
                                <tr><td>Valid until</td><td>${new Date(entry.certificate.notAfter).toLocaleString()}</td></tr>
                                <tr><td>Thumbprint</td><td class="wrap"><code>${entry.certificate.thumbprint}</code></td></tr>
                            ` : html`
                                <tr><td>Asked for</td><td>${entry.subject}</td></tr>
                            `}
                            ${entry.dnsNames.length    > 0 ? html`<tr><td>DNS names</td><td>${entry.dnsNames.join(', ')}</td></tr>` : ''}
                            ${entry.ipAddresses.length > 0 ? html`<tr><td>IP addresses</td><td>${entry.ipAddresses.join(', ')}</td></tr>` : ''}
                            <tr><td>Key</td><td>${keyTypeName(entry.keyType)}${entry.servedByTLS ? '' : ' - not for a listener'}</td></tr>
                            <tr><td>Asked on</td><td>${new Date(entry.createdAt).toLocaleString()}</td></tr>
                            ${entry.note ? html`<tr><td>Note</td><td>${entry.note}</td></tr>` : ''}
                        </table>

                        <div class="form-actions">
                            ${entry.hasRequest
                                  ? html`<a class="btn small" href="${api.tls.requestURL(purpose, entry.id)}" download>Download the request</a>`
                                  : ''}
                            ${mayManage && entry.hasRequest
                                  ? html`<button type="button" class="btn small" data-upload="${entry.id}">
                                             ${entry.certificate ? 'Replace the certificate' : 'Put the certificate in'}
                                         </button>`
                                  : ''}
                            ${mayManage
                                  ? html`<button type="button" class="btn small danger" data-remove="${entry.id}">Throw away</button>`
                                  : ''}
                        </div>

                        <div class="upload" id="upload-${entry.id}" hidden>
                            <label>The signed certificate, PEM encoded. Intermediates may come with it.
                                <textarea class="mono" rows="8" id="pem-${entry.id}"
                                          placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                            </label>
                            <div class="form-actions">
                                <button type="button" class="btn primary" data-save="${entry.id}">Keep it</button>
                                <span class="form-error" id="upload-error-${entry.id}" role="alert"></span>
                            </div>
                        </div>

                    </section>
                `;

            }

            function wire(): void {

                if (!mayManage)
                    return;

                const note  = must<HTMLElement>(content, '#form-note');
                const error = must<HTMLElement>(content, '#form-error');

                // What the chosen key means, said as it is chosen rather than
                // discovered after a trip to the certificate authority.
                const keyType     = must<HTMLSelectElement>(content, '#key-type');
                const keyTypeHint = must<HTMLElement>(content, '#key-type-note');

                const sayWhatItMeans = () => { keyTypeHint.textContent = keyTypeNote(keyType.value); };

                keyType.addEventListener('change', sayWhatItMeans);
                sayWhatItMeans();

                must<HTMLFormElement>(content, '#request-form').addEventListener('submit', event => {

                    event.preventDefault();
                    note.textContent  = '';
                    error.textContent = '';

                    const form = event.target as HTMLFormElement;

                    void (async () => {
                        try
                        {

                            const entry = await api.tls.request(purpose, {
                                              subject:      field(form, 'subject'),
                                              dnsNames:     list(field(form, 'dnsNames')),
                                              ipAddresses:  list(field(form, 'ipAddresses')),
                                              keyType:      field(form, 'keyType') as CertificateRequestBody['keyType'],
                                              note:         field(form, 'note')
                                          });

                            await load();

                            // The request is the whole point of having pressed
                            // the button, so it is offered at once rather than
                            // left to be found in the list.
                            window.location.href = api.tls.requestURL(purpose, entry.id);

                        }
                        catch (problem)
                        {
                            error.textContent = errorMessage(problem);
                        }
                    })();

                });

                for (const button of content.querySelectorAll<HTMLElement>('[data-upload]'))
                    button.addEventListener('click', () => {
                        const box = must<HTMLElement>(content, `#upload-${button.dataset['upload']}`);
                        box.hidden = !box.hidden;
                    });

                for (const button of content.querySelectorAll<HTMLElement>('[data-save]')) {

                    const id = button.dataset['save'] ?? '';

                    button.addEventListener('click', () => {

                        const problem = must<HTMLElement>(content, `#upload-error-${id}`);
                        problem.textContent = '';

                        void (async () => {
                            try
                            {
                                await api.tls.upload(purpose, id, must<HTMLTextAreaElement>(content, `#pem-${id}`).value);
                                await load();
                            }
                            catch (failure)
                            {
                                problem.textContent = errorMessage(failure);
                            }
                        })();

                    });

                }

                for (const button of content.querySelectorAll<HTMLElement>('[data-remove]')) {

                    const id = button.dataset['remove'] ?? '';

                    button.addEventListener('click', () => {

                        if (!confirm('Throw this certificate and its private key away? That cannot be undone.'))
                            return;

                        void (async () => {
                            try
                            {
                                await api.tls.remove(purpose, id);
                                await load();
                            }
                            catch (failure)
                            {
                                alert(errorMessage(failure));
                            }
                        })();

                    });

                }

            }

            async function load(): Promise<void> {

                try
                {

                    const next = await api.tls.store(purpose);

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

}



/** What a key type is called where a person reads it. */
function keyTypeName(keyType: string): string {
    return ({
        ec256:    'ECDSA P-256',
        ec384:    'ECDSA P-384',
        ec521:    'ECDSA P-521',
        rsa2048:  'RSA 2048',
        rsa3072:  'RSA 3072',
        rsa4096:  'RSA 4096',
        ed25519:  'Ed25519',
        ed448:    'Ed448',
        mldsa44:  'ML-DSA-44',
        mldsa65:  'ML-DSA-65',
        mldsa87:  'ML-DSA-87'
    } as Record<string, string>)[keyType] ?? keyType;
}

/**
 * What choosing it means, said where it is chosen.
 *
 * The second half of this list is the one worth a sentence: those requests are
 * perfectly good and the certificate that comes back will never be shown by
 * this meter, because .NET's TLS stack authenticates a server with RSA or
 * ECDSA. Somebody should learn that before the trip to their CA rather than
 * afterwards.
 */
function keyTypeNote(keyType: string): string {

    if (keyType.startsWith('ed') || keyType.startsWith('mldsa'))
        return `${keyTypeName(keyType)}: this meter will make the key and the request, and no listener of ` +
                'its own will ever show the certificate that comes back - the TLS stack authenticates a ' +
                'server with RSA or ECDSA only. Ask for this when the certificate is for something else.';

    if (keyType === 'ec521' || keyType === 'rsa4096')
        return `${keyTypeName(keyType)}: more than anything needs today, and shown by both listeners.`;

    return `${keyTypeName(keyType)}: shown by both listeners.`;

}


/** "a, b , c" as the three things somebody meant. */
function list(text: string): string[] {
    return text.split(',').map(part => part.trim()).filter(part => part.length > 0);
}


export const modbusCertificatesPage = serverCertificatesPage('modbus');
export const webCertificatesPage    = serverCertificatesPage('web');
