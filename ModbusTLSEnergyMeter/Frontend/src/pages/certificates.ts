import { api, type AnsweredRequest, type Certificate, type CertificateKind, type CertificateStore, type NewSigningRequest, type SigningRequest, type SigningRequests, type TLSListener } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '@node/html';
import { hasUsages, usageName, usagesOf } from '@node/pages/certificateUsages';
import type { Page } from '@node/router';
import { mayButNot, shell } from '@node/shell';
import { errorMessage, field, whileSaving } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { toURL } from '@node/basePath';

/**
 * The largest file this page will offer to import.
 *
 * A certificate chain is a few kilobytes; a megabyte is already somebody who
 * picked the wrong file. Refused here rather than at the meter so that the
 * answer is immediate and the browser does not base64 a video first.
 */
const largestImport = 1024 * 1024;


/**
 * How soon a certificate is worth warning about, in days: three weeks, which
 * is when the meter's own log starts saying so about the one a listener shows.
 */
const expiringSoon = 21;


/**
 * What the listeners an identity may be shown on are called on this page. The
 * servers a root or a server certificate is kept for are called what every
 * node calls them - see usageName.
 */
const listenerNames: Record<string, string> = {
    modbus:  'Modbus/TLS',
    web:     'web interface'
};

/** A listener after "shown on": the web interface with its article, Modbus/TLS without one. */
function onListener(listener: string): string {
    return listener === 'web' ? `the ${usageName(listener, listenerNames)}` : usageName(listener, listenerNames);
}

/** What a certificate told nothing about what it is for is for: every use - for an identity, every listener. */
function everyUse(kind: CertificateKind): string {
    return kind === 'tlsIdentity' ? 'on every listener' : 'for every use';
}


/**
 * What each kind is called on this page, the icon of its card, what its card
 * says under its name, and what the dialog that says what one is for adds.
 *
 * The store describes every kind itself, in words written for every node;
 * these are this meter's. A kind the store keeps and this page does not know
 * is shown under the store's own description.
 */
const aboutKind: Record<string, { title: string; icon: string; hint?: HTMLFragment; uses?: HTMLFragment }> = {

    tlsRoot: {
        title:  'TLS roots',
        icon:   'fa-shield-halved',
        hint:   html`What the chain of a time server or a name server this meter asks over TLS may end at, beside
                     the roots the machine itself knows - each told which of them it vouches for.`,
        uses:   html`A root kept for the time servers alone vouches for no name server, and the other way round -
                     except for a time server whose own entry on the NTS page names it by its fingerprint: naming
                     it there says the same, and more narrowly.`
    },

    clientRoot: {
        title:  'Client roots',
        icon:   'fa-certificate',
        hint:   html`What the certificate of a Modbus/TLS client has to be issued by: usually not a root at all but
                     the issuing CA below one, which signs the clients and nothing else - the root above it signs
                     the devices as well, and would let any of them in. More than one may be on, so that a new
                     issuer can be added while the old one still has to work; the last one cannot be switched off
                     or taken out, because a meter that accepts none turns every client away. The web interface is
                     not affected: there a person signs in with an account.`
    },

    tlsIdentity: {
        title:  'TLS identities',
        icon:   'fa-id-card',
        uses:   html`A listener only ever shows an identity that is for it. Taking the last one a listener could
                     show away from it is refused - put another one in first.`
    },

    tlsServer: {
        title:  'Server certificates',
        icon:   'fa-server',
        uses:   html`Which servers it belongs to. A time server is held to one by its fingerprint, in its own entry
                     on the NTS page.`
    }

};


/**
 * What each listener shows, whom to, and what that means for where its
 * certificate comes from - said where one is asked for, and where a listener
 * has none.
 */
const aboutListener: Record<string, { icon: string; checkedBy: string; nothing: string }> = {

    modbus: {
        icon:       'fa-plug-circle-bolt',
        checkedBy:  'Shown to a charging station or a controller, which has pinned the CA that issued it: a ' +
                    'certificate from anywhere else is refused by the peers, however valid it looks here.',
        nothing:    'The Modbus/TLS listener has no certificate it could show, so every charging station and ' +
                    'controller that connects is turned away at the handshake.'
    },

    web: {
        icon:       'fa-globe',
        checkedBy:  'Shown to a browser, and checked against its own trust store. The one this meter signed for ' +
                    'itself at the first start works, and a browser will say it does not know who signed it - ' +
                    'because it does not.',
        nothing:    'The web interface has no certificate it could show, so every browser that connects anew is ' +
                    'turned away at the handshake.'
    }

};


/**
 * Everything this meter believes, everything it presents, and the servers it
 * recognises - the node's certificate store - and the keys made here, with
 * the requests a CA is sent for them.
 *
 * Grouped by what a certificate is to this meter, which is the whole shape of
 * this page. A **root** is what it believes, every one of a kind that is
 * switched on at once: the TLS roots a time or name server's chain may end
 * at, and the client roots a Modbus/TLS client's certificate has to be issued
 * by. An **identity** is what it presents: the Modbus/TLS listener shows one
 * to a charging station, the web interface one to a browser, and of those a
 * listener may show it shows the one whose validity began last - asked at
 * every handshake, so that rolling over is not a button. Beside them the
 * **server certificates**, which are neither: kept so that a server can be
 * recognised by its fingerprint.
 *
 * A TLS root, a server certificate and an identity are told what they are
 * for when they are put in, and can be told again: a root put in for the name
 * servers vouches for no time, and an identity put in for the web interface
 * is never shown to a charging station.
 *
 * Certificates arrive three ways, and all of them are first class. "Import"
 * uploads a file and copies it in; "Re-read the directory" picks up whatever
 * somebody put there by hand, which on a machine you already have a shell on
 * is the shorter path; and a signing request makes the key here, where it
 * stays, and turns the certificate a CA sends back into an identity. Every
 * way, the store ends up the same, because the store is the directory.
 *
 * This was three pages while the meter kept three stores of its own: one for
 * the certificates of each listener, and one for the CAs clients were let in
 * by.
 */
export const certificatesPage: Page = {

    title: 'Certificates',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/certificates',
            title:     'Certificates',
            subtitle:  'The roots this meter believes, the certificates it presents, and the servers it recognises.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws an import or a request half filled in away as
        // thoroughly as leaving the page does, so it asks first.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {
            if (unsaved.mayBeLost())
                void load();
        });

        const mayChange = auth.can('certificates', 'edit');

        let cancelled = false;
        let current:   CertificateStore | null = null;
        let requests:  SigningRequests  | null = null;

        // What a client may do once it is let in. Not the store's, and never
        // changed from here - but beside the client roots it is the other
        // half of what they are about.
        let roles:     string[] = [];

        let busy = false;


        function draw(): void {

            if (current === null || requests === null)
                return;

            const store  = current;
            const asked  = requests;

            // A listener that runs and has nothing to show turns everybody
            // away, which is the first thing this page has to say.
            const unshown = store.listeners.filter(listener => store.shown[listener]?.used === true &&
                                                               store.shown[listener]?.current === null);

            render(content, html`

                ${mayChange ? '' : html`
                    <div class="notice">
                        ${mayButNot('look at the certificates', 'put one in, change one or ask for one')}
                    </div>
                `}

                ${unshown.map(listener => html`
                    <div class="notice">
                        ${aboutListener[listener]?.nothing ?? `The ${listener} listener has no certificate it could show.`}
                        ${mayChange ? 'Put in a TLS identity for it, or ask for one below.' : ''}
                    </div>
                `)}

                ${store.keysAreUnencrypted ? html`
                    <div class="notice">
                        The private keys in this store are <strong>not encrypted</strong>. Anybody who can read
                        <code class="path">${store.directory}</code> can pose as this meter - to a charging station
                        as much as to a browser.
                    </div>
                ` : ''}

                <div class="cards stacked">

                    <section class="card">
                        <h2><i class="fa-solid fa-folder-open"></i> The store</h2>
                        <p class="hint">
                            One file per certificate below <code class="path">${store.directory}</code>, with
                            <code>index.json</code> beside them recording what each one is called, whether it is
                            switched on and what it is kept for. Certificates already in that directory are read again
                            at every start, so copying one in is a way to install it.
                        </p>
                        ${mayChange ? html`
                            <div class="form-actions">
                                <button type="button" id="rescan" class="btn" ${busy ? html`disabled` : ''}>
                                    Re-read the directory
                                </button>
                                <span id="store-note"  class="form-notice" role="status"></span>
                                <span id="store-error" class="form-error"  role="alert"></span>
                            </div>
                        ` : ''}
                    </section>

                    ${mayChange ? importCard() : ''}

                </div>

                <h2 class="section-heading">What this meter believes</h2>
                <p class="hint">
                    Trust anchors. Every one of a kind that is switched on is believed at once, and they are asked
                    for at every handshake: switching one on or off takes effect with the next connection, and
                    connections already open are not touched.
                </p>
                <div class="cards stacked">
                    ${store.trustAnchors.map(kind => html`
                        ${kindCard(kind)}
                        ${kind === 'clientRoot' ? rolesCard() : ''}
                    `)}
                </div>

                <h2 class="section-heading">What this meter presents</h2>
                <p class="hint">
                    TLS identities, each with its private key: what the Modbus/TLS listener shows a charging station
                    or a controller, and what the web interface shows a browser. Each is told which of the two it is
                    for, and one never told is for both. Of those a listener may show that are switched on and valid,
                    it shows the one whose validity began last, and asks again at every handshake - so one put in
                    before the old one runs out takes over the moment it becomes valid, with nothing to press and
                    nothing restarted.
                    ${store.shown.web?.used === false ? html`
                        The web interface is served over plain HTTP at the moment, so it shows none of them, and what
                        is kept for it is kept for when it is served over HTTPS.
                    ` : ''}
                </p>
                <div class="cards stacked">
                    ${store.credentials.map(kind => kindCard(kind))}
                </div>

                <h2 class="section-heading">Signing requests</h2>
                <p class="hint">
                    A key made in this meter, and the request a CA is sent for it. The key never leaves the meter:
                    what goes out is the request, and what comes back is a certificate, checked against the key that
                    asked for it before it becomes an identity of the listener it was asked for. A request is kept
                    once it is answered, with its key, so that a certificate that runs out can be renewed by sending
                    the same request again.
                </p>
                <div class="cards stacked">
                    ${asked.requests.length === 0
                          ? html`<p class="muted small">None.</p>`
                          : asked.requests.map(requestView)}
                    ${mayChange ? requestCard() : ''}
                </div>

                ${store.recognised.length === 0 ? '' : html`
                    <h2 class="section-heading">What this meter recognises</h2>
                    <p class="hint">
                        Neither believed nor presented: the certificates of servers this meter connects to, kept so
                        that one can be recognised by its fingerprint - the fingerprint a time server can be held to
                        on the <a href="${toURL('/configuration/nts')}">NTS</a> page.
                    </p>
                    <div class="cards stacked">
                        ${store.recognised.map(kind => kindCard(kind))}
                    </div>
                `}

            `);

            wire();

        }


        /** The kinds in the order the page shows them, which is the order the import offers them in. */
        function kindsShown(): CertificateKind[] {
            const store = current!;
            return [ ...store.trustAnchors, ...store.credentials, ...store.recognised ];
        }

        /**
         * The boxes that say what a certificate of a kind is for, one per use
         * its kind may be told - its kind's own list, because a root is told
         * servers and an identity listeners. None ticked for every use, which
         * is what a certificate kept before there were uses is as well, and
         * what the meter would refuse to be told as an empty list.
         */
        function usagesFields(kind:    CertificateKind,
                              ticked:  readonly string[] | null | undefined): HTMLFragment {

            return html`
                <legend>${kind === 'tlsIdentity' ? 'Which listener may show it' : 'What it is kept for'}</legend>
                ${usagesOf(current!, kind).map(usage => html`
                    <label class="checkbox">
                        <input type="checkbox" name="usage" value="${usage}"
                               ${ticked?.includes(usage) ? html`checked` : ''} ${busy ? html`disabled` : ''} />
                        ${usageName(usage, listenerNames)}
                    </label>
                `)}
                <span class="hint">None ticked: ${everyUse(kind)}.</span>
            `;

        }


        /** The card that puts a new certificate on this meter. */
        function importCard(): HTMLFragment {

            const store  = current!;
            const kinds  = kindsShown();

            // Drawn as the kind chosen, as the browser would choose it anyway,
            // so that an untouched form is one: where a select draws no option
            // as selected, the browser shows the first, but its defaultSelected
            // stays false - and a page that asks before a draft is thrown
            // away, holding each control against how it was drawn, would ask
            // about one nobody had begun.
            const first  = kinds[0];
            const off    = busy ? html`disabled` : '';

            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-file-import"></i> Import a certificate</h2>

                    <form id="import-form" class="form-stack">

                        <label>The file
                            <input type="file" name="file" id="import-file"
                                   accept=".pem,.crt,.cer,.der,.p12,.pfx" ${off} />
                        </label>
                        <p class="hint">
                            PEM, DER or PKCS#12, copied into the store rather than referenced where it is. An
                            identity has to bring its private key, so a PEM for one holds the key beside the
                            certificate - which is how <code>openssl</code> writes a whole credential into one file.
                            A certificate for a key this meter made goes in under Signing requests, where its key is.
                        </p>

                        <label>What it is for
                            <select name="kind" id="import-kind" ${off}>
                                ${kinds.map(kind => html`
                                    <option value="${kind}" ${kind === first ? html`selected` : ''}>${store.kinds[kind].description}</option>
                                `)}
                            </select>
                        </label>

                        <fieldset class="usages" id="import-usages" ${first !== undefined && hasUsages(store, first) ? '' : html`hidden`}>
                            ${first === undefined ? '' : usagesFields(first, null)}
                        </fieldset>

                        <label>What opens it, if it is a protected PKCS#12
                            <input type="password" name="password" autocomplete="off" ${off} />
                        </label>
                        <p class="hint">
                            Used once, to read the file. The store keeps what it holds without a password, so this
                            is not written down anywhere.
                        </p>

                        <label>What to call it
                            <input type="text" name="label" maxlength="120" placeholder="its common name" ${off} />
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary" ${off}>Import</button>
                            <span id="import-note"  class="form-notice" role="status"></span>
                            <span id="import-error" class="form-error"  role="alert"></span>
                        </div>

                    </form>

                </section>
            `;

        }


        /** One kind, and everything in the store of that kind. */
        function kindCard(kind: CertificateKind): HTMLFragment {

            const store    = current!;
            const entries  = store.certificates[kind] ?? [];
            const about    = aboutKind[kind];

            return html`
                <section class="card">

                    <h2>
                        <i class="fa-solid ${about?.icon ?? 'fa-certificate'}"></i>
                        ${about?.title ?? store.kinds[kind]?.description ?? kind}
                    </h2>

                    ${about?.hint ? html`<p class="hint">${about.hint}</p>` : ''}

                    ${entries.length === 0
                          ? html`<p class="muted small">None.</p>`
                          : html`
                                <div class="table-scroll">
                                    <table class="records">
                                        <thead>
                                            <tr>
                                                <th>Name</th>
                                                <th>Subject</th>
                                                <th>Key</th>
                                                <th>Valid until</th>
                                                <th>State</th>
                                                ${mayChange ? html`<th></th>` : ''}
                                            </tr>
                                        </thead>
                                        <tbody>
                                            ${entries.map(row)}
                                        </tbody>
                                    </table>
                                </div>
                            `}

                </section>
            `;

        }


        /** One certificate: what it is, what it is for, and - an identity - where it is shown. */
        function row(entry: Certificate): HTMLFragment {

            const store  = current!;
            const days   = Math.floor((new Date(entry.notAfter).getTime() - Date.now()) / 86400000);
            const off    = busy ? html`disabled` : '';

            const state  = entry.expired        ? html`<span class="chip bad">expired</span>`
                         : entry.notYetValid    ? html`<span class="chip warn">not yet valid</span>`
                         : !entry.active        ? html`<span class="chip">switched off</span>`
                         : days <= expiringSoon ? html`<span class="chip warn">${days} day(s) left</span>`
                         :                        html`<span class="chip">on</span>`;

            // Where an identity takes over next, and when - the store says it
            // per listener, and the identity is what it is said about.
            const next   = store.listeners.filter(listener => store.shown[listener]?.next === entry.id);

            // Where it is shown and where it is next, which is what is looked
            // for first in a list of identities, and then what it is for. In
            // a line of their own that wraps: beside the name, a takeover
            // date ran the table out of its card.
            const chips  = [
                ...(entry.shownOn ?? []).map(listener => html`<span class="chip ok">shown on ${onListener(listener)}</span>`),
                ...next.map(listener => html`<span class="chip">next on ${onListener(listener)}${from(store.shown[listener]?.nextAt)}</span>`),
                ...(!hasUsages(store, entry.kind)
                        ? []
                        : entry.usages === null || entry.usages === undefined
                              ? [ html`<span class="chip">${everyUse(entry.kind)}</span>` ]
                              : entry.usages.map(usage => html`<span class="chip">${usageName(usage, listenerNames)}</span>`))
            ];

            return html`
                <tr>
                    <td>
                        ${entry.label}
                        <br /><code class="muted" title="SHA-256: ${entry.thumbprint}">${entry.id}</code>
                        ${chips.length > 0 ? html`<br /><span class="chips">${chips}</span>` : ''}
                    </td>
                    <td>
                        ${entry.subject}
                        ${entry.chainLength > 0 ? html`<br /><span class="muted">+${entry.chainLength} sub-CA(s)</span>` : ''}
                    </td>
                    <td>
                        ${entry.keyAlgorithm}
                        ${entry.hasPrivateKey ? html`<br /><span class="muted">with private key</span>` : ''}
                    </td>
                    <td>${new Date(entry.notAfter).toLocaleDateString()}</td>
                    <td>${state}</td>
                    ${mayChange ? html`
                        <td>
                            <button type="button" class="btn small" data-toggle="${entry.id}" ${off}>
                                ${entry.active ? 'Switch off' : 'Switch on'}
                            </button>
                            <button type="button" class="btn small" data-rename="${entry.id}" ${off}>Rename</button>
                            ${hasUsages(store, entry.kind)
                                  ? html`<button type="button" class="btn small" data-usages="${entry.id}" ${off}>Uses</button>`
                                  : ''}
                            <button type="button" class="btn small danger" data-remove="${entry.id}" ${off}>Delete</button>
                        </td>
                    ` : ''}
                </tr>
            `;

        }


        /**
         * What a client may do once it is let in - which is not decided on this
         * page at all.
         */
        function rolesCard(): HTMLFragment {

            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-user-shield"></i> SunSpec roles</h2>

                    <p class="muted small">
                        Being let in is not being allowed to do anything. What a client may do once its
                        certificate has chained to one of the client roots above is decided by the SunSpec role
                        inside that certificate, and not by anything on this page.
                    </p>

                    <table class="kv">
                        ${roles.map(role => html`<tr><td colspan="2"><code>${role}</code></td></tr>`)}
                    </table>

                </section>
            `;

        }


        /** One signing request: what it asks for, whether it was answered, and what can be done with it. */
        function requestView(request: SigningRequest): HTMLFragment {

            const answered  = request.state === 'answered';
            const off       = busy ? html`disabled` : '';

            return html`
                <section class="card signing-request">

                    <h2>
                        <i class="fa-solid ${aboutListener[request.listener]?.icon ?? 'fa-file-signature'}"></i>
                        ${request.subject}
                        <span class="chip ${answered ? 'ok' : 'warn'}">${request.state}</span>
                    </h2>

                    <table class="kv">
                        <tr><td>For</td><td>${onListener(request.listener)}</td></tr>
                        ${request.dnsNames.length    > 0 ? html`<tr><td>DNS names</td><td>${request.dnsNames.join(', ')}</td></tr>` : ''}
                        ${request.ipAddresses.length > 0 ? html`<tr><td>IP addresses</td><td>${request.ipAddresses.join(', ')}</td></tr>` : ''}
                        <tr><td>Key</td><td>${nameOf(request.keyType)}</td></tr>
                        <tr><td>Asked on</td><td>${new Date(request.createdAt).toLocaleString()}</td></tr>
                        ${request.note ? html`<tr><td>Note</td><td>${request.note}</td></tr>` : ''}
                        ${answered ? html`<tr><td>Put in as</td><td>${request.answeredBy.map(labelOf).join(', ')}</td></tr>` : ''}
                    </table>

                    <div class="form-actions">
                        <a class="btn small" href="${api.certificates.requestURL(request.id)}" download>Download the request</a>
                        ${mayChange
                              ? html`<button type="button" class="btn small danger" data-remove-request="${request.id}" ${off}>Throw away</button>`
                              : ''}
                    </div>

                    ${mayChange ? html`
                        <div class="upload">
                            <label>The signed certificate, PEM encoded, with the intermediates above it
                                <textarea class="mono" rows="6" data-pem="${request.id}" ${off}
                                          placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                            </label>
                            <div class="form-actions">
                                <button type="button" class="btn primary" data-answer="${request.id}" ${off}>
                                    ${answered ? 'Renew with the same key' : 'Put the certificate in'}
                                </button>
                                <span class="form-notice" data-answer-note="${request.id}"  role="status"></span>
                                <span class="form-error"  data-answer-error="${request.id}" role="alert"></span>
                            </div>
                        </div>
                    ` : ''}

                </section>
            `;

        }


        /** The card that makes a key here, and the request a CA is sent for it. */
        function requestCard(): HTMLFragment {

            const asked  = requests!;
            const off    = busy ? html`disabled` : '';

            // Drawn as the listener chosen, as importCard draws its kind, and
            // for the same reason.
            const first  = asked.listeners[0];

            return html`
                <section class="card">

                    <h2><i class="fa-solid fa-file-signature"></i> Ask for a new certificate</h2>

                    <form id="request-form" class="form-stack">

                        <label>Which listener it is for
                            <select name="listener" id="request-listener" ${off}>
                                ${asked.listeners.map(listener => html`
                                    <option value="${listener}" ${listener === first ? html`selected` : ''}>${usageName(listener, listenerNames)}</option>
                                `)}
                            </select>
                        </label>

                        <p class="hint" id="request-listener-note"></p>

                        <label>Subject
                            <input type="text" name="subject" required placeholder="CN=meter7.lan, O=Acme" ${off} />
                        </label>

                        <label>DNS names, separated by commas
                            <input type="text" name="dnsNames" placeholder="meter7.lan, meter7" ${off} />
                        </label>

                        <label>IP addresses, separated by commas
                            <input type="text" name="ipAddresses" placeholder="192.168.7.20" ${off} />
                        </label>

                        <label>Key
                            <select name="keyType" id="request-key-type" ${off}>
                                ${asked.keyTypes.map(keyType => html`
                                    <option value="${keyType.id}" ${keyType.id === asked.defaultKeyType ? html`selected` : ''}>
                                        ${keyType.name}
                                    </option>
                                `)}
                            </select>
                        </label>

                        <p class="hint" id="request-key-type-note"></p>

                        <label>Note
                            <input type="text" name="note" placeholder="what this is for" ${off} />
                        </label>

                        <div class="form-actions">
                            <button type="submit" class="btn primary" ${off}>Make a key and a request</button>
                            <span id="request-note"  class="form-notice" role="status"></span>
                            <span id="request-error" class="form-error"  role="alert"></span>
                        </div>

                        <span class="hint">
                            The key is made here and stays here. What you get is the request to hand to whoever
                            signs it; bring the certificate back to this page, to the request it answers.
                        </span>

                    </form>

                </section>
            `;

        }


        /** What a kind of key is called, or its id where it is one no longer offered. */
        function nameOf(id: string): string {
            return requests?.keyTypes.find(keyType => keyType.id === id)?.name ?? id;
        }

        /** What somebody choosing a kind of key should know, as the meter says it. */
        function remarkOf(id: string): string {

            const keyType = requests?.keyTypes.find(one => one.id === id);

            if (keyType === undefined)
                return '';

            return keyType.presentable === false
                       ? `${keyType.remark} This machine turned out not to be able to present such a certificate.`
                       : keyType.remark;

        }

        /** What a certificate of the store is called, or its handle where the store no longer has it. */
        function labelOf(id: string): string {
            return everything().find(one => one.id === id)?.label ?? id;
        }


        function wire(): void {

            if (!mayChange)
                return;

            must<HTMLButtonElement>(content, '#rescan').addEventListener('click', () => void rescan());

            const importForm = must<HTMLFormElement>(content, '#import-form');

            importForm.addEventListener('submit', event => {
                event.preventDefault();
                void doImport(importForm);
            });

            // What it is kept for is asked only of the kinds that are told it,
            // and each kind is told its own: a root the servers it vouches
            // for, an identity the listeners that may show it.
            must<HTMLSelectElement>(content, '#import-kind').addEventListener('change', event => {

                const kind    = (event.target as HTMLSelectElement).value as CertificateKind;
                const usages  = must<HTMLElement>(content, '#import-usages');

                usages.hidden = !hasUsages(current!, kind);
                render(usages, usagesFields(kind, null));

            });

            for (const button of content.querySelectorAll<HTMLElement>('[data-usages]'))
                button.addEventListener('click', () => editUsages(button.dataset['usages'] ?? ''));

            for (const button of content.querySelectorAll<HTMLElement>('[data-toggle]'))
                button.addEventListener('click', () => void toggle(button.dataset['toggle'] ?? ''));

            for (const button of content.querySelectorAll<HTMLElement>('[data-rename]'))
                button.addEventListener('click', () => void rename(button.dataset['rename'] ?? ''));

            for (const button of content.querySelectorAll<HTMLElement>('[data-remove]'))
                button.addEventListener('click', () => void remove(button.dataset['remove'] ?? ''));

            const requestForm = must<HTMLFormElement>(content, '#request-form');

            requestForm.addEventListener('submit', event => {
                event.preventDefault();
                void ask(requestForm);
            });

            // What the chosen listener and the chosen key mean, said as they
            // are chosen rather than discovered after a trip to the CA.
            const listener      = must<HTMLSelectElement>(content, '#request-listener');
            const listenerNote  = must<HTMLElement>      (content, '#request-listener-note');
            const keyType       = must<HTMLSelectElement>(content, '#request-key-type');
            const keyTypeNote   = must<HTMLElement>      (content, '#request-key-type-note');

            const sayWhatTheyMean = (): void => {
                listenerNote.textContent  = aboutListener[listener.value]?.checkedBy ?? '';
                keyTypeNote.textContent   = remarkOf(keyType.value);
            };

            listener.addEventListener('change', sayWhatTheyMean);
            keyType. addEventListener('change', sayWhatTheyMean);

            sayWhatTheyMean();

            for (const button of content.querySelectorAll<HTMLElement>('[data-answer]'))
                button.addEventListener('click', () => void answer(button.dataset['answer'] ?? ''));

            for (const button of content.querySelectorAll<HTMLElement>('[data-remove-request]'))
                button.addEventListener('click', () => void throwAway(button.dataset['removeRequest'] ?? ''));

        }


        async function doImport(form: HTMLFormElement): Promise<void> {

            const note   = must<HTMLElement>(content, '#import-note');
            const error  = must<HTMLElement>(content, '#import-error');

            note.textContent   = '';
            error.textContent  = '';

            const chosen = must<HTMLInputElement>(content, '#import-file').files?.[0];

            if (chosen === undefined) {
                error.textContent = 'Choose a file first.';
                return;
            }

            if (chosen.size > largestImport) {
                error.textContent = `That file is ${Math.round(chosen.size / 1024)} kB, and a certificate is a few. ` +
                                    'This is almost certainly not the file you meant.';
                return;
            }

            const data      = new FormData(form);
            const kind      = data.get('kind') as CertificateKind;
            const password  = String(data.get('password') ?? '');
            const label     = String(data.get('label')    ?? '').trim();
            const usages    = hasUsages(current!, kind) ? data.getAll('usage').map(String) : [];

            busy = true;

            let imported: Certificate;

            try
            {
                imported = await whileSaving(content, note, async () => api.certificates.import({
                                     kind,
                                     content:   await base64Of(chosen),
                                     password:  password.length > 0 ? password : undefined,
                                     label:     label.length    > 0 ? label    : undefined,
                                     // Left out for every use; the meter
                                     // refuses a certificate for no use.
                                     usages:    usages.length   > 0 ? usages   : undefined
                                 }));
            }
            catch (problem)
            {
                busy = false;
                error.textContent = errorMessage(problem);
                return;
            }

            busy = false;

            await load();

            sayAfterwards('#import-note', `Imported ${imported.label}, and switched on.`);

        }


        async function toggle(id: string): Promise<void> {

            const entry = everything().find(one => one.id === id);

            if (entry === undefined)
                return;

            await change(() => api.certificates.update(id, { active: !entry.active }));

        }


        async function rename(id: string): Promise<void> {

            const entry = everything().find(one => one.id === id);

            if (entry === undefined)
                return;

            // The label is one of the things about a stored certificate that
            // are somebody's to decide; everything else on the row is read out
            // of the file and is not up for editing.
            const given = prompt('What should this certificate be called?\n\n' +
                                 'Leave it empty for its own common name.', entry.label);

            if (given === null)
                return;

            await change(() => api.certificates.update(id, { label: given.trim().length > 0 ? given.trim() : null }));

        }


        /**
         * Say again what a certificate is for, in a dialog: the servers a TLS
         * root or a server certificate is kept for, the listeners an identity
         * may be shown on.
         *
         * A dialog with a Save rather than boxes in the row that save on every
         * click: each change is a line in the log book, and taking the last
         * tick away on the way to another one would have made the certificate
         * one for every use in between.
         */
        function editUsages(id: string): void {

            const entry = everything().find(one => one.id === id);

            if (entry === undefined)
                return;

            const about   = aboutKind[entry.kind];
            const dialog  = document.createElement('dialog');

            dialog.className = 'server-dialog';

            document.body.appendChild(dialog);

            // Shut it and take it away, as the NTS page's dialogs do: one that
            // is only closed stays in the document.
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            render(dialog, html`

                <h2><i class="fa-solid ${about?.icon ?? 'fa-certificate'}"></i> ${entry.label}</h2>

                <form id="usages-form" class="form-stack">

                    <fieldset class="usages">
                        ${usagesFields(entry.kind, entry.usages)}
                    </fieldset>

                    ${about?.uses ? html`<p class="hint">${about.uses}</p>` : ''}

                    <div class="form-actions">
                        <button type="submit" class="btn primary">Save</button>
                        <button type="button" class="btn" id="usages-cancel">Cancel</button>
                        <span id="usages-error" class="form-error" role="alert"></span>
                    </div>

                </form>

            `);

            const form = must<HTMLFormElement>(dialog, '#usages-form');

            form.addEventListener('submit', event => {

                event.preventDefault();

                const ticked = new FormData(form).getAll('usage').map(String);

                void (async () => {

                    try
                    {
                        // None ticked is every use again, which the meter is
                        // told as null: a list with nothing in it would be a
                        // certificate for no use, and is refused.
                        await whileSaving(dialog, null, () => api.certificates.update(id, { usages: ticked.length > 0 ? ticked : null }));
                    }
                    catch (problem)
                    {
                        must<HTMLElement>(dialog, '#usages-error').textContent = errorMessage(problem);
                        return;
                    }

                    dismiss();

                    // The store again rather than the one certificate the
                    // answer carries, as after every other change on this page.
                    await load();

                })();

            });

            must<HTMLButtonElement>(dialog, '#usages-cancel').addEventListener('click', dismiss);

            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            dialog.showModal();

        }


        async function remove(id: string): Promise<void> {

            const entry = everything().find(one => one.id === id);

            if (entry === undefined)
                return;

            // The file goes with it, and there is no copy anywhere else. Asked
            // once, naming what is about to go.
            if (!confirm(`Delete ${entry.label}?\n\nIts file is deleted from the store as well, and ` +
                         `a certificate with a private key cannot be put back without that key.`))
                return;

            await change(() => api.certificates.remove(id));

        }


        /**
         * Make a key and a request, and hand the request over at once: it is
         * the whole point of having pressed the button, so it is offered
         * rather than left to be found in the list.
         */
        async function ask(form: HTMLFormElement): Promise<void> {

            const note   = must<HTMLElement>(content, '#request-note');
            const error  = must<HTMLElement>(content, '#request-error');

            note.textContent   = '';
            error.textContent  = '';

            const remark = field(form, 'note');

            const request: NewSigningRequest = {
                listener:     field(form, 'listener') as TLSListener,
                subject:      field(form, 'subject'),
                dnsNames:     list(field(form, 'dnsNames')),
                ipAddresses:  list(field(form, 'ipAddresses')),
                keyType:      field(form, 'keyType'),
                note:         remark.length > 0 ? remark : undefined
            };

            busy = true;

            let made: SigningRequest;

            try
            {
                made = await whileSaving(content, note, () => api.certificates.createRequest(request));
            }
            catch (problem)
            {
                busy = false;
                error.textContent = errorMessage(problem);
                return;
            }

            busy = false;

            await load();

            sayAfterwards('#request-note', 'Made. The request is on its way to your downloads.');

            window.location.href = api.certificates.requestURL(made.id);

        }


        /**
         * Put in the certificate a CA signed for a request - checked by the
         * meter against the key that asked, and from then on an identity of
         * the listener it was asked for. A second one for the same request is
         * a renewal: another identity with the same key, which takes over when
         * it becomes valid.
         */
        async function answer(id: string): Promise<void> {

            const error  = must<HTMLElement>(content, `[data-answer-error="${id}"]`);
            const pem    = must<HTMLTextAreaElement>(content, `[data-pem="${id}"]`).value;

            error.textContent = '';

            if (pem.trim().length === 0) {
                error.textContent = 'Paste the signed certificate first.';
                return;
            }

            busy = true;

            let answered: AnsweredRequest;

            try
            {
                answered = await whileSaving(content, null, () => api.certificates.answerRequest(id, pem));
            }
            catch (problem)
            {
                busy = false;
                error.textContent = errorMessage(problem);
                return;
            }

            busy = false;

            await load();

            sayAfterwards(`[data-answer-note="${id}"]`, `Put in as ${answered.certificate.label}.`);

        }


        async function throwAway(id: string): Promise<void> {

            if (!confirm('Throw this request away, and its key with it?\n\nWhat was put into the store from it ' +
                         'stays there, but can no longer be renewed with the same key. That cannot be undone.'))
                return;

            await change(() => api.certificates.removeRequest(id));

        }


        /** Everything in the store, flattened - for finding one by its handle. */
        function everything(): Certificate[] {
            return Object.values(current?.certificates ?? {}).flat();
        }


        /**
         * One change, with the page held still while the meter is told, and
         * everything read again once it took it: a change to one certificate
         * can change what a listener shows, and what a request was answered
         * with.
         *
         * What the meter refuses - taking away the last certificate a listener
         * could show, or the last CA clients may be issued by - is said where
         * it cannot be missed, as on the meter's other pages.
         */
        async function change(doing: () => Promise<unknown>): Promise<void> {

            busy = true;

            try
            {
                await whileSaving(content, null, doing);
            }
            catch (problem)
            {
                busy = false;
                alert(errorMessage(problem));
                return;
            }

            busy = false;

            await load();

        }


        async function rescan(): Promise<void> {

            const note   = must<HTMLElement>(content, '#store-note');
            const error  = must<HTMLElement>(content, '#store-error');

            note.textContent   = '';
            error.textContent  = '';

            busy = true;

            try
            {
                await whileSaving(content, note, () => api.certificates.reload());
            }
            catch (problem)
            {
                busy = false;
                error.textContent = errorMessage(problem);
                return;
            }

            busy = false;

            await load();

            sayAfterwards('#store-note', `The directory was read again: ${everything().length} certificate(s).`);

        }


        /**
         * Say something once the page has been drawn again - which is why it
         * is looked for again, and why it is not said at all where the page
         * could not be loaded.
         */
        function sayAfterwards(selector: string, text: string): void {

            const where = content.querySelector<HTMLElement>(selector);

            if (where !== null)
                where.textContent = text;

        }


        async function load(): Promise<void> {

            try
            {

                // The roles with the store, although they are not in it: they
                // belong beside the client roots, and there is no page of the
                // client CAs any more to read them on.
                const [store, asked, configuration] = await Promise.all([
                                                          api.certificates.get(),
                                                          api.certificates.requests(),
                                                          api.certificates.configuration()
                                                      ]);

                if (cancelled)
                    return;

                current   = store;
                requests  = asked;
                roles     = configuration.sunSpecRoles;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`
                        <div class="error-box">The certificate store could not be loaded: ${errorMessage(problem)}</div>
                    `);
            }

        }

        // A file chosen to import and a request filled in are in their forms
        // alone until they are sent. What a certificate is for is chosen in
        // a modal dialog, which is not under content: while it is open,
        // neither Reload nor the menu can be reached, and it is closed only
        // by saving or by cancelling it.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        void load();

        return () => { cancelled = true; release(); };

    }

};


/** When the one that is next on a listener takes over, after its name - or nothing, where that is not known. */
function from(nextAt: string | null | undefined): string {
    return nextAt ? `, from ${new Date(nextAt).toLocaleString()}` : '';
}


/** A comma-separated field as the list it stands for. */
function list(text: string): string[] {
    return text.split(',').map(part => part.trim()).filter(part => part.length > 0);
}


/**
 * One file's bytes, base64-encoded.
 *
 * Through a data: URL rather than by walking the bytes, because the browser's
 * own encoder is the one that will not get a 3-megabyte string wrong. The
 * prefix up to the comma is the media type the reader chose and is dropped.
 */
function base64Of(file: File): Promise<string> {

    return new Promise((resolve, reject) => {

        const reader = new FileReader();

        reader.onerror = () => reject(new Error(`'${file.name}' could not be read.`));

        reader.onload  = () => {

            const asURL = String(reader.result ?? '');
            const comma = asURL.indexOf(',');

            if (comma < 0) {
                reject(new Error(`'${file.name}' could not be read.`));
                return;
            }

            resolve(asURL.slice(comma + 1));

        };

        reader.readAsDataURL(file);

    });

}
