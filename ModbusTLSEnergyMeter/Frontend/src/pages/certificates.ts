import { api, type AnsweredRequest, type Certificate, type CertificateKind, type CertificateStore, type NewSigningRequest, type SigningRequest, type SigningRequests, type TLSListener } from '../api/client';
import { auth } from '../auth';
import { usageName } from '@node/pages/certificateUsages';
import { certificatesPage as theNodesCertificatesPage, type CertificatesSection, type KindWords, type SectionContext } from '@node/pages/certificates';
import type { Page } from '@node/router';
import { errorMessage, field, whileSaving } from '@node/ui';
import { html, nothing, repeat, type TemplateResult } from '@node/view';


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


/**
 * What each kind is called on this page, the icon of its card, what its card
 * says under its name, and what the dialog that says what one is for adds.
 *
 * The store describes every kind itself, in words written for every node;
 * these are this meter's. A kind the store keeps and this page does not know
 * is shown under the store's own description. What a TLS root and a server
 * certificate are kept for is said as every node says it: the servers a
 * dialog of the NTS and the DNS page offers them to.
 */
const aboutKind: Record<CertificateKind, KindWords> = {

    tlsRoot: {
        title:  'TLS roots',
        icon:   'fa-shield-halved',
        hint:   html`What the chain of a time server or a name server this meter asks over TLS may end at, beside
                     the roots the machine itself knows - each told which of them it vouches for.`
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
        icon:   'fa-server'
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
 * recognises - the node's certificate store, on the node's page - and the
 * keys made here, with the requests a CA is sent for them.
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
 * Certificates arrive three ways, and all of them are first class. "Import"
 * uploads a file and copies it in; "Re-read the directory" picks up whatever
 * somebody put there by hand; and a signing request makes the key here, where
 * it stays, and turns the certificate a CA sends back into an identity. Every
 * way, the store ends up the same, because the store is the directory.
 *
 * The page is every node's (WWCP_Node's pages/certificates.ts); what is the
 * meter's is said here: its words for the kinds and the groups, what a
 * listener with nothing to show means, where an identity is shown now and
 * where next, the SunSpec roles below the client roots, and the signing
 * requests below the identities. This was three pages while the meter kept
 * three stores of its own, and then a page of its own of 1258 lines.
 */
export const certificatesPage: Page = theNodesCertificatesPage<CertificateStore>({

    title:         'Certificates',
    subtitle:      'The roots this meter believes, the certificates it presents, and the servers it recognises.',
    expiringSoon,
    usageNames:    listenerNames,
    kinds:         aboutKind,

    hints: {

        believes:     html`Trust anchors. Every one of a kind that is switched on is believed at once, and they are
                           asked for at every handshake: switching one on or off takes effect with the next
                           connection, and connections already open are not touched.`,

        presents:     store => html`
                          TLS identities, each with its private key: what the Modbus/TLS listener shows a charging
                          station or a controller, and what the web interface shows a browser. Each is told which of
                          the two it is for, and one never told is for both. Of those a listener may show that are
                          switched on and valid, it shows the one whose validity began last, and asks again at every
                          handshake - so one put in before the old one runs out takes over the moment it becomes
                          valid, with nothing to press and nothing restarted.
                          ${store.shown.web?.used === false ? html`
                              The web interface is served over plain HTTP at the moment, so it shows none of them, and
                              what is kept for it is kept for when it is served over HTTPS.
                          ` : nothing}
                      `,

        unencrypted:  html`can pose as this meter - to a charging station as much as to a browser.`,

        importing:    html`A certificate for a key this meter made goes in under Signing requests, where its key is.`

    },

    // A listener that runs and has nothing to show turns everybody away,
    // which is the first thing this page has to say.
    notices: store => store.listeners.
                          filter(listener => store.shown[listener]?.used === true && store.shown[listener]?.current === null).
                          map   (listener => html`
                              ${aboutListener[listener]?.nothing ?? `The ${listener} listener has no certificate it could show.`}
                              ${auth.can('certificates', 'edit') ? 'Put in a TLS identity for it, or ask for one below.' : nothing}
                          `),

    // Where an identity is shown, and where it takes over next and when - the
    // store says it per listener, and the identity is what it is said about.
    rowChips: (entry, store) => [
        ...((entry as Certificate).shownOn ?? []).map(listener => html`<span class="chip ok">shown on ${onListener(listener)}</span>`),
        ...store.listeners.filter(listener => store.shown[listener]?.next === entry.id).
                           map   (listener => html`<span class="chip">next on ${onListener(listener)}${from(store.shown[listener]?.nextAt)}</span>`)
    ],

    sections: context => [ rolesSection(), requestsSection(context) ]

});


/**
 * What a client may do once it is let in - which is not decided on this page
 * at all, but beside the client roots it is the other half of what they are
 * about. Below them, at the end of what the meter believes.
 */
function rolesSection(): CertificatesSection<CertificateStore> {

    let roles: string[] = [];

    return {

        below:  'believes',

        load:   async () => { roles = (await api.certificates.configuration()).sunSpecRoles; },

        draw:   () => html`
            <section class="card section-card" id="sunspec-roles">

                <h3><i class="fa-solid fa-user-shield"></i> SunSpec roles</h3>

                <p class="muted small">
                    Being let in is not being allowed to do anything. What a client may do once its certificate has
                    chained to one of the client roots above is decided by the SunSpec role inside that certificate,
                    and not by anything on this page.
                </p>

                <div class="table-scroll">
                    <table class="kv">
                        ${roles.map(role => html`<tr><td colspan="2"><code>${role}</code></td></tr>`)}
                    </table>
                </div>

            </section>
        `

    };

}


/**
 * The keys made in this meter, and the requests a CA is sent for them - below
 * the identities, which is what an answered one becomes.
 */
function requestsSection(context: SectionContext<CertificateStore>): CertificatesSection<CertificateStore> {

    let requests: SigningRequests | null = null;

    // The listener and the key chosen for a request, once others than the
    // ones it is drawn with are: what the notes under them say.
    let listenerChosen: string | undefined;
    let keyTypeChosen:  string | undefined;

    const mayChange = context.mayChange;


    /** One signing request: what it asks for, whether it was answered, and what can be done with it. */
    function requestView(request: SigningRequest): TemplateResult {

        const answered = request.state === 'answered';

        // The certificate pasted for a request is a form of its own, known by
        // the request it answers - a draft like the others, which Reload and
        // the menu ask about before they throw it away, and which the page
        // keeps when it is drawn anew for something done elsewhere on it.
        return html`
            <section class="card section-card signing-request">

                <h3>
                    <i class="fa-solid ${aboutListener[request.listener]?.icon ?? 'fa-file-signature'}"></i>
                    ${request.subject}
                    <span class="chip ${answered ? 'ok' : 'warn'}">${request.state}</span>
                </h3>

                <div class="table-scroll">
                    <table class="kv">
                        <tr><td>For</td><td>${onListener(request.listener)}</td></tr>
                        ${request.dnsNames.length    > 0 ? html`<tr><td>DNS names</td><td>${request.dnsNames.join(', ')}</td></tr>` : nothing}
                        ${request.ipAddresses.length > 0 ? html`<tr><td>IP addresses</td><td>${request.ipAddresses.join(', ')}</td></tr>` : nothing}
                        <tr><td>Key</td><td>${nameOf(request.keyType)}</td></tr>
                        <tr><td>Asked on</td><td>${new Date(request.createdAt).toLocaleString()}</td></tr>
                        ${request.note ? html`<tr><td>Note</td><td>${request.note}</td></tr>` : nothing}
                        ${answered ? html`<tr><td>Put in as</td><td>${request.answeredBy.map(labelOf).join(', ')}</td></tr>` : nothing}
                    </table>
                </div>

                <div class="form-actions">
                    <a class="btn small" href="${api.certificates.requestURL(request.id)}" download>Download the request</a>
                    ${mayChange
                          ? html`<button type="button" class="btn small danger" data-remove-request="${request.id}"
                                         @click=${() => void throwAway(request.id)}>Throw away</button>`
                          : nothing}
                </div>

                ${mayChange ? html`
                    <form class="upload" data-id="${request.id}" @submit=${(event: SubmitEvent) => { event.preventDefault(); void answer(request.id); }}>
                        <label>The signed certificate, PEM encoded, with the intermediates above it
                            <textarea class="mono" rows="6" name="pem" data-pem="${request.id}"
                                      placeholder="-----BEGIN CERTIFICATE-----"></textarea>
                        </label>
                        <div class="form-actions">
                            <button type="button" class="btn primary" data-answer="${request.id}"
                                    @click=${() => void answer(request.id)}>
                                ${answered ? 'Renew with the same key' : 'Put the certificate in'}
                            </button>
                            <span class="form-notice" data-answer-note="${request.id}"  role="status"></span>
                            <span class="form-error"  data-answer-error="${request.id}" role="alert"></span>
                        </div>
                    </form>
                ` : nothing}

            </section>
        `;

    }


    /** The card that makes a key here, and the request a CA is sent for it. */
    function requestCard(asked: SigningRequests): TemplateResult {

        // Drawn as the listener chosen, as the import draws its kind, and for
        // the same reason: an untouched form is one.
        const first = asked.listeners[0];

        return html`
            <section class="card section-card">

                <h3><i class="fa-solid fa-file-signature"></i> Ask for a new certificate</h3>

                <form id="request-form" class="form-stack" @submit=${(event: SubmitEvent) => { event.preventDefault(); void ask(event.currentTarget as HTMLFormElement); }}>

                    <label>Which listener it is for
                        <select name="listener" id="request-listener"
                                @change=${(event: Event) => { listenerChosen = (event.target as HTMLSelectElement).value; context.draw(); }}>
                            ${asked.listeners.map(listener => html`
                                <option value="${listener}" ?selected=${listener === first}>${usageName(listener, listenerNames)}</option>
                            `)}
                        </select>
                    </label>

                    <p class="hint" id="request-listener-note">${aboutListener[listenerChosen ?? first ?? '']?.checkedBy ?? ''}</p>

                    <label>Subject
                        <input type="text" name="subject" required placeholder="CN=meter7.lan, O=Acme" />
                    </label>

                    <label>DNS names, separated by commas
                        <input type="text" name="dnsNames" placeholder="meter7.lan, meter7" />
                    </label>

                    <label>IP addresses, separated by commas
                        <input type="text" name="ipAddresses" placeholder="192.168.7.20" />
                    </label>

                    <label>Key
                        <select name="keyType" id="request-key-type"
                                @change=${(event: Event) => { keyTypeChosen = (event.target as HTMLSelectElement).value; context.draw(); }}>
                            ${asked.keyTypes.map(keyType => html`
                                <option value="${keyType.id}" ?selected=${keyType.id === asked.defaultKeyType}>
                                    ${keyType.name}
                                </option>
                            `)}
                        </select>
                    </label>

                    <p class="hint" id="request-key-type-note">${remarkOf(keyTypeChosen ?? asked.defaultKeyType)}</p>

                    <label>Note
                        <input type="text" name="note" placeholder="what this is for" />
                    </label>

                    <div class="form-actions">
                        <button type="submit" class="btn primary">Make a key and a request</button>
                        <span id="request-note"  class="form-notice" role="status"></span>
                        <span id="request-error" class="form-error"  role="alert"></span>
                    </div>

                    <span class="hint">
                        The key is made here and stays here. What you get is the request to hand to whoever signs
                        it; bring the certificate back to this page, to the request it answers.
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
        return Object.values(context.store().certificates).flat().find(one => one.id === id)?.label ?? id;
    }


    /**
     * Make a key and a request, and hand the request over at once: it is the
     * whole point of having pressed the button, so it is offered rather than
     * left to be found in the list.
     */
    async function ask(form: HTMLFormElement): Promise<void> {

        const page   = context.page;
        const note   = page.querySelector<HTMLElement>('#request-note')!;
        const error  = page.querySelector<HTMLElement>('#request-error')!;

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

        let made: SigningRequest;

        try
        {
            made = await whileSaving(page, note, () => api.certificates.createRequest(request));
        }
        catch (problem)
        {
            error.textContent = errorMessage(problem);
            return;
        }

        // Asked: the form goes back to what it starts with.
        listenerChosen = undefined;
        keyTypeChosen  = undefined;

        await context.reload();

        form.reset();

        sayAfterwards('#request-note', 'Made. The request is on its way to your downloads.');

        window.location.href = api.certificates.requestURL(made.id);

    }


    /**
     * Put in the certificate a CA signed for a request - checked by the meter
     * against the key that asked, and from then on an identity of the listener
     * it was asked for. A second one for the same request is a renewal:
     * another identity with the same key, which takes over when it becomes
     * valid.
     */
    async function answer(id: string): Promise<void> {

        const page   = context.page;
        const error  = page.querySelector<HTMLElement>(`[data-answer-error="${id}"]`)!;
        const area   = page.querySelector<HTMLTextAreaElement>(`[data-pem="${id}"]`)!;
        const pem    = area.value;

        error.textContent = '';

        if (pem.trim().length === 0) {
            error.textContent = 'Paste the signed certificate first.';
            return;
        }

        let answered: AnsweredRequest;

        try
        {
            answered = await whileSaving(page, null, () => api.certificates.answerRequest(id, pem));
        }
        catch (problem)
        {
            error.textContent = errorMessage(problem);
            return;
        }

        await context.reload();

        // Put in: this request's form is emptied, and every other one keeps
        // what is pasted into it.
        area.closest('form')?.reset();

        sayAfterwards(`[data-answer-note="${id}"]`, `Put in as ${answered.certificate.label}.`);

    }


    /** Throw a request away, and its key with it - a refusal said on its own card. */
    async function throwAway(id: string): Promise<void> {

        if (!confirm('Throw this request away, and its key with it?\n\nWhat was put into the store from it ' +
                     'stays there, but can no longer be renewed with the same key. That cannot be undone.'))
            return;

        const error = context.page.querySelector<HTMLElement>(`[data-answer-error="${id}"]`);

        if (error !== null)
            error.textContent = '';

        try
        {
            await whileSaving(context.page, null, () => api.certificates.removeRequest(id));
        }
        catch (problem)
        {
            if (error !== null) {
                error.textContent = errorMessage(problem);
                error.scrollIntoView({ block: 'nearest' });
            }
            return;
        }

        await context.reload();

    }


    /**
     * Say something once the page has been drawn again - which is why it is
     * looked for again, and why it is not said at all where the page could
     * not be loaded.
     */
    function sayAfterwards(selector: string, text: string): void {

        const where = context.page.querySelector<HTMLElement>(selector);

        if (where !== null)
            where.textContent = text;

    }


    return {

        below:  'presents',

        load:   async () => { requests = await api.certificates.requests(); },

        // Reload: the notes under the selects go back with the forms.
        reset:  () => { listenerChosen = undefined; keyTypeChosen = undefined; },

        draw:   () => html`

            <h2>Signing requests</h2>
            <p class="hint">
                A key made in this meter, and the request a CA is sent for it. The key never leaves the meter: what
                goes out is the request, and what comes back is a certificate, checked against the key that asked
                for it before it becomes an identity of the listener it was asked for. A request is kept once it is
                answered, with its key, so that a certificate that runs out can be renewed by sending the same
                request again.
            </p>

            ${requests === null || requests.requests.length === 0
                  ? html`<p class="muted small">None.</p>`
                  : repeat(requests.requests, request => request.id, requestView)}

            ${mayChange && requests !== null ? requestCard(requests) : nothing}

        `

    };

}


/** When the one that is next on a listener takes over, after its name - or nothing, where that is not known. */
function from(nextAt: string | null | undefined): string {
    return nextAt ? `, from ${new Date(nextAt).toLocaleString()}` : '';
}


/** A comma-separated field as the list it stands for. */
function list(text: string): string[] {
    return text.split(',').map(part => part.trim()).filter(part => part.length > 0);
}
