import { api, type Certificate, type CertificateKind, type CertificateStore } from '../api/client';
import { auth } from '../auth';
import { usageName } from '@node/pages/certificateUsages';
import { certificatesPage as theNodesCertificatesPage, serverIdentitiesPage as theNodesServerIdentitiesPage,
         type CertificatesOptions, type CertificatesSection, type KindWords } from '@node/pages/certificates';
import type { Page } from '@node/router';
import { html, nothing } from '@node/view';


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

    tlsServerIdentity: {
        title:  'TLS server identities',
        icon:   'fa-id-card',
        uses:   html`A listener only ever shows an identity that is for it. Taking the last one a listener could
                     show away from it is refused - put another one in first.`
    },

    tlsServer: {
        title:  'Server certificates',
        icon:   'fa-server'
    },

    tlsIdentity: {
        title:  'TLS identities',
        icon:   'fa-user-shield',
        hint:   html`Whom this meter is to the meter in front of which it stands, over Modbus/TLS - a certificate with
                     its private key, carrying a SunSpec role, by which that meter decides what this one may do. See
                     the Upstream page.`
    }

};


/**
 * What it means that a listener has nothing to show - said at the top of the
 * page, where a listener has none.
 */
const withNothingToShow: Record<string, string> = {

    modbus:  'The Modbus/TLS listener has no certificate it could show, so every charging station and ' +
             'controller that connects is turned away at the handshake.',

    web:     'The web interface has no certificate it could show, so every browser that connects anew is ' +
             'turned away at the handshake.'

};


/**
 * Everything this meter believes, everything it presents, and the servers it
 * recognises - the node's certificate store, on the node's pages - and the
 * keys made here, which wait in it for their certificate.
 *
 * Two pages since WWCP_Node told certificates from identities: Certificates
 * keeps what is believed and recognised, without a private key - the roots,
 * with the SunSpec roles below the client roots, and the servers recognised;
 * Server identities keeps who the meter's own servers are, each with its
 * private key - the identities its listeners show, and on its "New key" tab
 * the keys made for them. The meter has no client identity, so no Identities
 * page.
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
 * somebody put there by hand; and "New key" makes the key here, where it
 * stays, with a signing request - the store's, which the meter has it make for
 * its listeners - and the certificate a CA sends back for it becomes an
 * identity of the listener it was asked for. Every way, the store ends up the
 * same, because the store is the directory.
 *
 * The page is every node's (WWCP_Node's pages/certificates.ts); what is the
 * meter's is said here: its words for the kinds and the groups, what a
 * listener with nothing to show means, where an identity is shown now and
 * where next, and the SunSpec roles below the client roots. This was three
 * pages while the meter kept three stores of its own, and then a page of its
 * own of 1258 lines; its signing requests were its own until the store made
 * keys.
 */
const options: CertificatesOptions<CertificateStore> = {

    title:         'Certificates',
    subtitle:      'The roots this meter believes and the servers it recognises - certificates alone, never with a private key.',
    expiringSoon,
    usageNames:    listenerNames,
    kinds:         aboutKind,

    hints: {

        believes:     html`Trust anchors. Every one of a kind that is switched on is believed at once, and they are
                           asked for at every handshake: switching one on or off takes effect with the next
                           connection, and connections already open are not touched.`,

        serves:       store => html`
                          TLS server identities, each with its private key: what the Modbus/TLS listener shows a charging
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

        importing:    html`A certificate that comes back for a key this meter made is put in as it came, without a key: it finds the key that waits for it.`

    },

    // A listener that runs and has nothing to show turns everybody away,
    // which is the first thing this page has to say.
    notices: store => store.listeners.
                          filter(listener => store.shown[listener]?.used === true && store.shown[listener]?.current === null).
                          map   (listener => html`
                              ${withNothingToShow[listener] ?? `The ${listener} listener has no certificate it could show.`}
                              ${auth.can('certificates', 'edit') ? 'Put in a TLS server identity for it under Server identities, or make a key for one there.' : nothing}
                          `),

    // Where an identity is shown, and where it takes over next and when - the
    // store says it per listener, and the identity is what it is said about.
    rowChips: (entry, store) => [
        ...((entry as Certificate).shownOn ?? []).map(listener => html`<span class="chip ok">shown on ${onListener(listener)}</span>`),
        ...store.listeners.filter(listener => store.shown[listener]?.next === entry.id).
                           map   (listener => html`<span class="chip">next on ${onListener(listener)}${from(store.shown[listener]?.nextAt)}</span>`)
    ],

    sections: () => [ rolesSection() ]

};

/** What the meter believes and recognises: the roots, the SunSpec roles below the client roots, the servers recognised. */
export const certificatesPage: Page = theNodesCertificatesPage<CertificateStore>(options);

/** Who the meter's own servers are: the identities its listeners show, the signing requests below them. */
export const serverIdentitiesPage: Page = theNodesServerIdentitiesPage<CertificateStore>(options);


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


/** When the one that is next on a listener takes over, after its name - or nothing, where that is not known. */
function from(nextAt: string | null | undefined): string {
    return nextAt ? `, from ${new Date(nextAt).toLocaleString()}` : '';
}

