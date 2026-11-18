// The certificate pages - the node's, with the meter's words and sections:
// Certificates the roots, the roles and the servers recognised, Server
// identities the identities the listeners show and the keys made for them -
// drawn against a stand-in meter: every certificate keeps its row; the upload
// offers every kind ticked its own uses, the listeners by their names, each
// kind on its own page; the store's "New key" tab makes the keys of the
// identities, told their listeners, on Server identities and nowhere else, and
// the keys that wait are among what the meter presents; the roles stand below
// the client roots; a listener with nothing to show is said at the top; where
// an identity is shown and where next is said in its row.
//
// The form a key is made with, and what is done with a key that waits, are
// the node's (certificateRequests.ts) and tested there.

import { asked, open, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { Certificate, CertificateKind, CertificateStore } from '../api/client.ts';
import type { SigningRequest } from '@node/api/client';

const { certificatesPage, serverIdentitiesPage } = await import('./certificates.ts');


function anIdentity(id: string, label: string, active = true): Certificate {
    return {
        id, label, active,
        kind:           'tlsServerIdentity',
        fileName:       `${id}.pem`,
        subject:        `CN=${label}`,
        issuer:         'CN=Device CA',
        serialNumber:   '01',
        thumbprint:     `${id}-thumbprint`,
        notBefore:      '2026-01-01T00:00:00Z',
        notAfter:       '2027-01-01T00:00:00Z',
        keyAlgorithm:   'ECDSA P-256',
        hasPrivateKey:  true,
        chainLength:    0,
        importedAt:     '2026-01-01T00:00:00Z',
        expired:        false,
        notYetValid:    false,
        usable:         active,
        description:    'A TLS identity',
        usages:         [ 'modbus' ],
        shownOn:        id === 'aaaa' ? [ 'modbus' ] : []
    } as unknown as Certificate;
}

/** A key made in the meter for one of its listeners, waiting for its certificate - as the node's store says it. */
function aKey(id: string, subject: string): SigningRequest {
    return { id, subject, kind: 'tlsServerIdentity', algorithm: 'ecdsa-p256', algorithmName: 'ECDSA P-256', createdAt: '2026-10-01T00:00:00Z',
             label: null, usages: [ 'modbus' ], template: 'tls-server', templateName: 'TLS server', role: null,
             keyUsages: [ 'digitalSignature' ], extendedKeyUsages: [ 'serverAuth' ], reachableAs: [ subject.replace(/^CN=/, '') ],
             csr: `-----BEGIN CERTIFICATE REQUEST-----\n${id}\n-----END CERTIFICATE REQUEST-----` } as SigningRequest;
}

/** How the stand-in's listeners stand: Modbus/TLS showing aaaa with nothing next, the web interface not served over HTTPS. */
interface Listeners {
    modbus?:  { used: boolean; current: string | null; next: string | null; nextAt: string | null };
    web?:     { used: boolean; current: string | null; next: string | null; nextAt: string | null };
}

/** A meter with two identities and two keys waiting for their certificates, that takes what is asked. */
function aMeter(listeners: Listeners = {}): (one: Asked) => unknown {

    let identities  = [ anIdentity('aaaa', 'meter-a'), anIdentity('bbbb', 'meter-b') ];
    const waiting   = [ aKey('r1', 'CN=meter7.lan'), aKey('r2', 'CN=meter8.lan') ];

    const store = (): CertificateStore => ({
        directory:           '/var/lib/meter/certificates',
        trustAnchors:        [ 'tlsRoot', 'clientRoot' ],
        credentials:         [ 'tlsServerIdentity' ],
        recognised:          [ 'tlsServer' ],
        kinds: {
            tlsRoot:            { description: 'A TLS root',             group: 'trustAnchor', page: 'certificates',       trustAnchor: true,  needsPrivateKey: false, hasUsages: true, usages: [ 'dns', 'nts' ] },
            clientRoot:         { description: 'A client root',          group: 'trustAnchor', page: 'certificates',       trustAnchor: true,  needsPrivateKey: false, hasUsages: true, usages: [] },
            tlsServer:          { description: 'A server certificate',   group: 'recognised',  page: 'certificates',       trustAnchor: false, needsPrivateKey: false, hasUsages: true, usages: [ 'dns', 'nts' ] },
            tlsServerIdentity:  { description: 'A TLS server identity',  group: 'credential',  page: 'serverIdentities',   trustAnchor: false, needsPrivateKey: true,  hasUsages: true, usages: [ 'modbus', 'web' ] }
        } as Record<CertificateKind, never>,
        usages:              [ 'dns', 'nts' ],
        certificates:        { tlsRoot: [], clientRoot: [], tlsServer: [], tlsIdentity: [], tlsServerIdentity: identities } as Record<CertificateKind, Certificate[]>,
        keysAreUnencrypted:  false,
        listeners:           [ 'modbus', 'web' ],
        shown: {
            modbus:  listeners.modbus ?? { used: true,  current: 'aaaa', next: null, nextAt: null },
            web:     listeners.web    ?? { used: false, current: null,   next: null, nextAt: null }
        },
        // The keys the store makes for the meter: its identities alone.
        requests: {
            directory:          '/var/lib/meter/certificates/requests',
            kinds:              [ 'tlsServerIdentity' ],
            entries:            waiting,
            algorithms:         [ { id: 'ecdsa-p256', name: 'ECDSA P-256', remark: 'What every peer reads.' },
                                  { id: 'rsa-3072',   name: 'RSA 3072',    remark: 'Slower, and as good.' } ],
            defaultAlgorithm:   'ecdsa-p256',
            maxSubjectLength:   200,
            templates:          [ { id: 'tls-server', name: 'TLS server', remark: 'For the names it is reachable as.', purpose: 'serverAuth', asksForNames: true,
                                    page: 'serverIdentities', keyUsages: [], extendedKeyUsages: [] } ],
            keyUsages:          [],
            extendedKeyUsages:  [ { id: 'serverAuth', name: 'TLS server authentication', remark: '', oid: '1.3.6.1.5.5.7.3.1' } ]
        }
    } as unknown as CertificateStore);

    return ({ method, path, body }) => {

        if (method === 'GET' && path === '/certificates')
            return store();

        if (method === 'GET' && path === '/configuration/certificates')
            return { sunSpecRoles: [ 'ReadOnlySunSpec', 'SuperAdministratorSunSpec' ] };

        if (method === 'PATCH' && path.startsWith('/certificates/')) {
            const id = decodeURIComponent(path.split('/')[2] ?? '');
            const { active } = body as { active?: boolean };
            identities = identities.map(one => one.id === id && active !== undefined ? anIdentity(one.id, one.label, active) : one);
            return identities.find(one => one.id === id);
        }

        if (method === 'DELETE' && path.startsWith('/certificates/') && !path.startsWith('/certificates/requests/')) {
            const id = decodeURIComponent(path.split('/')[2] ?? '');
            identities = identities.filter(one => one.id !== id);
            return store();
        }

        return undefined;

    };

}

const drawn       = (root: HTMLElement) => root.querySelector('table.records') !== null;
const drawnRoots  = (root: HTMLElement) => root.querySelector('#sunspec-roles') !== null;


test('a certificate keeps its row while another one is switched off, or the one before it deleted', async () => {

    const root  = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const row   = root.querySelector('[data-toggle="bbbb:tlsServerIdentity"]')!.closest('tr');

    root.querySelector<HTMLButtonElement>('[data-toggle="aaaa:tlsServerIdentity"]')!.click();

    await until(() => root.querySelector('[data-toggle="aaaa:tlsServerIdentity"]')!.textContent!.trim() === 'Switch on', 'the row did not say it was switched off');

    assert.ok(root.querySelector('[data-toggle="bbbb:tlsServerIdentity"]')!.closest('tr') === row, 'the row of the other certificate was drawn anew');

    root.querySelector<HTMLButtonElement>('[data-remove="aaaa:tlsServerIdentity"]')!.click();

    await until(() => root.querySelector('[data-toggle="aaaa:tlsServerIdentity"]') === null, 'the certificate was not deleted');

    assert.ok(root.querySelector('[data-toggle="bbbb:tlsServerIdentity"]')!.closest('tr') === row, 'the row of the other certificate was drawn anew when the one before it went');

});


test('each upload offers the kinds of its page, every kind ticked the uses it is offered, in boxes of its own, the listeners by their names', async () => {

    const kind   = (root: HTMLElement, name: string) => root.querySelector<HTMLInputElement>(`#upload-kinds input[name="kind"][value="${name}"]`);
    const usages = (root: HTMLElement, of: string) => root.querySelector<HTMLElement>(`[data-usages-of="${of}"]`);
    const boxes  = (root: HTMLElement, of: string) => [...root.querySelectorAll<HTMLInputElement>(`[data-usages-of="${of}"] input[name="usage-${of}"]`)];

    const tick = (root: HTMLElement, name: string) => {
        kind(root, name)!.checked = true;
        kind(root, name)!.dispatchEvent(new Event('change', { bubbles: true }));
    };

    // Who the meter's servers are: the identities, told their listeners.
    const servers = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);

    assert.deepEqual([...servers.querySelectorAll<HTMLInputElement>('#upload-kinds input[name="kind"]')].map(box => box.value), [ 'tlsServerIdentity' ],
                     'the upload of the server identities offers other kinds than the identities');
    assert.ok(servers.querySelector('[data-usages-of]') === null, 'uses were offered before a kind was ticked');

    tick(servers, 'tlsServerIdentity');

    await until(() => boxes(servers, 'tlsServerIdentity').map(box => box.value).join() === 'modbus,web', 'an identity was not offered its listeners');

    assert.deepEqual([...usages(servers, 'tlsServerIdentity')!.querySelectorAll('label.checkbox')].map(one => one.textContent!.trim()), [ 'Modbus/TLS', 'web interface' ],
                     'the listeners were not offered by their names');
    assert.match(usages(servers, 'tlsServerIdentity')!.textContent!, /None ticked: on every listener/);

    // What the meter believes and recognises: the roots, told their servers.
    const roots = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawnRoots);

    assert.ok(kind(roots, 'tlsServerIdentity') === null, 'the upload of the certificates offers an identity, which comes with its key');

    tick(roots, 'tlsRoot');

    await until(() => boxes(roots, 'tlsRoot').map(box => box.value).join() === 'dns,nts', 'a TLS root was not offered its servers');

    boxes(roots, 'tlsRoot')[1]!.checked = true;
    boxes(roots, 'tlsRoot')[1]!.dispatchEvent(new Event('change', { bubbles: true }));

    tick(roots, 'clientRoot');

    await until(() => usages(roots, 'clientRoot') !== null, 'a client root ticked was not offered a use of its own');

    assert.equal(boxes(roots, 'clientRoot').length, 0, 'a client root was offered uses it has none of');
    assert.deepEqual(boxes(roots, 'tlsRoot').map(box => box.checked), [ false, true ], 'the root lost what was ticked for it');

});


test('somebody who may only look gets no forms, and is told so', async () => {

    const root = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read' ], aMeter(),
                            root => root.querySelector('table.records') !== null && root.querySelector('[data-request-card="r1"]') !== null);

    assert.ok(root.querySelector('#import-form') === null, 'there is a form to import with');
    assert.ok(root.querySelector('#request-form') === null, 'there is a form to make a key with');
    assert.ok(root.querySelector('[data-bring-answer]') === null, 'there is a form to bring a certificate for a key with');
    assert.ok([...root.querySelectorAll<HTMLButtonElement>('[data-remove-request]')].every(button => button.disabled),
              'a button to throw a key away with can be pressed');
    assert.ok([...root.querySelectorAll<HTMLButtonElement>('[data-toggle], [data-remove]')].every(button => button.disabled),
              'a button to change a certificate with can be pressed');
    assert.match(root.querySelector('.notice')!.textContent!, /look at the store/);

});


test('the roles stand below the client roots on Certificates, and the identities and their keys are on Server identities alone', async () => {

    const orderOf = (root: HTMLElement) => [...root.querySelectorAll('#panel-usage [data-kind], #panel-usage #sunspec-roles')].
                                              map(one => one.getAttribute('data-kind') ?? one.id);
    const tabsOf  = (root: HTMLElement) => [...root.querySelectorAll('[role="tab"]')].map(tab => tab.textContent!.trim());

    const rootsPage = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawnRoots);
    const roots     = orderOf(rootsPage);
    const rootsAt   = (what: string) => roots.indexOf(what);

    assert.ok(rootsAt('clientRoot') >= 0 && rootsAt('sunspec-roles') === rootsAt('clientRoot') + 1, `the roles do not follow the client roots: ${roots.join(' | ')}`);
    assert.ok(rootsAt('tlsServer') > rootsAt('sunspec-roles'), `the servers recognised are not on Certificates: ${roots.join(' | ')}`);
    assert.ok(!roots.includes('tlsServerIdentity'), `identities are on Certificates: ${roots.join(' | ')}`);
    assert.ok(!tabsOf(rootsPage).includes('New key'), `Certificates offers to make a key: ${tabsOf(rootsPage).join(' | ')}`);
    assert.ok(rootsPage.querySelector('[data-request-card]') === null, 'the keys that wait are on Certificates');

    const serversPage = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const servers     = orderOf(serversPage);

    assert.ok(servers.includes('tlsServerIdentity'), `the identities are not on Server identities: ${servers.join(' | ')}`);
    assert.ok(!servers.includes('clientRoot') && !servers.includes('sunspec-roles'), `roots or roles are on Server identities: ${servers.join(' | ')}`);
    assert.ok(tabsOf(serversPage).includes('New key'), `Server identities offers no key to make: ${tabsOf(serversPage).join(' | ')}`);
    assert.deepEqual([...serversPage.querySelectorAll('[data-request-card]')].map(card => card.getAttribute('data-request-card')), [ 'r1', 'r2' ],
                     'the keys that wait are not among what the meter presents');

});


test('a key is made for an identity of one of the listeners, and asked for with what the meter makes keys for', async () => {

    const root    = await open(serverIdentitiesPage, '/configuration/server-identities?tab=request', [ 'certificates:read', 'certificates:edit' ], aMeter(),
                               root => root.querySelector('#request-form') !== null);
    const usages  = [...root.querySelectorAll<HTMLInputElement>('#request-usages input[name="usage"]')].map(box => box.value);

    assert.deepEqual(usages, [ 'modbus', 'web' ], 'a key is not offered the two listeners');
    assert.ok(root.querySelector('#request-names') !== null, 'a key for a server is not asked what it is reachable as');
    assert.ok(root.querySelector('#request-kind') === null, 'a kind is asked for where the meter makes keys for one alone');

});


test('a listener that runs with nothing to show is said at the top, and an identity says where it is shown and where next', async () => {

    const root = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ],
                            aMeter({ modbus: { used: true, current: null, next: 'bbbb', nextAt: '2026-12-24T18:00:00Z' } }), drawn);

    const notices = [...root.querySelectorAll('.notice')].map(one => one.textContent!.replace(/\s+/g, ' ').trim());

    assert.ok(notices.some(one => one.startsWith('The Modbus/TLS listener has no certificate it could show') &&
                                  one.endsWith('Put in a TLS server identity for it under Server identities, or make a key for one there.')),
              `the listener with nothing to show was not said: ${notices.join(' | ')}`);
    assert.ok(!notices.some(one => one.includes('web interface has no certificate')), 'the web interface, served over plain HTTP, was said to have nothing');

    const chipsOf = (id: string) => [...root.querySelector(`[data-toggle="${id}:tlsServerIdentity"]`)!.closest('tr')!.querySelectorAll('.row-chips .chip')].
                                        map(one => one.textContent!.trim());

    assert.deepEqual(chipsOf('aaaa'), [ 'shown on Modbus/TLS' ]);
    assert.equal(chipsOf('bbbb').length, 1);
    assert.match(chipsOf('bbbb')[0]!, /^next on Modbus\/TLS, from /);

    assert.match(root.textContent!, /served over plain HTTP at the moment/, 'the web interface over plain HTTP was not said');

});


test('what an identity is drawn with says nothing of plain HTTP where the web interface is served over HTTPS', async () => {

    const root = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ],
                            aMeter({ web: { used: true, current: 'bbbb', next: null, nextAt: null } }), drawn);

    assert.doesNotMatch(root.textContent!, /served over plain HTTP/);

});


