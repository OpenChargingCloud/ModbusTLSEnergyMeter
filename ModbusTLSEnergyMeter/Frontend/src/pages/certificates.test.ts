// The certificate pages - the node's, with the meter's words and sections:
// Certificates the roots, the roles and the servers recognised, Server
// identities the identities the listeners show and the signing requests -
// drawn against a stand-in meter: a request half filled in, and a certificate
// pasted for another, outlive a certificate being switched off beside them -
// the field, its text and its focus; every certificate keeps its row; the
// upload offers every kind ticked its own uses, the listeners by their names,
// each kind on its own page; a request answered empties its own form and no
// other; the roles stand below the client roots and the requests below the
// identities, each on its page; a listener with nothing to show is said at the
// top; where an identity is shown and where next is said in its row; what is
// typed into a request is held as a draft, and Reload empties it.

import { asked, change, field, open, said, type, until, type Asked } from '../../test/meter.ts';
import { unsaved } from '@node/unsaved';
import { chromeTakesTheFocus } from '@node/../test/dom.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { Certificate, CertificateKind, CertificateStore, SigningRequest, SigningRequests } from '../api/client.ts';

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

function aRequest(id: string, subject: string, answered = false): SigningRequest {
    return { id, subject, listener: 'modbus', createdAt: '2026-10-01T00:00:00Z', dnsNames: [], ipAddresses: [],
             keyType: 'ecdsa-p256', note: null, answeredBy: answered ? [ 'cccc' ] : [], state: answered ? 'answered' : 'awaiting a certificate' };
}

/** How the stand-in's listeners stand: Modbus/TLS showing aaaa with nothing next, the web interface not served over HTTPS. */
interface Listeners {
    modbus?:  { used: boolean; current: string | null; next: string | null; nextAt: string | null };
    web?:     { used: boolean; current: string | null; next: string | null; nextAt: string | null };
}

/** A meter with two identities and two requests waiting for their certificates, that takes what is asked. */
function aMeter(listeners: Listeners = {}): (one: Asked) => unknown {

    let identities  = [ anIdentity('aaaa', 'meter-a'), anIdentity('bbbb', 'meter-b') ];
    let waiting     = [ aRequest('r1', 'CN=meter7.lan'), aRequest('r2', 'CN=meter8.lan') ];

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
        certificates:        { tlsRoot: [], clientRoot: [], tlsServer: [], tlsServerIdentity: identities } as Record<CertificateKind, Certificate[]>,
        keysAreUnencrypted:  false,
        listeners:           [ 'modbus', 'web' ],
        shown: {
            modbus:  listeners.modbus ?? { used: true,  current: 'aaaa', next: null, nextAt: null },
            web:     listeners.web    ?? { used: false, current: null,   next: null, nextAt: null }
        }
    } as unknown as CertificateStore);

    const requests = (): SigningRequests => ({
        requests:        waiting,
        listeners:       [ 'modbus', 'web' ],
        keyTypes:        [ { id: 'ecdsa-p256', name: 'ECDSA P-256', remark: 'What every peer reads.' },
                           { id: 'rsa-3072',   name: 'RSA 3072',    remark: 'Slower, and as good.' } ] as never,
        defaultKeyType:  'ecdsa-p256'
    });

    return ({ method, path, body }) => {

        if (method === 'GET' && path === '/certificates')
            return store();

        if (method === 'GET' && path === '/certificates/requests')
            return requests();

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

        if (method === 'PUT' && path.startsWith('/certificates/requests/')) {
            const id = decodeURIComponent(path.split('/')[3] ?? '');
            waiting = waiting.map(one => one.id === id ? aRequest(one.id, one.subject, true) : one);
            identities = [ ...identities, anIdentity('cccc', 'meter-7') ];
            return { request: waiting.find(one => one.id === id), certificate: anIdentity('cccc', 'meter-7') };
        }

        return undefined;

    };

}

const drawn       = (root: HTMLElement) => root.querySelector('#request-form') !== null;
const drawnRoots  = (root: HTMLElement) => root.querySelector('#sunspec-roles') !== null;
const pemOf  = (root: HTMLElement, id: string) => root.querySelector<HTMLTextAreaElement>(`[data-pem="${id}"]`)!;


test('a request half filled in, and its focus, outlives a certificate being switched off', async () => {

    const root     = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const pasted   = pemOf(root, 'r2');

    pasted.value = '-----BEGIN CERTIFICATE-----\nMIIB';
    pasted.dispatchEvent(new Event('input', { bubbles: true }));

    const subject  = field(root, '#request-form', 'subject');

    type(subject, 'CN=meter9.lan', 5);

    // As Chrome does it: the field is switched off while the change is saved,
    // and loses its focus - which the page has to give back.
    const browser = chromeTakesTheFocus(root);

    root.querySelector<HTMLButtonElement>('[data-toggle="bbbb:tlsServerIdentity"]')!.click();

    await until(() => asked.some(one => one.method === 'PATCH' && one.path === '/certificates/bbbb'), 'nothing was switched off');
    await until(() => root.querySelector('[data-toggle="bbbb:tlsServerIdentity"]')!.textContent!.trim() === 'Switch on', 'the row did not say it was switched off');

    const after = field(root, '#request-form', 'subject');

    assert.ok(after === subject, 'the subject field was drawn anew');
    assert.equal(after.value, 'CN=meter9.lan');
    assert.ok(document.activeElement === subject, 'the subject field lost the focus');
    assert.equal(after.selectionStart, 5);

    browser.disconnect();

    assert.ok(pemOf(root, 'r2') === pasted, 'the certificate pasted for the other request was drawn anew');
    assert.equal(pasted.value, '-----BEGIN CERTIFICATE-----\nMIIB');

});


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


test('a request answered empties its own form, and no other', async () => {

    const root  = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);

    for (const id of [ 'r1', 'r2' ]) {
        pemOf(root, id).value = `-----BEGIN CERTIFICATE-----\n${id}`;
        pemOf(root, id).dispatchEvent(new Event('input', { bubbles: true }));
    }

    root.querySelector<HTMLButtonElement>('[data-answer="r1"]')!.click();

    await until(() => root.querySelector('[data-answer-note="r1"]')!.textContent === 'Put in as meter-7.', 'the answer was not said');

    assert.deepEqual(asked.find(one => one.method === 'PUT')?.body, { pem: '-----BEGIN CERTIFICATE-----\nr1' });
    assert.equal(pemOf(root, 'r1').value, '', 'the certificate put in stayed in its form');
    assert.equal(pemOf(root, 'r2').value, '-----BEGIN CERTIFICATE-----\nr2', 'the other request lost what was pasted for it');

    // Read again: the identity it became is in the store, the request says it was answered.
    assert.ok(root.querySelector('[data-toggle="cccc:tlsServerIdentity"]') !== null, 'the identity put in is not among the identities');
    assert.equal(root.querySelector('[data-answer="r1"]')!.closest('.signing-request')!.querySelector('h3 .chip')!.textContent, 'answered');

});


test('somebody who may only look gets no forms, and is told so', async () => {

    const root = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read' ], aMeter(),
                            root => root.querySelector('table.records') !== null && root.querySelector('.signing-request') !== null);

    assert.ok(root.querySelector('#import-form') === null, 'there is a form to import with');
    assert.ok(root.querySelector('#request-form') === null, 'there is a form to ask for a certificate with');
    assert.ok(root.querySelector('form.upload') === null, 'there is a form to answer a request with');
    assert.ok(root.querySelector('[data-remove-request]') === null, 'there is a button to throw a request away with');
    assert.ok([...root.querySelectorAll<HTMLButtonElement>('[data-toggle], [data-remove]')].every(button => button.disabled),
              'a button to change a certificate with can be pressed');
    assert.match(root.querySelector('.notice')!.textContent!, /look at the store/);

});


test('the roles stand below the client roots on Certificates, and the requests below the identities on Server identities', async () => {

    const orderOf = (root: HTMLElement) => [...root.querySelectorAll('#panel-usage [data-kind], #panel-usage #sunspec-roles, #panel-usage .signing-request, #panel-usage #request-form, #panel-usage h2')].
                                              map(one => one.getAttribute('data-kind') ?? (one.id || (one.classList.contains('signing-request') ? 'request' : one.textContent!.trim())));

    const roots   = orderOf(await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawnRoots));
    const rootsAt = (what: string) => roots.indexOf(what);

    assert.ok(rootsAt('clientRoot') >= 0 && rootsAt('sunspec-roles') === rootsAt('clientRoot') + 1, `the roles do not follow the client roots: ${roots.join(' | ')}`);
    assert.ok(rootsAt('tlsServer') > rootsAt('sunspec-roles'), `the servers recognised are not on Certificates: ${roots.join(' | ')}`);
    assert.ok(!roots.includes('tlsServerIdentity') && !roots.includes('request-form') && !roots.includes('request'),
              `identities or requests are on Certificates: ${roots.join(' | ')}`);

    const servers   = orderOf(await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn));
    const serversAt = (what: string) => servers.indexOf(what);

    assert.ok(serversAt('Signing requests') === serversAt('tlsServerIdentity') + 1, `the requests do not follow the identities: ${servers.join(' | ')}`);
    assert.ok(serversAt('request') > serversAt('Signing requests') && serversAt('request-form') > serversAt('request'),
              `the requests and the form to ask with are not below their heading: ${servers.join(' | ')}`);
    assert.ok(!servers.includes('clientRoot') && !servers.includes('sunspec-roles'), `roots or roles are on Server identities: ${servers.join(' | ')}`);

});


test('a listener that runs with nothing to show is said at the top, and an identity says where it is shown and where next', async () => {

    const root = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ],
                            aMeter({ modbus: { used: true, current: null, next: 'bbbb', nextAt: '2026-12-24T18:00:00Z' } }), drawn);

    const notices = [...root.querySelectorAll('.notice')].map(one => one.textContent!.replace(/\s+/g, ' ').trim());

    assert.ok(notices.some(one => one.startsWith('The Modbus/TLS listener has no certificate it could show') &&
                                  one.endsWith('Put in a TLS server identity for it under Server identities, or ask for one there.')),
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


test('a request half filled in, or a certificate pasted for one, is a draft that leaving asks about', async () => {

    for (const into of [ 'request', 'pem' ] as const) {

        const root = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);

        assert.ok(unsaved.mayBeLost() && said.length === 0, 'an untouched page asked before it was left');

        if (into === 'request')
            type(field(root, '#request-form', 'subject'), 'CN=meter9.lan');
        else
            type(pemOf(root, 'r1'), '-----BEGIN CERTIFICATE-----');

        unsaved.mayBeLost();

        assert.equal(said.length, 1, `what was typed into the ${into === 'request' ? 'request' : 'certificate pasted'} was not held`);

    }

});


test('Reload empties a request half filled in, and its notes go back to the first listener and the default key', async () => {

    const root      = await open(serverIdentitiesPage, '/configuration/server-identities', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const listener  = field<HTMLSelectElement>(root, '#request-form', 'listener');
    const keyType   = field<HTMLSelectElement>(root, '#request-form', 'keyType');
    const note      = () => root.querySelector('#request-listener-note')!.textContent!;
    const remark    = () => root.querySelector('#request-key-type-note')!.textContent!;

    type(field(root, '#request-form', 'subject'), 'CN=meter9.lan');
    change(listener, 'web');
    change(keyType,  'rsa-3072');

    await until(() => note().startsWith('Shown to a browser') && remark() === 'Slower, and as good.', 'the notes did not follow what was chosen');

    const before = asked.length;

    root.querySelector<HTMLButtonElement>('#reload')!.click();

    await until(() => asked.slice(before).some(one => one.path === '/certificates/requests'), 'Reload did not ask for the requests');
    await until(() => note().startsWith('Shown to a charging station'), 'the note of the listener did not go back to the first listener');

    assert.equal(remark(), 'What every peer reads.', 'the note of the key did not go back to the default key');
    assert.equal(field(root, '#request-form', 'subject').value, '', 'Reload left the subject typed');
    assert.equal(listener.value, 'modbus');
    assert.equal(keyType.value, 'ecdsa-p256');

});
