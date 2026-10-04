// The certificate page drawn against a stand-in meter: a request half filled
// in, and a certificate pasted for another, outlive a certificate being
// switched off beside them - the field, its text and its focus; every
// certificate keeps its row; the import form offers the uses of the kind
// chosen in boxes of that kind; a request answered empties its own form and
// no other.

import { asked, field, open, type, until, type Asked } from '../../test/meter.ts';
import { chromeTakesTheFocus } from '@node/../test/dom.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { Certificate, CertificateKind, CertificateStore, SigningRequest, SigningRequests } from '../api/client.ts';

const { certificatesPage } = await import('./certificates.ts');


function anIdentity(id: string, label: string, active = true): Certificate {
    return {
        id, label, active,
        kind:           'tlsIdentity',
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

/** A meter with two identities and two requests waiting for their certificates, that takes what is asked. */
function aMeter(): (one: Asked) => unknown {

    let identities  = [ anIdentity('aaaa', 'meter-a'), anIdentity('bbbb', 'meter-b') ];
    let waiting     = [ aRequest('r1', 'CN=meter7.lan'), aRequest('r2', 'CN=meter8.lan') ];

    const store = (): CertificateStore => ({
        directory:           '/var/lib/meter/certificates',
        trustAnchors:        [ 'tlsRoot', 'clientRoot' ],
        credentials:         [ 'tlsIdentity' ],
        recognised:          [],
        kinds: {
            tlsRoot:      { description: 'A TLS root',          trustAnchor: true,  needsPrivateKey: false, hasUsages: true,  usages: [ 'dns', 'nts' ] },
            clientRoot:   { description: 'A client root',       trustAnchor: true,  needsPrivateKey: false, hasUsages: false, usages: [] },
            tlsIdentity:  { description: 'A TLS identity',      trustAnchor: false, needsPrivateKey: true,  hasUsages: true,  usages: [ 'modbus', 'web' ] },
            tlsServer:    { description: 'A server certificate', trustAnchor: false, needsPrivateKey: false, hasUsages: true,  usages: [ 'dns', 'nts' ] }
        } as Record<CertificateKind, never>,
        usages:              [ 'dns', 'nts' ],
        certificates:        { tlsRoot: [], clientRoot: [], tlsIdentity: identities, tlsServer: [] } as Record<CertificateKind, Certificate[]>,
        keysAreUnencrypted:  false,
        listeners:           [ 'modbus', 'web' ],
        shown: {
            modbus:  { used: true,  current: 'aaaa', next: null, nextAt: null },
            web:     { used: false, current: null,   next: null, nextAt: null }
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

const drawn  = (root: HTMLElement) => root.querySelector('#request-form') !== null;
const pemOf  = (root: HTMLElement, id: string) => root.querySelector<HTMLTextAreaElement>(`[data-pem="${id}"]`)!;


test('a request half filled in, and its focus, outlives a certificate being switched off', async () => {

    const root     = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const pasted   = pemOf(root, 'r2');

    pasted.value = '-----BEGIN CERTIFICATE-----\nMIIB';
    pasted.dispatchEvent(new Event('input', { bubbles: true }));

    const subject  = field(root, '#request-form', 'subject');

    type(subject, 'CN=meter9.lan', 5);

    // As Chrome does it: the field is switched off while the change is saved,
    // and loses its focus - which the page has to give back.
    const browser = chromeTakesTheFocus(root);

    root.querySelector<HTMLButtonElement>('[data-toggle="bbbb"]')!.click();

    await until(() => asked.some(one => one.method === 'PATCH' && one.path === '/certificates/bbbb'), 'nothing was switched off');
    await until(() => root.querySelector('[data-toggle="bbbb"]')!.textContent!.trim() === 'Switch on', 'the row did not say it was switched off');

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

    const root  = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const row   = root.querySelector('[data-toggle="bbbb"]')!.closest('tr');

    root.querySelector<HTMLButtonElement>('[data-toggle="aaaa"]')!.click();

    await until(() => root.querySelector('[data-toggle="aaaa"]')!.textContent!.trim() === 'Switch on', 'the row did not say it was switched off');

    assert.ok(root.querySelector('[data-toggle="bbbb"]')!.closest('tr') === row, 'the row of the other certificate was drawn anew');

    root.querySelector<HTMLButtonElement>('[data-remove="aaaa"]')!.click();

    await until(() => root.querySelector('[data-toggle="aaaa"]') === null, 'the certificate was not deleted');

    assert.ok(root.querySelector('[data-toggle="bbbb"]')!.closest('tr') === row, 'the row of the other certificate was drawn anew when the one before it went');

});


test('the import form offers the uses of the kind chosen, in boxes of that kind', async () => {

    const root  = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);
    const kind  = field<HTMLSelectElement>(root, '#import-form', 'kind');
    const boxes = () => [...root.querySelectorAll<HTMLInputElement>('#import-usages input[name="usage"]')];

    assert.deepEqual(boxes().map(box => box.value), [ 'dns', 'nts' ], 'a TLS root was not offered its servers');

    kind.value = 'tlsIdentity';
    kind.dispatchEvent(new Event('change', { bubbles: true }));

    await until(() => boxes().map(box => box.value).join() === 'modbus,web', 'an identity was not offered its listeners');

    boxes()[1]!.checked = true;

    kind.value = 'tlsRoot';
    kind.dispatchEvent(new Event('change', { bubbles: true }));

    await until(() => boxes().map(box => box.value).join() === 'dns,nts', 'the root was not offered its servers again');

    assert.ok(boxes().every(box => !box.checked), 'what was ticked for an identity stayed ticked for a root');

    kind.value = 'clientRoot';
    kind.dispatchEvent(new Event('change', { bubbles: true }));

    await until(() => root.querySelector<HTMLElement>('#import-usages')!.hidden === true, 'a client root was offered uses it has none of');

});


test('a request answered empties its own form, and no other', async () => {

    const root  = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read', 'certificates:edit' ], aMeter(), drawn);

    for (const id of [ 'r1', 'r2' ]) {
        pemOf(root, id).value = `-----BEGIN CERTIFICATE-----\n${id}`;
        pemOf(root, id).dispatchEvent(new Event('input', { bubbles: true }));
    }

    root.querySelector<HTMLButtonElement>('[data-answer="r1"]')!.click();

    await until(() => root.querySelector('[data-answer-note="r1"]')!.textContent === 'Put in as meter-7.', 'the answer was not said');

    assert.deepEqual(asked.find(one => one.method === 'PUT')?.body, { pem: '-----BEGIN CERTIFICATE-----\nr1' });
    assert.equal(pemOf(root, 'r1').value, '', 'the certificate put in stayed in its form');
    assert.equal(pemOf(root, 'r2').value, '-----BEGIN CERTIFICATE-----\nr2', 'the other request lost what was pasted for it');

});


test('somebody who may only look gets no forms, and is told so', async () => {

    const root = await open(certificatesPage, '/configuration/certificates', [ 'certificates:read' ], aMeter(),
                            root => root.querySelector('table.records') !== null);

    assert.ok(root.querySelector('#import-form') === null, 'there is a form to import with');
    assert.ok(root.querySelector('#request-form') === null, 'there is a form to ask for a certificate with');
    assert.ok(root.querySelector('[data-toggle]') === null, 'there are buttons to change a certificate with');
    assert.match(root.querySelector('.notice')!.textContent!, /look at the certificates/);

});
