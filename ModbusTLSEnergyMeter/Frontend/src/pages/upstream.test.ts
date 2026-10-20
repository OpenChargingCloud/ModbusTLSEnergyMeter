// The Upstream page drawn against a stand-in meter: a meter that stands in
// front of none says so; a save sends where the meter behind is reached, over
// what and as whom, and shows how that goes; a meter behind that is not
// believed says why; somebody who may only read gets no form to change it.

import { asked, field, leave, open, submit, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { after, test } from 'node:test';

import type { UpstreamPage, UpstreamUpdate } from '../api/client.ts';

const { upstreamPage } = await import('./upstream.ts');

after(leave);


const reader = { id: 'aaaaaaaaaaaaaaaa', label: 'Upstream reader', role: 'ReadOnlySunSpec', subject: 'CN=Reader' };

function none(): UpstreamPage {
    return {
        upstream: false, host: null, port: null, unit: null, tls: false, identity: null, server: null,
        heldTo: null, judgement: null, known: null, state: null, identities: [ reader ], usage: 'upstream',
        defaults: { tcpPort: 502, tlsPort: 802, unit: 1 }, file: 'configuration.json'
    };
}

/** A meter that takes what is saved, and then says how reaching the meter behind goes. */
function aMeter(now: { page: UpstreamPage; untrusted?: boolean }): (one: Asked) => unknown {
    return ({ method, path, body }) => {

        if (method === 'GET' && path === '/configuration/upstream')
            return now.page;

        if (method === 'PUT' && path === '/configuration/upstream') {
            const update = body as UpstreamUpdate;
            const port   = update.port ?? (update.tls ? 802 : 502);
            now.page = update.host.trim() === ''
                           ? none()
                           : { ...none(), upstream: true, host: update.host.trim(), port, unit: update.unit ?? 1, tls: update.tls,
                               identity: update.identity, server: `${update.host.trim()}:${port}`,
                               state: { server: `${update.host.trim()}:${port}`, unit: update.unit ?? 1, tls: update.tls,
                                        state: now.untrusted ? 'untrusted' : 'connected', since: '2026-10-20T10:00:00.000Z',
                                        error: now.untrusted ? `The meter at ${update.host.trim()}:${port} is not believed: it showed another certificate.` : null,
                                        protocol: update.tls ? 'Tls13' : null, cipherSuite: update.tls ? 'TLS_AES_256_GCM_SHA384' : null,
                                        identity: update.tls ? reader : null, judged: null } };
            return now.page;
        }

        return undefined;

    };
}

const form   = '#upstream-form';
const drawn  = (root: HTMLElement) => root.querySelector('.cards') !== null;
const sent   = () => asked.filter(one => one.method === 'PUT' && one.path === '/configuration/upstream').map(one => one.body as UpstreamUpdate);
const typeIn = (input: HTMLInputElement, text: string) => { input.value = text; input.dispatchEvent(new Event('input', { bubbles: true })); };


test('a meter that stands in front of none says it measures with its own simulation', async () => {

    const root = await open(upstreamPage, '/configuration/upstream', [ 'meter:read', 'meter:edit' ], aMeter({ page: none() }), drawn);

    assert.match(root.querySelector('.upstream-none')!.textContent!, /its own simulation/);
    assert.equal(field<HTMLInputElement>(root, form, 'host').value, '');

});

test('a save sends where the meter behind is reached, over Modbus/TLS and as whom, and shows that it answers', async () => {

    const root = await open(upstreamPage, '/configuration/upstream', [ 'meter:read', 'meter:edit' ], aMeter({ page: none() }), drawn);

    typeIn(field<HTMLInputElement>(root, form, 'host'), ' 10.0.0.7 ');
    root.querySelector<HTMLInputElement>(`${form} input[name="tls"]`)!.checked = true;

    const identity = field<HTMLSelectElement>(root, form, 'identity');
    identity.value = reader.id;
    identity.dispatchEvent(new Event('change', { bubbles: true }));

    submit(root, form);

    await until(() => root.querySelector(`${form} .form-notice`)?.textContent === 'Saved.', 'not saved');

    const update = sent().at(-1)!;

    assert.equal(update.host,      '10.0.0.7');
    assert.equal(update.tls,       true);
    assert.equal(update.port,      null, 'a port not typed is not the default of the other protocol');
    assert.equal(update.identity,  reader.id);

    assert.match(root.querySelector('.upstream-state')!.textContent!, /connected/);
    assert.equal(field<HTMLInputElement>(root, form, 'host').value, '10.0.0.7', 'the page does not show what was saved');

});

test('a meter behind that is not believed says why', async () => {

    const root = await open(upstreamPage, '/configuration/upstream', [ 'meter:read', 'meter:edit' ], aMeter({ page: none(), untrusted: true }), drawn);

    typeIn(field<HTMLInputElement>(root, form, 'host'), 'meter-behind.local');
    root.querySelector<HTMLInputElement>(`${form} input[name="tls"]`)!.checked = true;

    submit(root, form);

    await until(() => root.querySelector('.upstream-error') !== null, 'why it is not believed is not said');

    assert.match(root.querySelector('.upstream-error')!.textContent!, /not believed/);
    assert.match(root.querySelector('.upstream-state')!.textContent!, /untrusted/);

});

test('somebody who may only read gets no button to change it', async () => {

    const root = await open(upstreamPage, '/configuration/upstream', [ 'meter:read' ], aMeter({ page: none() }), drawn);

    assert.equal(root.querySelector(`${form} button[type="submit"]`), null);
    assert.equal(field<HTMLInputElement>(root, form, 'host').disabled, true);

});
