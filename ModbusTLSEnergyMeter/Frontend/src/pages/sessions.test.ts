// The sessions page drawn against a stand-in meter: who is charging, typed
// and not started yet, outlives a reading being signed on its own and the
// document being put away beside it; a session started and stopped shows the
// key and then the document; a start the meter refuses says why and keeps
// what is typed.

import { asked, field, open, refused, submit, type, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { PublicKeyOut, SessionState } from '../api/client.ts';

const { sessionsPage } = await import('./sessions.ts');


const aPublicKey: PublicKeyOut = {
    keyId:          'p256',
    algorithm:      'secp256r1',
    fingerprint:    'p256-fingerprint',
    publicKey:      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE',
    encoding:       'base64',
    format:         'SubjectPublicKeyInfo',
    rawPublicKey:   '04ab',
    ocmfAlgorithm:  'ECDSA-secp256r1-SHA256'
};

/** A meter with no session yet, that starts, stops and signs as asked - or refuses to start. */
function aMeter(refusesToStart = false): (one: Asked) => unknown {

    let state: SessionState = { running: false, session: null };

    return ({ method, path }) => {

        if (method === 'GET' && path === '/sessions')
            return state;

        if (method === 'GET' && path === '/signedMeterValues')
            return { format: 'OCMF', timestamp: '2026-10-04T10:00:00Z', ocmf: 'OCMF|{"FV":"1.0"}|{"SD":"30"}', publicKey: aPublicKey };

        if (method === 'POST' && path === '/sessions/start') {

            if (refusesToStart)
                return refused(409, 'A session is running already.');

            state = { running: true, session: { sessionId: 's-1', startedAt: '2026-10-04T10:00:00Z', startValue: 1000,
                                                unit: 'Wh', keyId: 'p256', identification: null } as never };

            return { timestamp: '2026-10-04T10:00:00Z', sessionId: 's-1', startValue: 1000, unit: 'Wh', publicKey: aPublicKey };

        }

        if (method === 'POST' && path === '/sessions/stop') {
            state = { running: false, session: null };
            return { timestamp: '2026-10-04T11:00:00Z', sessionId: 's-1', startValue: 1000, stopValue: 3500,
                     energy_kWh: 2.5, unit: 'Wh', ocmf: 'OCMF|{"FV":"1.0"}|{"SD":"session"}', publicKey: aPublicKey };
        }

        return undefined;

    };

}

const drawn = (root: HTMLElement) => root.querySelector('#start-form') !== null;


test('who is charging, and its focus, outlives a reading being signed on its own and put away', async () => {

    const root  = await open(sessionsPage, '/sessions', [ 'meter:read', 'meter:run' ], aMeter(), drawn);
    const who   = field(root, '#start-form', 'identification');

    type(who, 'DEADBEEF01', 3);

    root.querySelector<HTMLButtonElement>('[data-value="ocmf"]')!.click();

    await until(() => root.querySelector<HTMLTextAreaElement>('#document')?.value.includes('"SD":"30"') === true,
                'the signed reading was not shown');

    let after = field(root, '#start-form', 'identification');

    assert.ok(after === who, 'the field was drawn anew when the reading was shown');
    assert.equal(after.value, 'DEADBEEF01');
    assert.ok(document.activeElement === who, 'the field lost the focus when the reading was shown');
    assert.equal(after.selectionStart, 3);

    root.querySelector<HTMLButtonElement>('#dismiss-document')!.click();

    await until(() => root.querySelector('#document') === null, 'the reading was not put away');

    after = field(root, '#start-form', 'identification');

    assert.ok(after === who, 'the field was drawn anew when the reading was put away');
    assert.equal(after.value, 'DEADBEEF01');

});


test('a session started shows its key, and stopped, its document', async () => {

    const root = await open(sessionsPage, '/sessions', [ 'meter:read', 'meter:run' ], aMeter(), drawn);

    type(field(root, '#start-form', 'identification'), 'DEADBEEF01');

    submit(root, '#start-form');

    await until(() => root.querySelector('#stop') !== null, 'the session did not show as running');

    assert.equal(root.querySelector<HTMLTextAreaElement>('#document-key')!.value, aPublicKey.publicKey);
    assert.ok(root.querySelector('#document') === null, 'a document was shown before the session stopped');
    assert.deepEqual(asked.find(one => one.path === '/sessions/start')?.body, { identification: 'DEADBEEF01' });

    root.querySelector<HTMLButtonElement>('#stop')!.click();

    await until(() => root.querySelector<HTMLTextAreaElement>('#document')?.value.includes('"SD":"session"') === true,
                'the signed session was not shown');

    await until(() => drawn(root), 'there is no form to start the next session with');
    assert.equal(field(root, '#start-form', 'identification').value, '', 'the next session started with the last one\'s name');

});


test('a start the meter refuses says why, and keeps what is typed', async () => {

    const root  = await open(sessionsPage, '/sessions', [ 'meter:read', 'meter:run' ], aMeter(true), drawn);
    const who   = field(root, '#start-form', 'identification');

    type(who, 'DEADBEEF01');

    submit(root, '#start-form');

    await until(() => root.querySelector('#session-error')!.textContent === 'A session is running already.',
                'the refusal was not said');

    assert.ok(field(root, '#start-form', 'identification') === who, 'the field was drawn anew');
    assert.equal(who.value, 'DEADBEEF01');

});


test('somebody who may only watch can neither start, stop nor sign', async () => {

    const root = await open(sessionsPage, '/sessions', [ 'meter:read' ], aMeter(),
                            root => root.querySelector('.card') !== null);

    assert.ok(root.querySelector('#start-form') === null, 'there is a form to start a session with');
    assert.ok(root.querySelector('[data-value]') === null, 'there is a button to sign a reading with');
    assert.match(root.querySelector('.notice')!.textContent!, /watch a charging session/);

});
