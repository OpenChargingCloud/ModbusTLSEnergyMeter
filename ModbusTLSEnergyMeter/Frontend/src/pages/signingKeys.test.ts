// The signing keys page drawn against a stand-in meter: what is typed into
// the form for a new key outlives a key being made the identity or removed
// beside it, a key made empties the form, and every key's card stays the
// element it was.

import { asked, field, open, said, submit, type, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { SigningKey, SigningKeys } from '../api/client.ts';

const { signingKeysPage } = await import('./signingKeys.ts');


function aKey(id: string, algorithm: string, isDefault: boolean): SigningKey {
    return {
        id, algorithm, isDefault,
        fingerprint:  `${id}-fingerprint`,
        createdAt:    '2026-10-04T10:00:00Z',
        note:         null,
        publicKey:    `-----BEGIN PUBLIC KEY-----\n${id}\n-----END PUBLIC KEY-----`
    } as SigningKey;
}

/** A meter with two keys, the first its identity, that takes what is asked of it. */
function aMeter(): (one: Asked) => unknown {

    let keys = [ aKey('p256', 'secp256r1', true), aKey('p384', 'secp384r1', false) ];

    const store = (): SigningKeys => ({
        keys,
        algorithms:      [ 'secp256r1', 'secp384r1', 'secp192r1' ],
        ocmfAlgorithms:  [ 'secp256r1', 'secp384r1' ],
        alfenAlgorithm:  'secp192r1',
        error:           null
    });

    return ({ method, path, body }) => {

        if (method === 'GET' && path === '/keys')
            return store();

        if (method === 'PUT' && path.endsWith('/default')) {
            const id = decodeURIComponent(path.split('/')[2] ?? '');
            keys = keys.map(key => ({ ...key, isDefault: key.id === id }));
            return store();
        }

        if (method === 'DELETE' && path.startsWith('/keys/')) {
            const id = decodeURIComponent(path.split('/')[2] ?? '');
            keys = keys.filter(key => key.id !== id);
            return store();
        }

        if (method === 'POST' && path === '/keys') {
            const { algorithm } = body as { algorithm: string };
            const made = aKey(`new-${keys.length}`, algorithm, false);
            keys = [ ...keys, made ];
            return { id: made.id, algorithm, publicKey: made.publicKey };
        }

        return undefined;

    };

}

const drawn = (root: HTMLElement) => root.querySelector('#add-form') !== null;


test('what is typed for a new key, and its focus, outlives another key being made the identity', async () => {

    const root  = await open(signingKeysPage, '/configuration/keys', [ 'keys:read', 'keys:edit' ], aMeter(), drawn);
    const note  = field(root, '#add-form', 'note');

    type(note, 'for the receipts', 4);

    root.querySelector<HTMLButtonElement>('[data-default="p384"]')!.click();

    await until(() => root.querySelector('[data-default="p256"]') !== null, 'the other key did not become the identity');

    const after = field(root, '#add-form', 'note');

    assert.ok(after === note, 'the note field was drawn anew');
    assert.equal(after.value, 'for the receipts');
    assert.ok(document.activeElement === note, 'the note field lost the focus');
    assert.equal(after.selectionStart, 4);

});


test('a key made empties the form it was asked for in', async () => {

    const root = await open(signingKeysPage, '/configuration/keys', [ 'keys:read', 'keys:edit' ], aMeter(), drawn);

    type(field(root, '#add-form', 'note'), 'for the receipts');

    submit(root, '#add-form');

    await until(() => root.querySelector('[data-key="new-2"]') !== null, 'the new key was not drawn');
    await until(() => field(root, '#add-form', 'note').value === '', 'the form kept what it was asked with');

    assert.ok(asked.some(one => one.method === 'POST' && one.path === '/keys'), 'nothing was asked to be made');

});


test('a key keeps its card while the one before it is removed', async () => {

    const root  = await open(signingKeysPage, '/configuration/keys', [ 'keys:read', 'keys:edit' ], aMeter(), drawn);
    const card  = root.querySelector('[data-key="p384"]')!.closest('section');

    root.querySelector<HTMLButtonElement>('[data-remove="p256"]')!.click();

    await until(() => root.querySelector('[data-key="p256"]') === null, 'the key was not removed');

    assert.ok(root.querySelector('[data-key="p384"]')!.closest('section') === card, 'the card of the key that stayed was drawn anew');
    assert.ok(said.some(question => question.includes("'p256'")), 'removing was not asked first');

});


test('what an algorithm is good for follows the one chosen', async () => {

    const root    = await open(signingKeysPage, '/configuration/keys', [ 'keys:read', 'keys:edit' ], aMeter(), drawn);
    const select  = field<HTMLSelectElement>(root, '#add-form', 'algorithm');

    select.value = 'secp192r1';
    select.dispatchEvent(new Event('change', { bubbles: true }));

    await until(() => root.querySelector('#algorithm-purpose')!.textContent!.includes('Alfen only'),
                'the purpose did not follow the algorithm chosen');

});


test('somebody who may only look gets no form, and is told so', async () => {

    const root = await open(signingKeysPage, '/configuration/keys', [ 'keys:read' ], aMeter(),
                            root => root.querySelector('[data-key="p256"]') !== null);

    assert.ok(root.querySelector('#add-form') === null, 'there is a form to make a key with');
    assert.ok(root.querySelector('[data-remove]') === null, 'there is a button to remove a key with');
    assert.match(root.querySelector('.notice')!.textContent!, /look at the signing keys/);

});
