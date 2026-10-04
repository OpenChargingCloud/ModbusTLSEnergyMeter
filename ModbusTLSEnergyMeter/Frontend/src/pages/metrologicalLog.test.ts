// The log book page drawn against a stand-in meter: only what is evidence is
// shown, a line keeps its element when the log is read again with a newer
// entry above it, the level filter hides what is below it, and checking the
// log says what was found - or what went wrong - and gives the button back.

import { open, refused, until, answer, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { LogEntry, LogVerification } from '../api/client.ts';

const { metrologicalLogPage } = await import('./metrologicalLog.ts');
const { logs }                = await import('@node/logs/store.ts');


function anEntry(id: number, level: LogEntry['level'], message: string, metrological = true): LogEntry {
    return {
        id, level, message,
        timestamp:  `2026-10-04T10:00:${String(id).padStart(2, '0')}Z`,
        tags:       [ 'modbus' ],
        ...(metrological ? { metrological: true as const } : {})
    };
}

/** A meter whose log holds these entries, and which checks its log book like so. */
function aMeter(entries: () => LogEntry[], verification: () => unknown): (one: Asked) => unknown {
    return ({ method, path }) => {

        if (method === 'GET' && path === '/logs')
            return { lastId: Math.max(0, ...entries().map(entry => entry.id)), capacity: 500, tags: [ 'modbus' ], entries: entries() };

        if (method === 'GET' && path === '/logs/verify')
            return verification();

        return undefined;

    };
}

const intact: LogVerification = { persisted: true, intact: true, entries: 3, keyId: 'p256', head: 'abc123',
                                  path: '/var/lib/meter/logs', keepDays: 0, files: [] };

const lines = (root: HTMLElement) => [...root.querySelectorAll<HTMLElement>('#log .line')];


test('only what is evidence is shown, and a line keeps its element as the log grows', async () => {

    let entries = [ anEntry(1, 'notice', 'started'), anEntry(2, 'info', 'not evidence', false), anEntry(3, 'warning', 'refused a write') ];

    const root = await open(metrologicalLogPage, '/metrological-log', [ 'log:read' ], aMeter(() => entries, () => intact),
                            root => lines(root).length === 2);

    assert.deepEqual(lines(root).map(line => line.querySelector('.msg')!.textContent), [ 'refused a write', 'started' ]);

    const refusedAWrite = lines(root)[0];

    entries = [ ...entries, anEntry(4, 'notice', 'a new certificate') ];
    await logs.reload();

    await until(() => lines(root).length === 3, 'the newer entry was not drawn');

    assert.equal(lines(root)[0]!.querySelector('.msg')!.textContent, 'a new certificate');
    assert.ok(lines(root)[1] === refusedAWrite, 'a line that was there was drawn anew');
    assert.equal(root.querySelector('#count')!.textContent, '3 entries');

});


test('the level chosen hides what is below it', async () => {

    const entries = [ anEntry(1, 'notice', 'started'), anEntry(2, 'warning', 'refused a write') ];

    const root = await open(metrologicalLogPage, '/metrological-log', [ 'log:read' ], aMeter(() => entries, () => intact),
                            root => lines(root).length === 2);

    const level = root.querySelector<HTMLSelectElement>('#level')!;
    level.value = 'warning';
    level.dispatchEvent(new Event('change', { bubbles: true }));

    await until(() => lines(root).length === 1, 'the notice was not hidden');
    assert.equal(root.querySelector('#count')!.textContent, '1 of 2 entries');

});


test('checking the log says what it found, or why it could not, and gives the button back', async () => {

    const entries = [ anEntry(1, 'notice', 'started') ];
    let verdict: () => unknown = () => intact;

    const root = await open(metrologicalLogPage, '/metrological-log', [ 'log:read' ], aMeter(() => entries, () => verdict()),
                            root => lines(root).length === 1);

    const button = root.querySelector<HTMLButtonElement>('#verify')!;

    button.click();

    await until(() => root.querySelector('.verdict .chip.ok')?.textContent === 'intact', 'the verdict was not drawn');
    await until(() => !button.disabled, 'the button was not given back');
    assert.match(root.querySelector('.verdict')!.textContent!, /signed by key\s+p256/);

    verdict = () => refused(500, 'The log book could not be read.');
    answer(aMeter(() => entries, () => verdict()));

    button.click();

    await until(() => root.querySelector('#verdict .error-box')?.textContent === 'The log book could not be read.',
                'the failure was not said');
    assert.ok(root.querySelector('.verdict') === null, 'the earlier verdict was left standing');
    await until(() => !button.disabled && button.textContent === 'Check the log', 'the button was not given back');

});
