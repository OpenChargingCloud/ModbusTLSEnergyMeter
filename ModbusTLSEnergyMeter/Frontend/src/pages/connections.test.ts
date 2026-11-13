// The connections page drawn against a stand-in meter: nobody while nobody
// is connected; each connection with its role, where it comes from, what it
// asked and whose certificate it showed; a certificate without a role said
// to be one; and what Reload brings is what is there then.

import { asked, open, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { ModbusConnection } from '../api/client.ts';

const { connectionsPage } = await import('./connections.ts');


function aConnection(id: number, role: string | null, more: Partial<ModbusConnection> = {}): ModbusConnection {
    return {
        id, role,
        peer:               `192.168.1.${id}:5${id}000`,
        clientSubject:      `CN=client-${id}, O=Test`,
        clientFingerprint:  `AB${id}`.padEnd(64, '0'),
        protocol:           'TLS 1.3',
        since:              new Date(Date.now() - 90_000).toISOString(),
        requests:           0,
        refused:            0,
        lastRequest:        null,
        ...more
    };
}

/** A meter with the connections it is given - which may change under it. */
function aMeter(connections: () => ModbusConnection[]): (one: Asked) => unknown {
    return ({ method, path }) =>
        method === 'GET' && path === '/meter/connections'
            ? { connections: connections() }
            : undefined;
}

const drawn = (root: HTMLElement) => root.querySelector('#connections') !== null;

const cells = (root: HTMLElement, id: number) =>
    [ ...root.querySelectorAll(`[data-connection="${id}"] td`) ].map(cell => (cell.textContent ?? '').replace(/\s+/g, ' ').trim());


test('nobody, while nobody is connected', async () => {

    const root = await open(connectionsPage, '/connections', [ 'log:read' ], aMeter(() => []), drawn);

    assert.equal(root.querySelector('#count')?.textContent, 'nobody');
    assert.equal(root.querySelector('#nobody')?.textContent, 'Nobody is connected to this meter over Modbus/TLS.');
    assert.equal(root.querySelector('table'), null);

});


test('each connection with its role, where it comes from, what it asked and whose certificate it showed', async () => {

    const root = await open(connectionsPage, '/connections', [ 'log:read' ],
                            aMeter(() => [ aConnection(3, 'GridServiceSunSpec', { requests: 12, refused: 1, lastRequest: new Date().toISOString() }),
                                           aConnection(4, null) ]),
                            drawn);

    assert.equal(root.querySelector('#count')?.textContent, '2 connections');

    const station = cells(root, 3);

    assert.equal(station[0], '3');
    assert.equal(station[1], 'GridServiceSunSpec');
    assert.equal(station[2], '192.168.1.3:53000');
    assert.match(station[4]!, /^12 1 refused last /);
    assert.equal(station[5], 'CN=client-3, O=Test TLS 1.3');

    // The fingerprint is there for whoever compares it, without widening the table.
    assert.equal(root.querySelector('[data-connection="3"] td:last-child')?.getAttribute('title'), `SHA-256 ${'AB3'.padEnd(64, '0')}`);

    const stranger = cells(root, 4);

    assert.equal(stranger[1], 'no role');
    assert.equal(stranger[4], '0', 'neither a refusal nor a last request that was not');

});


test('what Reload brings is who is connected then, and a connection that stayed is the row it was', async () => {

    let now = [ aConnection(1, 'ReadOnlySunSpec'), aConnection(2, 'GridServiceSunSpec') ];

    const root   = await open(connectionsPage, '/connections', [ 'log:read' ], aMeter(() => now), drawn);
    const stayed = root.querySelector('[data-connection="2"]');

    now = [ aConnection(2, 'GridServiceSunSpec', { requests: 5 }) ];

    const before = asked.filter(one => one.method === 'GET' && one.path === '/meter/connections').length;

    document.querySelector<HTMLButtonElement>('#reload')!.click();

    await until(() => root.querySelector('#count')?.textContent === '1 connection', 'Reload did not bring who is connected now');

    assert.equal(asked.filter(one => one.method === 'GET' && one.path === '/meter/connections').length, before + 1);
    assert.equal(root.querySelector('[data-connection="1"]'), null);
    assert.equal(root.querySelector('[data-connection="2"]'), stayed);
    assert.equal(cells(root, 2)[4], '5');

});
