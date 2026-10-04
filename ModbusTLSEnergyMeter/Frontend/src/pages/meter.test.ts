// The meter page drawn against a stand-in meter: its numbers follow every
// poll in the elements they were drawn in; a mode chosen and not set yet
// outlives a poll; a mode changed through the other door moves an untouched
// selector along; a mode set empties the draft; a refusal says why and keeps
// the choice.

import { asked, field, leave, open, refused, submit, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { after, test } from 'node:test';

import type { MeterModeName, MeterReadings } from '../api/client.ts';

const { meterPage } = await import('./meter.ts');

// The page polls every two seconds; left, it stops.
after(leave);


const descriptions: Record<MeterModeName, string> = {
    net:     'net, at the grid connection point',
    import:  'import only, in front of a load',
    export:  'export only, in front of a generator'
};

function readings(power: number, mode: MeterModeName): MeterReadings {
    const phase = (name: string, share: number) => ({ name, voltage_V: 230, current_A: Math.abs(power * share) / 230, power_W: power * share });
    return {
        manufacturer: 'OpenChargingCloud', model: 'Simulated', options: '', version: '1', serialNumber: 'meter-001',
        unitAddress: 1, sunSpecModel: 203, frequency_Hz: 50,
        phases:      [ phase('L1', 1 / 3), phase('L2', 1 / 3), phase('L3', 1 / 3) ],
        total:       phase('Total', 1),
        energy:      { imported_Wh: 1000, exported_Wh: 0 },
        meterMode:   { name: mode, value: [ 'net', 'import', 'export' ].indexOf(mode), description: descriptions[mode] },
        simulation:  { load_W: 3000, generation_W: 0, timeOfDay: '2026-10-04T22:00:00Z', dayLength_s: 86400 }
    } as unknown as MeterReadings;
}

/** A meter that reads so and is in this mode - both may be changed while the page is open. */
function aMeter(now: { power: number; mode: MeterModeName; refusesModes?: boolean }): (one: Asked) => unknown {
    return ({ method, path, body }) => {

        if (method === 'GET' && path === '/meter')
            return readings(now.power, now.mode);

        if (method === 'GET' && path === '/status')
            return { serialNumber: 'meter-001', device: 'simulated', startedAt: '2026-10-04T09:00:00Z',
                     modbus: { address: '0.0.0.0', port: 802, running: true, baseAddress: 40000, registerCount: 200 },
                     web: { url: 'http://127.0.0.1/' } };

        if (method === 'PUT' && path === '/meter/mode') {
            if (now.refusesModes)
                return refused(409, 'The mode register is locked.');
            now.mode = (body as { mode: MeterModeName }).mode;
            return { name: now.mode, value: 0, description: descriptions[now.mode] };
        }

        return undefined;

    };
}

const drawn  = (root: HTMLElement) => root.querySelector('#mode-form') !== null && root.querySelector('#total-power')!.textContent !== '-';
const polled = (n: number) => () => asked.filter(one => one.method === 'GET' && one.path === '/meter').length >= n;


test('the numbers follow a poll in the elements they were drawn in, and a mode chosen outlives it', async () => {

    const now   = { power: 3000, mode: 'net' as MeterModeName };
    const root  = await open(meterPage, '/meter', [ 'meter:read', 'meter:edit' ], aMeter(now), drawn);

    const power  = root.querySelector('#total-power')!;
    const mode   = field<HTMLSelectElement>(root, '#mode-form', 'mode');

    assert.equal(mode.value, 'net');

    mode.focus();
    mode.value = 'export';
    mode.dispatchEvent(new Event('change', { bubbles: true }));

    now.power = -1500;

    await until(polled(2), 'the meter was not polled again', 4000);
    await until(() => root.querySelector('#total-power')!.textContent === '-1,500' || root.querySelector('#total-power')!.textContent === '-1.500',
                'the poll did not bring the new power', 4000);

    assert.ok(root.querySelector('#total-power') === power, 'the power was drawn into a new element');
    assert.equal(root.querySelector('#direction')!.textContent, 'exporting');
    assert.ok(field<HTMLSelectElement>(root, '#mode-form', 'mode') === mode, 'the selector was drawn anew');
    assert.equal(mode.value, 'export', 'the poll took the mode chosen out of the selector');
    assert.ok(document.activeElement === mode, 'the selector lost the focus');

});


test('a mode changed through the other door moves an untouched selector along', async () => {

    const now   = { power: 3000, mode: 'net' as MeterModeName };
    const root  = await open(meterPage, '/meter', [ 'meter:read', 'meter:edit' ], aMeter(now), drawn);

    now.mode = 'import';

    await until(() => root.querySelector('#mode-chip')!.textContent === 'import', 'the poll did not bring the new mode', 4000);
    await until(() => field<HTMLSelectElement>(root, '#mode-form', 'mode').value === 'import', 'the selector stayed where it was');

});


test('a mode set is said, and the selector is no draft any more', async () => {

    const now   = { power: 3000, mode: 'net' as MeterModeName };
    const root  = await open(meterPage, '/meter', [ 'meter:read', 'meter:edit' ], aMeter(now), drawn);
    const mode  = field<HTMLSelectElement>(root, '#mode-form', 'mode');

    mode.value = 'import';
    mode.dispatchEvent(new Event('change', { bubbles: true }));

    submit(root, '#mode-form');

    await until(() => root.querySelector('#form-note')!.textContent === `This meter is now ${descriptions.import}.`, 'the mode set was not said');
    await until(() => root.querySelector('#mode-chip')!.textContent === 'import', 'the page did not show the new mode');

    assert.equal(mode.value, 'import');
    // The selected attribute is what defaultSelected reflects in a browser;
    // happy-dom leaves defaultSelected out.
    assert.ok([...mode.options].find(option => option.value === 'import')!.hasAttribute('selected'),
              'the mode set is not the default of the selector, so it would count as a draft');

    // No draft any more, so the selector follows the register again when the
    // other door changes it.
    now.mode = 'export';

    await until(() => root.querySelector('#mode-chip')!.textContent === 'export', 'the poll did not bring the new mode', 4000);
    await until(() => mode.value === 'export', 'the selector stayed at the mode set, as if it still were a draft');

});


test('a mode the meter refuses says why, and keeps the one chosen', async () => {

    const now   = { power: 3000, mode: 'net' as MeterModeName, refusesModes: true };
    const root  = await open(meterPage, '/meter', [ 'meter:read', 'meter:edit' ], aMeter(now), drawn);
    const mode  = field<HTMLSelectElement>(root, '#mode-form', 'mode');

    mode.value = 'export';
    mode.dispatchEvent(new Event('change', { bubbles: true }));

    submit(root, '#mode-form');

    await until(() => root.querySelector('#form-error')!.textContent === 'The mode register is locked.', 'the refusal was not said');

    assert.equal(mode.value, 'export');

});


test('somebody who may only read gets the numbers and no commands', async () => {

    const now  = { power: 3000, mode: 'net' as MeterModeName };
    const root = await open(meterPage, '/meter', [ 'meter:read' ], aMeter(now),
                            root => root.querySelector('#total-power')?.textContent !== '-' && root.querySelector('#total-power') !== null);

    assert.ok(root.querySelector('#mode-form') === null, 'there are commands to send');

});
