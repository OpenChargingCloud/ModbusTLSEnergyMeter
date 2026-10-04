import { api, type MeterModeName, type MeterReadings, type Status } from '../api/client';
import { auth } from '../auth';
import { html as stringHTML, must } from '@node/html';
import type { Page } from '@node/router';
import { shell } from '@node/shell';
import { errorMessage, formatNumber } from '@node/ui';
import { anyFormTypedSinceDrawn, unsaved } from '@node/unsaved';
import { html, nothing, render } from '@node/view';

/** How often the readings are fetched again. */
const POLL_INTERVAL = 2000;

/** The three modes of register 40094, as the selector offers them. */
const MODES: { name: MeterModeName; label: string }[] = [
    { name: 'net',     label: '0 - net, at the grid connection point'    },
    { name: 'import',  label: '1 - import only, in front of a load'      },
    { name: 'export',  label: '2 - export only, in front of a generator' }
];

/**
 * What this meter is measuring, and what it is measuring it as.
 *
 * The readings and the mode come from the register block, so this page shows
 * what a Modbus client reading the same meter would see. Next to them, and
 * marked as not being registers, is what the simulated site is doing: the load
 * and the generation are what the mode selects BETWEEN, and without them a
 * meter in front of a generator reading zero at three in the morning looks
 * broken rather than dark.
 *
 * Drawn by view.ts, every two seconds: a draw changes only what differs - the
 * numbers - and leaves the mode selector alone, the mode chosen in it and the
 * focus. The register's mode is the selector's default, so that the form is a
 * draft only once somebody has chosen another, and an untouched selector
 * follows the register when the other door changes it.
 */
export const meterPage: Page = {

    title: 'Meter',

    render({ root }) {

        const content = shell(root, {
            active:    '/meter',
            title:     'Meter',
            subtitle:  'What this meter is measuring right now.',
            actions:   stringHTML`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        // Reload throws a mode chosen and not set away, so it asks first - and
        // then puts the selector back as the register has it, since a poll
        // leaves a choice somebody has made alone.
        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => {

            if (!unsaved.mayBeLost())
                return;

            content.querySelector<HTMLFormElement>('#mode-form')?.reset();

            void load();

        });

        const mayWrite = auth.can('meter', 'edit');

        let cancelled = false;
        let drawn     = false;
        let status: Status | null = null;


        /** The page, every time: what does not change stays, the numbers are written anew. */
        function draw(meter: MeterReadings): void {

            const total = meter.total;

            render(content, html`

                <div class="cards">

                    <section class="card">

                        <h2>
                            <i class="fa-solid fa-bolt"></i> Measuring
                            <span class="chip" id="mode-chip" title="${meter.meterMode.description}">${meter.meterMode.name}</span>
                        </h2>

                        <div class="reading ${total.power_W < 0 ? 'exporting' : ''}" id="reading">
                            <span class="value" id="total-power">${formatNumber(total.power_W, 0)}</span>
                            <span class="unit">W</span>
                        </div>
                        <p class="muted small reading-note" id="direction">${total.power_W > 0 ? 'importing'
                                                                           : total.power_W < 0 ? 'exporting'
                                                                                               : 'nothing flowing'}</p>

                        <div class="table-scroll">
                            <table class="numbers">
                                <thead>
                                    <tr><th></th><th>V</th><th>A</th><th>W</th></tr>
                                </thead>
                                <tbody>
                                    ${[...meter.phases, total].map((phase, index) => html`
                                        <tr class="${index === meter.phases.length ? 'sum' : ''}">
                                            <td>${phase.name}</td>
                                            <td id="v-${index}">${formatNumber(phase.voltage_V, 1)}</td>
                                            <td id="a-${index}">${formatNumber(phase.current_A, 2)}</td>
                                            <td id="w-${index}">${formatNumber(phase.power_W,   0)}</td>
                                        </tr>
                                    `)}
                                </tbody>
                            </table>
                        </div>

                        <p class="hint">
                            Positive power is energy flowing into the site, negative is energy
                            flowing out of it. The currents are magnitudes either way - the
                            direction is in the sign of the power alone.
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-gauge-high"></i> Energy</h2>

                        <div class="table-scroll">
                            <table class="kv">
                                <tr><td>Imported</td><td id="imported">${formatNumber(meter.energy.imported_Wh, 0)} Wh</td></tr>
                                <tr><td>Exported</td><td id="exported">${formatNumber(meter.energy.exported_Wh, 0)} Wh</td></tr>
                                <tr><td>Frequency</td><td id="frequency">${formatNumber(meter.frequency_Hz, 2)} Hz</td></tr>
                            </table>
                        </div>

                        <p class="hint">
                            Both counters only ever grow, as a meter's do: whichever way power is
                            flowing adds to one of them, and nothing subtracts from either.
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-sun"></i> The simulated site</h2>

                        <div class="table-scroll">
                            <table class="kv">
                                <tr><td>Load</td><td id="load">${formatNumber(meter.simulation.load_W, 0)} W</td></tr>
                                <tr><td>Generation</td><td id="generation">${formatNumber(meter.simulation.generation_W, 0)} W</td></tr>
                                <tr><td>Time of day</td><td id="time-of-day">${timeOfDay(meter.simulation.timeOfDay)}</td></tr>
                                <tr><td>A day takes</td><td id="day-length">${dayLength(meter.simulation.dayLength_s)}</td></tr>
                            </table>
                        </div>

                        <p class="hint">
                            Not registers: this is what the site behind the meter is doing, and the
                            mode decides how much of it this meter sees. <span id="why">${whyThisReading(meter)}</span>
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-circle-info"></i> This meter</h2>

                        <div class="table-scroll">
                            <table class="kv">
                                <tr><td>Manufacturer</td><td>${meter.manufacturer}</td></tr>
                                <tr><td>Model</td><td>${meter.model} (SunSpec ${meter.sunSpecModel})</td></tr>
                                <tr><td>Serial number</td><td>${meter.serialNumber}</td></tr>
                                <tr><td>Unit address</td><td>${meter.unitAddress}</td></tr>
                                ${status ? html`
                                    <tr><td>Modbus/TLS</td><td>${status.modbus.address}:${status.modbus.port}</td></tr>
                                    <tr><td>Registers</td><td>${status.modbus.baseAddress} - ${status.modbus.baseAddress + status.modbus.registerCount - 1}</td></tr>
                                    <tr><td>Running since</td><td>${new Date(status.startedAt).toLocaleString()}</td></tr>
                                ` : nothing}
                            </table>
                        </div>

                    </section>

                    ${mayWrite ? html`
                        <section class="card">

                            <h2><i class="fa-solid fa-sliders"></i> Commanded registers</h2>

                            <form id="mode-form" class="form-stack" @submit=${setMode}>

                                <label>Meter mode (register 40094)
                                    <select name="mode" id="mode">
                                        ${MODES.map(mode => html`
                                            <option value="${mode.name}" ?selected=${mode.name === meter.meterMode.name}>${mode.label}</option>
                                        `)}
                                    </select>
                                </label>

                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Set mode</button>
                                    <button type="button" class="btn" id="reset-energy" @click=${clearTheCounters}>Clear energy counters</button>
                                    <span id="form-note"  class="form-notice" role="status"></span>
                                    <span id="form-error" class="form-error"  role="alert"></span>
                                </div>

                                <span class="hint">
                                    The same two registers a Modbus client writes, through the same
                                    device - so both doors end up in the log the same way.
                                </span>

                            </form>

                        </section>
                    ` : nothing}

                </div>
            `);

            drawn = true;

        }


        /** What the two commanded registers said when they answered. */
        function say(text: string, failed = false): void {
            must<HTMLElement>(content, '#form-note').textContent   = failed ? '' : text;
            must<HTMLElement>(content, '#form-error').textContent  = failed ? text : '';
        }

        function setMode(event: SubmitEvent): void {

            event.preventDefault();
            say('');

            const form = event.currentTarget as HTMLFormElement;
            const mode = must<HTMLSelectElement>(form, '#mode').value as MeterModeName;

            void (async () => {
                try
                {
                    const now = await api.meter.setMode(mode);
                    say(`This meter is now ${now.description}.`);
                    await load(false);
                    // Set, it is no draft any more: the selector's default is
                    // the register's mode now, and the form goes back to it.
                    form.reset();
                }
                catch (problem)
                {
                    say(errorMessage(problem), true);
                }
            })();

        }

        function clearTheCounters(): void {

            if (!confirm('Clear both energy counters of this meter?'))
                return;

            say('');

            void (async () => {
                try
                {
                    await api.meter.resetEnergy();
                    say('Both counters are back at zero.');
                    await load(false);
                }
                catch (problem)
                {
                    say(errorMessage(problem), true);
                }
            })();

        }

        /**
         * Load what the page shows. `withStatus` is false while polling: what a
         * meter is does not change every two seconds, and asking anyway would
         * be a second request per tick for a table that never moves.
         */
        async function load(withStatus = true): Promise<void> {

            try
            {

                const [meter, nextStatus] = await Promise.all([
                    api.meter.get(),
                    withStatus ? api.status() : Promise.resolve(status)
                ]);

                if (cancelled)
                    return;

                status = nextStatus;

                draw(meter);

            }
            catch (problem)
            {

                if (cancelled)
                    return;

                // A failed poll must not wipe a page that is showing something:
                // the next tick is two seconds away, and a meter that blinked
                // is not a meter that stopped.
                if (drawn)
                    return;

                render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);

            }

        }

        void load();

        // The only page worth polling: everything else changes when somebody
        // changes it, and the log has a stream of its own.
        const timer = window.setInterval(() => void load(false), POLL_INTERVAL);

        // A mode chosen and not set yet is in the form alone.
        const release = unsaved.heldBy(() => anyFormTypedSinceDrawn(content));

        return () => {
            cancelled = true;
            window.clearInterval(timer);
            release();
        };

    }

};


/** Why the meter reads what it reads, given what the site is doing. */
function whyThisReading(meter: MeterReadings): string {

    switch (meter.meterMode.name)
    {

        case 'import':
            return 'In front of a load it sees the load and not the generator, whether or not the sun is up.';

        case 'export':
            return meter.simulation.generation_W > 0
                       ? 'In front of a generator it sees the generation and not the load.'
                       : 'In front of a generator with the sun down there is nothing to see: zero is the reading, not a fault.';

        default:
            return 'At the grid connection point it sees the difference, so it imports at night and exports when there is more sun than load.';

    }

}

/** The simulated clock, to the minute - the seconds are noise on this page. */
function timeOfDay(iso: string): string {

    const moment = new Date(iso);

    return Number.isNaN(moment.getTime())
               ? iso
               : moment.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', hour12: false });

}

/** "a real day", or how much less than one it was compressed to. */
function dayLength(seconds: number): string {

    if (Math.abs(seconds - 86400) < 1)
        return 'a real day';

    return seconds >= 3600
               ? `${(seconds / 3600).toFixed(1)} h of real time`
               : `${Math.round(seconds / 60)} min of real time`;

}
