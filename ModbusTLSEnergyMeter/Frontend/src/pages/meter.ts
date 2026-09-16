import { api, type MeterModeName, type MeterReadings, type Status } from '../api/client';
import { auth } from '../auth';
import { html, must, render } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage, formatNumber } from '../ui';

/** How often the readings are fetched again. */
const POLL_INTERVAL = 2000;

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
 * The page is built once and then only its numbers are written again. Drawing
 * the whole thing every two seconds would be simpler and would also take the
 * cursor out of the mode selector twice a second's worth of reading time.
 */
export const meterPage: Page = {

    title: 'Meter',

    render({ root }) {

        const content = shell(root, {
            active:    '/meter',
            title:     'Meter',
            subtitle:  'What this meter is measuring right now.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayWrite = auth.can('WriteRegisters');

        let cancelled = false;
        let built     = false;
        let status: Status | null = null;


        /** The page itself, once: everything that does not change. */
        function build(meter: MeterReadings): void {

            render(content, html`

                <div class="cards">

                    <section class="card">

                        <h2>
                            <i class="fa-solid fa-bolt"></i> Measuring
                            <span class="chip" id="mode-chip"></span>
                        </h2>

                        <div class="reading" id="reading">
                            <span class="value" id="total-power">-</span>
                            <span class="unit">W</span>
                        </div>
                        <p class="muted small reading-note" id="direction"></p>

                        <div class="table-scroll">
                            <table class="numbers">
                                <thead>
                                    <tr><th></th><th>V</th><th>A</th><th>W</th></tr>
                                </thead>
                                <tbody>
                                    ${[...meter.phases, meter.total].map((phase, index) => html`
                                        <tr class="${index === meter.phases.length ? 'sum' : ''}">
                                            <td>${phase.name}</td>
                                            <td id="v-${index}">-</td>
                                            <td id="a-${index}">-</td>
                                            <td id="w-${index}">-</td>
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

                        <table class="kv">
                            <tr><td>Imported</td><td id="imported">-</td></tr>
                            <tr><td>Exported</td><td id="exported">-</td></tr>
                            <tr><td>Frequency</td><td id="frequency">-</td></tr>
                        </table>

                        <p class="hint">
                            Both counters only ever grow, as a meter's do: whichever way power is
                            flowing adds to one of them, and nothing subtracts from either.
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-sun"></i> The simulated site</h2>

                        <table class="kv">
                            <tr><td>Load</td><td id="load">-</td></tr>
                            <tr><td>Generation</td><td id="generation">-</td></tr>
                            <tr><td>Time of day</td><td id="time-of-day">-</td></tr>
                            <tr><td>A day takes</td><td id="day-length">-</td></tr>
                        </table>

                        <p class="hint">
                            Not registers: this is what the site behind the meter is doing, and the
                            mode decides how much of it this meter sees. <span id="why"></span>
                        </p>

                    </section>

                    <section class="card">

                        <h2><i class="fa-solid fa-circle-info"></i> This meter</h2>

                        <table class="kv">
                            <tr><td>Manufacturer</td><td>${meter.manufacturer}</td></tr>
                            <tr><td>Model</td><td>${meter.model} (SunSpec ${meter.sunSpecModel})</td></tr>
                            <tr><td>Serial number</td><td>${meter.serialNumber}</td></tr>
                            <tr><td>Unit address</td><td>${meter.unitAddress}</td></tr>
                            ${status ? html`
                                <tr><td>Modbus/TLS</td><td>${status.modbus.address}:${status.modbus.port}</td></tr>
                                <tr><td>Registers</td><td>${status.modbus.baseAddress} - ${status.modbus.baseAddress + status.modbus.registerCount - 1}</td></tr>
                                <tr><td>Running since</td><td>${new Date(status.startedAt).toLocaleString()}</td></tr>
                            ` : ''}
                        </table>

                    </section>

                    ${mayWrite ? html`
                        <section class="card">

                            <h2><i class="fa-solid fa-sliders"></i> Commanded registers</h2>

                            <form id="mode-form" class="form-stack">

                                <label>Meter mode (register 40094)
                                    <select name="mode" id="mode">
                                        <option value="net">0 - net, at the grid connection point</option>
                                        <option value="import">1 - import only, in front of a load</option>
                                        <option value="export">2 - export only, in front of a generator</option>
                                    </select>
                                </label>

                                <div class="form-actions">
                                    <button type="submit" class="btn primary">Set mode</button>
                                    <button type="button" class="btn" id="reset-energy">Clear energy counters</button>
                                    <span id="form-note"  class="form-notice" role="status"></span>
                                    <span id="form-error" class="form-error"  role="alert"></span>
                                </div>

                                <span class="hint">
                                    The same two registers a Modbus client writes, through the same
                                    device - so both doors end up in the log the same way.
                                </span>

                            </form>

                        </section>
                    ` : ''}

                </div>
            `);

            if (mayWrite)
                wireCommands();

            built = true;

        }

        /** The numbers, every time. */
        function fill(meter: MeterReadings): void {

            const cell = (id: string, text: string): void => {
                const element = content.querySelector(`#${id}`);
                if (element !== null)
                    element.textContent = text;
            };

            const total = meter.total;

            cell('total-power', formatNumber(total.power_W, 0));
            cell('direction',   total.power_W > 0 ? 'importing'
                              : total.power_W < 0 ? 'exporting'
                                                  : 'nothing flowing');

            must<HTMLElement>(content, '#reading').className = `reading ${total.power_W < 0 ? 'exporting' : ''}`;

            [...meter.phases, total].forEach((phase, index) => {
                cell(`v-${index}`, formatNumber(phase.voltage_V, 1));
                cell(`a-${index}`, formatNumber(phase.current_A, 2));
                cell(`w-${index}`, formatNumber(phase.power_W,   0));
            });

            cell('imported',    `${formatNumber(meter.energy.imported_Wh, 0)} Wh`);
            cell('exported',    `${formatNumber(meter.energy.exported_Wh, 0)} Wh`);
            cell('frequency',   `${formatNumber(meter.frequency_Hz, 2)} Hz`);

            cell('load',        `${formatNumber(meter.simulation.load_W, 0)} W`);
            cell('generation',  `${formatNumber(meter.simulation.generation_W, 0)} W`);
            cell('time-of-day', timeOfDay(meter.simulation.timeOfDay));
            cell('day-length',  dayLength(meter.simulation.dayLength_s));

            cell('mode-chip',   meter.meterMode.name);
            cell('why',         whyThisReading(meter));

            must<HTMLElement>(content, '#mode-chip').title = meter.meterMode.description;

            // The mode can be changed through the other door as well, so the
            // selector follows the register - but not while somebody is using
            // it, or a poll would take the choice out of their hands.
            const select = content.querySelector<HTMLSelectElement>('#mode');

            if (select !== null && document.activeElement !== select)
                select.value = meter.meterMode.name;

        }

        /** The two commanded registers, and what they say when they answered. */
        function wireCommands(): void {

            const form   = must<HTMLFormElement>(content, '#mode-form');
            const note   = must<HTMLElement>(content, '#form-note');
            const error  = must<HTMLElement>(content, '#form-error');

            function say(text: string, failed = false): void {
                note.textContent  = failed ? '' : text;
                error.textContent = failed ? text : '';
            }

            form.addEventListener('submit', event => {

                event.preventDefault();
                say('');

                const mode = must<HTMLSelectElement>(form, '#mode').value as MeterModeName;

                void (async () => {
                    try
                    {
                        const now = await api.meter.setMode(mode);
                        say(`This meter is now ${now.description}.`);
                        await load(false);
                    }
                    catch (problem)
                    {
                        say(errorMessage(problem), true);
                    }
                })();

            });

            must<HTMLButtonElement>(content, '#reset-energy').addEventListener('click', () => {

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

            });

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

                if (!built)
                    build(meter);

                fill(meter);

            }
            catch (problem)
            {

                if (cancelled)
                    return;

                // A failed poll must not wipe a page that is showing something:
                // the next tick is two seconds away, and a meter that blinked
                // is not a meter that stopped.
                if (built)
                    return;

                render(content, html`<div class="error-box">${errorMessage(problem)}</div>`);

            }

        }

        void load();

        // The only page worth polling: everything else changes when somebody
        // changes it, and the log has a stream of its own.
        const timer = window.setInterval(() => void load(false), POLL_INTERVAL);

        return () => {
            cancelled = true;
            window.clearInterval(timer);
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
