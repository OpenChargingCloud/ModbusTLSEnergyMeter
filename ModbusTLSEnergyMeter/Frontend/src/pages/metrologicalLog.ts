import { api, logLevels, type LogEntry, type LogLevel } from '../api/client';
import { html, must, render, type HTMLFragment } from '../html';
import { drawOrder } from '../logs/order';
import { logs } from '../logs/store';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage, formatTime, formatTimestamp, isAtLeast } from '../ui';

/**
 * The log as evidence: what it says, and whether it can still be believed.
 *
 * Every Modbus request is in here, allowed or refused. A log that recorded
 * only what was permitted could not afterwards answer who was turned away,
 * how often, or with which certificate - which is the question this page
 * exists for.
 *
 * Its twin under /logs shows the same entries as they arrive and is the one
 * to watch while something is going wrong. This one is for afterwards: it
 * walks the files on disk, checks that every line matches its own hash,
 * follows the line before it and carries the signature of a key this meter
 * holds, and says so plainly when it does not.
 *
 * The list is fed by the store, which follows the meter's event stream from
 * the moment somebody signs in - so this page opens on what happened while
 * they were elsewhere rather than on an empty list. Filtering happens here,
 * over what is already in the browser, which is why it is instant.
 */
export const metrologicalLogPage: Page = {

    title: 'Metrological log',

    render({ root }) {

        const content = shell(root, {
            active:    '/metrological-log',
            title:     'Metrological log',
            subtitle:  'What this meter recorded, and whether the record on disk is still intact.',
            actions:   html`<button type="button" id="verify" class="btn small">Check the log</button>`
        });

        let tag:      string   = '';
        let minimum:  LogLevel = 'debug';

        render(content, html`
            <div class="log-filters">

                <label>Tag
                    <select id="tag">
                        <option value="">everything</option>
                    </select>
                </label>

                <label>From level
                    <select id="level">
                        ${logLevels.map(level => html`<option value="${level}">${level}</option>`)}
                    </select>
                </label>

                <span class="chip" id="count"></span>
                <span class="stream-state" id="stream"></span>

            </div>

            <div id="verdict"></div>
            <div class="log" id="log"></div>
            <p class="log-foot muted small" id="foot"></p>
        `);

        const tagSelect    = must<HTMLSelectElement>(content, '#tag');
        const levelSelect  = must<HTMLSelectElement>(content, '#level');
        const list         = must<HTMLElement>(content, '#log');
        const count        = must<HTMLElement>(content, '#count');
        const stream       = must<HTMLElement>(content, '#stream');
        const foot         = must<HTMLElement>(content, '#foot');
        const verdict      = must<HTMLElement>(content, '#verdict');

        tagSelect.addEventListener('change', () => {
            tag = tagSelect.value;
            drawList();
        });

        levelSelect.addEventListener('change', () => {
            minimum = levelSelect.value as LogLevel;
            drawList();
        });


        function matches(entry: LogEntry): boolean {
            return isAtLeast(entry.level, minimum) &&
                   (tag === '' || entry.level === tag || entry.tags.includes(tag));
        }

        function drawTags(): void {

            const known = new Set(Array.from(tagSelect.options).map(option => option.value));

            for (const name of [...logs.tags].sort())
                if (!known.has(name))
                    tagSelect.add(new Option(name, name));

            tagSelect.value = tag;

        }

        /** Newest first: what just happened is what somebody came here for. */
        function drawList(): void {

            const shown = drawOrder(logs.entries.filter(matches));

            render(list, html`${shown.map(line)}`);

            count.textContent = shown.length === logs.entries.length
                                    ? `${shown.length} entries`
                                    : `${shown.length} of ${logs.entries.length} entries`;

            foot.textContent = logs.capacity > 0
                                   ? `This meter keeps the newest ${logs.capacity} entries in memory; the log on disk goes back further.`
                                   : '';

        }

        function drawStream(): void {
            stream.className   = `stream-state ${logs.streamConnected ? 'on' : 'off'}`;
            stream.textContent = logs.streamConnected ? 'live' : 'reconnecting';
        }

        const unsubscribe = logs.onChange(event => {

            if (event.type === 'error') {
                render(verdict, html`<div class="error-box">${event.text}</div>`);
                return;
            }

            if (event.type === 'stream') {
                drawStream();
                return;
            }

            drawTags();
            drawList();

        });

        drawTags();
        drawList();
        drawStream();

        // Somebody who opens this page wants what is there now, not what was
        // there when they signed in.
        void logs.reload();


        must<HTMLButtonElement>(root, '#verify').addEventListener('click', () => {

            const button = must<HTMLButtonElement>(root, '#verify');

            button.disabled    = true;
            button.textContent = 'Checking ...';

            void (async () => {
                try
                {
                    render(verdict, verdictOf(await api.verifyLog()));
                }
                catch (problem)
                {
                    render(verdict, html`<div class="error-box">${errorMessage(problem)}</div>`);
                }
                finally
                {
                    button.disabled    = false;
                    button.textContent = 'Check the log';
                }
            })();

        });

        return () => unsubscribe();

    }

};


/** One line of the log. */
function line(entry: LogEntry): HTMLFragment {

    const denied = entry.tags.includes('denied');

    return html`
        <div class="line ${entry.level} ${denied ? 'denied' : ''}" title="${formatTimestamp(entry.timestamp)}">
            <span class="ts">${formatTime(entry.timestamp)}</span>
            <span class="chip level ${entry.level}">${entry.level}</span>
            <span class="msg">${entry.message}</span>
            <span class="tags">${entry.tags.join(' ')}</span>
        </div>
    `;

}


/** What walking the log on disk found, and what that is worth. */
function verdictOf(result: Awaited<ReturnType<typeof api.verifyLog>>): HTMLFragment {

    if (!result.persisted)
        return html`<div class="notice">${result.why ?? 'This meter keeps its log in memory only.'}</div>`;

    return html`
        <section class="card verdict">

            <h2>
                <i class="fa-solid fa-file-signature"></i> The log on disk
                <span class="chip ${result.intact ? 'on' : 'alert'}">${result.intact ? 'intact' : 'broken'}</span>
            </h2>

            ${result.intact
                  ? html`<p class="small">
                             Every one of the ${result.entries} lines matches its own hash, follows the
                             line before it, and is signed by key <code>${result.keyId}</code>.
                         </p>`
                  : html`<p class="form-error">${result.firstProblem}</p>`}

            <table class="kv">
                <tr><td>Head</td><td class="wrap"><code>${result.head}</code></td></tr>
                <tr><td>Where</td><td class="wrap">${result.path}</td></tr>
                <tr><td>Kept</td><td>${result.keepDays} days</td></tr>
                ${(result.files ?? []).map(file => html`
                    <tr>
                        <td>${file.name}</td>
                        <td>${file.entries} lines - ${file.intact ? 'intact' : file.problem}</td>
                    </tr>
                `)}
            </table>

            <p class="hint">
                The signing key sits beside the log, so this says the files were not edited by
                anybody who lacked it - not that nobody holding it rewrote them. Compare the head
                against a copy kept elsewhere to find out whether the log was replaced or cut short.
            </p>

        </section>
    `;

}
