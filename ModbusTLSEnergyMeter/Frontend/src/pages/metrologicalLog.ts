import { api, logLevels, type LogEntry, type LogLevel } from '../api/client';
import { drawOrder } from '@node/logs/order';
import { logs } from '@node/logs/store';
import type { Page } from '@node/router';
import { shell } from '@node/shell';
import { errorMessage, formatTime, formatTimestamp, isAtLeast } from '@node/ui';
import { html, nothing, render, repeat, type TemplateResult } from '@node/view';

/**
 * The log book: the entries that are evidence, what they say, and whether they
 * can still be believed.
 *
 * Every refused Modbus request is in here, and every write - a log that
 * recorded only what was permitted could not afterwards answer who was turned
 * away, how often, or with which certificate, which is the question this page
 * exists for - and beside them the clock, the time servers' certificates, the
 * certificates this meter shows, and its starts and stops.
 *
 * Its twin under /logs shows every entry as it arrives, these among them, and
 * is the one to watch while something is going wrong. This one is for
 * afterwards: it walks the files on disk, checks that every line matches its
 * own hash, follows the line before it and carries the signature of a key this
 * meter holds, and says so plainly when it does not.
 *
 * The list is fed by the store, which follows the meter's event stream from
 * the moment somebody signs in - so this page opens on what happened while
 * they were elsewhere rather than on an empty list. Filtering happens here,
 * over what is already in the browser, which is why it is instant.
 *
 * Drawn by view.ts: a draw changes only what differs, so that the lines that
 * were there stay the elements they were - and what is selected in them stays
 * selected - while newer ones arrive above them.
 */
export const metrologicalLogPage: Page = {

    title: 'Metrological log',

    render({ root }) {

        const content = shell(root, {
            active:    '/metrological-log',
            title:     'Metrological log',
            subtitle:  'What this meter recorded, and whether the record on disk is still intact.',
            actions:   html`<button type="button" id="verify" class="btn small"
                                @click=${(event: Event) => verify(event.currentTarget as HTMLButtonElement)}>Check the log</button>`
        });

        let tag:      string   = '';
        let minimum:  LogLevel = 'debug';

        /** What checking the log on disk found, or why it could not: nothing until it is asked. */
        let verdict: TemplateResult | typeof nothing = nothing;


        function matches(entry: LogEntry): boolean {
            return isAtLeast(entry.level, minimum) &&
                   (tag === '' || entry.level === tag || entry.tags.includes(tag));
        }

        /** What of the log in the browser is in the log book as well. */
        function book(): LogEntry[] {
            return logs.entries.filter(entry => entry.metrological === true);
        }

        /** Newest first: what just happened is what somebody came here for. */
        function draw(): void {

            const all    = book();
            const shown  = drawOrder(all.filter(matches));

            render(content, html`
                <div class="log-filters">

                    <label>Tag
                        <select id="tag" @change=${(event: Event) => { tag = (event.target as HTMLSelectElement).value; draw(); }}>
                            <option value="" ?selected=${tag === ''}>everything</option>
                            ${[...logs.tags].sort().map(name => html`<option value="${name}" ?selected=${name === tag}>${name}</option>`)}
                        </select>
                    </label>

                    <label>From level
                        <select id="level" @change=${(event: Event) => { minimum = (event.target as HTMLSelectElement).value as LogLevel; draw(); }}>
                            ${logLevels.map(level => html`<option value="${level}" ?selected=${level === minimum}>${level}</option>`)}
                        </select>
                    </label>

                    <span class="chip" id="count">${shown.length === all.length
                                                         ? `${shown.length} entries`
                                                         : `${shown.length} of ${all.length} entries`}</span>
                    <span class="stream-state ${logs.streamConnected ? 'on' : 'off'}" id="stream">${logs.streamConnected ? 'live' : 'reconnecting'}</span>

                </div>

                <div id="verdict">${verdict}</div>
                <div class="log" id="log">${repeat(shown, entry => entry.id, line)}</div>
                <p class="log-foot muted small" id="foot">${logs.capacity > 0
                    ? `This meter keeps the newest ${logs.capacity} entries of its log in memory, these among them; the log book on disk goes back further.`
                    : ''}</p>
            `);

        }

        const unsubscribe = logs.onChange(event => {

            if (event.type === 'error')
                verdict = html`<div class="error-box">${event.text}</div>`;

            draw();

        });

        draw();

        // Somebody who opens this page wants what is there now, not what was
        // there when they signed in.
        void logs.reload();


        /** Check the log on disk, the button held still and saying so meanwhile. */
        function verify(button: HTMLButtonElement): void {

            button.disabled    = true;
            button.textContent = 'Checking ...';

            void (async () => {
                try
                {
                    verdict = verdictOf(await api.verifyLog());
                }
                catch (problem)
                {
                    verdict = html`<div class="error-box">${errorMessage(problem)}</div>`;
                }
                finally
                {
                    button.disabled    = false;
                    button.textContent = 'Check the log';
                }
                draw();
            })();

        }

        return () => unsubscribe();

    }

};


/** One line of the log. */
function line(entry: LogEntry): TemplateResult {

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
function verdictOf(result: Awaited<ReturnType<typeof api.verifyLog>>): TemplateResult {

    if (!result.persisted)
        return html`<div class="notice">${result.why ?? 'This meter keeps its log in memory only.'}</div>`;

    return html`
        <section class="card verdict">

            <h2>
                <i class="fa-solid fa-file-signature"></i> The log book on disk
                <span class="chip ${result.intact ? 'ok' : 'bad'}">${result.intact ? 'intact' : 'broken'}</span>
            </h2>

            ${result.intact
                  ? html`<p class="small">
                             Every one of the ${result.entries} lines matches its own hash, follows the
                             line before it, and is signed by key <code>${result.keyId}</code>.
                         </p>`
                  : html`<p class="form-error">${result.firstProblem}</p>`}

            <div class="table-scroll">
                <table class="kv">
                    <tr><td>Head</td><td class="wrap"><code>${result.head}</code></td></tr>
                    <tr><td>Where</td><td class="wrap">${result.path}</td></tr>
                    <tr><td>Kept</td><td>${(result.keepDays ?? 0) > 0 ? `${result.keepDays} days` : 'whole - nothing is thrown away'}</td></tr>
                    ${(result.files ?? []).map(file => html`
                        <tr>
                            <td>${file.name}</td>
                            <td>${file.entries} lines - ${file.intact ? 'intact' : file.problem}</td>
                        </tr>
                    `)}
                </table>
            </div>

            <p class="hint">
                The signing key sits beside the log, so this says the files were not edited by
                anybody who lacked it - not that nobody holding it rewrote them. Compare the head
                against a copy kept elsewhere to find out whether the log was replaced or cut short.
            </p>

        </section>
    `;

}
