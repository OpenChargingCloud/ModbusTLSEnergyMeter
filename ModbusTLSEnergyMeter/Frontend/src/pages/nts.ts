import { api, type Clock, type NTSConfiguration, type NTSServerEntry, type NTSServerResult, type NTSSyncResult, type NTSTimeSource, type NTSUpdate, type TimeServerTest } from '../api/client';
import { auth } from '../auth';
import { html, must, render, type HTMLFragment } from '../html';
import type { Page } from '../router';
import { shell } from '../shell';
import { errorMessage, formatTimestamp, whileSaving } from '../ui';
import { entryOf, nameTaken, readable, withServer, withoutServer, type UsualPorts } from './ntsServers';

/**
 * Where this meter reads the time: its time servers, the rules for believing
 * them, and what legal time rests on.
 *
 * The page is the group, because the group is what the clock is checked
 * against. It used to lead with a form for one server - and saving that form,
 * for whatever reason, told the meter a lone host name, which the meter read as
 * a group of one: the PTB's four went down to the one in the form, and the
 * legal time authority went with them until the next start. Now each server is
 * a row with a Test and an Edit of its own, the group is added to at the end of
 * its list, and what the group is held to is a form of its own below it.
 *
 * The cards stand one under the other, read from the top down: whether, who,
 * by which rules, whose time counts as legal - then this meter's clock as it
 * stands, and last the button that puts all of it to work, with what came of
 * it.
 *
 * Every change takes effect at once, and the meter is told the whole list each
 * time - which is why the list is only ever changed by exactly one server at a
 * time, from a dialog, and why a change the meter refuses leaves the page as
 * it was.
 *
 * The parts are drawn separately, so that a sync or a saved server does not
 * throw away what is being typed into one of the forms.
 */
export const ntsPage: Page = {

    title: 'NTS client',

    render({ root }) {

        const content = shell(root, {
            active:    '/configuration/nts',
            title:     'NTS client',
            subtitle:  'Where this meter reads the time, and how it knows the answer is real.',
            actions:   html`<button type="button" id="reload" class="btn small">Reload</button>`
        });

        render(content, html`<div class="loading">Loading ...</div>`);

        must<HTMLButtonElement>(root, '#reload').addEventListener('click', () => void load());

        const mayChange = auth.can('ChangeNetworkSettings');
        const mayTest   = auth.can('RunDiagnostics');

        let cancelled = false;
        let current: NTSConfiguration | null = null;
        let clock:   Clock | null            = null;

        /** The answer to the sync this page asked for, until the page is loaded again. */
        let result:  NTSSyncResult | null    = null;
        let syncing = false;


        /** The ports a server is asked on unless its entry says otherwise. */
        function usualPorts(): UsualPorts {
            return {
                ntsKE:  current?.limits.defaultNTSKEPort ?? 4460,
                ntp:    current?.limits.defaultNTPPort   ?? 123
            };
        }

        /** The list as the meter has it, as entries it can be told again. */
        function entries(): NTSServerEntry[] {
            const usual = usualPorts();
            return (current?.timeSources ?? []).map(source => entryOf(source, usual));
        }


        /** The whole page, from what the meter last said. */
        function draw(): void {

            if (current === null || clock === null)
                return;

            render(content, html`

                ${mayChange ? '' : html`
                    <div class="notice">
                        Signed in as ${auth.user?.roleTitle ?? 'somebody'}, which may look at the time
                        servers but not change them.
                    </div>
                `}

                <div class="cards stacked">
                    <section class="card" id="nts-switch"></section>
                    <section class="card" id="nts-servers"></section>
                    <section class="card" id="nts-policy"></section>
                    <section class="card" id="nts-legal"></section>
                    <section class="card" id="nts-clock"></section>
                    <section class="card" id="nts-sync"></section>
                </div>

            `);

            drawSwitch();
            drawServers();
            drawPolicy();
            drawLegal();
            drawClock();
            drawSync();

            wire();

        }


        /** Whether this meter asks anybody at all. */
        function drawSwitch(): void {

            const configuration = current!;

            render(must<HTMLElement>(content, '#nts-switch'), html`

                <h2><i class="fa-solid fa-power-off"></i> Time synchronisation</h2>

                <label class="switch">
                    <input type="checkbox" id="enabled"
                           ${configuration.enabled ? html`checked` : ''}
                           ${mayChange ? '' : html`disabled`} />
                    <span>${configuration.enabled ? 'switched on' : 'switched off'}</span>
                </label>

                <p class="hint">
                    Switched off, this meter asks its time servers nothing at all, and its clock is not
                    legal time: nothing outside it has confirmed the time since.
                </p>

                <span id="switch-error" class="form-error" role="alert"></span>

            `);

        }


        /**
         * The synchronisation this page shows: the one just asked for, or the
         * last one the meter remembers - and none at all while the next one is
         * being asked for, neither the verdict nor what each server said. Left
         * standing under the spinning button, the last one read as the new
         * answer.
         */
        function shownSync(): NTSSyncResult | null {
            return syncing ? null : result ?? current?.lastSync ?? null;
        }


        /** The time servers, and what each of them said. */
        function drawServers(): void {

            const configuration = current!;
            const sources       = configuration.timeSources;
            const sync          = shownSync();
            const switchedOn    = sources.filter(source => source.enabled).length;

            render(must<HTMLElement>(content, '#nts-servers'), html`

                <h2><i class="fa-solid fa-users"></i> Time servers</h2>

                <div class="time-server-list">
                    ${sources.length === 0
                          ? html`<p class="muted small">No time server configured.</p>`
                          : sources.map((source, index) => serverView(source, index, whatItSaid(sync, source), sync !== null))}
                </div>

                <div class="form-actions">
                    <button type="button" id="add-server" class="btn" title="Add a time server"
                            aria-label="Add a time server" ${mayChange ? '' : html`disabled`}>
                        <i class="fa-solid fa-plus"></i>
                    </button>
                    <span class="hint">
                        At least ${configuration.group.minServers} of the ${switchedOn} switched on must answer,
                        and a disagreement of ${configuration.group.maxDeviationSeconds} s or more is written
                        down. Servers sharing a priority are asked together; a lower priority is asked first.
                    </span>
                </div>

            `);

        }


        /** What the group is held to, as a form. */
        function drawPolicy(): void {

            const configuration = current!;
            const settings      = configuration.settings;
            const limits        = configuration.limits;
            const held          = configuration.group.minServers;
            const off           = mayChange ? '' : html`disabled`;

            render(must<HTMLElement>(content, '#nts-policy'), html`

                <h2><i class="fa-solid fa-sliders"></i> Group policy</h2>

                <form id="policy-form" class="form-stack">

                    <label>Servers that must answer
                        <input type="number" name="minServers" min="1" max="255" step="1"
                               value="${settings.minServers}" ${off} />
                        <span class="hint">
                            ${held < settings.minServers
                                  ? html`Held to ${held} for as long as only ${held} ${held === 1 ? 'is' : 'are'} switched on.`
                                  : html`Two is the fewest that notice a server which is wrong rather than away.`}
                        </span>
                    </label>

                    <label>Agreed deviation in seconds
                        <input type="number" name="maxDeviationSeconds" step="0.001"
                               min="${limits.minDeviation}" max="${limits.maxDeviation}"
                               value="${settings.maxDeviationSeconds}" ${off} />
                        <span class="hint">How far apart their answers may be before the disagreement is written into the log.</span>
                    </label>

                    <label>Check the clock every ... seconds
                        <input type="number" name="checkEverySeconds" step="1"
                               min="${limits.minCheckEvery}" max="${limits.maxCheckEvery}"
                               value="${settings.checkEverySeconds}" ${off} />
                    </label>

                    <label>Timeout of a test in seconds
                        <input type="number" name="timeoutSeconds" step="0.1" min="0.1" max="${limits.maxTimeout}"
                               value="${settings.timeoutSeconds ?? ''}" ${off} />
                        <span class="hint">
                            What a server's Test allows each of its two steps, the key exchange and the time request.
                            "Check the clock now" asks the way the clock check does, with timeouts of its own.
                        </span>
                    </label>

                    <div class="form-actions">
                        <button type="submit" class="btn primary" ${off}>Save</button>
                        <span id="policy-note"  class="form-notice" role="status"></span>
                        <span id="policy-error" class="form-error"  role="alert"></span>
                    </div>

                    <span class="hint">Saved to <span class="path">${configuration.file}</span>, and in effect at once.</span>

                </form>

            `);

        }


        /**
         * Whose time counts as legal time, as a form.
         *
         * A statement of its own and not one of the group's rules: no meter can
         * find out by itself who stands behind a time server. Naming one is the
         * operator vouching for it, and it is what makes the question "is this
         * legal time" mean anything at all.
         */
        function drawLegal(): void {

            const configuration = current!;
            const settings      = configuration.settings;
            const limits        = configuration.limits;
            const off           = mayChange ? '' : html`disabled`;

            render(must<HTMLElement>(content, '#nts-legal'), html`

                <h2><i class="fa-solid fa-scale-balanced"></i> What counts as legal time</h2>

                <form id="legal-form" class="form-stack">

                    <label>Authority
                        <input type="text" name="legalTimeAuthority" maxlength="${limits.maxAuthorityLength}"
                               value="${settings.legalTimeAuthority ?? ''}" placeholder="PTB" ${off} />
                        <span class="hint">Emptied and saved, no authority is named, and this meter's time is never legal time.</span>
                    </label>

                    <label>Tolerance in seconds
                        <input type="number" name="legalTimeToleranceSeconds" step="0.001"
                               min="${limits.minTolerance}" max="${limits.maxTolerance}"
                               value="${settings.legalTimeToleranceSeconds}" ${off} />
                        <span class="hint">How far off this meter's clock may be found and still keep legal time.</span>
                    </label>

                    <label>Max age of a check in seconds
                        <input type="number" name="legalTimeMaxAgeSeconds" step="1"
                               min="${limits.minMaxAge}" max="${limits.maxMaxAge}"
                               value="${settings.legalTimeMaxAgeSeconds}" ${off} />
                    </label>

                    <div class="form-actions">
                        <button type="submit" class="btn primary" ${off}>Save</button>
                        <span id="legal-note"  class="form-notice" role="status"></span>
                        <span id="legal-error" class="form-error"  role="alert"></span>
                    </div>

                </form>

            `);

        }


        /** This meter's clock as it stands, and what it is worth. */
        function drawClock(): void {

            const time  = clock!;
            const sync  = current?.lastSync ?? null;

            render(must<HTMLElement>(content, '#nts-clock'), html`

                <h2>
                    <i class="fa-solid fa-hourglass-half"></i> This meter's clock
                    <span class="chip ${time.legal ? 'on' : 'alert'}">${time.legal ? 'legal time' : 'unverified'}</span>
                </h2>

                <div class="kv-list">
                    ${kv('Now', formatTimestamp(time.now))}
                    ${kv('Checked against', time.nts.servers === null
                                                ? 'nobody - NTS is switched off'
                                                : html`${time.nts.servers.join(', ')}${time.nts.servers.length > 1
                                                                                            ? html` <span class="muted">- at least ${time.nts.minServers} must answer</span>`
                                                                                            : ''}`)}
                    ${kv('Last sync', sync === null ? 'never' : formatTimestamp(sync.at))}
                    ${kv('Last sync result', sync === null ? '-' : sync.ok ? 'a time was found' : (sync.error ?? 'no time was found'))}
                    ${kv('Last check', time.nts.checkedAt === null
                                           ? 'never'
                                           : html`${formatTimestamp(time.nts.checkedAt)}${time.nts.answered !== null
                                                                                            ? html` <span class="muted">- ${time.nts.answered} of ${time.nts.asked} answered</span>`
                                                                                            : ''}`)}
                    ${kv('Offset', ms(time.nts.offset_ms, true))}
                    ${kv('Authority', time.authority ?? 'none configured')}
                    ${kv('Tolerance', `${Math.round(time.toleranceSeconds * 1000)} ms`)}
                    ${kv('Max age of a check', `${Math.round(time.maxAgeSeconds / 60)} min`)}
                </div>

                <p class="hint">${verdict(time)}. "Last check" is the last synchronisation that found a time;
                                 "Last sync" is the last one, whichever way it went.</p>

            `);

        }


        /**
         * The button that asks all the servers, and what the group concluded.
         *
         * A card of its own at the end of the page, below everything it puts
         * to work: the servers, and the rules they are held to.
         */
        function drawSync(): void {

            const sync = shownSync();

            render(must<HTMLElement>(content, '#nts-sync'), html`

                <h2><i class="fa-solid fa-rotate"></i> Synchronisation</h2>

                <div class="sync-bar">
                    <button type="button" id="sync" class="btn primary large" ${mayTest && !syncing ? '' : html`disabled`}>
                        <i class="fa-solid fa-rotate ${syncing ? 'fa-spin' : ''}"></i>
                        ${syncing ? 'Asking the servers ...' : 'Check the clock now'}
                    </button>
                    <span class="hint">
                        ${mayTest
                              ? html`
                                    Asks every server that is switched on, the way the clock check does: a key
                                    exchange over TLS, then one authenticated NTP request each. Every step goes
                                    into the log. The clock of this meter is not stepped by it.
                                `
                              : html`Asking the servers needs a role that may run diagnostics.`}
                    </span>
                </div>

                <span id="sync-error" class="form-error" role="alert"></span>

                ${sync === null ? '' : verdictView(sync)}

            `);

        }


        /**
         * One time server: who it is, what it said last, and what can be done
         * with it.
         *
         * A server switched on can be missing from a synchronisation without
         * anything being wrong with it: the bands are asked in turn, and one
         * with a higher priority is not asked when those before it were
         * enough. Its row says so rather than showing nothing, which looks like
         * a server that has been forgotten.
         */
        function serverView(source:  NTSTimeSource,
                            index:   number,
                            said:    NTSServerResult | undefined,
                            synced:  boolean): HTMLFragment {

            const usual  = usualPorts();
            const ports  = source.ntsKEPort !== usual.ntsKE || source.ntpPort !== usual.ntp
                               ? `, ports ${source.ntsKEPort} and ${source.ntpPort}`
                               : '';

            return html`
                <div class="time-server-row ${source.enabled ? '' : 'off'}">

                    <div class="who">
                        <span class="name">${readable(source.hostname)}</span>
                        <span class="muted small">
                            priority ${source.priority}${ports}${source.enabled ? '' : html`, <strong>switched off</strong>`}
                        </span>
                    </div>

                    <div class="said">
                        ${said === undefined
                              ? synced && source.enabled
                                    ? html`<span class="muted">not asked in the last synchronisation</span>`
                                    : ''
                              : said.ok
                                    ? html`<span class="answer ok">${ms(said.offset_ms, true)}, round trip ${ms(said.roundTrip_ms)}</span>`
                                    : html`<span class="answer bad">${said.error ?? (said.authenticated === false
                                                                                           ? 'answered, but the answer did not authenticate'
                                                                                           : 'no answer')}</span>`}
                        <span class="muted small">
                            ${source.lastExchange
                                  ? html`${source.cookies ?? 0} cookie(s)${source.aeadAlgorithm ? `, ${source.aeadAlgorithm}` : ''}, exchanged ${formatTimestamp(source.lastExchange)}`
                                  : 'not asked yet'}
                        </span>
                    </div>

                    <div class="root-ca">
                        ${source.rootCA
                              ? html`
                                    <span class="ca-name" title="${source.rootCA.subject}">
                                        <span class="muted small">Root CA</span> ${source.rootCA.name}
                                    </span>
                                    <span class="fingerprint" title="SHA-256 fingerprint of the root CA">${fingerprintView(source.rootCA.fingerprint)}</span>
                                `
                              : html`<span class="muted small">Root CA: no key exchange yet</span>`}
                        ${pinsView(source)}
                    </div>

                    <div class="actions">
                        <button type="button" class="btn small" data-test="${index}"
                                title="Ask this server, and only this one" ${mayTest ? '' : html`disabled`}>
                            <i class="fa-solid fa-list-check"></i> Test
                        </button>
                        <button type="button" class="btn small" data-edit="${index}" ${mayChange ? '' : html`disabled`}>
                            <i class="fa-solid fa-pen"></i> Edit
                        </button>
                    </div>

                </div>
            `;

        }


        /**
         * What a server is held to beyond the usual checks, and what its last
         * key exchange made of it - only where there is something to say: a
         * server held to nothing, whose certificate was accepted, says nothing
         * here.
         */
        function pinsView(source: NTSTimeSource): HTMLFragment {

            const pins       = source.heldTo    ?? null;
            const judgement  = source.judgement ?? null;

            return html`
                ${pins === null
                      ? ''
                      : html`
                            <span class="muted small">
                                Held to${pins.onMismatch === 'record' ? ' - a mismatch is only written down' : ''}
                            </span>
                            ${pins.certificate
                                  ? html`<span class="fingerprint" title="SHA-256 fingerprint of the certificate it has to show">certificate ${fingerprintView(pins.certificate)}</span>`
                                  : ''}
                            ${pins.root
                                  ? html`<span class="fingerprint" title="SHA-256 fingerprint of the root its chain has to end at">root ${fingerprintView(pins.root)}</span>`
                                  : ''}
                        `}
                ${judgement === null || judgement.outcome === 'accepted'
                      ? ''
                      : html`<span><span class="chip ${judgement.accepted ? 'warn' : 'alert'}"
                                         title="At the key exchange of ${formatTimestamp(judgement.at)}">${outcomeText(judgement.outcome)}</span></span>`}
            `;

        }


        /**
         * A fingerprint that breaks in the middle and nowhere else.
         *
         * Two halves of 32 read against a pinned fingerprint far better than a
         * line broken wherever the column happens to end - and at every width
         * the column has, they are the same two halves. The break is a <wbr>
         * rather than a space, so that copying it copies the fingerprint.
         */
        function fingerprintView(fingerprint: string): HTMLFragment {
            return html`${(fingerprint.match(/.{1,32}/g) ?? [fingerprint]).map(part => html`${part}<wbr>`)}`;
        }


        /** What the group concluded, in one line under the button that asked. */
        function verdictView(sync: NTSSyncResult): HTMLFragment {

            const group = sync.group;

            return html`
                <div class="query-result sync-verdict ${sync.ok ? 'ok' : 'bad'}">
                    <strong>${sync.ok ? 'Succeeded:' : 'Failed:'}</strong>
                    ${sync.ok && group
                          ? html`${group.answered} of ${sync.servers?.length ?? 0} server(s) answered
                                 (${group.required} required), offset ${ms(group.offset_ms, true)},
                                 spread ${ms(group.spread_ms)}`
                          : html`${sync.error ?? 'no reason was given'}`}
                    <span class="muted small">
                        - ${formatTimestamp(sync.at)}${sync.runtime_ms ? `, ${sync.runtime_ms} ms` : ''}
                    </span>
                    ${group?.deviationExceeded
                          ? html`<div class="small">The servers disagree by more than the agreed deviation - the log says by how much.</div>`
                          : ''}
                </div>
            `;

        }


        /** What one server said in a synchronisation, if it was asked in it. */
        function whatItSaid(sync:    NTSSyncResult | null,
                            source:  NTSTimeSource): NTSServerResult | undefined {

            const name = readable(source.hostname).toLowerCase();

            return sync?.servers?.find(server => readable(server.hostname).toLowerCase() === name);

        }


        /**
         * Add a time server, or change or delete one, in a dialog.
         *
         * A dialog rather than fields in the row: a server has five things that
         * can be said about it, and the list is for reading which servers there
         * are. And the meter is told the whole list when this is saved, so the
         * dialog is also where it becomes clear that exactly one server is
         * being changed.
         *
         * @param index  the server's place in the list, or null to add one.
         */
        function editServer(index: number | null): void {

            if (current === null)
                return;

            const configuration  = current;
            const list           = entries();
            const shown          = index === null ? null : configuration.timeSources[index] ?? null;
            const usual          = usualPorts();

            if (index !== null && shown === null)
                return;

            const dialog = document.createElement('dialog');

            dialog.className = 'server-dialog';

            document.body.appendChild(dialog);

            // Shut it and take it away: a dialog that is only closed stays in
            // the document, and the next one opened would find two forms of
            // the same name.
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            render(dialog, html`

                <h2><i class="fa-solid fa-clock"></i> ${shown === null ? 'A new time server' : readable(shown.hostname)}</h2>

                <form id="server-form" class="form-stack">

                    <label>Host name
                        <input type="text" name="hostname" placeholder="ptbtime1.ptb.de"
                               value="${shown === null ? '' : readable(shown.hostname)}" />
                        <span class="hint">
                            A name and not an address: the key exchange checks the server's TLS certificate
                            against it.
                        </span>
                    </label>

                    <label>Priority
                        <input type="number" name="priority" min="0" max="255" step="1"
                               value="${shown?.priority ?? 0}" />
                        <span class="hint">A lower priority is asked first; servers sharing one are asked together.</span>
                    </label>

                    <label>NTS-KE port
                        <input type="number" name="ntsKEPort" min="1" max="65535" placeholder="${usual.ntsKE}"
                               value="${shown !== null && shown.ntsKEPort !== usual.ntsKE ? shown.ntsKEPort : ''}" />
                    </label>

                    <label>NTP port
                        <input type="number" name="ntpPort" min="1" max="65535" placeholder="${usual.ntp}"
                               value="${shown !== null && shown.ntpPort !== usual.ntp ? shown.ntpPort : ''}" />
                        <span class="hint">Left empty, the usual ones: ${usual.ntsKE} and ${usual.ntp}.</span>
                    </label>

                    <label class="checkbox">
                        <input type="checkbox" name="enabled" ${shown === null || shown.enabled ? html`checked` : ''} />
                        Ask this server
                        <span class="hint">Switched off, it stays in the list and is not asked.</span>
                    </label>

                    <label>Certificate fingerprint <span class="muted small">(optional)</span>
                        <input type="text" name="certificateFingerprint" autocomplete="off" spellcheck="false"
                               value="${shown?.heldTo?.certificate ?? ''}" />
                        <span class="hint">
                            The SHA-256 fingerprint of the certificate this server has to show, on top of the
                            usual checks.${shown?.certificate
                                               ? html` At its last key exchange it showed ${fingerprintView(shown.certificate)}.`
                                               : ''}
                        </span>
                    </label>

                    <label>Root CA fingerprint <span class="muted small">(optional)</span>
                        <input type="text" name="rootFingerprint" autocomplete="off" spellcheck="false"
                               value="${shown?.heldTo?.root ?? ''}" />
                        <span class="hint">
                            The SHA-256 fingerprint of the root its chain has to end at - one of this meter's
                            own certificate store will do where the machine knows none.${shown?.rootCA
                                                                                               ? html` Its chain ended at ${fingerprintView(shown.rootCA.fingerprint)}.`
                                                                                               : ''}
                        </span>
                    </label>

                    <label>When a fingerprint does not match
                        <select name="onMismatch">
                            <option value="refuse" ${shown?.heldTo?.onMismatch !== 'record' ? html`selected` : ''}>refuse the server</option>
                            <option value="record" ${shown?.heldTo?.onMismatch === 'record' ? html`selected` : ''}>use it, and write the mismatch into the log book</option>
                        </select>
                    </label>

                    <div class="form-actions">
                        <button type="submit" class="btn primary">Save</button>
                        <button type="button" class="btn" id="server-cancel">Cancel</button>
                        ${shown === null
                              ? ''
                              : html`<button type="button" class="btn danger" id="server-delete">
                                         <i class="fa-solid fa-trash"></i> Delete
                                     </button>`}
                        <span id="server-error" class="form-error" role="alert"></span>
                    </div>

                </form>

            `);

            const form   = must<HTMLFormElement>(dialog, '#server-form');
            const error  = must<HTMLElement>    (dialog, '#server-error');

            /**
             * Tell the meter the list with the one change in it, and close only
             * when it took it. What it refuses - a server below the quorum, the
             * last one - is said in the dialog, and the list the page shows is
             * still the one the meter has.
             */
            async function tell(servers: NTSServerEntry[]): Promise<void> {

                error.textContent = '';

                try
                {
                    current = await whileSaving(dialog, null, () => api.nts.save({ servers }));
                }
                catch (problem)
                {
                    error.textContent = errorMessage(problem);
                    return;
                }

                dismiss();

                if (!cancelled) {
                    drawServers();
                    await refreshClock();
                }

            }

            form.addEventListener('submit', event => {

                event.preventDefault();

                const data      = new FormData(form);
                const hostname  = readable(String(data.get('hostname') ?? '').trim());
                const ntsKE     = String(data.get('ntsKEPort') ?? '').trim();
                const ntp       = String(data.get('ntpPort')   ?? '').trim();
                const priority  = Number(data.get('priority')  ?? 0);
                const heldTo    = String(data.get('certificateFingerprint') ?? '').trim();
                const rootedIn  = String(data.get('rootFingerprint')        ?? '').trim();
                const mismatch  = String(data.get('onMismatch')             ?? 'refuse');

                if (hostname.length === 0) {
                    error.textContent = 'A host name is needed.';
                    return;
                }

                if (nameTaken(list, hostname, index)) {
                    error.textContent = `${hostname} is in the list already.`;
                    return;
                }

                const entry: NTSServerEntry = { hostname };

                if (priority !== 0)                                      entry.priority   = priority;
                if (ntsKE.length > 0 && Number(ntsKE) !== usual.ntsKE)  entry.ntsKEPort  = Number(ntsKE);
                if (ntp.length   > 0 && Number(ntp)   !== usual.ntp)    entry.ntpPort    = Number(ntp);
                if (data.get('enabled') === null)                        entry.enabled    = false;
                if (heldTo.length   > 0)                                 entry.certificateFingerprint  = heldTo;
                if (rootedIn.length > 0)                                 entry.rootFingerprint         = rootedIn;
                if ((heldTo.length > 0 || rootedIn.length > 0) &&
                    mismatch === 'record')                               entry.onMismatch              = 'record';

                void tell(withServer(list, index, entry));

            });

            must<HTMLButtonElement>(dialog, '#server-cancel').addEventListener('click', dismiss);

            if (shown !== null && index !== null)
                must<HTMLButtonElement>(dialog, '#server-delete').addEventListener('click', () => {

                    if (!confirm(`Delete ${readable(shown.hostname)}?\n\n` +
                                 `It is taken out of the list, and out of ${configuration.file}.`))
                        return;

                    void tell(withoutServer(list, index));

                });

            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            dialog.showModal();

            must<HTMLInputElement>(dialog, 'input[name="hostname"]').focus();

        }


        /**
         * Ask one time server everything, in a dialog, line by line.
         *
         * "Check the clock now" answers whether the group has a time; this
         * answers where one server got to, which is the question somebody has
         * when it did not. The steps are the ones the exchange actually has -
         * the name, the TCP connection, the TLS handshake and what the
         * certificate claims, the key exchange, the authenticated request -
         * and each is timed, so a server that is merely slow can be told from
         * one that is refusing.
         *
         * @param host  which server, asked on the ports it is configured with.
         *              Sent as it is read, without the root's dot, because the
         *              meter writes it into the log as it was sent.
         */
        async function testServer(host: string): Promise<void> {

            const dialog = document.createElement('dialog');

            dialog.className = 'test-dialog';

            render(dialog, html`
                <h2>Asking ${readable(host)}</h2>
                <div class="test-steps" id="test-steps">
                    <div class="loading">Name, key exchange, authenticated time request ...</div>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn" id="test-close" disabled>Close</button>
                </div>
            `);

            document.body.appendChild(dialog);
            dialog.showModal();

            // Shut it and take it away, as the server's dialog does: one that
            // is only closed stays in the document.
            const dismiss = (): void => { dialog.close(); dialog.remove(); };

            dialog.addEventListener('close',  dismiss);
            dialog.addEventListener('cancel', dismiss);

            const close = must<HTMLButtonElement>(dialog, '#test-close');

            close.addEventListener('click', dismiss);

            let result: TimeServerTest;

            try
            {
                result = await api.nts.test(host);
            }
            catch (problem)
            {
                render(must<HTMLElement>(dialog, '#test-steps'), html`
                    <div class="error-box">The test could not be run: ${errorMessage(problem)}</div>
                `);
                close.disabled = false;
                close.focus();
                return;
            }

            render(must<HTMLElement>(dialog, '#test-steps'), html`
                <div class="${result.ok ? 'notice' : 'error-box'}">
                    ${result.ok
                          ? html`${readable(result.host)} answered. ${result.runtime_ms} ms altogether.`
                          : html`${readable(result.host)} did not answer. ${result.runtime_ms} ms altogether.`}
                </div>
                <ol class="test-log">
                    ${result.steps.map(step => html`
                        <li class="level-${step.level}">
                            <span class="at">+${step.at_ms} ms</span>
                            <span class="text">${step.text}</span>
                        </li>
                    `)}
                </ol>
            `);

            close.disabled = false;
            close.focus();

        }


        /**
         * Listen on the parts rather than on what is in them, because the parts
         * are redrawn one at a time and a listener on a button that was redrawn
         * away would be listening to nothing.
         */
        function wire(): void {

            must<HTMLElement>(content, '#nts-switch').addEventListener('change', event => {

                const box = event.target as HTMLInputElement;

                if (box.id === 'enabled')
                    void switchTo(box.checked);

            });

            must<HTMLElement>(content, '#nts-servers').addEventListener('click', event => {

                const button = (event.target as HTMLElement).closest<HTMLButtonElement>('button');

                if (button === null || button.disabled)
                    return;

                if (button.id === 'add-server')
                    editServer(null);

                else if (button.dataset['edit'] !== undefined)
                    editServer(Number(button.dataset['edit']));

                else if (button.dataset['test'] !== undefined) {

                    const source = current?.timeSources[Number(button.dataset['test'])];

                    if (source !== undefined)
                        void testServer(readable(source.hostname));

                }

            });

            must<HTMLElement>(content, '#nts-sync').addEventListener('click', event => {

                const button = (event.target as HTMLElement).closest<HTMLButtonElement>('#sync');

                if (button !== null && !button.disabled)
                    void runSync();

            });

            must<HTMLElement>(content, '#nts-policy').addEventListener('submit', event => {

                event.preventDefault();

                const data     = new FormData(event.target as HTMLFormElement);
                const timeout  = String(data.get('timeoutSeconds') ?? '').trim();

                const update: NTSUpdate = {
                    minServers:           Number(data.get('minServers')),
                    maxDeviationSeconds:  Number(data.get('maxDeviationSeconds')),
                    checkEverySeconds:    Number(data.get('checkEverySeconds'))
                };

                // An empty field leaves the timeout as it is, rather than
                // making it nothing at all.
                if (timeout.length > 0)
                    update.timeoutSeconds = Number(timeout);

                void saveForm('#nts-policy', '#policy-note', '#policy-error', update,
                              () => { drawPolicy(); drawServers(); });

            });

            must<HTMLElement>(content, '#nts-legal').addEventListener('submit', event => {

                event.preventDefault();

                const data       = new FormData(event.target as HTMLFormElement);
                const authority  = String(data.get('legalTimeAuthority') ?? '').trim();

                void saveForm('#nts-legal', '#legal-note', '#legal-error', {
                    // An emptied field takes the authority away rather than
                    // naming one called "".
                    legalTimeAuthority:         authority.length > 0 ? authority : null,
                    legalTimeToleranceSeconds:  Number(data.get('legalTimeToleranceSeconds')),
                    legalTimeMaxAgeSeconds:     Number(data.get('legalTimeMaxAgeSeconds'))
                }, drawLegal);

            });

        }


        /** Switch the whole thing on or off. */
        async function switchTo(on: boolean): Promise<void> {

            must<HTMLElement>(content, '#switch-error').textContent = '';

            try
            {
                current = await whileSaving(must<HTMLElement>(content, '#nts-switch'), null,
                                            () => api.nts.save({ enabled: on }));
            }
            catch (problem)
            {
                // Back to what the meter has, which is not what the box says
                // now that somebody has clicked it.
                drawSwitch();
                must<HTMLElement>(content, '#switch-error').textContent = errorMessage(problem);
                return;
            }

            drawSwitch();
            await refreshClock();

        }


        /**
         * Tell the meter what one of the two forms says - only what that form
         * says, which the meter lays over the rest - and redraw what shows it.
         */
        async function saveForm(card:     string,
                                noteAt:   string,
                                errorAt:  string,
                                update:   NTSUpdate,
                                redraw:   () => void): Promise<void> {

            must<HTMLElement>(content, noteAt). textContent = '';
            must<HTMLElement>(content, errorAt).textContent = '';

            try
            {
                current = await whileSaving(must<HTMLElement>(content, card), must<HTMLElement>(content, noteAt),
                                            () => api.nts.save(update));
            }
            catch (problem)
            {
                must<HTMLElement>(content, errorAt).textContent = errorMessage(problem);
                return;
            }

            redraw();
            await refreshClock();

            must<HTMLElement>(content, noteAt).textContent = 'Saved, and in effect.';

        }


        async function runSync(): Promise<void> {

            // Its own card for the button and the verdict, and the list for
            // what each server said.
            syncing = true;
            drawSync();
            drawServers();

            try
            {
                result = await api.nts.sync();

                // Again, because an exchange moves the cookies and the record of
                // the last key exchange that each row is showing, and the clock
                // card has a new last check.
                [current, clock] = await Promise.all([api.nts.get(), api.clock()]);
            }
            catch (problem)
            {
                syncing = false;
                drawSync();
                drawServers();
                must<HTMLElement>(content, '#sync-error').textContent = errorMessage(problem);
                return;
            }

            syncing = false;

            if (cancelled)
                return;

            drawSync();
            drawServers();
            drawClock();

        }


        /** The clock card again, which shows the group and the authority too. */
        async function refreshClock(): Promise<void> {

            try
            {
                clock = await api.clock();
            }
            catch
            {
                // The card keeps what it had; the next Reload says why.
                return;
            }

            if (!cancelled)
                drawClock();

        }


        async function load(): Promise<void> {

            try
            {

                const [nextSettings, nextClock] = await Promise.all([api.nts.get(), api.clock()]);

                if (cancelled)
                    return;

                current  = nextSettings;
                clock    = nextClock;
                result   = null;

                draw();

            }
            catch (problem)
            {
                if (!cancelled)
                    render(content, html`<div class="error-box">The NTS configuration could not be loaded: ${errorMessage(problem)}</div>`);
            }

        }

        void load();

        return () => { cancelled = true; };

    }

};


/** One name and its value, the way the other cards write them. */
function kv(name: string, value: string | HTMLFragment): HTMLFragment {
    return html`<div class="kv"><span class="k">${name}</span><span class="v">${value}</span></div>`;
}


/**
 * The clock's verdict in a sentence. Whether it is legal time is the meter's
 * to say, and it says so as a fact; this only puts its reason into words.
 */
function verdict(time: Clock): string {

    if (time.legal)
        return 'Checked, recent and within tolerance';

    switch (time.why) {
        case 'notClaimed':    return 'No time authority is configured';
        case 'ntsOff':        return 'NTS is switched off';
        case 'neverChecked':  return 'The clock has not been checked yet';
        case 'stale':         return 'The last check is too old';
        case 'offBy':         return 'The clock is further off than the tolerance allows';
        default:              return 'Not legal time';
    }

}


/** What the meter made of a time server's certificate, in words. */
function outcomeText(outcome: string): string {

    switch (outcome) {
        case 'recorded':       return 'fingerprint differs - used, and written down';
        case 'pinMismatch':    return 'fingerprint differs - refused';
        case 'untrusted':      return 'certificate not trusted - refused';
        case 'wrongName':      return 'certificate for another name - refused';
        case 'noCertificate':  return 'showed no certificate - refused';
        default:               return outcome;
    }

}


/**
 * Milliseconds the way the meter's log writes them: one place after a point,
 * and a sign where the number says which way.
 */
function ms(value: number | null | undefined, signed = false): string {

    if (value === null || value === undefined)
        return '-';

    const sign = signed ? (value < 0 ? '-' : '+') : '';

    return `${sign}${Math.abs(value).toFixed(1)} ms`;

}
