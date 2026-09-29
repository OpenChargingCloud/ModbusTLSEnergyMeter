/**
 * What the NTS page tells the meter when a time server is added, edited or
 * deleted, asked directly.
 *
 * Run with `npm test`. The meter is sent the whole list every time, so what is
 * pinned here is that the list sent is the list shown with exactly one change
 * in it - and that it reads the way the configuration file would.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { NTSTimeSource, ServerPins } from '../api/client';
import { entryOf, nameTaken, pinsShown, readable, sentOf, withServer, withoutServer } from './ntsServers.ts';


const usual = { ntsKE: 4460, ntp: 123 };

/** A server as the meter shows it. */
const shown = (hostname: string, more: Partial<NTSTimeSource> = {}): NTSTimeSource =>
    ({ hostname, priority: 0, ntsKEPort: 4460, ntpPort: 123, enabled: true, ...more });

/** What the meter says a server is held to: nothing, but for what is given. */
const heldTo = (more: Partial<ServerPins> = {}): ServerPins =>
    ({ certificate: null, root: null, certificates: [], roots: [], onMismatch: 'refuse', trustOnFirstUse: null, ...more });


describe('a time server turned back into its entry', () => {

    it('is a bare name when everything else is the usual', () => {

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.'), usual),
                         { hostname: 'ptbtime1.ptb.de' });

    });

    it('says what is not the usual, and nothing that is', () => {

        assert.deepEqual(entryOf(shown('time.local.', { priority: 9, ntsKEPort: 4461, enabled: false }), usual),
                         { hostname: 'time.local', priority: 9, ntsKEPort: 4461, enabled: false });

    });

    it('keeps what it is held to, which the next save of anything else would otherwise delete', () => {

        const certificate = 'A'.repeat(64);
        const root        = 'B'.repeat(64);

        assert.deepEqual(entryOf(shown('ptbtime1.ptb.de.', { heldTo: heldTo({ certificate, certificates: [ certificate ] }) }), usual),
                         { hostname: 'ptbtime1.ptb.de', certificateFingerprint: certificate });

        assert.deepEqual(entryOf(shown('ptbtime2.ptb.de.', { heldTo: heldTo({ root, roots: [ root ], onMismatch: 'record' }) }), usual),
                         { hostname: 'ptbtime2.ptb.de', rootFingerprint: root, onMismatch: 'record' });

    });

    it('holds a server to nothing it was not held to', () => {

        assert.deepEqual(entryOf(shown('ptbtime3.ptb.de.', { heldTo: null, certificate: 'C'.repeat(64) }), usual),
                         { hostname: 'ptbtime3.ptb.de' },
                         'the certificate a server showed is not a pin');

    });

    it('says what a mismatch comes to only beside a pin, which the meter would refuse the whole list over', () => {

        // Held to nothing yet, to learn its root, and to write a mismatch
        // down once it has: sent as it was, "onMismatch" without a pin.
        assert.deepEqual(entryOf(shown('ptbtime4.ptb.de.', { heldTo: heldTo({ onMismatch: 'record', trustOnFirstUse: 'root' }) }), usual),
                         { hostname: 'ptbtime4.ptb.de' });

    });

});


describe('what the page showed a time server held to', () => {

    const certificate       = 'a'.repeat(64);
    const otherCertificate  = 'b'.repeat(64);
    const root              = 'c'.repeat(64);

    it('is its first certificate and its first root, and a mismatch written down, in the keys an entry says them with', () => {

        assert.deepEqual(pinsShown(heldTo({ certificate, certificates: [ certificate, otherCertificate ], root, roots: [ root ], onMismatch: 'record' })),
                         { certificateFingerprint: certificate, rootFingerprint: root, onMismatch: 'record' });

    });

    it('is nothing of what the page does not show: a root still to be learned, a mismatch let through', () => {

        assert.deepEqual(pinsShown(heldTo({ onMismatch: 'record', trustOnFirstUse: 'root' })), {});
        assert.deepEqual(pinsShown(heldTo({ certificate, certificates: [ certificate ], onMismatch: 'accept' })),
                         { certificateFingerprint: certificate });

    });

    it('is nothing for a server held to nothing - which is still said', () => {

        assert.deepEqual(pinsShown(null),       {});
        assert.deepEqual(pinsShown(undefined),  {});

    });

});


describe('a time server sent back', () => {

    const root = 'c'.repeat(64);

    it('goes with what the page showed it held to, so that a root it learned while the page was open is kept', () => {

        // Loaded still to learn its root: the page shows nothing, and says
        // so - from which the meter can tell that a root the server holds by
        // the time of the save was not taken away here.
        assert.deepEqual(sentOf(shown('ptbtime1.ptb.de.', { heldTo: heldTo({ trustOnFirstUse: 'root' }) }), usual),
                         { hostname: 'ptbtime1.ptb.de', pinsAsShown: {} });

    });

    it('says the pins it sends were shown so, for the meter to tell that nothing was changed', () => {

        assert.deepEqual(sentOf(shown('ptbtime2.ptb.de.', { priority: 1, heldTo: heldTo({ root, roots: [ root ], onMismatch: 'record' }) }), usual),
                         { hostname: 'ptbtime2.ptb.de', priority: 1, rootFingerprint: root, onMismatch: 'record',
                           pinsAsShown: { rootFingerprint: root, onMismatch: 'record' } });

    });

    it('says a server shown held to nothing was shown so', () => {

        assert.deepEqual(sentOf(shown('ptbtime3.ptb.de.', { heldTo: null }), usual),
                         { hostname: 'ptbtime3.ptb.de', pinsAsShown: {} });

    });

    // Asked of the page's source, as Node has no browser to open it in.
    const page = readFileSync(new URL('./nts.ts', import.meta.url), 'utf-8');

    it('is what the NTS page sends every server of its list as', () => {

        assert.match(page, /\.map\(source => sentOf\(source, usual\)\)/,
                     'the NTS page sends its list without what it showed each server held to');

    });

    it('is what the dialog sends the server it edits as, where the page loaded it', () => {

        assert.match(page, /if \(shown !== null\)\s+entry\.pinsAsShown = pinsShown\(shown\.heldTo\);/,
                     'the NTS dialog saves a server without what it showed it held to');

    });

});


describe('the list a change sends', () => {

    const list = [ { hostname: 'a.example' }, { hostname: 'b.example' }, { hostname: 'c.example' } ];

    it('replaces exactly the one that was edited', () => {

        assert.deepEqual(withServer(list, 1, { hostname: 'b.example', enabled: false }),
                         [ { hostname: 'a.example' }, { hostname: 'b.example', enabled: false }, { hostname: 'c.example' } ]);

    });

    it('adds a new one at the end', () => {

        assert.deepEqual(withServer(list, null, { hostname: 'd.example' }).map(entry => entry.hostname),
                         [ 'a.example', 'b.example', 'c.example', 'd.example' ]);

    });

    it('leaves out exactly the one that was deleted', () => {

        assert.deepEqual(withoutServer(list, 0).map(entry => entry.hostname),
                         [ 'b.example', 'c.example' ]);

    });

    it('leaves the list it was made from alone, which is what the page goes back to when the meter says no', () => {

        withServer(list, 0, { hostname: 'x.example' });
        withoutServer(list, 2);

        assert.deepEqual(list.map(entry => entry.hostname), [ 'a.example', 'b.example', 'c.example' ]);

    });

});


describe('a name that is already taken', () => {

    const list = [ { hostname: 'ptbtime1.ptb.de' }, { hostname: 'ptbtime2.ptb.de' } ];

    it('is taken whatever its case and its root dot', () => {

        assert.equal(nameTaken(list, 'PTBTIME2.ptb.de.', null), true);

    });

    it('is not taken by the server being edited itself, or it could not be saved unchanged', () => {

        assert.equal(nameTaken(list, 'ptbtime2.ptb.de', 1), false);

    });

    it('is read without the root dot', () => {

        assert.equal(readable('ptbtime1.ptb.de.'), 'ptbtime1.ptb.de');
        assert.equal(readable('ptbtime1.ptb.de'),  'ptbtime1.ptb.de');

    });

});
