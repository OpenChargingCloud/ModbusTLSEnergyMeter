/**
 * What the DNS page tells the meter about a name server, asked directly.
 *
 * Run with `npm test`. The meter is sent the whole list every time, so what is
 * pinned here is that each server the page loaded goes back with what it was
 * held to then - which the page neither shows nor changes - and a server
 * added on the page goes without.
 */

import { strict as assert }  from 'node:assert';
import { readFileSync }      from 'node:fs';
import { describe, it }      from 'node:test';

import type { DNSServer } from '../api/client';
import { pinKeysOf, sentOf } from './dnsServers.ts';


const root       = 'a'.repeat(64);
const otherRoot  = 'b'.repeat(64);

/** 1.1.1.1 over TLS as the meter shows it, still to learn its root when the page loaded it. */
const learning: DNSServer = {
    address: '1.1.1.1', port: 853, transport: 'TLS', queryTimeoutSeconds: null,
    trustOnFirstUse: 'root',
    heldTo: { certificate: null, root: null, certificates: [], roots: [], onMismatch: 'refuse', trustOnFirstUse: 'root' }
};

/** A name server over UDP as the meter shows it, held to nothing. */
const plain: DNSServer = { address: '192.0.2.1', port: 53, transport: 'UDP', queryTimeoutSeconds: 2, heldTo: null };


describe('what a name server was held to when the page loaded it', () => {

    it('is said in the keys its entry says it with, and nothing else of the entry', () => {

        assert.deepEqual(pinKeysOf(learning), { trustOnFirstUse: 'root' });

        const pinned: DNSServer = {
            address: '9.9.9.9', port: 853, transport: 'TLS', queryTimeoutSeconds: null,
            rootFingerprints: [ root, otherRoot ], onMismatch: 'record',
            heldTo: { certificate: null, root, certificates: [], roots: [ root, otherRoot ], onMismatch: 'record', trustOnFirstUse: null }
        };

        assert.deepEqual(pinKeysOf(pinned), { rootFingerprints: [ root, otherRoot ], onMismatch: 'record' });

    });

    it('is nothing for a server held to nothing', () => {

        assert.deepEqual(pinKeysOf(plain), {});

    });

});


describe('a name server sent back', () => {

    it('goes with what it was held to, so that a root it learned while the page was open is kept', () => {

        assert.deepEqual(sentOf(learning), { ...learning, pinsAsShown: { trustOnFirstUse: 'root' } });

    });

    it('says a server held to nothing was so', () => {

        assert.deepEqual(sentOf(plain), { ...plain, pinsAsShown: {} });

    });

    it('says nothing of a server added on the page, which the meter has nothing of', () => {

        const added: DNSServer = { address: '9.9.9.9', port: 53, transport: 'UDP', queryTimeoutSeconds: null };

        assert.deepEqual(sentOf(added), added);

    });

    it('leaves the server it was made from alone, which is what the page goes on editing', () => {

        sentOf(learning);

        assert.equal('pinsAsShown' in learning, false);

    });

    it('is what the DNS page saves its name servers as', () => {

        // Asked of the page's source, as Node has no browser to open it in.
        const page = readFileSync(new URL('./dns.ts', import.meta.url), 'utf-8');

        assert.match(page, /servers:\s+servers\.filter\(.*\)\.map\(sentOf\)/,
                     'the DNS page sends its name servers without what they were held to when it loaded them');

    });

});
