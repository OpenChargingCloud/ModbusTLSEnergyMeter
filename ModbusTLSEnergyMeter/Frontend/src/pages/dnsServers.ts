import type { DNSServer, PinKeys } from '../api/client';

/**
 * What the DNS page tells the meter about a name server.
 *
 * Apart from the page, because this is the part that decides what the meter is
 * told - and the meter is told the whole list every time, so a pin this gets
 * wrong is a pin gone from a server nobody touched. The page around it only
 * draws and asks.
 */


/** Every key an entry says what its server is held to with. */
const pinKeys = [ 'certificateFingerprint', 'certificateFingerprints',
                  'rootFingerprint',        'rootFingerprints',
                  'onMismatch',             'trustOnFirstUse' ] as const;


/**
 * What a name server's entry says it is held to, in the keys it says it with,
 * and nothing else of the entry.
 *
 * The page shows none of it and changes none of it: it goes back as the meter
 * wrote it.
 */
export function pinKeysOf(server: PinKeys): PinKeys {

    const keys: Record<string, unknown> = {};

    for (const key of pinKeys)
        if (server[key] !== undefined)
            keys[key] = server[key];

    return keys as PinKeys;

}


/**
 * A name server as the page sends it: as the page has it, and - for a server
 * the page loaded - what it was held to when the page loaded it, under
 * "pinsAsShown".
 *
 * The page sends the whole list, from what it loaded, and a name server over
 * TLS that learned its root on first use while the page was open is held to
 * it by then. Sent without what the page had, the list is what every server
 * is held to from then on, and the page's next save of anything takes that
 * root away again. Told what the page had, the meter changes only what was
 * changed on the page - and on this page nothing of what a server is held to
 * is.
 *
 * Not for a server added on the page, which the meter has nothing of.
 */
export function sentOf(server: DNSServer): DNSServer {

    return server.heldTo === undefined
               ? server
               : { ...server, pinsAsShown: pinKeysOf(server) };

}
