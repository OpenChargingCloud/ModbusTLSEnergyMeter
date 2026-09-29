import type { NTSServerEntry, NTSTimeSource, PinKeys, ServerPins } from '../api/client';

/**
 * The list of time servers as the NTS page edits it.
 *
 * Apart from the page, because this is the part that decides what the meter is
 * told - and the meter is told the whole list every time, so a mistake here is
 * a server deleted that nobody touched. The page around it only draws and
 * asks.
 */


/** The ports a server is asked on unless its entry says otherwise. */
export interface UsualPorts {
    ntsKE:  number;
    ntp:    number;
}


/**
 * A name as somebody reads it: without the root's dot. The meter hands its
 * names back fully qualified, and "ptbtime1.ptb.de." is correct and looks like
 * a typing mistake.
 */
export function readable(hostname: string): string {
    return hostname.endsWith('.') ? hostname.slice(0, -1) : hostname;
}


/**
 * A server as the meter shows it, turned back into what its configuration
 * says - with everything that is the usual left out.
 *
 * Left out rather than repeated, because the meter writes back what it is
 * sent: an entry carrying the usual ports and priority 0 becomes an object in
 * the file where a bare name was, and the file stops reading the way somebody
 * would have written it.
 */
export function entryOf(source: NTSTimeSource, usual: UsualPorts): NTSServerEntry {

    const entry: NTSServerEntry = { hostname: readable(source.hostname) };

    if (source.priority  !== 0)            entry.priority   = source.priority;
    if (source.ntsKEPort !== usual.ntsKE)  entry.ntsKEPort  = source.ntsKEPort;
    if (source.ntpPort   !== usual.ntp)    entry.ntpPort    = source.ntpPort;
    if (!source.enabled)                   entry.enabled    = false;

    // What it is held to, which the page shows and does not always edit - and
    // the list goes back whole, so a pin left out here is a pin deleted by
    // the next save of anything else.
    return { ...entry, ...pinsShown(source.heldTo) };

}


/**
 * What the page shows a server held to - its first certificate, its first
 * root, and whether a mismatch is only written down - in the keys its entry
 * says it with.
 *
 * What the page does not show, it cannot have changed: a second certificate
 * or root from the configuration file, a root still to be learned on first
 * use, a mismatch that is let through. Sent beside the entry as what the page
 * showed, it is what the meter keeps.
 *
 * A mismatch only beside a pin: the meter refuses one on a server held to
 * none, and would refuse the whole list with it.
 */
export function pinsShown(heldTo: ServerPins | null | undefined): PinKeys {

    const keys: PinKeys = {};

    if (heldTo?.certificate)  keys.certificateFingerprint  = heldTo.certificate;
    if (heldTo?.root)         keys.rootFingerprint         = heldTo.root;

    if ((keys.certificateFingerprint || keys.rootFingerprint) && heldTo?.onMismatch === 'record')
        keys.onMismatch = 'record';

    return keys;

}


/**
 * A time server as the page sends it back: its entry, and what the page
 * showed it held to under "pinsAsShown".
 *
 * The page sends the whole list, from what it loaded, and a server that
 * learned its root on first use while the page was open is held to it by
 * then, without the page having shown it. Sent without what the page showed,
 * the list is what every server is held to from then on, and the save of
 * another server's priority takes that root away again. Told what the page
 * showed, the meter changes only what was changed on the page.
 */
export function sentOf(source: NTSTimeSource, usual: UsualPorts): NTSServerEntry {
    return { ...entryOf(source, usual), pinsAsShown: pinsShown(source.heldTo) };
}


/**
 * The list with one server replaced, or with one added at the end when there
 * is no place given.
 *
 * A new list rather than the old one changed: the old one is what the meter
 * still has, and it is what the page has to go back to when the meter says no.
 */
export function withServer(list:   readonly NTSServerEntry[],
                           index:  number | null,
                           entry:  NTSServerEntry): NTSServerEntry[] {

    return index === null
               ? [...list, entry]
               : list.map((other, at) => at === index ? entry : other);

}


/** The list without the server at that place. */
export function withoutServer(list:   readonly NTSServerEntry[],
                              index:  number): NTSServerEntry[] {

    return list.filter((_, at) => at !== index);

}


/**
 * Whether another server of the list already has this name - the one at the
 * place being edited does not count, or a server could not be saved unchanged.
 *
 * Compared the way names compare: without the root's dot, and without case.
 */
export function nameTaken(list:      readonly NTSServerEntry[],
                          hostname:  string,
                          except:    number | null): boolean {

    const wanted = readable(hostname.trim()).toLowerCase();

    return list.some((other, at) => at !== except &&
                                    readable(other.hostname).toLowerCase() === wanted);

}
