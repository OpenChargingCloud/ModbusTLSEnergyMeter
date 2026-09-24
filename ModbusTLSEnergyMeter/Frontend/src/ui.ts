import type { LogLevel } from './api/client';

export function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

/** Only same-site paths may be used as a "next" target after signing in. */
export function safeNext(value: string | null): string | null {
    return value !== null && value.startsWith('/') && !value.startsWith('//')
               ? value
               : null;
}

/**
 * Anything on a page that can be typed into or pressed.
 *
 * Kept as one type because the only thing wanted of them here is that they can
 * all be switched off and on again.
 */
type Control = HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement | HTMLButtonElement;

/** What a page says while it is telling the meter. */
export const beingSaved = 'Saving ...';

/**
 * Hold part of a page still while the meter is being told, and say so.
 *
 * What cannot be typed while the answer is on its way cannot be thrown away by
 * the answer when it redraws the page - the sibling projects measured exactly
 * that on a slow link, with a server added while an earlier save was still
 * being answered, and gone afterwards without a word. And a page that does not
 * react is a page people press again.
 *
 * Controls that were already switched off stay off afterwards: a role that may
 * look but not change must not be handed a live form by a save that failed.
 */
export async function whileSaving<T>(Page:    HTMLElement,
                                     Saying:  HTMLElement | null,
                                     Doing:   () => Promise<T>): Promise<T> {

    const controls    = [...Page.querySelectorAll<Control>('input, select, textarea, button')];
    const alreadyOff  = new Set(controls.filter(control => control.disabled));

    for (const control of controls)
        control.disabled = true;

    if (Saying !== null)
        Saying.textContent = beingSaved;

    try
    {
        return await Doing();
    }
    finally
    {
        for (const control of controls)
            if (!alreadyOff.has(control))
                control.disabled = false;

        // Whatever happened, it is no longer happening. What it turned into -
        // "Saved", or a sentence about why not - is the page's to say.
        if (Saying !== null)
            Saying.textContent = '';
    }

}

/** Read a form field as a trimmed string. */
export function field(form: HTMLFormElement, name: string, trim = true): string {
    const value = String(new FormData(form).get(name) ?? '');
    return trim ? value.trim() : value;
}

/** Whether a checkbox in a form is ticked. */
export function checked(form: HTMLFormElement, name: string): boolean {
    return new FormData(form).get(name) !== null;
}

/** Read a form field as a number; NaN when it is empty or not one. */
export function numberField(form: HTMLFormElement, name: string): number {
    return Number(field(form, name));
}


/**
 * Put text on the clipboard, and say what happened in words a person can act
 * on.
 *
 * The clipboard is only there on a secure origin, and a meter reached at a LAN
 * address over plain HTTP is not one. Saying so beats a button that silently
 * does nothing - which is why this returns a message rather than a boolean.
 */
export async function copyText(Text: string, Fallback?: HTMLInputElement | HTMLTextAreaElement): Promise<string> {

    try {
        await navigator.clipboard.writeText(Text);
        return 'Copied.';
    }
    catch {

        Fallback?.select();

        return Fallback
                   ? 'Selected - copy it with Ctrl+C.'
                   : 'This browser will not let the page copy; select the text and copy it.';

    }

}


// Numbers

/**
 * A measurement, with the digits it is worth and nothing where there is no
 * value. An empty cell reads as a page that failed to render.
 */
export function formatNumber(value: number | null | undefined, digits = 2): string {

    if (value === null || value === undefined || Number.isNaN(value))
        return '-';

    return value.toLocaleString([], {
               minimumFractionDigits: digits,
               maximumFractionDigits: digits
           });

}


// Times

/**
 * The formatters, made once.
 *
 * toLocaleTimeString builds one of these on every call, and the log page calls
 * it twice per line. The charging station measured 234 ms of a 597 ms redraw
 * at 1959 entries on the clock alone, against 63 ms with the formatter kept.
 * They read the browser's locale when the page loads, which is the one moment
 * it can change.
 */
const timeOfDay = new Intl.DateTimeFormat([], {
                          hour:                    '2-digit',
                          minute:                  '2-digit',
                          second:                  '2-digit',
                          fractionalSecondDigits:  3,
                          hour12:                  false
                      });

const wholeMoment = new Intl.DateTimeFormat([], { dateStyle: 'medium', timeStyle: 'medium' });

/** The time of day with milliseconds - the column in front of every log line. */
export function formatTime(iso: string): string {

    const date = new Date(iso);

    if (Number.isNaN(date.getTime()))
        return iso;

    return timeOfDay.format(date);

}

/** The whole moment, for the title of a log line and for the details. */
export function formatTimestamp(iso: string): string {

    const date = new Date(iso);

    return Number.isNaN(date.getTime())
               ? iso
               : wholeMoment.format(date) +
                 `.${String(date.getMilliseconds()).padStart(3, '0')}`;

}

/** How long ago, in the words somebody would use. */
export function formatSince(iso: string): string {

    const then = new Date(iso).getTime();

    if (Number.isNaN(then))
        return iso;

    const seconds = Math.max(0, Math.round((Date.now() - then) / 1000));

    if (seconds <   60)  return `${seconds}s ago`;
    if (seconds < 3600)  return `${Math.round(seconds /    60)}m ago`;
    if (seconds < 86400) return `${Math.round(seconds /  3600)}h ago`;

    return `${Math.round(seconds / 86400)}d ago`;

}


// Log levels

/** Whether a level is at least as loud as another. */
export function isAtLeast(level: LogLevel, minimum: LogLevel): boolean {

    const order: LogLevel[] = ['debug', 'info', 'notice', 'warning', 'error', 'critical'];

    return order.indexOf(level) >= order.indexOf(minimum);

}
