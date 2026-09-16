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

/** The time of day with milliseconds - the column in front of every log line. */
export function formatTime(iso: string): string {

    const date = new Date(iso);

    if (Number.isNaN(date.getTime()))
        return iso;

    return date.toLocaleTimeString([], {
               hour:                    '2-digit',
               minute:                  '2-digit',
               second:                  '2-digit',
               fractionalSecondDigits:  3,
               hour12:                  false
           });

}

/** The whole moment, for the title of a log line and for the details. */
export function formatTimestamp(iso: string): string {

    const date = new Date(iso);

    return Number.isNaN(date.getTime())
               ? iso
               : date.toLocaleString([], { dateStyle: 'medium', timeStyle: 'medium' }) +
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
