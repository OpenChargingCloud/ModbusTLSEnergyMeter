/**
 * The rules the pages share, asked directly.
 *
 * Run with `npm test`. What is pinned is what was found wrong: a number field
 * left empty was read as 0, and the DNS page told the meter to retry never
 * and to follow no CNAME - or sent a timeout of 0, which the meter refused
 * the whole save over - where the field said nothing.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import { numberField } from './ui.ts';


/** A form, as far as reading it goes. */
class FormOf {
    readonly fields: Record<string, string>;
    constructor(fields: Record<string, string>) {
        this.fields = fields;
    }
}

// The browser's FormData reads a form; Node's takes none.
(globalThis as unknown as { FormData: unknown }).FormData = class {
    readonly form: FormOf;
    constructor(form: FormOf) {
        this.form = form;
    }
    get(name: string): string | null {
        return this.form.fields[name] ?? null;
    }
};

const form = (fields: Record<string, string>) => new FormOf(fields) as unknown as HTMLFormElement;


describe('a number field', () => {

    it('is not a number when it is empty - which goes to the meter as null, and null is not given', () => {

        const read = numberField(form({ maxRetries: '' }), 'maxRetries');

        assert.ok(Number.isNaN(read), `read as ${read}`);
        assert.equal(JSON.stringify({ maxRetries: read }), '{"maxRetries":null}');

    });

    it('is not a number when it holds nothing but blanks, or is not there at all', () => {

        assert.ok(Number.isNaN(numberField(form({ maxRetries: '   ' }), 'maxRetries')));
        assert.ok(Number.isNaN(numberField(form({}),                    'maxRetries')));

    });

    it('is the number it holds, 0 among them', () => {

        assert.equal(numberField(form({ maxRetries: '0' }),                    'maxRetries'),          0);
        assert.equal(numberField(form({ queryTimeoutSeconds: ' 2.5 ' }),       'queryTimeoutSeconds'), 2.5);

    });

});
