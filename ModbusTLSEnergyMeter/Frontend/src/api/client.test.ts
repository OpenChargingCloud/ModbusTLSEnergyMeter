/**
 * Where the client asks the node's JSON API what every node answers.
 *
 * Run with `npm test`, which is Node's own runner reading the TypeScript as it
 * stands - no bundler, no browser, no dependency that is not already here.
 *
 * What is pinned is what moved when the meter's API became the node's with
 * the meter's own routes on top: who is signed in is asked at auth/me, the
 * clock at /v1/clock, and "Sync now" is answered with the whole NTS
 * configuration, the result inside it. At their old places the node answers
 * with its JSON 404, which a page would show as a clock nobody can read.
 */

import { strict as assert }  from 'node:assert';
import { registerHooks }     from 'node:module';
import { describe, it }      from 'node:test';

// The pages are written for webpack, which does not want the extension in a
// relative import; Node does.
registerHooks({
    resolve(specifier, context, next) {
        return specifier.startsWith('.') && !specifier.endsWith('.ts')
                   ? next(`${specifier}.ts`, context)
                   : next(specifier, context);
    }
});

// The client reads config.ts, which reads <meta> tags when it is loaded.
(globalThis as unknown as { document: unknown }).document = { querySelector: () => null };

const { api } = await import('./client.ts');


/** What the meter was asked. */
let asked: { url: string, method: string }[] = [];

/** Make the meter answer every request with the given JSON. */
const meterAnswers = (JSON_: unknown) => {

    asked = [];

    (globalThis as unknown as { fetch: unknown }).fetch = (url: string, init: { method: string }) => {

        asked.push({ url, method: init.method });

        return Promise.resolve({
            ok:          true,
            status:      200,
            statusText:  '',
            text:        () => Promise.resolve(JSON.stringify(JSON_))
        } as unknown as Response);

    };

};


describe('the routes every node has', () => {

    it('asks who is signed in at auth/me', async () => {

        meterAnswers({ username: 'root', roles: [ 'systemadmin' ], permissions: [ 'meter:read' ], role: 'systemadmin' });

        const me = await api.auth.me();

        assert.equal(asked[0]!.url,     '/api/v1/auth/me');
        assert.equal(asked[0]!.method,  'GET');
        assert.equal(me.username,       'root');

    });

    it('asks the clock at /v1/clock, where every node has it', async () => {

        meterAnswers({ now: '2026-09-28T00:00:00Z', source: 'system' });

        await api.clock();

        assert.equal(asked[0]!.url, '/api/v1/clock');

    });

    it('takes the result of "Sync now" out of the NTS configuration it comes in', async () => {

        // The node answers a synchronisation with the whole NTS configuration,
        // because the exchange moves the cookies and the key material the page
        // is showing - and the result of it inside, which is what the page
        // reads.
        meterAnswers({ enabled: true, servers: [], result: { ok: true, at: '2026-09-28T00:00:00Z', server: 'ptbtime1.ptb.de' } });

        const result = await api.nts.sync();

        assert.equal(asked[0]!.url,     '/api/v1/configuration/nts/sync');
        assert.equal(asked[0]!.method,  'POST');
        assert.equal(result.ok,         true);
        assert.equal(result.server,     'ptbtime1.ptb.de');

    });

});
