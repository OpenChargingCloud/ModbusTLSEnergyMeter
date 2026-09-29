/**
 * What the meter's client adds to every node's, asked directly.
 *
 * Run with `npm test`, which is Node's own runner reading the TypeScript as it
 * stands, with WWCP_Node's resolve hook for "@node/...". Every node's routes
 * are WWCP_Node's to test; what is pinned here is what a meter puts beside
 * them - its own routes, merged into the same objects without taking any of
 * every node's away - and the one request it makes to the HTTPExt API, a
 * change of one's own password, with the words Hermod says no in.
 */

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

import { api, ApiError, NoAnswer } from './client.ts';


/** What the meter was asked. */
let asked: { url: string; method: string; body?: string }[] = [];

/** Make the meter answer every request with this status and JSON - none for 204. */
const meterAnswers = (Status: number, JSON_?: unknown) => {

    asked = [];

    (globalThis as unknown as { fetch: unknown }).fetch = (url: string, init: { method: string; body?: string }) => {

        asked.push({ url, method: init.method, body: init.body });

        return Promise.resolve({
            ok:           Status >= 200 && Status < 300,
            status:       Status,
            statusText:   '',
            text:         () => Promise.resolve(JSON_ === undefined ? '' : JSON.stringify(JSON_)),
            arrayBuffer:  () => Promise.resolve(new ArrayBuffer(0))
        } as unknown as Response);

    };

};


describe('the meter\'s client', () => {

    it('is every node\'s routes, with the meter\'s own beside them in the same objects', () => {

        const everyNodes  = [ api.auth.me, api.auth.login, api.auth.logout, api.status, api.clock, api.logs,
                              api.dns.get, api.dns.save, api.nts.get, api.nts.save, api.nts.test, api.nts.sync,
                              api.certificates.get, api.certificates.import, api.certificates.update,
                              api.certificates.remove, api.certificates.reload ];

        const theMeters   = [ api.auth.changePassword, api.meter.get, api.meter.setMode, api.meter.resetEnergy,
                              api.certificates.requests, api.certificates.createRequest, api.certificates.requestURL,
                              api.certificates.answerRequest, api.certificates.removeRequest, api.certificates.configuration,
                              api.accounts.list, api.keys.list, api.signing.session, api.verifyLog ];

        for (const route of [ ...everyNodes, ...theMeters ])
            assert.equal(typeof route, 'function');

        assert.equal(api.eventsURL, '/api/v1/events');

    });

    it('asks the meter\'s own routes below /api/v1, as every node\'s', async () => {

        meterAnswers(200, {});

        await api.meter.get();
        await api.certificates.requests();
        await api.status();

        assert.deepEqual(asked.map(request => `${request.method} ${request.url}`),
                         [ 'GET /api/v1/meter', 'GET /api/v1/certificates/requests', 'GET /api/v1/status' ]);

        assert.equal(api.certificates.requestURL('ab cd'), '/api/v1/certificates/requests/ab%20cd');

    });

    it('signs out at every node\'s door rather than at the accounts', async () => {

        meterAnswers(204);

        await api.auth.logout();

        assert.equal(`${asked[0]!.method} ${asked[0]!.url}`, 'POST /api/v1/auth/logout');

    });

});


describe('a change of one\'s own password', () => {

    it('goes to the HTTPExt API, where Hermod checks the current one', async () => {

        meterAnswers(204);

        assert.equal(await api.auth.changePassword('the old one', 'the new one'), undefined);

        assert.equal(`${asked[0]!.method} ${asked[0]!.url}`, 'POST /ext/auth/password');
        assert.deepEqual(JSON.parse(asked[0]!.body!), { currentPassword: 'the old one', newPassword: 'the new one' });

    });

    it('is refused in Hermod\'s own words', async () => {

        meterAnswers(403, { description: 'The current password is wrong.' });

        await assert.rejects(api.auth.changePassword('not it', 'the new one'),
                             (problem: unknown) => problem instanceof ApiError &&
                                                   problem.isForbidden &&
                                                   problem.message === 'The current password is wrong.');

    });

    it('says the meter could not be reached, rather than that a fetch failed', async () => {

        (globalThis as unknown as { fetch: unknown }).fetch = () => Promise.reject(new TypeError('Failed to fetch'));

        await assert.rejects(api.auth.changePassword('the old one', 'the new one'),
                             (problem: unknown) => problem instanceof NoAnswer &&
                                                   problem.reason === 'could not be reached' &&
                                                   !problem.message.includes('Failed to fetch'));

    });

});
