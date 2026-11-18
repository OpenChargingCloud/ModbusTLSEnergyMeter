/**
 * What the meter's own pages are held to: what every page of every kind of
 * node is, by the rules of WWCP_Node's test/pages.ts.
 *
 * Run with `npm test`. "@node/.." is WWCP_Node/Frontend, where the rules are.
 */

import { everyPageIn } from '@node/../test/pages.ts';


everyPageIn(new URL('./', import.meta.url), {
    // certificates.ts has no form of its own since the node's store makes
    // the meter's keys: the form a key is made with is the node's.
    withForms:      [ 'accounts.ts', 'meter.ts', 'sessions.ts', 'signingKeys.ts', 'upstream.ts' ]
});
