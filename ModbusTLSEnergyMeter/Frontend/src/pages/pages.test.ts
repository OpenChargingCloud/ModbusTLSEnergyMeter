/**
 * What the meter's own pages are held to: what every page of every kind of
 * node is, by the rules of WWCP_Node's test/pages.ts.
 *
 * Run with `npm test`. "@node/.." is WWCP_Node/Frontend, where the rules are.
 */

import { everyPageIn } from '@node/../test/pages.ts';


everyPageIn(new URL('./', import.meta.url), {
    withForms:      [ 'accounts.ts', 'certificates.ts', 'meter.ts', 'sessions.ts', 'signingKeys.ts' ],
    heldElsewhere:  { 'certificates.ts': "its forms are sections of the node's certificates page, which holds every form under its content" }
});
