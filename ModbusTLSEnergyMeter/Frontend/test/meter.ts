/*
 * The meter the pages' tests in src/pages/*.test.ts draw against: WWCP_Node's
 * stand-in node (test/node.ts), which every kind's page tests share - a
 * stand-in for fetch, and a document of happy-dom to draw a page into - told
 * that it is an energy meter, and who is signed in to it.
 *
 * Imported first, before a page: lit-html looks for the document as it is
 * loaded, and the pages load it.
 *
 *   import { open, ... } from '../../test/meter.ts';
 *   const { signingKeysPage } = await import('./signingKeys.ts');
 */

import { standIn } from '@node/../test/node.ts';
export * from '@node/../test/node.ts';

standIn({ name: 'Energy Meter', icon: 'fa-gauge-high',
          user: { name: 'Alice', organization: 'Test', role: 'systemadmin', roleTitle: 'Administrator',
                  roles: [ 'systemadmin' ], mayReadTheLog: true } });
