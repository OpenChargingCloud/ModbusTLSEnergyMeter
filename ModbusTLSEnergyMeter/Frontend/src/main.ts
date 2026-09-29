import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { dnsPage } from '@node/pages/dns';
import { nodeMenu, startNode } from '@node/start';
import type { Me } from './api/client';

import { meterPage }            from './pages/meter';
import { certificatesPage }     from './pages/certificates';
import { signingKeysPage }      from './pages/signingKeys';
import { sessionsPage }         from './pages/sessions';
import { accountsPage }         from './pages/accounts';
import { metrologicalLogPage }  from './pages/metrologicalLog';


// The certificates had three pages while the meter kept three stores of its
// own. A bookmark to one of them still arrives - at the page that has all of
// them now, which asks for the sign-in where one is needed.
const toCertificates = (): string => '/configuration/certificates';

// What a meter has pages for beside what every node has: what it measures and
// signs, its signing keys and its accounts, and the log book beside the log.
// The sign-in, the log, the frame and following the log while somebody is
// signed in are every node's - see WWCP_Node's start.ts.
startNode({

    name:  'Energy Meter',
    icon:  'fa-gauge-high',

    menu: [
        { path: '/meter',                        label: 'Meter',             icon: 'fa-bolt',            permission: [ 'meter:read' ] },
        nodeMenu.configuration([
            nodeMenu.dns,
            nodeMenu.nts,
            nodeMenu.certificates,
            { path: '/configuration/keys',       label: 'Signing keys',      icon: 'fa-key',             permission: [ 'keys:read' ] }
        ]),
        { path: '/sessions',                     label: 'Sessions',          icon: 'fa-file-signature',  permission: [ 'meter:read' ] },
        nodeMenu.logs,
        // The log book is the meter's own, and whoever may read the log may
        // read what of it is evidence.
        { path: '/metrological-log',             label: 'Metrological log',  icon: 'fa-file-shield',     permission: [ 'log:read' ] },
        // Everybody signed in may open it: everybody has a password of their
        // own to change.
        { path: '/configuration/accounts',       label: 'Accounts',          icon: 'fa-users' }
    ],

    routes: [
        { path: '/configuration/certificates/modbus',   page: certificatesPage,  guard: toCertificates },
        { path: '/configuration/certificates/web',      page: certificatesPage,  guard: toCertificates },
        { path: '/configuration/certificates/clients',  page: certificatesPage,  guard: toCertificates }
    ],

    pages: {

        // "/" is the meter, and is a page of its own rather than a redirect
        // to /meter: the sign-in remembers where somebody was going, and for
        // the first visit that is "/".
        '/':                             meterPage,
        '/meter':                        meterPage,
        // The configuration opens on its first page, the name servers - the
        // node's page, as the one of the time servers is; startNode brings
        // both under their own paths.
        '/configuration':                dnsPage,
        '/configuration/certificates':   certificatesPage,
        '/configuration/keys':           signingKeysPage,
        '/configuration/accounts':       accountsPage,
        '/sessions':                     sessionsPage,
        '/metrological-log':             metrologicalLogPage

    },

    logs: {
        subtitle:  'Everything this meter does, as it happens - refused Modbus requests included.'
    },

    // A meter names the role somebody holds the way a person says it, and
    // what it grants, rather than the names of the groups behind it.
    who: me => ({
        line:   (me as Me).roleTitle       ?? 'no role here',
        title:  (me as Me).roleDescription ?? 'Signed in with no role in this meter.'
    }),

    signIn: {
        line:  'Sign in to look after this meter.',
        hint:  'The first administrator and its password are printed on the console the first time this meter starts.'
    }

});
