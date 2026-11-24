import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { dnsPage } from '@node/pages/dns';
import { nodeMenu, startNode } from '@node/start';
import type { Me } from './api/client';

import { meterPage }            from './pages/meter';
import { certificatesPage, serverIdentitiesPage } from './pages/certificates';
import { signingKeysPage }      from './pages/signingKeys';
import { sessionsPage }         from './pages/sessions';
import { accountsPage }         from './pages/accounts';
import { metrologicalLogPage }  from './pages/metrologicalLog';
import { upstreamPage }         from './pages/upstream';
import { connectionsPage }      from './pages/connections';
import { readerServerPage }     from './pages/readerServer';

import { connectionsPage as readerConnectionsPage } from '@node/connecting/pages/connections';
import { clientTrustPage }      from '@node/connecting/pages/clientTrust';
import { webSocketLoginsPage }  from '@node/connecting/pages/webSocketLogins';
import { setConnectionsResource, setLoginServer, setNodeNoun, setNodeTraits, setStationsResource } from '@node/connecting/settings';

// What reads this meter without Modbus/TLS - a charging station, a local
// controller - connects over a WebSocket or SSH. Each is written down twice,
// as everybody who connects to a node is: as a connection of the type
// "MeterReader", which lets it in, and as a login, which says what it signs
// in with and, by its group, as which SunSpec role it reads. Both are drawn by
// the pages every node with a WebSocket server draws them with - WWCP_Node's
// connecting/ -, told here that they are a meter's: below
// "/configuration/reader-server", at the resource "meterReaders" - spelt in
// small letters in a permission, as the meter sends them -, and of meter
// readers, which speak Modbus and know nothing of OCPP's security profiles.
setConnectionsResource('meterreaders');
setStationsResource('meterreaders');
setNodeNoun('meter', 'energy meter');
setNodeTraits({ oneNodePerOCPPVersion: false, isConnectedTo: true, connectsDown: false,
                examples: { description: 'Ladepunkt 1, reading this meter', url: 'wss://meter.example.org:2357/reader-01' } });
setLoginServer({
    root:              '/configuration/reader-server',
    page:              '/configuration/reader-server',
    loginsPage:        '/configuration/reader-server/logins',
    trustPage:         '/configuration/reader-server/trust',
    login:             'meter reader',
    logins:            'meter readers',
    who:               'a charging station, a local controller, or whatever else reads this meter',
    example:           'reader-01',
    describedAs:       'Ladepunkt 1',
    protocol:          'Modbus',
    icon:              'fa-gauge',
    securityProfiles:  false,
    sshChannels:       false,
    allowedOf:         Server => (Server as { configuration?: { clientAuthentication?: ('httpAuthWithoutTLS' | 'httpAuthOverTLS' | 'tlsClientCertificate')[] } }).configuration?.clientAuthentication ?? []
});


// The certificates had three pages while the meter kept three stores of its
// own. A bookmark to one of them still arrives - the listeners' at the page of
// what the meter's servers show, the clients' at the one of the roots - which
// asks for the sign-in where one is needed.
const toCertificates        = (): string => '/configuration/certificates';
const toServerIdentities    = (): string => '/configuration/server-identities';

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
            // The SSH server: every node's page, for the administrators here -
            // it lists every account's keys and sessions, which a viewer and an
            // auditor of this meter are not shown.
            nodeMenu.ssh,
            nodeMenu.certificates,
            nodeMenu.serverIdentities,
            { path: '/configuration/keys',       label: 'Signing keys',      icon: 'fa-key',             permission: [ 'keys:read' ] },
            // What it measures with: its own simulation, or the meter in front
            // of which it stands.
            { path: '/configuration/upstream',   label: 'Upstream',          icon: 'fa-link',            permission: [ 'meter:read' ] },
            // What reads this meter over a WebSocket or SSH, and as which role.
            { path: '/configuration/reader-server',         label: 'Meter readers',     icon: 'fa-gauge',         permission: [ 'meterreaders:read' ] },
            { path: '/configuration/reader-server/logins',  label: 'WebSocket logins',  icon: 'fa-users-gear',    permission: [ 'meterreaders:read' ] },
            { path: '/configuration/reader-server/trust',   label: 'Accepted chains',   icon: 'fa-user-shield',   permission: [ 'certificates:read' ] },
            { path: '/configuration/connections',           label: 'Reader connections', icon: 'fa-network-wired', permission: [ 'meterreaders:read' ] }
        ]),
        { path: '/sessions',                     label: 'Sessions',          icon: 'fa-file-signature',  permission: [ 'meter:read' ] },
        // Who is connected over Modbus/TLS now: what the log says afterwards,
        // at the moment - and so for whoever may read the log.
        { path: '/connections',                  label: 'Connections',       icon: 'fa-plug',            permission: [ 'log:read' ] },
        nodeMenu.logs,
        // The log book is the meter's own, and whoever may read the log may
        // read what of it is evidence.
        { path: '/metrological-log',             label: 'Metrological log',  icon: 'fa-file-shield',     permission: [ 'log:read' ] },
        // Everybody signed in may open it: everybody has a password of their
        // own to change.
        { path: '/configuration/accounts',       label: 'Accounts',          icon: 'fa-users' }
    ],

    routes: [
        { path: '/configuration/certificates/modbus',   page: serverIdentitiesPage,  guard: toServerIdentities },
        { path: '/configuration/certificates/web',      page: serverIdentitiesPage,  guard: toServerIdentities },
        { path: '/configuration/certificates/clients',  page: certificatesPage,      guard: toCertificates }
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
        '/configuration/certificates':       certificatesPage,
        '/configuration/server-identities':  serverIdentitiesPage,
        '/configuration/keys':           signingKeysPage,
        '/configuration/upstream':       upstreamPage,
        '/configuration/reader-server':         readerServerPage,
        '/configuration/reader-server/logins':  webSocketLoginsPage,
        '/configuration/reader-server/trust':   clientTrustPage,
        '/configuration/connections':           readerConnectionsPage,
        '/configuration/accounts':       accountsPage,
        '/sessions':                     sessionsPage,
        '/connections':                  connectionsPage,
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
