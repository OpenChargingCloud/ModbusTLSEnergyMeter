import './styles/app.scss';

// FontAwesome: the CSS ends up in the extracted stylesheet, the referenced
// font files become hashed assets below /assets/.
import '@fortawesome/fontawesome-free/css/fontawesome.css';
import '@fortawesome/fontawesome-free/css/solid.css';

import { auth } from './auth';
import { html, must, render } from './html';
import { logs } from './logs/store';
import { Router } from './router';

import { meterPage }         from './pages/meter';
import { dnsPage }           from './pages/dns';
import { ntsPage }           from './pages/nts';
import { modbusCertificatesPage, webCertificatesPage } from './pages/serverCertificates';
import { clientTrustPage }   from './pages/clientTrust';
import { logsPage }          from './pages/logs';
import { loginPage }         from './pages/login';
import { notFoundPage }      from './pages/notFound';


const root = document.getElementById('app');

if (root === null)
    throw new Error("The '#app' element is missing!");

render(root, html`<div id="page" class="page"></div>`);

const router = new Router({
    routes: [
        // "/" is the meter, and is a route of its own rather than a redirect
        // to /meter: the sign-in remembers where somebody was going, and for
        // the first visit that is "/" - which would otherwise be a page that
        // exists on the way in and not on the way back.
        { path: '/',                           page: meterPage,         guard: auth.requireSignIn },
        { path: '/meter',                      page: meterPage,         guard: auth.requireSignIn },
        { path: '/configuration',              page: dnsPage,           guard: auth.requireSignIn },
        { path: '/configuration/dns',          page: dnsPage,           guard: auth.requireSignIn },
        { path: '/configuration/nts',          page: ntsPage,           guard: auth.requireSignIn },
        { path: '/configuration/certificates',         page: modbusCertificatesPage,  guard: auth.requireSignIn },
        { path: '/configuration/certificates/modbus',  page: modbusCertificatesPage,  guard: auth.requireSignIn },
        { path: '/configuration/certificates/web',     page: webCertificatesPage,     guard: auth.requireSignIn },
        { path: '/configuration/certificates/clients', page: clientTrustPage,         guard: auth.requireSignIn },
        { path: '/logs',                       page: logsPage,          guard: auth.requireSignIn },
        { path: '/login',                      page: loginPage }
    ],
    outlet:       must<HTMLElement>(root, '#page'),
    notFound:     notFoundPage,
    titleSuffix:  ' · Energy Meter'
});

// Signed in: follow the meter's log from now on, whichever page is open - so
// that opening the Logs page shows what happened while somebody was reading
// the configuration, and not an empty list. Every Modbus request is in there,
// which is the thing most worth not missing.
// Signed out - by the button, or because the session expired and a request
// came back with 401: close the stream, forget the log, show the sign-in.
auth.onChange(user => {

    if (user !== null) {

        // The stream and the log are the same permission, and somebody who
        // may only read the meter would get a 401-shaped silence instead.
        if (auth.can('ReadConfiguration'))
            logs.start();

        return;

    }

    logs.stop();

    if (location.pathname !== '/login')
        router.navigate(auth.requireSignIn(new URL(location.href)) ?? '/login', true);

});

// Find out who is signed in before the first page renders, so that a reload on
// a deep URL does not flash the sign-in page on its way back to where it was.
void (async () => {
    await auth.refresh();
    router.start();
})();
