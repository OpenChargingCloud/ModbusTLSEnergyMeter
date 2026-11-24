/**
 * The page of the meter readers drawn, in a document of happy-dom, against a
 * stand-in meter: the server as it is, who is connected, and as which SunSpec
 * role each login reads - and nothing of it, where nobody has a login yet.
 */

import { open, type Asked } from '../../test/meter.ts';

import { strict as assert }  from 'node:assert';
import { describe, it }      from 'node:test';

const { readerServerPage } = await import('./readerServer.ts');


function server(connected: string[], roles: Record<string, string | null>): Record<string, unknown> {
    return {
        configuration:  { enabled: true, port: 2357, clientAuthentication: [ 'httpAuthOverTLS', 'tlsClientCertificate' ], ssh: { enabled: true } },
        state:          { running: true, tls: true, ssh: true, sshPort: 22 },
        connected,
        roles
    };
}

function answering(Server: Record<string, unknown>) {
    return (asked: Asked) => asked.path === '/configuration/reader-server' ? Server : undefined;
}


describe('the page of the meter readers', () => {

    it('says the server is listening, who is connected, and as which role each reads', async () => {

        await open(readerServerPage, '/configuration/reader-server', [ 'meterreaders:read' ],
                   answering(server([ 'reader-01' ], { 'reader-01': 'ReadOnlySunSpec', 'reader-02': null })),
                   root => root.querySelector('#reader-roles') !== null);

        assert.match(document.querySelector('#reader-websocket')?.textContent ?? '', /listening on port 2357, over TLS/);
        assert.match(document.querySelector('#reader-ssh')?.textContent       ?? '', /served on port 22/);
        assert.match(document.querySelector('#reader-connected')?.textContent ?? '', /reader-01/);

        const rows = [ ...document.querySelectorAll('#reader-roles tbody tr') ].map(row => row.textContent?.replace(/\s+/g, ' ').trim());

        assert.deepEqual(rows, [ 'reader-01 ReadOnlySunSpec', 'reader-02 none - every request is refused' ]);

    });

    it('says so, where nobody is connected and nobody has a login', async () => {

        await open(readerServerPage, '/configuration/reader-server', [ 'meterreaders:read' ],
                   answering(server([], {})), root => root.querySelector('#reader-roles') !== null);

        assert.match(document.querySelector('#reader-connected')?.textContent ?? '', /No meter reader is connected/);
        assert.match(document.querySelector('#reader-roles')?.textContent     ?? '', /No meter reader has a login yet/);

    });

});
