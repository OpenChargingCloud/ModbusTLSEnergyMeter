// The accounts page drawn against a stand-in meter: a new account typed and
// not added yet, and its focus, outlives another account's role being
// changed beside it; a role the meter refuses goes back to what the meter
// has; an account added empties its form and shows its password once; every
// account keeps its card.

import { asked, change, field, open, refused, said, submit, type, until, type Asked } from '../../test/meter.ts';

import { strict as assert } from 'node:assert';
import { test } from 'node:test';

import type { Account, RoleInfo } from '../api/client.ts';

const { accountsPage } = await import('./accounts.ts');


const roles: RoleInfo[] = [
    { role: 'viewer',      title: 'Viewer',        description: 'Watches and changes nothing.', permissions: [] },
    { role: 'operator',    title: 'Operator',      description: 'Runs sessions.',               permissions: [] },
    { role: 'systemadmin', title: 'Administrator', description: 'Does everything.',             permissions: [] }
];

function anAccount(userId: string, role: string, isYou = false): Account {
    return { userId, role, isYou, name: null, email: `${userId}@example.org`, roles: [ role ],
             roleTitle: roles.find(one => one.role === role)!.title, permissions: [] };
}

/** A meter with alice (you) and bob, that takes what is asked - or refuses a role. */
function aMeter(refusesRoles = false): (one: Asked) => unknown {

    let accounts = [ anAccount('alice', 'systemadmin', true), anAccount('bob', 'viewer'), anAccount('carol', 'operator') ];

    return ({ method, path, body }) => {

        if (method === 'GET' && path === '/accounts')
            return { accounts, roles };

        if (method === 'PUT' && path.endsWith('/role')) {
            if (refusesRoles)
                return refused(403, 'Only an administrator may hand out that role.');
            const userId = decodeURIComponent(path.split('/')[2] ?? '');
            const { role } = body as { role: string };
            accounts = accounts.map(account => account.userId === userId ? anAccount(userId, role, account.isYou) : account);
            return accounts.find(account => account.userId === userId);
        }

        if (method === 'PUT' && path.endsWith('/password'))
            return { account: accounts.find(account => path.includes(account.userId)), password: 'Reset-Password-1' };

        if (method === 'DELETE' && path.startsWith('/accounts/')) {
            const userId = decodeURIComponent(path.split('/')[2] ?? '');
            accounts = accounts.filter(account => account.userId !== userId);
            return { userId, wasYou: false };
        }

        if (method === 'POST' && path === '/accounts') {
            const { userId, role } = body as { userId: string; role: string };
            const made = anAccount(userId, role);
            accounts = [ ...accounts, made ];
            return { account: made, password: 'Made-Password-1' };
        }

        return undefined;

    };

}

const drawn = (root: HTMLElement) => root.querySelector('#add-form') !== null;


test('a new account typed, and its focus, outlives another account being given a role', async () => {

    const root    = await open(accountsPage, '/configuration/accounts', [ 'accounts:read', 'accounts:edit' ], aMeter(), drawn);
    const userId  = field(root, '#add-form', 'userId');

    type(userId, 'rory', 2);

    change(root.querySelector<HTMLSelectElement>('[data-role-for="bob"]')!, 'operator');

    await until(() => asked.some(one => one.method === 'PUT' && one.path === '/accounts/bob/role'), 'the role was not set');
    await until(() => asked.filter(one => one.method === 'GET' && one.path === '/accounts').length === 2, 'the accounts were not read again');
    await until(() => root.querySelector('[data-role-for="bob"]') !== null, 'bob was not drawn again');

    const after = field(root, '#add-form', 'userId');

    assert.ok(after === userId, 'the field was drawn anew');
    assert.equal(after.value, 'rory');
    assert.ok(document.activeElement === userId, 'the field lost the focus');
    assert.equal(after.selectionStart, 2);

});


test('a role the meter refuses goes back to the one it has', async () => {

    const root    = await open(accountsPage, '/configuration/accounts', [ 'accounts:read', 'accounts:edit' ], aMeter(true), drawn);
    const choice  = root.querySelector<HTMLSelectElement>('[data-role-for="bob"]')!;

    change(choice, 'systemadmin');

    await until(() => asked.some(one => one.method === 'PUT' && one.path === '/accounts/bob/role'), 'the role was not asked for');
    await until(() => root.querySelector<HTMLSelectElement>('[data-role-for="bob"]')!.value === 'viewer',
                'the refused role stayed chosen');

});


test('an account added empties its form, shows its password once, and gets a card', async () => {

    const root = await open(accountsPage, '/configuration/accounts', [ 'accounts:read', 'accounts:edit' ], aMeter(), drawn);

    type(field(root, '#add-form', 'userId'), 'rory');

    submit(root, '#add-form');

    await until(() => root.querySelector('[data-role-for="rory"]') !== null, 'the new account has no card');
    await until(() => root.querySelector<HTMLInputElement>('#issued-password')?.value === 'Made-Password-1',
                'the password was not shown');
    assert.equal(field(root, '#add-form', 'userId').value, '', 'the form kept the account it added');

    root.querySelector<HTMLButtonElement>('#dismiss-password')!.click();

    await until(() => root.querySelector('#issued-password') === null, 'the password was not put away');

});


test('an account keeps its card while another one gets a new password, or the one before it goes', async () => {

    const root  = await open(accountsPage, '/configuration/accounts', [ 'accounts:read', 'accounts:edit' ], aMeter(), drawn);
    const card  = root.querySelector('[data-role-for="carol"]')!.closest('section');

    root.querySelector<HTMLButtonElement>('[data-reset="bob"]')!.click();

    await until(() => root.querySelector<HTMLInputElement>('#issued-password')?.value === 'Reset-Password-1',
                'the new password was not shown');

    assert.ok(root.querySelector('[data-role-for="carol"]')!.closest('section') === card, 'the card of carol was drawn anew');

    root.querySelector<HTMLButtonElement>('[data-remove="bob"]')!.click();

    await until(() => root.querySelector('[data-role-for="bob"]') === null, 'bob was not removed');

    assert.ok(root.querySelector('[data-role-for="carol"]')!.closest('section') === card, 'the card of carol was drawn anew when bob went');

});


test('somebody who may not see the accounts changes their own password only', async () => {

    const root = await open(accountsPage, '/configuration/accounts', [], ({ path }) => path === '/accounts/roles' ? { roles } : undefined,
                            root => root.querySelector('#password-form') !== null);

    assert.ok(root.querySelector('#add-form') === null, 'there is a form to add an account with');
    assert.ok(root.querySelector('[data-role-for]') === null, 'the accounts are shown');
    assert.match(root.querySelector('.notice')!.textContent!, /change its own password/);

});


test('Reload asks before it throws an account half typed away, and then reads the page again with the form empty', async () => {

    const root    = await open(accountsPage, '/configuration/accounts', [ 'accounts:read', 'accounts:edit' ], aMeter(), drawn);

    type(field(root, '#add-form', 'userId'), 'rory');

    const before  = asked.length;

    root.querySelector<HTMLButtonElement>('#reload')!.click();

    await until(() => asked.slice(before).some(one => one.method === 'GET' && one.path === '/accounts'), 'Reload did not read the page again');
    await until(() => field(root, '#add-form', 'userId').value === '', 'Reload kept what was typed');

    assert.equal(said.length, 1, `Reload asked ${said.length} time(s) before it threw what was typed away`);

});
