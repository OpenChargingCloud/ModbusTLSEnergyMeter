import { config } from '../config';


// What the JSON API answers. Everything below /api/v1 needs the session
// cookie, which the browser sends by itself because every request here is
// same-origin. Signing in and out is not below /api/v1 at all: that is
// Hermod's account API at /accounts, and the two are kept apart here the same
// way they are kept apart on the meter.


/** How loudly a log entry asks to be read. */
export type LogLevel = 'debug' | 'info' | 'notice' | 'warning' | 'error' | 'critical';

/** The levels in the order the meter defines them, quietest first. */
export const logLevels: LogLevel[] = ['debug', 'info', 'notice', 'warning', 'error', 'critical'];

/** One thing that happened inside the meter. */
export interface LogEntry {
    /** A number that only ever grows, so the page can tell what it has seen. */
    id:         number;
    timestamp:  string;
    level:      LogLevel;
    /** What it is about: "modbus", "nts", "web", ... - without the level. */
    tags:       string[];
    message:    string;
    /** Whatever else belongs to it, when there is more than one line to say. */
    data?:      unknown;
}

/** What a page of the log brings back. */
export interface LogPage {
    /** The newest id of the whole log, whatever this page was filtered by. */
    lastId:    number;
    capacity:  number;
    tags:      string[];
    entries:   LogEntry[];
}

/**
 * What somebody signed in to this meter may do.
 *
 * A copy of what the meter enforces, not the enforcement: it is here so that a
 * page can leave out what this person may not do instead of offering it and
 * letting them find out by being refused. Every request is checked again on
 * arrival, so editing this list in a browser buys a button that answers 403.
 */
export type Permission = 'ReadMeter'
                       | 'ReadConfiguration'
                       | 'ChangeNetworkSettings'
                       | 'RunDiagnostics'
                       | 'WriteRegisters'
                       | 'ManageCertificates'
                       | 'ManageAccounts';


/** One of the roles this meter hands out, and what holding it means. */
export interface RoleInfo {
    /** What the meter calls it: "IsAdmin", "IsMember", ... */
    role:         string;
    /** What a person calls it: "Administrator", "Member", ... */
    title:        string;
    description:  string;
    permissions:  Permission[];
}

/** Somebody who may sign in to this meter. */
export interface Account {
    userId:       string;
    name:         string | null;
    email:        string;
    /** Their role, or null when they hold none and may therefore do nothing. */
    role:         string | null;
    roleTitle:    string;
    permissions:  Permission[];
    /** Whether this is the account the request was made with. */
    isYou:        boolean;
}

/** Who may sign in, and the roles that can be given out. */
export interface AccountList {
    accounts:  Account[];
    roles:     RoleInfo[];
}

/** What comes back when an account is made or its password reset. */
export interface AccountWithPassword {
    account:   Account;
    /**
     * The password the meter made, shown this once and kept nowhere it could
     * be read back - null when one was given rather than generated.
     */
    password:  string | null;
}

/** What is left of an account that has been removed. */
export interface AccountRemoved {
    removed:  string;
    /** Whether that was the account this browser is signed in as. */
    wasYou:   boolean;
}

/** What is needed to make an account. */
export interface NewAccount {
    userId:     string;
    role:       string;
    name?:      string;
    email?:     string;
    /** Left out on purpose, so that the meter makes one instead. */
    password?:  string;
}

/** Who is signed in to the web interface. */
export interface Me {
    userId:       string;
    name:         string | null;
    organization: string;
    /** Their role in the meter's organization, or null when they have none. */
    role:         string | null;
    permissions:  Permission[];
}

/** How the meter is doing right now. */
export interface Status {
    version:       string;
    serialNumber:  string;
    device:        string;
    startedAt:     string;
    uptime_s:      number;
    modbus: {
        address:        string;
        port:           number;
        running:        boolean;
        baseAddress:    number;
        registerCount:  number;
    };
    web: { url: string };
}


// The meter itself

/** What kind of meter this is, which is what decides how energy flows. */
export type MeterModeName = 'net' | 'import' | 'export';

export interface MeterMode {
    /** What stands in register 40094. */
    value:        0 | 1 | 2;
    name:         MeterModeName;
    /** Where this meter sits, in a sentence. */
    description:  string;
}

/** One phase, or all three added up. */
export interface Phase {
    name:       string;
    voltage_V:  number;
    current_A:  number;
    power_W:    number;
}

/**
 * What the simulated site is doing - which is in no register.
 *
 * The load and the generation are what the mode selects between, so without
 * them a page can show that a meter reads zero but not why.
 */
export interface Simulation {
    load_W:        number;
    generation_W:  number;
    /** Where the simulated day has got to; the real time unless it was compressed. */
    timeOfDay:     string;
    dayLength_s:   number;
}

/** Everything the meter is measuring, as its registers say it. */
export interface MeterReadings {
    manufacturer:  string;
    model:         string;
    options:       string;
    version:       string;
    serialNumber:  string;
    unitAddress:   number;
    sunSpecModel:  number;
    frequency_Hz:  number;
    phases:        Phase[];
    total:         Phase;
    energy:        { exported_Wh: number; imported_Wh: number };
    meterMode:     MeterMode;
    simulation:    Simulation;
}


// Name resolution and time

/** One name server this meter asks. */
export interface DNSServer {
    address:    string;
    port:       number;
    transport:  string;
}

/** How this meter resolves names. */
export interface DNSConfiguration {
    enabled:              boolean;
    servers:              DNSServer[];
    recursionDesired:     boolean;
    useCache:             boolean;
    dnssecOK:             boolean;
    followCNAMEs:         boolean;
    queryTimeoutSeconds:  number;
    maxCNAMEFollows:      number;
    maxRetries:           number;
    file?:                string;
}

/** What a PUT to the name resolution may carry. */
export type DNSUpdate = Partial<Omit<DNSConfiguration, 'file'>>;

/**
 * Where this meter reads the time.
 *
 * Everything is optional: this is the section as it stands in the
 * configuration file, and what the meter was never told is not written.
 */
export interface NTSConfiguration {
    enabled?:                    boolean;
    hostname?:                   string;
    ntsKEPort?:                  number;
    ntpPort?:                    number;
    timeoutSeconds?:             number;
    checkEverySeconds?:          number;
    legalTimeAuthority?:         string;
    legalTimeToleranceSeconds?:  number;
    legalTimeMaxAgeSeconds?:     number;
}

export interface NTSUpdate {
    enabled?:                    boolean;
    hostname?:                   string;
    ntsKEPort?:                  number;
    ntpPort?:                    number;
    timeoutSeconds?:             number;
    checkEverySeconds?:          number;
    legalTimeAuthority?:         string | null;
    legalTimeToleranceSeconds?:  number;
    legalTimeMaxAgeSeconds?:     number;
}

/** What this meter's clock is, and whether anybody may call it legal time. */
export interface Clock {
    now:                  string;
    ntsEnabled:           boolean;
    server:               string;
    checkEvery_s:         number;
    lastCheck:            string | null;
    lastCheckServer:      string | null;
    lastCheckAge_s:       number | null;
    lastCheckOffset_ms:   number | null;
    legalAuthority:       string | null;
    legalTolerance_ms:    number;
    legalMaxAge_s:        number;
    isLegalTime:          boolean;
    /** Why it is, or why it is not. */
    why:                  string;
}


// Certificates

export interface Certificate {
    subject:     string;
    issuer:      string;
    notBefore:   string;
    notAfter:    string;
    thumbprint:  string;
}

export interface Certificates {
    meter:         Certificate;
    clientCA:      Certificate;
    sunSpecRoles:  string[];
}


// The certificate stores

/** Which listener a store of certificates belongs to. */
export type CertificatePurpose = 'modbus' | 'web';

/** What a certificate is, once there is one. */
export interface CertificateInfo {
    subject:      string;
    issuer:       string;
    notBefore:    string;
    notAfter:     string;
    thumbprint:   string;
    chainLength:  number;
}

/**
 * One identity a listener can show: a key that never leaves the meter, the
 * request that was handed out for it, and the certificate once it came back.
 */
export interface CertificateEntry {
    id:           string;
    createdAt:    string;
    subject:      string;
    dnsNames:     string[];
    ipAddresses:  string[];
    keyType:      string;
    note:         string | null;
    hasRequest:   boolean;
    /** "valid", "not valid yet", "expired", "awaiting a certificate", ... */
    state:        string;
    certificate:  CertificateInfo | null;
}

export interface CertificateStore {
    purpose:    CertificatePurpose;
    path:       string;
    /** The entry being shown now, if any. */
    currentId:  string | null;
    /** The entry that takes over next, if one is waiting. */
    nextId:     string | null;
    nextAt:     string | null;
    entries:    CertificateEntry[];
}

/** What a new signing request asks for. */
export interface CertificateRequestBody {
    subject:      string;
    dnsNames?:    string[];
    ipAddresses?: string[];
    keyType?:     'ec256' | 'rsa3072';
    note?:        string;
}

/** One certificate inside an accepted client chain. */
export interface TrustedChainCertificate {
    subject:     string;
    issuer:      string;
    notBefore:   string;
    notAfter:    string;
    thumbprint:  string;
    expired:     boolean;
    isRoot:      boolean;
}

/** One CA a Modbus/TLS client certificate may chain to. */
export interface TrustedChain {
    id:            string;
    name:          string;
    addedAt:       string;
    enabled:       boolean;
    certificates:  TrustedChainCertificate[];
}

export interface ClientTrust {
    path:    string;
    chains:  TrustedChain[];
}

/** Both server stores and the accepted client chains, in one answer. */
export interface CertificateOverview {
    modbus:   CertificateStore;
    web:      CertificateStore;
    clients:  ClientTrust;
    https:    boolean;
}


// The log on disk

/** One file of the log, and whether it is still what it was. */
export interface LogFileVerdict {
    name:      string;
    entries:   number;
    intact:    boolean;
    problem?:  string;
}

/**
 * What walking the log on disk found.
 *
 * `persisted` is false for a meter keeping its log in memory only, and then
 * there is nothing to check rather than something that failed.
 */
export interface LogVerification {
    persisted:      boolean;
    why?:           string;
    intact?:        boolean;
    entries?:       number;
    keyId?:         string;
    head?:          string;
    path?:          string;
    keepDays?:      number;
    firstProblem?:  string;
    files?:         LogFileVerdict[];
}


export class ApiError extends Error {

    constructor(public readonly status:  number,
                message:                 string,
                public readonly body?:   unknown) {
        super(message);
        this.name = 'ApiError';
    }

    get isUnauthorized(): boolean {
        return this.status === 401;
    }

    get isForbidden(): boolean {
        return this.status === 403;
    }

}


let unauthorizedHandler: (() => void) | null = null;

/** Called whenever the API answers 401, i.e. the session is gone. */
export function onUnauthorized(handler: () => void): void {
    unauthorizedHandler = handler;
}


async function request<T>(method: string, url: string, body?: unknown): Promise<T> {

    const headers: Record<string, string> = { 'Accept': 'application/json' };

    if (body !== undefined)
        headers['Content-Type'] = 'application/json';

    // Same origin, so the session cookie travels with every request.
    const response = await fetch(url, {
                               method,
                               headers,
                               credentials: 'same-origin',
                               body: body !== undefined ? JSON.stringify(body) : undefined
                           });

    if (response.status === 401)
        unauthorizedHandler?.();

    if (response.status === 204) {
        // Nothing to read, but reading it lets the browser finish the request
        // cleanly instead of aborting an unconsumed body.
        await response.arrayBuffer();
        return undefined as T;
    }

    const text = await response.text();
    let json: unknown = null;

    try {
        json = text.length > 0 ? JSON.parse(text) : null;
    }
    catch {
        if (response.ok)
            throw new ApiError(response.status, `Invalid JSON in the response of ${method} ${url}`, text);
    }

    if (!response.ok) {

        const message = typeof json === 'object' && json !== null
                            ? ('error'       in json && typeof json.error       === 'string' ? json.error :
                               'description' in json && typeof json.description === 'string' ? json.description :
                               `${response.status} ${response.statusText}`)
                            : `${response.status} ${response.statusText}`;

        throw new ApiError(response.status, message, json);

    }

    return json as T;

}

const meterAPI    = <T>(method: string, path: string, body?: unknown) => request<T>(method, config.apiBase      + path, body);
const accountsAPI = <T>(method: string, path: string, body?: unknown) => request<T>(method, config.accountsBase + path, body);


export const api = {

    /** The Server-Sent Events stream; the browser sends the session cookie along. */
    eventsURL: `${config.apiBase}/events`,

    auth: {
        me:      ()                                 => meterAPI   <Me>  ('GET',  '/me'),
        login:   (login: string, password: string)  => accountsAPI<void>('POST', '/auth/login', { login, password }),
        logout:  ()                                 => accountsAPI<void>('POST', '/auth/logout'),

        /**
         * Your own password. The current one has to come with it - which is
         * what stops whoever finds an unlocked browser from taking the account
         * over - and every other session of the account ends.
         */
        changePassword: (currentPassword: string, newPassword: string) =>
                            accountsAPI<void>('POST', '/auth/password', { currentPassword, newPassword })
    },

    status:  () => meterAPI<Status>('GET', '/status'),

    meter: {
        get:          ()                     => meterAPI<MeterReadings>('GET',  '/meter'),
        /** The number a Modbus client would write, or the word a person would say. */
        setMode:      (mode: MeterModeName)  => meterAPI<MeterMode>    ('PUT',  '/meter/mode', { mode }),
        /** The same register a Modbus client writes, so there is one way of clearing them. */
        resetEnergy:  ()                     => meterAPI<unknown>      ('POST', '/meter/energy/reset', {})
    },

    dns: {
        get:   ()                   => meterAPI<DNSConfiguration>('GET', '/configuration/dns'),
        save:  (update: DNSUpdate)  => meterAPI<DNSConfiguration>('PUT', '/configuration/dns', update)
    },

    nts: {
        get:   ()                   => meterAPI<NTSConfiguration>('GET',  '/configuration/nts'),
        save:  (update: NTSUpdate)  => meterAPI<NTSConfiguration>('PUT',  '/configuration/nts', update),
        /** One key exchange and one authenticated NTP request, with every step in the log. */
        sync:  ()                   => meterAPI<unknown>         ('POST', '/configuration/nts/sync', {})
    },

    clock:         () => meterAPI<Clock>       ('GET', '/configuration/time'),
    certificates:  () => meterAPI<Certificates>('GET', '/configuration/certificates'),

    /**
     * The certificates this meter shows.
     *
     * Two stores, and deliberately not one: what a charging station checks
     * comes from a device PKI, what a browser checks comes from wherever the
     * operator's web certificates come from, and nothing issues a certificate
     * both of them would accept.
     */
    tls: {

        overview:  ()                        => meterAPI<CertificateOverview>('GET', '/certificates'),
        store:     (p: CertificatePurpose)   => meterAPI<CertificateStore>   ('GET', `/certificates/servers/${p}`),

        /** Make a key and write a signing request for it. The key stays there. */
        request:   (p: CertificatePurpose, body: CertificateRequestBody) =>
                       meterAPI<CertificateEntry>('POST', `/certificates/servers/${p}/requests`, body),

        /** Where the browser fetches the request itself; it arrives as a file. */
        requestURL: (p: CertificatePurpose, id: string) =>
                       `${config.apiBase}/certificates/servers/${p}/${id}/request`,

        /** The signed certificate coming back, checked against the key that asked. */
        upload:    (p: CertificatePurpose, id: string, pem: string) =>
                       meterAPI<CertificateStore>('PUT', `/certificates/servers/${p}/${id}`, { pem }),

        remove:    (p: CertificatePurpose, id: string) =>
                       meterAPI<CertificateStore>('DELETE', `/certificates/servers/${p}/${id}`)

    },

    /**
     * Who may sign in to this meter, and as what.
     *
     * Reading the list needs ManageAccounts; reading what the roles mean does
     * not, because it names nobody and is what somebody who was given one
     * wants to know about their own.
     */
    accounts: {
        list:           ()                             => meterAPI<AccountList>        ('GET',    '/accounts'),
        roles:          ()                             => meterAPI<{ roles: RoleInfo[] }>('GET',  '/accounts/roles'),
        create:         (account: NewAccount)          => meterAPI<AccountWithPassword>('POST',   '/accounts', account),
        setRole:        (userId: string, role: string) => meterAPI<Account>             ('PUT',   `/accounts/${encodeURIComponent(userId)}/role`, { role }),
        /** A new password for somebody who has lost theirs; not for your own account. */
        resetPassword:  (userId: string)               => meterAPI<AccountWithPassword>('PUT',   `/accounts/${encodeURIComponent(userId)}/password`, {}),
        remove:         (userId: string)               => meterAPI<AccountRemoved>     ('DELETE', `/accounts/${encodeURIComponent(userId)}`)
    },

    /** Which CAs a Modbus/TLS client certificate may chain to. */
    trust: {
        get:         ()                              => meterAPI<ClientTrust>('GET',    '/certificates/clients'),
        add:         (name: string, pem: string)     => meterAPI<ClientTrust>('POST',   '/certificates/clients', { name, pem }),
        setEnabled:  (id: string, enabled: boolean)  => meterAPI<ClientTrust>('PUT',   `/certificates/clients/${id}`, { enabled }),
        remove:      (id: string)                    => meterAPI<ClientTrust>('DELETE', `/certificates/clients/${id}`)
    },

    /**
     * A page of the log, oldest of the returned entries first.
     *
     * @param limit  at most this many entries
     * @param after  only what is newer than this id
     * @param tag    only entries carrying this tag - a level counting as one
     */
    logs: (limit?: number, after?: number, tag?: string) => {

        const query = new URLSearchParams();

        if (limit !== undefined)  query.set('limit', String(limit));
        if (after !== undefined)  query.set('after', String(after));
        if (tag)                  query.set('tag',   tag);

        const suffix = query.size > 0 ? `?${query}` : '';

        return meterAPI<LogPage>('GET', `/logs${suffix}`);

    },

    /** Walk the log on disk: every line against its hash, the chain and the signature. */
    verifyLog: () => meterAPI<LogVerification>('GET', '/logs/verify')

};
