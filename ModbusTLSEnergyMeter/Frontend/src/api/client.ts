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

/** One key this meter puts its name to a reading with. */
export interface SigningKey {
    id:           string;
    /** The signature suite, e.g. "ECDSA-P256", "Ed448" or "ML-DSA-65". */
    algorithm:    string;
    createdAt:    string;
    /** The public half, uppercase hexadecimal. */
    publicKey:    string;
    /** Eight bytes of its SHA-256, so two keys can be told apart by eye. */
    fingerprint:  string;
    /** Whether this is the key the meter signs with when nobody names one. */
    isDefault:    boolean;
    note:         string | null;
}

/** The signing keys of this meter, and what a new one may be. */
export interface SigningKeys {
    keys:            SigningKey[];
    /** Every algorithm a key can be made for. */
    algorithms:      string[];
    /** Those of them an OCMF document can say it was signed with. */
    ocmfAlgorithms:  string[];
    /** The one the Alfen format takes, and takes no other. */
    alfenAlgorithm:  string;
    error:           string | null;
}

/**
 * A public key as an answer hands it out.
 *
 * Not one shape: an OCMF reader hands an ECDSA key to a DER parser and expects
 * a SubjectPublicKeyInfo, and hands an Ed25519 or ML-DSA key straight to the
 * signature suite and expects the raw key. `format` says which this is.
 */
export interface PublicKeyOut {
    keyId:          string;
    algorithm:      string;
    fingerprint:    string;
    publicKey:      string;
    encoding:       string;
    format:         string;
    rawPublicKey:   string;
    ocmfAlgorithm:  string | null;
}

/** What comes back for one signed reading. */
export interface SignedMeterValue {
    format:     string;
    timestamp:  string;
    ocmf?:      string;
    alfen?:     string;
    note?:      string;
    publicKey:  PublicKeyOut;
}

/** The charging session this meter is measuring. */
export interface ChargingSession {
    sessionId:       string;
    startedAt:       string;
    startValue:      number;
    unit:            string;
    keyId:           string;
    identification:  string | null;
}

/** Whether one is running, and which. */
export interface SessionState {
    running:  boolean;
    session:  ChargingSession | null;
}

/** What starting a session answers with. */
export interface SessionStarted {
    timestamp:   string;
    sessionId:   string;
    startValue:  number;
    unit:        string;
    publicKey:   PublicKeyOut;
}

/** What stopping it answers with: the whole session as one signed document. */
export interface SessionStopped {
    timestamp:   string;
    sessionId:   string;
    startValue:  number;
    stopValue:   number;
    energy_kWh:  number;
    unit:        string;
    ocmf:        string;
    publicKey:   PublicKeyOut;
}


/** Who is signed in to the web interface. */
export interface Me {
    userId:       string;
    name:         string | null;
    organization: string;
    /** Their role in the meter's organization, or null when they have none. */
    role:         string | null;
    /**
     * The same role as a person would say it: "Read-only administrator" rather
     * than "IsAdminReadOnly".
     *
     * Sent with the role rather than looked up, because every page that tells
     * somebody what they may not do here names their role in the same sentence,
     * and none of them should have to fetch a table to translate one word.
     * Null when they hold no role, so a page can fall back to its own wording.
     */
    roleTitle:        string | null;
    /** What that role grants, in the same words the role table uses. */
    roleDescription:  string | null;
    permissions:      Permission[];
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
 * One time server as the configuration names it. Whatever is left out is the
 * usual: priority 0, the usual ports, switched on.
 */
export interface NTSServerEntry {
    hostname:    string;
    priority?:   number;
    ntsKEPort?:  number;
    ntpPort?:    number;
    enabled?:    boolean;
}

/**
 * What a save sends. Only what is given is changed; the rest of the section
 * stays as it is. The list of servers is sent whole.
 */
export interface NTSUpdate {
    enabled?:                    boolean;
    servers?:                    NTSServerEntry[];
    minServers?:                 number;
    maxDeviationSeconds?:        number;
    checkEverySeconds?:          number;
    /** Null takes the authority away. */
    legalTimeAuthority?:         string | null;
    legalTimeToleranceSeconds?:  number;
    legalTimeMaxAgeSeconds?:     number;
}

/** How one synchronisation went. */
export interface NTSSyncResult {
    ok:           boolean;
    at:           string;
    error?:       string;
    server?:      string;
    runtime_ms?:  number;
    offset_ms?:   number | null;

    /** What the group concluded: the median, how many answered, how far apart. */
    group?:       {
        name:               string;
        answered:           number;
        required:           number;
        offset_ms:          number | null;
        spread_ms:          number | null;
        deviationExceeded:  boolean;
    };

    /** One entry per server asked, answered or not. */
    servers?:     NTSServerResult[];
}

/** What one time server of the group said. */
export interface NTSServerResult {
    hostname:       string;
    ok:             boolean;
    offset_ms?:     number | null;
    roundTrip_ms?:  number | null;
    authenticated?: boolean | null;
    keyExchange?:   string;
    error?:         string | null;
}

/** One server of this meter's group, and what its key exchange is doing. */
export interface NTSTimeSource {
    hostname:       string;
    priority:       number;
    ntsKEPort:      number;
    ntpPort:        number;
    enabled:        boolean;
    cookies?:       number | null;
    lastExchange?:  string | null;
}

/**
 * Where this meter reads the time: its group of time servers, the rules for
 * believing them, and what legal time rests on.
 */
export interface NTSConfiguration {
    enabled:      boolean;

    /**
     * What may be changed, as it is in effect. The quorum is the one wanted;
     * the group's own can be lower while it has fewer servers switched on.
     */
    settings:     {
        timeoutSeconds:             number | null;
        checkEverySeconds:          number;
        minServers:                 number;
        maxDeviationSeconds:        number;
        legalTimeAuthority:         string | null;
        legalTimeToleranceSeconds:  number;
        legalTimeMaxAgeSeconds:     number;
    };

    /** Every server this meter has, switched on or not, in the order configured. */
    timeSources:  NTSTimeSource[];
    group:        { name: string; minServers: number; maxDeviationSeconds: number };
    lastSync:     NTSSyncResult | null;
    limits:       {
        maxTimeout:          number;
        minCheckEvery:       number;
        maxCheckEvery:       number;
        minDeviation:        number;
        maxDeviation:        number;
        minTolerance:        number;
        maxTolerance:        number;
        minMaxAge:           number;
        maxMaxAge:           number;
        maxAuthorityLength:  number;
        defaultNTSKEPort:    number;
        defaultNTPPort:      number;
    };
    file:         string;
}

/** What this meter's clock is, and whether anybody may call it legal time. */
export interface Clock {
    now:                  string;
    ntsEnabled:           boolean;
    /** The group the clock is checked against - null while NTS is switched off. */
    group:                string | null;
    /** Its servers switched on, in the order they are asked - null while switched off. */
    servers:              string[] | null;
    /** How many of them have to answer - null while switched off. */
    minServers:           number | null;
    checkEvery_s:         number;
    lastCheck:            string | null;
    lastCheckServer:      string | null;
    lastCheckAsked:       number | null;
    lastCheckAnswered:    number | null;
    lastCheckAge_s:       number | null;
    lastCheckOffset_ms:   number | null;
    /** The last synchronisation, whichever way it went - lastCheck is the last that found a time. */
    lastSync:             string | null;
    lastSyncResult:       string | null;
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
    /**
     * Whether a TLS listener of this meter could ever show this one.
     *
     * False for the Edwards curves and for ML-DSA: .NET's SslStream
     * authenticates a server with RSA or ECDSA, so a certificate over one of
     * those is a perfectly good certificate for use somewhere else and is never
     * handed to a listener here.
     */
    servedByTLS:  boolean | null;
    /** "valid", "not for a listener", "not valid yet", "expired", ... */
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
    /** One of the ids from the overview's `keyTypes`, e.g. "ecdsa-p256". */
    keyType?:     string;
    note?:        string;
}

/**
 * One kind of key a certificate can be asked for.
 *
 * Hermod's list, served by the meter, so that a kind added there turns up here
 * without this file being touched.
 */
export interface KeyAlgorithmInfo {
    /** How it is written in a request, e.g. "ecdsa-p256". */
    id:           string;
    /** How it is written on a page, e.g. "ECDSA P-256 (secp256r1)". */
    name:         string;
    /** What somebody choosing it should know. */
    remark:       string;
    /**
     * Whether this machine turned out to be able to present such a certificate
     * in a TLS handshake - absent while nobody has tried.
     *
     * Found out by doing it rather than read from a list: whether an Ed25519
     * certificate can be served depends on the operating system, the runtime
     * and the year.
     */
    presentable?: boolean;
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
    modbus:    CertificateStore;
    web:       CertificateStore;
    clients:   ClientTrust;
    https:     boolean;
    /** What a request may ask for, and what each one means. */
    keyTypes:  KeyAlgorithmInfo[];
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
        /** Every server switched on, asked the way the clock check asks them, with every step in the log. */
        sync:  ()                   => meterAPI<NTSSyncResult>   ('POST', '/configuration/nts/sync', {})
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

    /**
     * The keys this meter signs readings with.
     *
     * Not the TLS certificates and not kept with them: a TLS key says "this
     * listener is this host" for the length of a connection, and these say
     * "this meter measured this" and have to go on meaning it for years.
     */
    keys: {
        list:        ()                                     => meterAPI<SigningKeys>('GET',    '/keys'),
        create:      (algorithm: string, note?: string)     => meterAPI<PublicKeyOut>('POST',  '/keys', { algorithm, note }),
        /** Sign with this one from now on; changes nothing about what was signed before. */
        setDefault:  (id: string)                           => meterAPI<SigningKeys>('PUT',   `/keys/${encodeURIComponent(id)}/default`),
        remove:      (id: string)                           => meterAPI<SigningKeys>('DELETE', `/keys/${encodeURIComponent(id)}`)
    },

    /** Readings this meter has put its name to, and the sessions they belong to. */
    signing: {

        /** One reading that belongs to no charging session. */
        value:  (format: 'ocmf' | 'alfen', key?: string) => {

            const query = new URLSearchParams({ format });

            if (key)
                query.set('key', key);

            return meterAPI<SignedMeterValue>('GET', `/signedMeterValues?${query}`);

        },

        session:  ()  => meterAPI<SessionState>('GET', '/sessions'),

        start:    (identification?: string, identificationType?: string) =>
                      meterAPI<SessionStarted>('POST', '/sessions/start', { identification, identificationType }),

        /** Answers with one OCMF document holding both readings. */
        stop:     ()  => meterAPI<SessionStopped>('POST', '/sessions/stop', {})

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
