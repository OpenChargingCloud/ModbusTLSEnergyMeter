import { apiURL,
         extRequest,
         nodeAPI,
         request,
         type Certificate        as NodeCertificate,
         type CertificateImport  as NodeCertificateImport,
         type CertificateStore   as NodeCertificateStore,
         type NodeConfiguration,
         type NodeMe,
         type NodeResource,
         type NodeStatus,
         type Operation }  from '@node/api/client';


// What every node answers - the log, name resolution, the time, the store,
// who is signed in - and how it is asked are WWCP_Node's, and every page here
// reads them from this module as before. What follows is what a meter adds:
// its resources, what its status and "me" say beyond every node's, the kinds
// its store keeps and the listeners they are shown on, and its own routes -
// the meter, the accounts, the signing keys, the sessions, the log on disk.
export * from '@node/api/client';


/**
 * What there is to be allowed to do something with: the node's resources -
 * configuration, dns, nts, certificates - and the meter's.
 */
export type Resource = NodeResource | 'meter' | 'keys' | 'log' | 'accounts';

/**
 * What somebody signed in to this meter may do: an operation on a resource,
 * "meter:edit".
 *
 * A copy of what the meter enforces, not the enforcement: it is here so that a
 * page can leave out what this person may not do instead of offering it and
 * letting them find out by being refused. Every request is checked again on
 * arrival, so editing this list in a browser buys a button that answers 403.
 * Spelt out resource by resource by the meter, so "*" never arrives here.
 */
export type Permission = `${Resource}:${Operation}`;


/** One of the roles this meter hands out, and what holding it means. */
export interface RoleInfo {
    /** What the meter calls it - the name of its user group: "systemadmin", "viewer", ... */
    role:         string;
    /** What a person calls it: "Administrator", "Viewer", ... - or its name, for a role the configuration file adds. */
    title:        string;
    /** Null for a role the configuration file adds without saying what it is for. */
    description:  string | null;
    permissions:  Permission[];
}

/** Somebody who may sign in to this meter. */
export interface Account {
    userId:       string;
    name:         string | null;
    email:        string;
    /** Their strongest role, or null when they hold none and may therefore do nothing. */
    role:         string | null;
    /** Every role they hold - one per group of that name they are in - in the node's order: the viewer first, the administrators last. */
    roles:        string[];
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
/** Who is signed in to the web interface: every node's answer, and what a meter adds. */
export interface Me extends NodeMe<Resource> {
    name:          string | null;
    organization:  string;
    /** Their strongest role on this meter, or null when they have none. */
    role:          string | null;
    /**
     * The same role as a person would say it: "Administrator" rather than
     * "systemadmin".
     *
     * Sent with the role rather than looked up, because every page that tells
     * somebody what they may not do here names their role in the same sentence,
     * and none of them should have to fetch a table to translate one word.
     * Null when they hold no role, so a page can fall back to its own wording.
     */
    roleTitle:        string | null;
    /** What that role grants, in the same words the role table uses. */
    roleDescription:  string | null;
}

/**
 * How the meter is doing right now: every node's status, and which meter it
 * is, where Modbus/TLS listens and where the web interface is.
 */
export interface Status extends NodeStatus {
    serialNumber:  string;
    device:        string;
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


// Certificates

/**
 * What a certificate in the node's store is to this meter. A root is believed:
 * a TLS root at the end of a time or name server's chain, a client root at the
 * end of a Modbus/TLS client's. An identity is what one of the two listeners
 * shows. A server certificate is neither, but kept to recognise a server by
 * its fingerprint.
 */
export type CertificateKind = 'tlsRoot' | 'clientRoot' | 'tlsServer' | 'tlsIdentity';

/** One of the two listeners of this meter that show a certificate: the Modbus/TLS port, and the web interface. */
export type TLSListener = 'modbus' | 'web';

/**
 * One certificate in the store, as every node's store has it - its usages
 * being "dns" and "nts" for a TLS root or a server certificate, "modbus" and
 * "web" for an identity, and left out for a client root, which is for
 * Modbus/TLS alone - and, for an identity, the listeners that show it now.
 */
export interface Certificate extends NodeCertificate<CertificateKind> {
    /** An identity only: the listeners that show it right now. */
    shownOn?:  TLSListener[];
}

/** What one listener shows now, and what takes over from it next - by handle. */
export interface ListenerCertificates {
    /** Null when it has nothing it could show, and every handshake on it fails. */
    current:  string | null;
    /** The earliest of those switched on for it that are not valid yet, and when it will be. */
    next:     string | null;
    nextAt:   string | null;
    /** Whether the listener runs at all: the web interface only with HTTPS. */
    used:     boolean;
}

/** The whole store, grouped the way it is shown: every node's, and what each listener shows. */
export interface CertificateStore extends NodeCertificateStore<CertificateKind> {
    /** What an identity may be told it is for. */
    listeners:     TLSListener[];
    certificates:  Record<CertificateKind, Certificate[]>;
    shown:         Record<TLSListener, ListenerCertificates>;
}

/** What an import sends: the file, base64-encoded, and what to make of it. */
export type CertificateImport = NodeCertificateImport<CertificateKind>;

/** A certificate, as far as a page asks about one it does not keep. */
export interface CertificateSummary {
    subject:     string;
    issuer:      string;
    notBefore:   string;
    notAfter:    string;
    thumbprint:  string;
}

/** The certificates this meter was started with, as they stand, and the roles a client certificate may carry. */
export interface CertificateConfiguration {
    /** What Modbus/TLS clients are shown now - or, while the store has nothing to show them, what the meter was started with. */
    meter:         CertificateSummary;
    /** The CA the meter was started with. */
    clientCA:      CertificateSummary;
    sunSpecRoles:  string[];
}


// Signing requests

/**
 * A key made in this meter, and the request a CA is sent for it: waiting for
 * its certificate, or answered and kept, so that the same key can be
 * certified again.
 */
export interface SigningRequest {
    id:           string;
    /** Which listener the certificate is for. */
    listener:     TLSListener;
    createdAt:    string;
    subject:      string;
    dnsNames:     string[];
    ipAddresses:  string[];
    /** One of the ids of `keyTypes`, e.g. "ecdsa-p256". */
    keyType:      string;
    note:         string | null;
    /** The handles of the identities its answers became, where the store still has them. */
    answeredBy:   string[];
    state:        'awaiting a certificate' | 'answered';
}

/** The signing requests of this meter, newest first, and what a new one may ask for. */
export interface SigningRequests {
    requests:        SigningRequest[];
    listeners:       TLSListener[];
    /** What a request may ask for, and what each one means. */
    keyTypes:        KeyAlgorithmInfo[];
    /** What is asked for when nobody says. */
    defaultKeyType:  string;
}

/** What a new signing request asks for. */
export interface NewSigningRequest {
    listener:      TLSListener;
    subject:       string;
    dnsNames?:     string[];
    ipAddresses?:  string[];
    /** One of the ids of `keyTypes`; the default one where it is left out. */
    keyType?:      string;
    note?:         string;
}

/** What putting in the certificate for a request answers with: the request, and the identity it became. */
export interface AnsweredRequest {
    request:      SigningRequest;
    certificate:  Certificate;
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


// Asking

/** The routes every node has, typed with what a meter says its own of them are. */
const node = nodeAPI<{ me: Me; status: Status; configuration: NodeConfiguration; kind: CertificateKind; store: CertificateStore }>();

export const api = {

    ...node,

    auth: {

        ...node.auth,

        /**
         * Your own password. The current one has to come with it - which is
         * what stops whoever finds an unlocked browser from taking the account
         * over - and every other session of the account ends.
         */
        changePassword: (currentPassword: string, newPassword: string) =>
                            extRequest<void>('POST', '/auth/password', { currentPassword, newPassword })

    },

    meter: {
        get:          ()                     => request<MeterReadings>('GET',  '/meter'),
        /** The number a Modbus client would write, or the word a person would say. */
        setMode:      (mode: MeterModeName)  => request<MeterMode>    ('PUT',  '/meter/mode', { mode }),
        /** The same register a Modbus client writes, so there is one way of clearing them. */
        resetEnergy:  ()                     => request<unknown>      ('POST', '/meter/energy/reset', {})
    },

    /**
     * The node's certificate store: what this meter believes, what its two
     * listeners show and the servers it recognises - and the keys made here,
     * with the requests a CA is sent for them.
     *
     * One store where there were three. What a charging station checks still
     * comes from a device PKI and what a browser checks from wherever the
     * operator's web certificates come from, and nothing issues a certificate
     * both of them would accept - which is why an identity is told which
     * listener it is for, rather than kept in a store of its listener's own.
     * Every node's routes of the store refuse, besides, what would leave a
     * listener with nothing to show, or Modbus/TLS clients with no CA to be
     * issued by.
     */
    certificates: {

        ...node.certificates,

        /** The keys made here with their requests, and what a new one may ask for. */
        requests:       ()                            => request<SigningRequests>         ('GET',    '/certificates/requests'),

        /**
         * Make a key and write a signing request for it. The key stays here.
         *
         * Given three minutes rather than the half of one any other write
         * gets, as the local controller gives its own: an RSA key is a search
         * for two primes that takes as long as it takes, and a meter may be a
         * small board.
         */
        createRequest:  (signing: NewSigningRequest)  => request<SigningRequest>          ('POST',   '/certificates/requests', signing, 3 * 60_000),

        /** Where the browser fetches the request itself; it arrives as a file. */
        requestURL:     (id: string)                  => apiURL(`/certificates/requests/${encodeURIComponent(id)}`),

        /**
         * The signed certificate coming back, with the intermediates above
         * it, checked against the key that asked. A second one for the same
         * request is a renewal for the same key.
         */
        answerRequest:  (id: string, pem: string)     => request<AnsweredRequest>         ('PUT',    `/certificates/requests/${encodeURIComponent(id)}`, { pem }),

        /** Throw a request away, and its key with it. What was put into the store from it stays there. */
        removeRequest:  (id: string)                  => request<SigningRequests>         ('DELETE', `/certificates/requests/${encodeURIComponent(id)}`),

        /** What the meter was started with, and the SunSpec roles a client certificate may carry. */
        configuration:  ()                            => request<CertificateConfiguration>('GET',    '/configuration/certificates')

    },

    /**
     * Who may sign in to this meter, and as what.
     *
     * Reading the list needs accounts:read; reading what the roles mean does
     * not, because it names nobody and is what somebody who was given one
     * wants to know about their own.
     */
    accounts: {
        list:           ()                             => request<AccountList>          ('GET',    '/accounts'),
        roles:          ()                             => request<{ roles: RoleInfo[] }>('GET',    '/accounts/roles'),
        create:         (account: NewAccount)          => request<AccountWithPassword>  ('POST',   '/accounts', account),
        setRole:        (userId: string, role: string) => request<Account>              ('PUT',    `/accounts/${encodeURIComponent(userId)}/role`, { role }),
        /** A new password for somebody who has lost theirs; not for your own account. */
        resetPassword:  (userId: string)               => request<AccountWithPassword>  ('PUT',    `/accounts/${encodeURIComponent(userId)}/password`, {}),
        remove:         (userId: string)               => request<AccountRemoved>       ('DELETE', `/accounts/${encodeURIComponent(userId)}`)
    },

    /**
     * The keys this meter signs readings with.
     *
     * Not the TLS certificates and not kept with them: a TLS key says "this
     * listener is this host" for the length of a connection, and these say
     * "this meter measured this" and have to go on meaning it for years.
     */
    keys: {
        list:        ()                                  => request<SigningKeys> ('GET',    '/keys'),
        create:      (algorithm: string, note?: string)  => request<PublicKeyOut>('POST',   '/keys', { algorithm, note }),
        /** Sign with this one from now on; changes nothing about what was signed before. */
        setDefault:  (id: string)                        => request<SigningKeys> ('PUT',    `/keys/${encodeURIComponent(id)}/default`),
        remove:      (id: string)                        => request<SigningKeys> ('DELETE', `/keys/${encodeURIComponent(id)}`)
    },

    /** Readings this meter has put its name to, and the sessions they belong to. */
    signing: {

        /** One reading that belongs to no charging session. */
        value:  (format: 'ocmf' | 'alfen', key?: string) => {

            const query = new URLSearchParams({ format });

            if (key)
                query.set('key', key);

            return request<SignedMeterValue>('GET', `/signedMeterValues?${query}`);

        },

        session:  ()  => request<SessionState>('GET', '/sessions'),

        start:    (identification?: string, identificationType?: string) =>
                      request<SessionStarted>('POST', '/sessions/start', { identification, identificationType }),

        /** Answers with one OCMF document holding both readings. */
        stop:     ()  => request<SessionStopped>('POST', '/sessions/stop', {})

    },

    /**
     * Walk the log on disk: every line against its hash, the chain and the
     * signature. Given three minutes rather than the quarter of one any other
     * read gets: it reads every file the meter kept, and the log book is kept
     * whole.
     */
    verifyLog: () => request<LogVerification>('GET', '/logs/verify', undefined, 3 * 60_000)

};
