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
    /**
     * Whether it is in the log book as well - signed, chained and kept whole -
     * because it is evidence: a refusal, a write, the clock. Absent where not.
     */
    metrological?:  boolean;
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
 * What there is to be allowed to do something with: the node's resources -
 * configuration, dns, nts, certificates - and the meter's.
 */
export type Resource = 'configuration'
                     | 'dns'
                     | 'nts'
                     | 'certificates'
                     | 'meter'
                     | 'keys'
                     | 'log'
                     | 'accounts';

/** The three things one may be allowed to do with a resource, the same on every node. */
export type Operation = 'read' | 'edit' | 'run';

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
export interface Me {
    username:     string;
    name:         string | null;
    organization: string;
    /** Their strongest role on this meter, or null when they have none. */
    role:         string | null;
    /** Every role they hold - one per group of that name they are in - in the node's order: the viewer first, the administrators last. */
    roles:        string[];
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

/**
 * One name server this meter asks - and what it is held to, in the keys the
 * meter writes that under, which the DNS page does not show and sends back as
 * they came.
 */
export interface DNSServer extends PinKeys {
    /** An IP address or a host name. */
    address:              string;
    port:                 number;
    transport:            string;
    /** Its own query timeout, or null for the one in the settings. */
    queryTimeoutSeconds:  number | null;
    /**
     * What it is held to, as the meter says it: null for nothing beyond the
     * usual checks - and not there at all on a server added on the page,
     * which the meter has nothing of.
     */
    heldTo?:              ServerPins | null;
    /**
     * What the page had it held to, in the keys above: the meter changes
     * only what was changed on the page, and keeps what the server learned
     * while the page was open. Only on a server the page loaded, and never
     * read back.
     */
    pinsAsShown?:         PinKeys;
}

/** What may be changed about the name resolution while the meter runs. */
export interface DNSSettings {
    queryTimeoutSeconds:  number;
    /** null leaves it to the server's own default. */
    recursionDesired:     boolean | null;
    useCache:             boolean;
    dnssecOK:             boolean;
    followCNAMEs:         boolean;
    maxCNAMEFollows:      number;
    maxRetries:           number;
}

/** How this meter resolves names. */
export interface DNSConfiguration {
    enabled:    boolean;
    servers:    DNSServer[];
    settings:   DNSSettings;
    /** What was decided when the client was made, and is not on offer. */
    fixed:      Record<string, unknown>;
    limits: {
        maxServers:       number;
        maxQueryTimeout:  number;
        transports:       string[];
        recordTypes:      string[];
    };
    file:       string;
}

/**
 * What a PUT to the name resolution may carry - the shape of the "dns"
 * section of the configuration file, flat. What is left out stays as it is.
 */
export interface DNSUpdate {
    enabled?:              boolean;
    servers?:              DNSServer[];
    queryTimeoutSeconds?:  number;
    recursionDesired?:     boolean | null;
    useCache?:             boolean;
    dnssecOK?:             boolean;
    followCNAMEs?:         boolean;
    maxCNAMEFollows?:      number;
    maxRetries?:           number;
}

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
    /** The SHA-256 fingerprint of the certificate it has to show. */
    certificateFingerprint?:  string;
    /** The SHA-256 fingerprint of the root its chain has to end at. */
    rootFingerprint?:         string;
    /** What a fingerprint that does not match does: refuse the server - what a pin means anyway - or only write it down. */
    onMismatch?:              PinMismatch;
    /**
     * What the page showed the server held to, in the keys above: the meter
     * changes only what was changed on the page, and keeps what the server
     * learned while the page was open. Only on a server the page loaded.
     */
    pinsAsShown?:             PinKeys;
}

/**
 * What a fingerprint that does not match does: refuse the server, use it and
 * write the mismatch down, or use it and only say so in the log. The NTS
 * dialog offers the first two; the third is only ever read here.
 */
export type PinMismatch = 'refuse' | 'record' | 'accept';

/** What a server is held to from the first time it is believed. */
export type TrustOnFirstUse = 'root' | 'certificate';

/** What a time server or a name server is held to, where it is held to anything. */
export interface ServerPins {
    /** The first certificate and the first root - what the NTS page shows and edits. */
    certificate:       string | null;
    root:              string | null;
    /** All of them, where the configuration file holds it to more than one. */
    certificates?:     string[];
    roots?:            string[];
    onMismatch:        PinMismatch;
    /** What it learns the first time it is believed, where it is to learn anything. */
    trustOnFirstUse?:  TrustOnFirstUse | null;
}

/**
 * What a server is held to, in the keys its entry is written with: one of a
 * kind under the singular key, several under the plural - the way the
 * configuration file says it, and the way the meter takes it back.
 */
export interface PinKeys {
    certificateFingerprint?:   string;
    certificateFingerprints?:  string[];
    rootFingerprint?:          string;
    rootFingerprints?:         string[];
    onMismatch?:               PinMismatch;
    trustOnFirstUse?:          TrustOnFirstUse;
}

/** What the meter made of the certificate a time server showed at its last key exchange. */
export interface TimeServerJudgement {
    server:       string;
    at:           string;
    accepted:     boolean;
    /** "accepted", "recorded", "pinMismatch", "untrusted", "wrongName" or "noCertificate". */
    outcome:      string;
    /** The fingerprint of the certificate it showed, or null when it showed none. */
    certificate:  string | null;
    /** The fingerprint of the root its chain ends at, or null when it ends at none this meter trusts. */
    root:         string | null;
    /** The label of the root of the meter's own store the chain ends at, where the machine did not know that root. */
    anchoredBy:   string | null;
    heldTo:       { certificate: string | null; root: string | null } | null;
}

/**
 * What a save sends. Only what is given is changed; the rest of the section
 * stays as it is. The list of servers is sent whole.
 */
export interface NTSUpdate {
    enabled?:                    boolean;
    servers?:                    NTSServerEntry[];
    /** What a server's Test allows each of its two steps. */
    timeoutSeconds?:             number;
    minServers?:                 number;
    maxDeviationSeconds?:        number;
    checkEverySeconds?:          number;
    /** Null takes the authority away. */
    legalTimeAuthority?:         string | null;
    legalTimeToleranceSeconds?:  number;
    legalTimeMaxAgeSeconds?:     number;
}

/** One line of what happened while a time server was being asked. */
export interface TimeServerTestStep {
    at_ms:  number;
    level:  'info' | 'notice' | 'warning' | 'error';
    text:   string;
}

/** What came of asking one time server everything. */
export interface TimeServerTest {
    host:        string;
    ok:          boolean;
    runtime_ms:  number;
    steps:       TimeServerTestStep[];
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
    aeadAlgorithm?: string | null;

    /**
     * The root CA the certificate chain of the last key exchange ended at -
     * the chain this meter built, so the root it judged the certificate by -
     * or null before the first exchange.
     */
    rootCA?:        NTSRootCA | null;

    /** The SHA-256 fingerprint of the certificate the last key exchange showed. */
    certificate?:   string | null;
    /** What this server is held to, or null when it is held to nothing but the usual checks. */
    heldTo?:        ServerPins | null;
    /** What the meter made of the certificate at the last key exchange. */
    judgement?:     TimeServerJudgement | null;
}

/** A root CA, by a name to call it, its subject, and its SHA-256 fingerprint. */
export interface NTSRootCA {
    name:         string;
    subject:      string;
    fingerprint:  string;
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
    now:        string;
    /** Always "system": said out loud, because the check below did not set it. */
    source:     string;
    nts: {
        enabled:       boolean;
        /** The group the clock is checked against, its servers and its quorum; null while switched off. */
        group:         string | null;
        /** The one server by name when the group has only one. */
        server:        string | null;
        servers:       string[] | null;
        minServers:    number | null;
        /** The last check: which server's answer it went by, how many were asked and how many answered. */
        lastServer:    string | null;
        asked:         number | null;
        answered:      number | null;
        checkedAt:     string | null;
        ageSeconds:    number | null;
        offset_ms:     number | null;
        everySeconds:  number;
    };
    legal:             boolean;
    authority:         string | null;
    /** null while legal; otherwise "notClaimed", "ntsOff", "neverChecked", "stale" or "offBy". */
    why:               string | null;
    toleranceSeconds:  number;
    maxAgeSeconds:     number;
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
 * One certificate in the store. Everything but its label, whether it is
 * switched on and what it is for is read out of the file.
 */
export interface Certificate {
    /** The handle it is addressed by: the first 16 digits of its fingerprint. */
    id:             string;
    kind:           CertificateKind;
    fileName:       string;
    label:          string;
    subject:        string;
    issuer:         string;
    serialNumber:   string;
    /** Its SHA-256 fingerprint in full, for comparing against what a CA said. */
    thumbprint:     string;
    notBefore:      string;
    notAfter:       string;
    keyAlgorithm:   string;
    hasPrivateKey:  boolean;
    /** How many further certificates travel with it, e.g. its sub-CAs. */
    chainLength:    number;
    /** Whether this meter is using it. Somebody switches this; time does not. */
    active:         boolean;
    importedAt:     string;
    expired:        boolean;
    notYetValid:    boolean;
    /** Active, and inside its own validity. */
    usable:         boolean;
    description:    string;
    /**
     * What it is for - "dns" and "nts" for a TLS root or a server
     * certificate, "modbus" and "web" for an identity - and null there for
     * every use. Left out for a client root, which is for Modbus/TLS alone.
     */
    usages?:        string[] | null;
    /** An identity only: the listeners that show it right now. */
    shownOn?:       TLSListener[];
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

/** The whole store, grouped the way it is shown. */
export interface CertificateStore {
    directory:     string;
    /** The kinds that are trust anchors, in the order they are shown. */
    trustAnchors:  CertificateKind[];
    /** The kinds that are presented, in the order they are shown. */
    credentials:   CertificateKind[];
    /** The kinds that are neither: kept to recognise a server by its fingerprint. */
    recognised:    CertificateKind[];
    kinds:         Record<CertificateKind, {
                       description:     string;
                       trustAnchor:     boolean;
                       needsPrivateKey: boolean;
                       /** Whether one of this kind is told what it is for. */
                       hasUsages:       boolean;
                       /** What one of this kind may be told it is for; empty where it is not told. */
                       usages:          string[];
                   }>;
    /** What a TLS root or a server certificate may be told it is for. */
    usages:        string[];
    /** What an identity may be told it is for. */
    listeners:     TLSListener[];
    certificates:  Record<CertificateKind, Certificate[]>;
    shown:         Record<TLSListener, ListenerCertificates>;
    /** Whether anything in the store carries a private key, which is kept unencrypted. */
    keysAreUnencrypted: boolean;
}

/** What an import sends: the file, base64-encoded, and what to make of it. */
export interface CertificateImport {
    kind:       CertificateKind;
    /** The file's bytes, base64-encoded. PEM, DER or PKCS#12. */
    content:    string;
    /** What opens it, where it is a protected PKCS#12. Used once and not kept. */
    password?:  string;
    /** What to call it; its common name where this is left out. */
    label?:     string;
    /** What it is for, where its kind is told; left out for every use. */
    usages?:    string[];
}

/** What a change to a stored certificate may say. Everything else is read from the file. */
export interface CertificateUpdate {
    active?:  boolean;
    label?:   string | null;
    /** What it is for; null for every use again, and left out to leave it alone. */
    usages?:  string[] | null;
}

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


/**
 * The meter answering, and saying no.
 *
 * The fields are written out rather than declared in the constructor's
 * parameters: the tests run the client in Node, which strips the types and
 * nothing more, and a parameter property is code that has to be generated
 * rather than a type that can be taken away.
 */
export class ApiError extends Error {

    readonly status:  number;
    readonly body?:   unknown;

    constructor(status:   number,
                message:  string,
                body?:    unknown) {

        super(message);

        this.name    = 'ApiError';
        this.status  = status;
        this.body    = body;

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
const accountsAPI = <T>(method: string, path: string, body?: unknown) => request<T>(method, config.extBase      + path, body);


export const api = {

    /** The Server-Sent Events stream; the browser sends the session cookie along. */
    eventsURL: `${config.apiBase}/events`,

    auth: {
        me:      ()                                 => meterAPI   <Me>  ('GET',  '/auth/me'),
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
        /**
         * Every server switched on, asked the way the clock check asks them,
         * with every step in the log. The node answers with the whole NTS
         * configuration, which the exchange has moved, and the result in it.
         */
        sync:  async ()             => (await meterAPI<NTSConfiguration & { result: NTSSyncResult }>('POST', '/configuration/nts/sync', {})).result,
        /**
         * Ask one time server everything: the name, the key exchange with its
         * certificate, the authenticated NTP request, each one written down as
         * it happens.
         *
         * @param host  which server, asked on the ports it is configured with -
         *              or undefined for the single client's.
         */
        test:  (host?: string)      => meterAPI<TimeServerTest>  ('POST', '/configuration/nts/test', { host })
    },

    /** What time it is here, and what that is worth - at the same path on every node. */
    clock:  () => meterAPI<Clock>('GET', '/clock'),

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
     */
    certificates: {

        /** The whole store, grouped by kind, and what each listener shows now and next. */
        get:            ()                                       => meterAPI<CertificateStore>        ('GET',    '/certificates'),

        /**
         * Put a certificate into the store.
         *
         * Importing the same file twice is the same entry - the handle is its
         * fingerprint - so this is safe to repeat.
         */
        import:         (certificate: CertificateImport)         => meterAPI<Certificate>             ('POST',   '/certificates', certificate),

        /**
         * Switch one on or off, rename it, or say what it is for. Refused
         * where that would leave a listener with nothing to show, or
         * Modbus/TLS clients with no CA to be issued by.
         */
        update:         (id: string, update: CertificateUpdate)  => meterAPI<Certificate>             ('PATCH',  `/certificates/${encodeURIComponent(id)}`, update),

        /** Take one out of the store and delete its file - refused on the same grounds. */
        remove:         (id: string)                             => meterAPI<CertificateStore>        ('DELETE', `/certificates/${encodeURIComponent(id)}`),

        /**
         * Read the store's directory again.
         *
         * For certificates somebody copied in rather than uploaded - which is
         * a perfectly good way to install one on a machine you already have a
         * shell on.
         */
        reload:         ()                                       => meterAPI<CertificateStore>        ('POST',   '/certificates/reload', {}),

        /** The keys made here with their requests, and what a new one may ask for. */
        requests:       ()                                       => meterAPI<SigningRequests>         ('GET',    '/certificates/requests'),

        /** Make a key and write a signing request for it. The key stays here. */
        createRequest:  (request: NewSigningRequest)             => meterAPI<SigningRequest>          ('POST',   '/certificates/requests', request),

        /** Where the browser fetches the request itself; it arrives as a file. */
        requestURL:     (id: string)                             => `${config.apiBase}/certificates/requests/${encodeURIComponent(id)}`,

        /**
         * The signed certificate coming back, with the intermediates above
         * it, checked against the key that asked. A second one for the same
         * request is a renewal for the same key.
         */
        answerRequest:  (id: string, pem: string)                => meterAPI<AnsweredRequest>         ('PUT',    `/certificates/requests/${encodeURIComponent(id)}`, { pem }),

        /** Throw a request away, and its key with it. What was put into the store from it stays there. */
        removeRequest:  (id: string)                             => meterAPI<SigningRequests>         ('DELETE', `/certificates/requests/${encodeURIComponent(id)}`),

        /** What the meter was started with, and the SunSpec roles a client certificate may carry. */
        configuration:  ()                                       => meterAPI<CertificateConfiguration>('GET',    '/configuration/certificates')

    },

    /**
     * Who may sign in to this meter, and as what.
     *
     * Reading the list needs accounts:read; reading what the roles mean does
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
