# ModbusTLSEnergyMeter

A simulated three-phase energy meter that speaks **Modbus/TLS** (*mbaps*, the
registered port 802) and nothing else: there is no plaintext listener, every
peer must present a client certificate, and what that peer may do is decided by
the **SunSpec role** carried in an X.509v3 extension of its certificate.

This is the library. It is one class - `ModbusTLSEnergyMeter` - that a test, a
service or another program can host without starting a process:

```csharp
await using var meter = new ModbusTLSEnergyMeter(
                            SerialNumber:       "EnergyMeter01",
                            ServerPfxPath:      "pki/server.pfx",
                            ServerPfxPassword:  "demo",
                            ClientCACertPath:   "pki/issuing-clients-ca.crt",
                            MeterMode:          SunSpecMeterMode.ImportOnly,
                            HTTPS:              true
                        );

await meter.StartAsync();
```

Nothing listens until `StartAsync`, everything it does is said through its
`ILogger` and its properties, and `DisposeAsync` gives both listeners back.
[ModbusTLSEnergyMeterCLI](../../README.md) is the command line around this, and
is the shortest way to try any of what follows.

It is meant to stand in for the meters that
[ChargingStationCLI](https://github.com/OpenChargingCloud/ChargingStationCLI) and
[LocalControllerCLI](https://github.com/OpenChargingCloud/LocalControllerCLI)
need for their own use cases.


## Two doors

Modbus/TLS is what a charging station or a local controller speaks to this
meter, and what a peer may do there is decided by the role in its client
certificate - a machine-to-machine decision, made per request, with no notion of
a person. The HTTP side is where a person signs in to see and change what the
meter is, and what they may do is decided by their role in the meter's
organization.

Neither one's rights are expressible in the other's vocabulary, which is why
there are two ports and not one.


## What it simulates

A site with a load and a photovoltaic generator, and the meter reads whichever
part of it the **mode register** says it is in front of:

| Mode | 40094 | Where the meter sits | What it reads |
|------|:-----:|----------------------|---------------|
| `net`    | 0 | at the grid connection point | load minus generation: signed power, both counters move |
| `import` | 1 | in front of a load - what a charging station's meter is | power never negative, only `TotWhImp` moves |
| `export` | 2 | in front of a generator | power never positive, only `TotWhExp` moves, and zero at night |

**Sign convention**, which all of that rests on: positive real power is energy
flowing *into* the site (imported, the meter running forwards), negative is
energy flowing out of it (exported). The currents are magnitudes and stay
positive either way, the way a real meter reports them - the direction is in the
sign of the power alone. `A` is the total AC current, which is the three phases
added up; `PhV` is their average.

Both energy counters only ever grow, as a meter's do. Whichever way power is
flowing at the moment adds to one of them, and nothing subtracts from either.
What is added is what the reading says: after a step the counter has grown by
exactly `|W| × Δt`, the remainder of a step carried rather than truncated -
otherwise a 1200 W load, which is a third of a watt-hour per second, would be
lost entirely to a counter that can only add whole ones.

The load and the generation follow the time of day, so a meter left running
looks like a day: quiet at night, exporting around noon. `SimulatedDayLength`
compresses that day for a demo - it only speeds up those two curves, never the
counters, which always count real seconds so that anything watching in real time
can check them against the power it is reading.

The mode can be changed through either door, and both end up in the log the same
way: a Modbus client writes register 40094 with the role for it, or a person
uses `PUT /api/v1/meter/mode` and the web page over it. A value that is not one
of the three leaves the register as it was - a Modbus write can only be answered
with "illegal address", which would be a lie, so reading the register back and
finding the old mode is the older and plainer way of being told no.

The simulation lives in Hermod's `SunSpecMeterDevice`, which is also where it
can be stepped by hand (`Advance`) rather than by its own background task.


## The registers

SunSpec Common Model 1 followed by a subset of Meter Model 213, based at 40000:

| Address | Contents |
|---------|----------|
| 40000 - 40001 | `SunS` marker |
| 40002 - 40069 | Common Model 1: manufacturer, model, options, version, serial |
| 40068 | unit address - **protected** |
| 40070 - 40071 | Meter Model 213 header, id and length |
| 40072 - 40076 | current: total, L1, L2, L3, scale factor (-2) |
| 40077 - 40081 | voltage: average, L1, L2, L3, scale factor (-1) |
| 40082 - 40083 | frequency, scale factor (-2) |
| 40084 - 40088 | power: total, L1, L2, L3, scale factor (0) - signed |
| 40089 - 40093 | energy exported, energy imported, scale factor (0) |
| 40094 | meter mode - **commanded**, `0` net, `1` import only, `2` export only |
| 40095 | reset energy - **commanded**, write `0xCAFE` to clear both counters |
| 40096 - 40097 | end-of-models marker |

Everything not marked is read-only; a write to it is refused whatever the role.
Measurements move once a second.

Addresses here are absolute, as SunSpec writes them. Clients that count
registers from one - Hermod's own Modbus client among them - need the usual
offset of 1.


## Roles

Every client certificate carries exactly one role in the extension
`1.3.6.1.4.1.50316.802.1`, as an ASN.1 `UTF8String` - the Modbus.org PEN, per
[MBTLS] §8.4 and SunSpecTCP-29..31. The meter reads it during the handshake and
decides each request against it:

| Role | read | write commanded | write protected |
|------|:----:|:---------------:|:---------------:|
| `ReadOnlySunSpec`             | yes | no  | no  |
| `GridServiceSunSpec`          | yes | yes | no  |
| `NetworkAdministratorSunSpec` | yes | yes | yes |
| `SuperAdministratorSunSpec`   | yes | yes | yes |

A certificate without a role gets Modbus exception 01 for everything, as
SunSpecTCP-32 requires.

The decision is taken in the TLS frontend, once per request, before a single
Modbus byte reaches the device behind it.


## Signing in

Beside the Modbus/TLS listener there is an HTTP server, on port 2351 by default,
where a person signs in to administer the meter. Accounts, organizations and
sessions are Hermod's `HTTPExtAPI`, and the role somebody holds in the meter's
organization - `IsAdmin`, `IsAdminReadOnly`, `IsMember`, `IsGuest` - is what
separates who may change this meter from who may only watch it.

At the first start there are no accounts, so one administrator is made and its
password reported once, through `GeneratedUserId` and `GeneratedPassword`, for
the host to print. That account is an `IsAdmin` of the organization
`EnergyMeter`. Accounts live under `DataPath`.

Three things are served, and each answers for itself because Hermod dispatches
to the most specific of them first:

| | |
|---|---|
| `/` | the web interface |
| `/accounts` | signing in, users, organizations - Hermod's `HTTPExtAPI` |
| `/api/v1` | this meter's own JSON API |

Signing in is a `POST` to `/accounts/auth/login` with
`{"login": ..., "password": ...}`, which answers with the session cookies that
every resource below is read with.


### More than one of them

The first administrator is not meant to be the only account. Under
Configuration -> Accounts an administrator makes more, gives each a role, resets
a password somebody has lost, and takes an account away again; everybody else
finds their own account there and nothing else.

Three of the four roles change nothing, which is the reason the page exists.
Watching what a meter is doing - on a night shift, over the phone, for an audit
- should not need the account that can also clear the energy counters or replace
the certificate. `IsMember` sees the readings and the configuration and touches
neither; `IsGuest` sees only the readings; `IsAdminReadOnly` additionally sees
the certificates and may ask a time server whether it answers, which sends
traffic and is therefore not folded into reading.

No password is asked for when an account is made: the meter makes one, shows it
once, and keeps it nowhere it could be read back. The person it was made for
replaces it at `POST /accounts/auth/password`, which asks for the current one
first - the one thing an administrator's reset cannot ask for, and the reason
the two are different routes.

Two rules, and only two:

* **The last administrator cannot be demoted or removed.** A meter with none
  left cannot be given another one from a browser, cannot be given a new
  certificate and cannot be told which CAs to accept; the only way back is a
  text editor on its disk. Stepping down is allowed as soon as somebody else is
  an administrator, which is what handing a meter over looks like.
* **A password is reset for somebody else, never for yourself.** That route asks
  for no current password, because an administrator does not know it - pointed
  at your own account it would be a way for whoever finds an unlocked browser to
  take it over.

A role that changes ends every session of that account, and so does a reset: a
browser holding the old answer of `/me` would go on offering buttons that now
answer 403, and a reset that left the old session alive would not have taken the
account back.


## The JSON API

Everything below `/api/v1` needs the session cookie, and each resource names the
permission it wants. What a person may do follows from their role in the
organization `EnergyMeter`:

| Role | read meter | read config | change DNS/NTS | diagnostics | write registers | certificates | accounts |
|------|:----------:|:-----------:|:--------------:|:-----------:|:---------------:|:------------:|:--------:|
| `IsAdmin`          | yes | yes | yes | yes | yes | yes | yes |
| `IsAdminReadOnly`  | yes | yes | no  | yes | no  | no  | no  |
| `IsMember`         | yes | yes | no  | no  | no  | no  | no  |
| `IsGuest`          | yes | no  | no  | no  | no  | no  | no  |

Managing certificates is its own permission and not part of changing network
settings, because it is a bigger thing than any of those: which certificate this
meter shows is who it says it is, and which CAs it trusts is who may talk to it
at all. Somebody who may repoint a name server has not thereby been handed the
identity of the device.

A role this meter does not know, and an account belonging to no organization of
it, grant nothing at all.

The names in that table are what the API speaks. What a page shows is the
readable form - "Read-only administrator" rather than `IsAdminReadOnly` - and it
travels with the role in `/api/v1/me` rather than being looked up, because every
page that tells somebody what they may not do here names their role in the same
sentence and none of them should need a second request to translate one word.

| Resource | |
|----------|---|
| `GET  /api/v1/me` | who is signed in, their role - as this meter spells it and as a person would say it - and their permissions |
| `GET  /api/v1/status` | serial, uptime, both listeners |
| `GET  /api/v1/meter` | the readings with scale factors applied, the mode, and what the simulated site is doing |
| `GET  /api/v1/meter/registers?start=&count=` | the raw register block |
| `PUT  /api/v1/meter/mode` | `{"mode": 0\|1\|2}` or `{"mode": "net"\|"import"\|"export"}` |
| `POST /api/v1/meter/energy/reset` | clear both energy counters |
| `GET  /api/v1/configuration` | every section at once |
| `GET/PUT /api/v1/configuration/dns` | how it resolves names |
| `GET/PUT /api/v1/configuration/nts` | where it reads the time |
| `POST /api/v1/configuration/nts/sync` | check the clock now |
| `GET  /api/v1/configuration/time` | what time it is, and what that is worth |
| `GET  /api/v1/configuration/certificates` | which certificates it was started with |
| `GET  /api/v1/certificates` | both server stores and the accepted client CAs, in one answer |
| `GET  /api/v1/certificates/servers/{modbus\|web}` | one store |
| `POST /api/v1/certificates/servers/{purpose}/requests` | make a key and a signing request for it |
| `GET  /api/v1/certificates/servers/{purpose}/{id}/request` | that request, as a file |
| `PUT  /api/v1/certificates/servers/{purpose}/{id}` | `{"pem": ...}`, the signed certificate coming back |
| `DELETE /api/v1/certificates/servers/{purpose}/{id}` | throw an entry and its key away |
| `GET/POST /api/v1/certificates/clients` | the CAs Modbus/TLS clients may chain to |
| `PUT/DELETE /api/v1/certificates/clients/{id}` | switch one off, or remove it |
| `GET  /api/v1/signedMeterValues?format=&key=` | one reading, signed; `ocmf` or `alfen` |
| `GET  /api/v1/sessions` | the charging session that is running, if one is |
| `POST /api/v1/sessions/start` | begin one; answers with the time and the public key |
| `POST /api/v1/sessions/stop` | end it; answers with one OCMF document holding both readings |
| `GET  /api/v1/keys` | the signing keys, without their private halves |
| `POST /api/v1/keys` | make one: `{"algorithm": "Ed448"}` |
| `PUT  /api/v1/keys/{id}/default` | sign with this one from now on |
| `DELETE /api/v1/keys/{id}` | throw one away, with everything it could still prove |
| `GET  /api/v1/accounts` | who may sign in, and the roles that can be given out |
| `POST /api/v1/accounts` | make one; leaving out the password gets one the meter made |
| `GET  /api/v1/accounts/roles` | what each role is called and what it grants |
| `PUT  /api/v1/accounts/{id}/role` | `{"role": "IsMember"}` |
| `PUT  /api/v1/accounts/{id}/password` | a new password for somebody who lost theirs |
| `DELETE /api/v1/accounts/{id}` | take an account away |
| `GET  /api/v1/logs?limit=&after=&tag=` | what happened, newest last |
| `GET  /api/v1/logs/verify` | walk the log on disk and check every line |
| `GET  /api/v1/events` | the log as a Server-Sent Events stream |

A `PUT` writes the configuration file before the change takes effect, and
answers with the section as it now stands. Unknown paths below `/api` answer
with a JSON 404 rather than falling through to the accounts.

```bash
curl -c jar -X POST http://127.0.0.1:2351/accounts/auth/login -H 'Content-Type: application/json' -d '{"login":"admin","password":"..."}'
```

```bash
curl -b jar http://127.0.0.1:2351/api/v1/meter
```

`GET /api/v1/meter` answers with the registers made readable, and beside them -
marked as belonging to no register - what the simulated site is doing:

```json
{ "total":      { "name": "total", "voltage_V": 229.5, "current_A": 19.69, "power_W": -4525 },
  "energy":     { "exported_Wh": 11, "imported_Wh": 18 },
  "meterMode":  { "value": 2, "name": "export",
                  "description": "in front of a generator: exporting only" },
  "simulation": { "load_W": 3225, "generation_W": 4525,
                  "timeOfDay": "2026-09-16T08:40:12+02:00", "dayLength_s": 600 } }
```

The load and the generation are what the mode selects *between*, so a page or a
client that has only the result cannot say why a meter in front of a generator
is reading zero at three in the morning.

State-changing requests are refused when a browser says they came from another
site, and 403 is used rather than 401 where signing in again would not help.


## The web interface

The same frame a charging station wears - a menu on the left, a page on the
right - so that somebody looking after both does not have to learn two
interfaces.

It lives in `ModbusTLSEnergyMeter/Frontend`: HTML, SCSS and TypeScript, bundled
by webpack into `Frontend/dist`, which the project file embeds into the assembly
as manifest resources. A meter is still one binary to deploy and still needs
nothing installed beside it; what changed is that the page has a toolchain
rather than being one file with everything inside it.

```bash
npm ci        # once
npm run build # or: npm run watch
npm run typecheck
```

`dotnet build` does this by itself when anything below `Frontend/src` changed,
and `-p:SkipFrontendBuild=true` leaves it alone.

Pages: the meter and what it is measuring, the DNS client, the NTS client with
the state of the clock, a page each for the two certificate stores and one for
the accepted client CAs, the signing keys, the charging sessions, the accounts,
and the log. The DNS and NTS pages are
forms - name servers can be added and removed, timeouts and ports changed, and
the time authority named - and each save writes the configuration file before
the change takes effect. Accounts is the one page everybody signed in can reach,
because everybody has a password of their own to change; what an administrator
additionally sees there is everybody else's account. What somebody may not do is not offered: the controls
are absent rather than disabled-and-refused, though every request is checked
again on arrival, so a browser that puts them back gains nothing but a 403.

Every URL that is not one of the APIs and does not look like a file of the
bundle gets the stub with status 200, which is what makes a reload on a deep
link and a bookmark to one work. A URL that does look like a file and is not one
gets a real 404: a mistyped script tag must not hand the browser HTML to run.


## Certificates

Two stores and a trust store, under `<DataPath>/certificates/`. What lives in
each of them is decided by who checks it:

| | `certificates/modbus/` | `certificates/web/` |
|---|---|---|
| shown to | a charging station or a controller | a browser |
| issued by | a device PKI | wherever the operator's web certificates come from |
| checked against | the CA that peer has pinned | the browser's own trust store |
| first entry | the certificate this meter was started with, adopted | one this meter signs for itself |

They are deliberately not one store. A certificate both would accept would have
to be issued by a CA that is both pinned by the charging station and trusted by
the browser, and nothing issues such a thing.

### Asking for one

The private key is made in the meter and never leaves it. What goes out is a
PKCS#10 request; what comes back is a certificate, which is checked against the
key that asked for it before it is kept - a certificate this meter has no key
for is no use to it, and finding that out at the next handshake would be
finding it out as an outage.

```
POST /api/v1/certificates/servers/web/requests
     {"subject": "CN=meter7.lan, O=Acme", "dnsNames": ["meter7.lan"], "keyType": "ec256"}
GET  /api/v1/certificates/servers/web/<id>/request      -> the .csr, as a file
PUT  /api/v1/certificates/servers/web/<id>              {"pem": "-----BEGIN CERTIFICATE-----..."}
```

or the same three steps as three controls on the page.

### On which key

The kinds of key come from Hermod's `KeyAlgorithm`, and the list is served with
the certificates so that a kind added there turns up on the page without
anything here changing:

| | |
|---|---|
| `ecdsa-p256`, `ecdsa-p384`, `ecdsa-p521` | ECDSA on the NIST curves. `ecdsa-p521` is secp521r1 - there is no secp521r2 |
| `rsa-2048`, `rsa-3072`, `rsa-4096` | RSA |
| `ed25519`, `ed448` | Edwards curves |
| `ml-dsa-44`, `ml-dsa-65`, `ml-dsa-87` | ML-DSA, FIPS 204 |
| `slh-dsa-sha2-128s`, `slh-dsa-sha2-192s` | SLH-DSA, FIPS 205 - post-quantum on hash functions alone |

Everything goes through Bouncy Castle, including the kinds .NET could do by
itself: .NET cannot sign a request with an Ed448 or an ML-DSA key, and a store
that generated one way and read back another would be a store with two sets of
bugs in it.

**Whether a certificate can then be shown is a different question, and it is not
answered from a list.** It depends on the operating system's TLS stack, on the
runtime and on the year - an Ed25519 certificate is refused by one platform and
served by the next. Hermod finds out by doing it: one TLS handshake against
itself, once per algorithm. A store written before knew the answer from a table
in its own source, which would have been wrong on somebody's machine from the
day it was written.

So `keyTypes` in the certificates overview carries three answers per algorithm -
yes, no, and nobody has tried - and an entry says `servedByTLS` once there is a
certificate to ask about. One this meter cannot present is kept, says "not for a
listener", and is never handed to either listener.

The old spellings this store used before Hermod had a list - `ec256`, `rsa3072`,
`mldsa65` - are still read, so a certificate already in a store is not lost over
a rename. Nothing writes them any more.

### Which one is shown

Of the certificates that are valid at this moment, the one whose validity began
last. Nothing else decides it, and nothing has to be pressed:

* Both listeners ask the store **at every handshake**. A certificate that is
  valid now is shown to the next peer that connects - no restart, and existing
  connections are not disturbed.
* A certificate uploaded today that becomes valid in two days is simply not the
  answer until then, and is the answer from the second it is. The page says
  which one is waiting and when it takes over.
* "Newest" is by `notBefore` and not by when it was uploaded, because what a
  certificate says about itself is the thing both ends of a handshake can check.
* An expired one stops being shown. Once a minute the meter looks again, so that
  a rollover is written down when it happens rather than whenever the next peer
  turns up - on a quiet meter that could be the following afternoon.

An entry is kept with its key until it is thrown away, so the certificate this
meter was running under last month can still be pointed at. The one being shown
cannot be removed while it is the only one that could be: a listener with
nothing to show refuses every handshake, and doing that to oneself through a web
page is not a mistake worth making possible.

### Who may connect

`certificates/trust/` holds the CAs a **Modbus/TLS client** certificate may
chain to - more than one, on purpose. A meter in the field is reached by peers
whose certificates were issued by different people, and even with one issuer,
replacing it happens while both the old and the new one still have to work. A
single pinned CA makes that a flag day.

Anchors are asked for at every handshake as well, so adding or removing one
takes effect on the next connection. The last accepted CA cannot be removed: a
meter that accepts none refuses every Modbus/TLS client.

This is only about Modbus/TLS. The web interface authenticates nobody by
certificate; there a person signs in with an account.

### The intermediates

A certificate signed by an issuing CA under a root is no use on its own: a peer
that holds only the root cannot build a path to it. So whatever came in the PEM
alongside the certificate is kept and sent with it - both listeners build an
`SslStreamCertificateContext` from the leaf and those intermediates, once per
distinct chain and with `offline: true`, so that building it never reaches for
the network. A server that pauses a handshake to fetch something is a server
somebody can hold still by not answering.

A root that turns up in the file is dropped rather than sent: bytes on the wire
that change nothing. So is the leaf, if it appears twice.

**This works on Linux and not on Windows**, and the difference is not in this
code. On Linux the intermediates go out as given - measured, not assumed: the
same certificate that arrives alone from a meter on Windows arrives with its
issuing CA from one on Linux, as `openssl s_client -showcerts` counts them.
Windows builds the chain it sends inside SChannel, from that machine's own
certificate stores, and ignores what a program hands it; the intermediates have
to be installed in the local computer's intermediate CA store instead. A meter
started on Windows with intermediates in its store says so in its log at
startup, rather than leaving it to be discovered as a handshake that fails for
no visible reason.


## Signed meter values

A reading over the JSON API is a number this meter says it measured. A signed
one is a number somebody can still check in a year, against a key that was this
meter's before the reading was taken.

The documents are written here and read by [ChargyCore.NET][chargy], which is
the same code that verifies real charging sessions under the German calibration
law. Everything below was established by producing a document and handing it to
that reader.

### The meter's own key

At the first start the meter makes itself a signing key and says so:

```
[notice signing] No signing key yet, so this meter made itself one:
                 '20260916-084817-ce51ba' (ECDSA-P256), fingerprint 06acf9619045e01e.
                 It is the identity of this meter and does not change.
```

It is kept under `<data>/keys`, apart from the TLS certificates and deliberately
so. A TLS key says "this listener is this host" for the length of a connection
and is replaced whenever a CA issues a new certificate; this one says "this
meter measured this", and has to go on meaning that for as long as anybody may
want to check a reading.

More keys can be made, because the formats disagree about cryptography and
cannot be talked out of it:

| Algorithm | |
|---|---|
| `ECDSA-P256` | OCMF's own algorithm, and what a meter makes for itself |
| `ECDSA-P384`, `ECDSA-P521`, `ECDSA-secp256k1` | the other curves OCMF names |
| `Ed25519`, `Ed448` | Edwards curves; the payload is signed directly |
| `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` | lattice signatures, for a document meant to outlive a quantum computer |
| `ECDSA-secp192r1` | only for Alfen, which parses no other curve |

The last one is 192 bits and nobody should choose it for anything new; it is
here because the Alfen format carries a 25 byte compressed point and refuses
everything else.

A key can be made, made the identity, and removed - never the last one, because
a meter with no signing key can still measure and nothing it measures can be
shown to have come from it.

### A reading on its own

```bash
curl -b jar "http://127.0.0.1:2351/api/v1/signedMeterValues?format=ocmf"
```

```json
{ "format":     "OCMF",
  "timestamp":  "2026-09-16T08:48:17Z",
  "ocmf":       "OCMF|{\"FV\":\"1.0\", ...}|{\"SD\":\"3045...\",\"SA\":\"ECDSA-secp256r1-SHA256\",\"SE\":\"hex\"}",
  "publicKey":  { "publicKey": "3059...", "encoding": "hex", "format": "SubjectPublicKeyInfo" } }
```

`format` is `ocmf` or `alfen`, and `key` names a key other than the identity.
OCMF calls a reading that belongs to no charging session a fiscal reading and
counts it in a sequence of its own, which is the `"PG": "F12"` in the payload.

The public key comes with the answer in the shape that format's reader wants it,
which is not one shape: an OCMF reader hands an ECDSA key to a DER parser and
expects a SubjectPublicKeyInfo, and hands an Ed25519 or ML-DSA key straight to
the signature suite and expects the raw key. Getting that wrong produces a
document that is signed correctly and reads as a forgery.

### A charging session

```bash
curl -b jar -X POST http://127.0.0.1:2351/api/v1/sessions/start -H 'Content-Type: application/json' -d '{"identification":"DEADBEEF01","identificationType":"ISO14443"}'
```

```json
{ "timestamp":   "2026-09-16T08:48:18Z",
  "sessionId":   "20260916-084818-4e6b7b",
  "startValue":  0.0,
  "unit":        "kWh",
  "publicKey":   { "publicKey": "3059...", "encoding": "hex", "format": "SubjectPublicKeyInfo" } }
```

The public key is the point of answering at all: whoever gets it now can check
the document that comes back at the end against a key they were given before the
session began.

The start reading is kept here rather than handed out. A start reading on its
own is a number saying a meter stood somewhere at some moment, which is not
evidence of anything.

```bash
curl -b jar -X POST http://127.0.0.1:2351/api/v1/sessions/stop -H 'Content-Type: application/json' -d '{}'
```

```json
{ "timestamp":   "2026-09-16T08:48:27Z",
  "startValue":  0.0,
  "stopValue":   0.003,
  "energy_kWh":  0.003,
  "ocmf":        "OCMF|{...\"RD\":[{\"TX\":\"B\",\"RV\":0.0,...},{\"TX\":\"E\",\"RV\":0.003,...}]}|{...}" }
```

One document with both readings in it, and not two documents. That is what makes
it a charging session: two separately signed readings are two facts about a
meter, and the energy between them is an inference somebody else has to be
trusted to have drawn correctly. Here the subtraction is inside what was signed.

One session at a time, because this meter is one measuring point. Starting a
second while the first runs is a 409 naming the one that is open, and the key
the session started with is the key it is signed with at the end - a document
whose two readings were signed by different keys is not one document.


### Across a restart

A car left plugged in while the software is restarted is the ordinary case, not
the strange one, so a session that was running is still running when the meter
comes back:

```
[info   meter]    The energy counters came back where they were left: 5 imported, 0 exported (scale factor 0).
[notice sessions] The charging session '20260916-123213-dbc394' was running when this meter last
                  stopped and still is: started 2026-09-16 12:32:13Z at 0 kWh.
```

Two things have to survive for that to mean anything, and the second is the one
that is easy to miss. The session itself is kept in `<data>/sessions/session.json`
while it runs and taken away when it stops - a stopped session that came back
could be stopped a second time, into a second document for one charging session.

And the meter has to still be standing where it was. A real energy meter's
register is monotonic and survives losing power; most of what makes it a meter
rather than a sensor is that it does. This simulation held its counters in
memory, so every restart put them back to zero - invisible until something spans
a restart, and then a charging session that used a negative amount of energy. The
counters now live in `<data>/meter-state.json` and go back into the registers
before the first reading is taken.

Where that still fails, it says so rather than signing nonsense: if the counter
has gone backwards past where a session began - cleared, or lost further than the
last write - stopping it is refused and the session stays open until the counter
passes its start reading again.

### What the timestamp admits

Every OCMF reading carries one letter saying how far the clock behind it can be
trusted. This meter writes `S` only when a time server has actually answered,
and `I` otherwise. Claiming a synchronised clock it does not have would be lying
about the one field of a reading that cannot be checked afterwards - see
[Name resolution and the time](#name-resolution-and-the-time).


### Where they are on the page

Sessions sits beside the Meter rather than under Configuration: a charging
session is something this meter does, not something about how it is set up. It
shows whether one is running, starts and stops it, and signs a single reading on
demand. The signing keys sit under Configuration next to the certificates, which
is where somebody looking for "what this meter proves itself with" will look for
them even though they are not certificates.

Two things are handed over on that page and never again: the public key when a
session starts, and the document when it stops. Both come with a copy button,
because a document that is not written down when it is shown is gone - which is
the same rule the meter itself works by.

### Alfen

`format=alfen` writes the format of an Alfen charging station:

```
AP;0;3;APV7E5L6WT25QCJZSAMAPNF2PXMZ46UAJKZHJNXY;IKKLQAM6WIKM...====;J23QNXYVROMEN36...===;
```

Six fields, everything after the version base32 because the whole thing has to
survive being printed on a receipt and typed back in by hand. The data set is 82
bytes, little endian throughout, with no separators: the layout is the
specification.

**Checked by the reader, not by the writer.** A test here builds a record, and
then ChargyCore parses it back: every field comes back as it went in, the buffer
its verifier rebuilds is byte for byte the one that was signed, the signature
checks out over that buffer with ChargyCore's own curve and suite, and finally
`AlfenCrypt01.VerifyMeasurement` says `ValidSignature` about it. Five links, and
the last one is the one that counts: the four before it are this project
agreeing with itself.

That last link was missing for a while, and not because anything written here
failed it. `VerifyMeasurement` reaches from a reading to its measurement and
from there to the charging session, and ChargyCore's own constructors left both
of those null for anything they were handed - so it answered "Not an Alfen
measurement!", and one level up it rebuilt a buffer eight bytes different and
called a good record a forgery. Fixed there rather than worked around here.

What this is not, and the answer says so: an Alfen adapter. The format has
fields for one - an adapter identification, its firmware version and that
firmware's checksum - and this fills them from the meter's own serial number and
version, because leaving them empty would fail the signature they are part of.
A record from here is an Alfen-shaped record signed by this meter, which is what
makes it useful for exercising software that reads the format and what stops it
being an Alfen meter value.

[chargy]: https://github.com/OpenChargingCloud/ChargyCore.NET


## The log

Everything that happens inside this meter goes into one log: **every Modbus
request, allowed or refused**, every clock check, every change somebody made and
who made it, and whatever Hermod says while doing its part. The last 2000
entries are kept in memory, a host can mirror them to a console, and a browser
follows the same log over `/api/v1/events`.

It survives a restart. Every entry is also written as one line of JSON to
`<DataPath>/logs/meter-YYYY-MM-DD.jsonl`, and the newest of them are read back
at the next start - numbering included, so that a browser following the log is
not handed entries it has already seen. One file per day, thirty days kept
(`LogKeepDays`, `0` keeps the log in memory only). One line per entry because
that is the format that survives being read by something other than this
program: grep finds a line, jq takes it apart, and a file truncated by a power
cut loses its last line and nothing else.

### And it is signed

Every line carries the hash of the line before it and a signature of its own:

```json
{ "id": 16, "timestamp": "...", "level": "warning", "tags": ["modbus","request","denied"],
  "message": "(none) 0x03 @40000+98 -> refused: no role extension in client cert",
  "data": { ... },
  "prev": "wJ8...=", "key": "d13924a2fd92f261",
  "hash": "1xx...=", "sig": "MEUCIQ...==" }
```

The key is ECDSA over P-256, made at the first start and kept in
`logs/signing-key.pem` (mode 600); the public half sits beside it as
`signing-key.pub.pem`. Its own key rather than the meter certificate: those
answer different questions, and a certificate that is reissued would leave the
old log needing the old certificate for ever.

Checking it is one question, asked deliberately: `GET /api/v1/logs/verify`, the
**Check the log** button on the Logs page, or `--verify-log` on the command
line. Three things are checked per line, and they catch different things - the
hash catches a line that was edited, the chain catches a line that was removed,
moved or inserted, and the signature catches a line written by something that
did not have this meter's key.

**What this is worth, and what it is not.** The key sits next to the log it
signs, so somebody who can write that directory can also read the key and sign a
log of their own invention. Signing catches a file that was edited, truncated in
the middle, reordered, or copied from another meter; it does not catch an
attacker who took the key. Cutting the *end* off a log is not caught either -
every remaining line is genuine and the file cannot know how long it was meant
to be. What catches both is the `head`, the hash of the newest line, reported by
all three of the routes above: write it down somewhere this meter cannot reach,
and a log that no longer leads to it has been rewritten no matter how well it
signs itself.

Pruning breaks the chain on purpose: the oldest file left begins with a line
pointing at a day that was thrown away, and a check of the whole log says so.

```bash
jq -r 'select(.tags | index("denied")) | "\(.timestamp) \(.data.peer) \(.data.denyReason)"' data/logs/meter-*.jsonl
```

A request carries the whole of what was decided about it:

```json
{ "connectionId": 3, "peer": "127.0.0.1:50665", "role": null,
  "unitId": 1, "transactionId": 1, "functionCode": "0x03", "function": "ReadHoldingRegisters",
  "address": 40000, "quantity": 98,
  "allowed": false, "denyReason": "no role extension in client cert",
  "exceptionCode": "IllegalFunction", "responseBytes": 2, "duration_ms": 0.4 }
```

Refusals are warnings and carry the tag `denied`, so "show me everything that
was turned away" is one filter rather than a search through everything that was
not. A meter that recorded only what it permitted could not answer that question
afterwards at all.

Reading the log needs `ReadConfiguration` and not merely `ReadMeter`: it holds
the addresses peers connect from and every certificate that was turned away,
which is more than somebody allowed to watch the readings was given.


## Name resolution and the time

Both are read from a configuration file, in the same two sections that a
LocalController uses, so one file can be written once and copied:

```json
{
  "dns": { "enabled": true, "servers": [ "udp://192.168.1.1:53" ] },
  "nts": { "enabled": true, "hostname": "ptbtime1.ptb.de", "checkEvery": "00:15:00",
           "legalTimeAuthority": "PTB" }
}
```

A section that is absent is not a section set to nothing: it means the file has
no opinion, and what the constructor was handed stands. The clock is checked
against the NTS server on that interval - authenticated, and without stepping
the meter's own clock - because a reading is only worth what the timestamp on it
is worth.

"Legal time" is not a claim this meter can make on its own. It holds only while
a check against a time source **the operator has vouched for** is both recent
enough and close enough; without a named authority this is an ordinary clock
that happens to be checked, and `/api/v1/configuration/time` says so in as many
words.


## What it does not do yet

* **A hard stop loses up to ten seconds of energy.** The counters are written
  down every ten seconds, at both ends of a charging session, and on an orderly
  stop; a process that is killed comes back where the last write left it. The
  loss is always downwards - a counter that came back slightly high would be a
  meter billing for energy nobody used.
* **A certificate this machine cannot present is kept and never shown.** Which
  ones those are is found out rather than assumed - see above - and .NET cannot
  hold an Ed448 or an ML-DSA private key at all, which is its own reason. Such
  an entry reads "not for a listener".
* **The pagination counters restart at zero if their file cannot be read.** OCMF
  numbers every document a meter signs so that a gap is visible; a meter that
  lost the file leaves exactly such a gap, which is the intended behaviour and
  worth knowing about.

* One meter per process. The unit identifier in the frame is not used to route,
  so several meters means several instances on several ports.
* The simulated day is the same day all year: sunrise at 6, sunset at 20, one
  bell curve in between. Enough for "does this controller do the right thing
  when the site exports", not enough for a seasonal study.
* An account is a person and a role, and that is the whole of it: there are no
  per-resource rights, so somebody who may write the meter mode may write all of
  it. Four roles are enough for a meter and would not be enough for much else.
* Nothing expires. An account stays until somebody takes it away, and there is
  no lockout after repeated wrong passwords beyond the rate limiting Hermod
  already does on signing in.
* A refused request is written down twice: once by the Modbus/TLS frontend in
  Hermod, which says `RBAC DENY ...` as it always did, and once by this meter as
  the audit record above. The second is the one with the data attached; the
  first is not ours to remove.
* Nothing carries the head of the log anywhere else by itself. Until something
  does - a syslog sink, a witness, a line in somebody's notes - the signing
  proves the files were not edited, and not that they are all the files there
  were. See the caveat above.


### Acknowledgements

This software is partly sponsored by the [NLnet Zero Commons Fund](https://nlnet.nl/commonsfund/) as part of the [EVQI](https://nlnet.nl/project/EVQI/) project and within this tested against the [Apache PLC4x](https://plc4x.apache.org) project.    
It is also part of the security extensions for the **Open Charge Point Protocol**.
