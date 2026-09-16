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
                            MeterMode:          SunSpecMeterMode.ImportOnly
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


## The JSON API

Everything below `/api/v1` needs the session cookie, and each resource names the
permission it wants. What a person may do follows from their role in the
organization `EnergyMeter`:

| Role | read meter | read config | change DNS/NTS | diagnostics | write registers |
|------|:----------:|:-----------:|:--------------:|:-----------:|:---------------:|
| `IsAdmin`          | yes | yes | yes | yes | yes |
| `IsAdminReadOnly`  | yes | yes | no  | yes | no  |
| `IsMember`         | yes | yes | no  | no  | no  |
| `IsGuest`          | yes | no  | no  | no  | no  |

A role this meter does not know, and an account belonging to no organization of
it, grant nothing at all.

| Resource | |
|----------|---|
| `GET  /api/v1/me` | who is signed in, their role and their permissions |
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
the state of the clock, the certificates, and the log. The DNS and NTS pages are
forms - name servers can be added and removed, timeouts and ports changed, and
the time authority named - and each save writes the configuration file before
the change takes effect. What somebody may not do is not offered: the controls
are absent rather than disabled-and-refused, though every request is checked
again on arrival, so a browser that puts them back gains nothing but a 403.

Every URL that is not one of the APIs and does not look like a file of the
bundle gets the stub with status 200, which is what makes a reload on a deep
link and a bookmark to one work. A URL that does look like a file and is not one
gets a real 404: a mistyped script tag must not hand the browser HTML to run.


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

* One meter per process. The unit identifier in the frame is not used to route,
  so several meters means several instances on several ports.
* The simulated day is the same day all year: sunrise at 6, sunset at 20, one
  bell curve in between. Enough for "does this controller do the right thing
  when the site exports", not enough for a seasonal study.
* New accounts have to be made in code. Hermod's user-creation routes are
  commented out in this version, so only the first administrator appears by
  itself; the tests in `ModbusTLSEnergyMeterTests` show how to add more. There
  is no page for accounts either.
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
