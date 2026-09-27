# Connecting Real Machines and Networks

Written for: an operator or engineer deploying Sovereign Defender against their own
infrastructure.

Until the asset registry existed, this platform had no way to be pointed at anything.
Telemetry arrived as anonymous flows and the cluster view showed synthetic nodes. This
document covers the path from a running server to a real machine appearing in the
cockpit with its traffic in the detection pipeline.

## 1. Mint an enrolment token

From the cockpit: open **ASSET FLEET** in the right-hand arsenal stack and press
`[ ENROL A MACHINE ]`. It prints the command to run, with the token already in it.

From the command line:

```bash
curl -X POST http://<server>:3000/api/v1/assets/enrollment-token \
  -H "x-api-key: $ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"note":"web tier, rack 4"}'
```

The token is **single-use**, expires in **24 hours**, and is stored only as a SHA-256
digest. The plaintext exists exactly once, in that response. Minting requires the admin
key; enrolment itself does not, because the sensor runs on a host that must not hold the
admin secret — the token is the whole authority it needs.

A reusable token would spread into every host image it was baked into, and an
unauthenticated registry would let an attacker flood the inventory with fake hosts and
bury the real one. That is a denial of *visibility* rather than of service, and far
harder to notice.

## 2. Run the sensor on the machine you want watched

Copy `sensor/sovereign-sensor.mjs` to that host. It needs **Node 18 or newer and nothing
else** — zero dependencies, standard library only, so it runs on a locked-down box with
no package manager and nothing to vet.

```bash
node sovereign-sensor.mjs --server http://<server>:3000 --token sd_enroll_...
```

Check the collectors work before enrolling anything:

```bash
node sovereign-sensor.mjs --dry-run --verbose
```

A dry run collects, prints one cycle and exits. On a Windows workstation it looks like:

```
[sensor 13:21:53] dry run — sockets:344 listening:36 established:27 processes:321 users:— flows:40
[sensor 13:21:53] sample flow: {"sourceIP":"162.159.133.234","destinationIP":"192.168.1.139",
                                "protocol":"TCP","port":51980,"packetSize":0,...}
```

Options: `--interval <sec>` (default 30), `--max-flows <n>` (default 40),
`--label <name>` (default hostname).

### What it collects

| Collected | Source |
| --- | --- |
| hostname, platform, arch, network interfaces | `node:os` |
| established and listening sockets: addresses, ports, state | `ss -tunap`, else `netstat` |
| process count, logged-in user count | `ps` / `tasklist`, `who` / `query user` |
| uptime, load average, free memory | `node:os` |

### What it deliberately does not collect

- **No packet capture.** Reading payload bytes off the wire needs elevated privilege and
  turns a monitoring agent into an interception tool. Connection metadata answers the
  questions a SOC asks first.
- **No file contents, command lines, keystrokes or screen.** File integrity is covered by
  FIM, on paths an operator explicitly declares.
- **No outbound traffic except to the `--server` address.** The platform is zero-egress
  and its sensor has to be too.

### Why a field can be missing rather than zero

If a collector cannot run — `ss` absent, permission denied, an unparseable line — the
sensor **omits** that field instead of sending `0`.

This distinction is load-bearing. A zero means "measured, and found none". A missing
field means "not observed". Sending zero for a collector that never ran would tell the
platform it is watching a quiet host when it should be told it has a blind sensor. In the
sample above, `users:—` is exactly that: `query user` did not work on that box, and the
posture omits the count rather than claiming nobody is logged in.

## 3. Declare a network range

A range scopes scans and reporting. No sensor runs on it, so no liveness is claimed for
it.

```bash
curl -X POST http://<server>:3000/api/v1/assets/network \
  -H "x-api-key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"cidr":"10.20.0.0/24","label":"DMZ"}'
```

Or type the CIDR into the fleet panel and press `[ NET ]`.

## 4. What happens to the traffic

```
sensor  →  POST /api/v1/soc/ingest-telemetry/batch
        →  AIThreatAgent: behavioural score + threat-intel corroboration
        →  DecisionEngine: ALLOW / CHALLENGE / BLOCK
        →  unified telemetry  →  cockpit threat feed, radar tracers, kill chain
```

Flows are scored by the same engine that scores everything else; nothing about a sensor
flow is privileged or exempt.

Flows are **prioritised before the cap**: public remotes first, then RFC1918 private,
then loopback. A plain first-N slice was the original implementation and the first live
run disproved it — on a workstation the socket table is dominated by loopback, so forty
`127.0.0.1` entries shipped and every genuine external connection was silently dropped.
The cap now costs the least informative flows instead of the most.

`packetSize` is reported as `0` because this sensor does not capture packets and the
ingestion contract requires the field. That is the honest value for "no bytes measured";
inventing a plausible size would feed a fabricated feature straight into the threat
score, which is the worst place in the system for a made-up number.

## 5. Liveness, and why it is derived

| State | Meaning |
| --- | --- |
| `ONLINE` | heartbeat within 3× the declared interval |
| `STALE` | within 10× |
| `OFFLINE` | beyond 10× |
| `NEVER_REPORTED` | enrolled, never heartbeat — or a declared network range |

Liveness is computed server-side from the age of the last heartbeat, never taken from the
sensor, because **a sensor that dies cannot report that it is dead**. An asset that stops
reporting degrades on its own, which is the only way silence becomes visible. Verified
behaviour: after the sensor was stopped and the server restarted, the asset came back
from disk with its 200 ingested flows intact and its state correctly derived as
`OFFLINE`.

## 6. Isolation

```bash
curl -X POST http://<server>:3000/api/v1/assets/<id>/isolate \
  -H "x-api-key: $ADMIN_API_KEY" -H "Content-Type: application/json" \
  -d '{"isolate":true}'
```

Or open the asset in the fleet panel and press `[ ISOLATE_NODE ]`.

The response separates two things that must never be conflated:

```json
{ "enforced": true, "containment": { "targetIp": "...", "status": "ACTIVE_BLACKHOLE" },
  "containmentError": null }
```

`asset.isolated` is the operator's recorded decision. `enforced` says whether the kernel
containment rule was actually applied. A registry flag without an enforced rule is a
claim the network does not honour, so when the two diverge the UI says
*"flagged but NOT enforced"* with the reason, rather than showing a green isolation badge
over a host that is still talking.

An asset with no known IP cannot be isolated, and the button is inert with that reason on
hover rather than appearing armed.

## 7. Durability

The registry persists to `data/assets.db` via `node:sqlite`. If that directory is
unwritable it degrades to an in-memory store rather than taking the server down, and
`summary.durable` reports `false`. The fleet panel then warns that the inventory will not
survive a restart — an inventory an operator trusts and then loses is worse than one they
knew was temporary.

## API reference

| Method | Path | Auth |
| --- | --- | --- |
| POST | `/api/v1/assets/enrollment-token` | admin |
| GET | `/api/v1/assets/enrollment-tokens` | admin |
| POST | `/api/v1/assets/enrollment-token/revoke` | admin |
| POST | `/api/v1/assets/enroll` | enrolment token |
| POST | `/api/v1/assets/:id/heartbeat` | asset id |
| GET | `/api/v1/assets` | none |
| GET | `/api/v1/assets/:id` | none |
| POST | `/api/v1/assets/network` | admin |
| POST | `/api/v1/assets/:id/isolate` | admin |
| DELETE | `/api/v1/assets/:id` | admin |

## Known limits

These are real and worth stating rather than discovering later.

- **Heartbeats are not authenticated per asset.** Anyone who learns an asset id can post a
  posture for it. The enrolment token gates *joining* the fleet, not *reporting* into it.
  A per-asset secret issued at enrolment is the fix.
- **No mutual TLS and no transport encryption** unless the server sits behind a TLS
  terminator. Over an untrusted network the sensor's traffic is readable.
- **Posture is self-reported** and labelled as such throughout the UI. Nothing here
  verifies that a host's claims about itself are true.
- **One sensor process per host.** There is no supervision, service unit or auto-restart;
  use `systemd`, a Windows service wrapper or a scheduled task for production.
