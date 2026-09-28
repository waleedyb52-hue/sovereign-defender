#!/usr/bin/env node
/**
 * SOVEREIGN DEFENDER — HOST SENSOR
 *
 * This is the platform's connection to a real machine. Run it on any host and that host
 * appears in the cockpit's fleet, heartbeats its measured posture, and ships its actual
 * network connections into the detection pipeline, where the existing AI agent scores
 * them exactly as it scores anything else.
 *
 *   node sensor/sovereign-sensor.mjs --server http://10.0.0.5:3000 --token sd_enroll_...
 *
 * Get a token from the cockpit's fleet panel, or:
 *   curl -XPOST -H "x-api-key: $ADMIN_API_KEY" http://<server>:3000/api/v1/assets/enrollment-token
 *
 * WHAT IT COLLECTS, and nothing beyond it:
 *   - host identity: hostname, platform, arch, network interfaces      (node:os)
 *   - established TCP/UDP connections: local and remote address, port  (ss / netstat)
 *   - listening sockets, process count, logged-in user count
 *   - uptime, load
 *
 * WHAT IT DOES NOT DO, deliberately:
 *   - No packet capture. Reading payload bytes off the wire needs elevated privilege and
 *     turns a monitoring agent into an interception tool; connection metadata answers
 *     the questions a SOC actually asks first.
 *   - No file contents, no command lines, no keystrokes, no screen. FIM covers integrity
 *     on paths an operator explicitly declares.
 *   - No outbound traffic except to the server address passed on the command line. The
 *     platform is zero-egress and its sensor has to be too.
 *
 * ZERO DEPENDENCIES. Node's standard library only, so it runs on a locked-down host with
 * no package manager and nothing to vet. Works on Windows, Linux and macOS.
 *
 * ON HONESTY, which matters as much in the sensor as in the UI: this ships only what it
 * measured. If a collector fails — no `ss`, no permission, an unparseable line — the
 * field is omitted rather than defaulted to zero. A zero is a measurement meaning "none
 * found"; a missing field means "not observed". Sending zero for an unavailable
 * collector would tell the platform a quiet host when it should be told a blind sensor.
 */

import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { arpNeighbours, defaultGateways, localSegments, sweepRange, DEFAULT_PORTS } from './discovery.mjs';
import { promisify } from 'node:util';

const exec = promisify(execFile);

const VERSION = '1.0.0';

/* ── Arguments ─────────────────────────────────────────────────────────────── */

function parseArgs(argv) {
  const out = { interval: 30, maxFlows: 40, label: null, dryRun: false, verbose: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--server') out.server = next();
    else if (a === '--token') out.token = next();
    else if (a === '--interval') out.interval = Math.max(5, Number(next()) || 30);
    else if (a === '--max-flows') out.maxFlows = Math.max(1, Math.min(200, Number(next()) || 40));
    else if (a === '--label') out.label = next();
    else if (a === '--credential-file') out.credentialFile = next();
    else if (a === '--sweep') out.sweep = next();
    else if (a === '--sweep-ports') out.sweepPorts = next();
    else if (a === '--no-arp') out.noArp = true;
    else if (a === '--dry-run') out.dryRun = true;
    else if (a === '--verbose' || a === '-v') out.verbose = true;
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

const args = parseArgs(process.argv);

/* ── Credential ────────────────────────────────────────────────────────────── */

/**
 * The platform issues this host a credential at its first enrolment and returns it once.
 * It is kept in a file only this user can read, and sent on every request. On restart
 * the sensor refreshes its enrolment with the credential instead of the single-use
 * token, which is already spent.
 */
const credentialFile =
  args.credentialFile ?? path.join(os.homedir(), '.sovereign-sensor', `${os.hostname()}.credential.json`);

function loadCredential() {
  try {
    const c = JSON.parse(fs.readFileSync(credentialFile, 'utf8'));
    return c && c.server === args.server && typeof c.secret === 'string' ? c : null;
  } catch {
    return null;
  }
}

function saveCredential(assetId, secret) {
  fs.mkdirSync(path.dirname(credentialFile), { recursive: true, mode: 0o700 });
  fs.writeFileSync(credentialFile, JSON.stringify({ server: args.server, assetId, secret }), { mode: 0o600 });
}

let credential = null;

if (args.help || (!args.dryRun && (!args.server || (!args.token && !loadCredential())))) {
  console.log(`
Sovereign Defender host sensor v${VERSION}

  --server   <url>    Platform base URL, e.g. http://10.0.0.5:3000   (required)
  --token    <token>  Single-use enrolment token (first run, or to re-key)
  --credential-file <path>  Where the issued credential is kept
                      default ~/.sovereign-sensor/<hostname>.credential.json
  --interval <sec>    Heartbeat and collection cadence, default 30
  --max-flows <n>     Max connections shipped per cycle, default 40
  --label    <name>   Friendly name for this asset, default hostname
  --dry-run           Collect and print, send nothing
  --verbose           Print each cycle's payload counts

Network discovery:
  --no-arp            Skip the ARP neighbour read (it is on by default)
  --sweep    <cidr>   ACTIVE TCP connect sweep of a private range, once at startup
  --sweep-ports <csv> Ports for the sweep, default a 12-port service set

PASSIVE by default. The ARP read sends nothing: it reports devices this host has
already exchanged frames with. --sweep is ACTIVE and opens real connections, which
appear in the target's logs and may trip its IDS. It refuses public address space
and anything wider than /22, in code. Only sweep networks you are authorised to test.

Collects host identity, connection metadata, LAN neighbours and posture counts only.
No packet capture, no file contents, no command lines.
`);
  process.exit(args.help ? 0 : 1);
}

const log = (...m) => console.log(`[sensor ${new Date().toISOString().slice(11, 19)}]`, ...m);
const vlog = (...m) => args.verbose && log(...m);

/* ── Identity ──────────────────────────────────────────────────────────────── */

function interfaces() {
  const out = [];
  const nics = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(nics)) {
    for (const a of addrs ?? []) {
      if (a.internal) continue;
      out.push(`${name}:${a.address}`);
    }
  }
  return out;
}

function primaryIp() {
  const nics = os.networkInterfaces();
  for (const addrs of Object.values(nics)) {
    for (const a of addrs ?? []) {
      if (!a.internal && a.family === 'IPv4') return a.address;
    }
  }
  return null;
}

/* ── Collectors ────────────────────────────────────────────────────────────── */

/**
 * Run a command and return stdout, or null if it is unavailable.
 *
 * Null rather than an empty string, so the caller can tell "the tool is not here" from
 * "the tool ran and found nothing". Collapsing those is how a sensor reports a blind
 * host as a quiet one.
 */
async function tryExec(cmd, cmdArgs) {
  try {
    const { stdout } = await exec(cmd, cmdArgs, { timeout: 12000, maxBuffer: 8 * 1024 * 1024, windowsHide: true });
    return stdout;
  } catch {
    return null;
  }
}

const IS_WIN = process.platform === 'win32';

/** Established and listening sockets, as {local, localPort, remote, remotePort, state, proto}. */
async function collectSockets() {
  if (IS_WIN) {
    const out = await tryExec('netstat', ['-ano']);
    if (out == null) return null;
    const rows = [];
    for (const line of out.split(/\r?\n/)) {
      // e.g.  TCP    10.0.0.5:52144    93.184.216.34:443    ESTABLISHED   4812
      const m = /^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s*(\S*)\s*(\d*)\s*$/.exec(line);
      if (!m) continue;
      const [, proto, local, remote, state] = m;
      const l = splitAddr(local);
      const r = splitAddr(remote);
      if (!l) continue;
      rows.push({ proto, local: l.host, localPort: l.port, remote: r?.host ?? null, remotePort: r?.port ?? null, state: state || (proto === 'UDP' ? 'STATELESS' : '') });
    }
    return rows;
  }

  // Linux and macOS: prefer ss, fall back to netstat.
  let out = await tryExec('ss', ['-tunap']);
  let usedSs = out != null;
  if (out == null) out = await tryExec('netstat', ['-tunap']);
  if (out == null) out = await tryExec('netstat', ['-an']);
  if (out == null) return null;

  const rows = [];
  for (const line of out.split(/\r?\n/)) {
    if (/^(Netid|Proto|Active)/i.test(line)) continue;
    const parts = line.trim().split(/\s+/);
    if (parts.length < 5) continue;
    const proto = /udp/i.test(parts[0]) ? 'UDP' : /tcp/i.test(parts[0]) ? 'TCP' : null;
    if (!proto) continue;
    // ss:      Netid State Recv-Q Send-Q Local:Port Peer:Port
    // netstat: Proto Recv-Q Send-Q Local Foreign State
    const local = usedSs ? parts[4] : parts[3];
    const remote = usedSs ? parts[5] : parts[4];
    const state = usedSs ? parts[1] : (parts[5] ?? '');
    const l = splitAddr(local);
    const r = splitAddr(remote);
    if (!l) continue;
    rows.push({ proto, local: l.host, localPort: l.port, remote: r?.host ?? null, remotePort: r?.port ?? null, state });
  }
  return rows;
}

function splitAddr(raw) {
  if (!raw || raw === '*' || raw === '*:*') return null;
  // IPv6 in brackets, or trailing :port
  const m = /^\[?([^\]]*)\]?:(\d+|\*)$/.exec(raw);
  if (!m) return null;
  const host = m[1] === '*' || m[1] === '' ? '0.0.0.0' : m[1];
  const port = m[2] === '*' ? 0 : Number(m[2]);
  return { host, port };
}

async function collectProcessCount() {
  if (IS_WIN) {
    const out = await tryExec('tasklist', ['/FO', 'CSV', '/NH']);
    if (out == null) return null;
    return out.split(/\r?\n/).filter(l => l.trim().length > 0).length;
  }
  const out = await tryExec('ps', ['-e', '-o', 'pid=']);
  if (out == null) return null;
  return out.split(/\r?\n/).filter(l => l.trim().length > 0).length;
}

async function collectUserCount() {
  if (IS_WIN) {
    const out = await tryExec('query', ['user']);
    if (out == null) return null;
    const lines = out.split(/\r?\n/).filter(l => l.trim());
    return Math.max(0, lines.length - 1); // drop the header
  }
  const out = await tryExec('who', []);
  if (out == null) return null;
  return out.split(/\r?\n/).filter(l => l.trim()).length;
}

/* ── Transport ─────────────────────────────────────────────────────────────── */

async function post(pathname, body) {
  const res = await fetch(new URL(pathname, args.server), {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(credential ? { Authorization: `Bearer ${credential.secret}` } : {})
    },
    body: JSON.stringify(body)
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`${pathname} -> ${res.status} ${json?.error ?? ''}`);
  return json;
}

/* ── Flow mapping ──────────────────────────────────────────────────────────── */

/**
 * Map a socket to the platform's telemetry contract:
 *   { sourceIP, destinationIP, protocol, port, packetSize, payloadSignature?, timestamp }
 *
 * `packetSize` is reported as 0 because this sensor does not capture packets, and the
 * field is required by the contract. Zero is the honest value for "no bytes were
 * measured" — inventing a plausible size would feed a fabricated feature straight into
 * the threat score, which is the worst place in the system for a made-up number.
 *
 * `payloadSignature` carries the socket state and a service hint, which is genuinely
 * what was observed, rather than a synthetic payload string.
 */
function socketToFlow(s, selfIp) {
  const proto = s.proto === 'UDP' ? 'UDP' : 'TCP';
  const remote = s.remote && s.remote !== '0.0.0.0' && s.remote !== '::' ? s.remote : null;
  if (!remote) return null;
  if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(remote)) return null; // IPv4 only, per the contract
  return {
    sourceIP: remote,
    destinationIP: s.local === '0.0.0.0' ? (selfIp ?? '127.0.0.1') : s.local,
    protocol: proto,
    port: s.localPort ?? 0,
    packetSize: 0,
    payloadSignature: `host-sensor observed ${proto} ${s.state || 'UNKNOWN'} remote:${s.remotePort ?? '?'}`,
    timestamp: new Date().toISOString()
  };
}

/** 0 = public (report first), 1 = private, 2 = loopback (drop first under the cap). */
function remotePriority(ip) {
  if (/^127\./.test(ip)) return 2;
  if (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^172\.(1[6-9]|2\d|3[01])\./.test(ip) || /^169\.254\./.test(ip)) return 1;
  return 0;
}

/* ── Main loop ─────────────────────────────────────────────────────────────── */

let assetId = null;

async function enroll() {
  credential = credential ?? loadCredential();
  const body = {
    // With a stored credential the token is not needed; with neither, the server refuses.
    ...(args.token ? { token: args.token } : {}),
    hostname: os.hostname(),
    platform: `${os.platform()} ${os.release()}`,
    arch: os.arch(),
    primaryIp: primaryIp(),
    interfaces: interfaces(),
    heartbeatIntervalSec: args.interval,
    sensorVersion: VERSION,
    label: args.label ?? os.hostname()
  };
  let r;
  try {
    r = await post('/api/v1/assets/enroll', body);
  } catch (err) {
    // A stale credential (the asset was removed and re-created) falls back to the token.
    if (credential && args.token) {
      credential = null;
      r = await post('/api/v1/assets/enroll', body);
    } else {
      throw err;
    }
  }
  assetId = r.asset.id;
  if (r.credential) {
    credential = { server: args.server, assetId, secret: r.credential };
    saveCredential(assetId, r.credential);
    log(`credential issued and stored at ${credentialFile}`);
  }
  log(`enrolled as ${assetId} (${r.asset.label}) on ${body.platform}`);
}

async function cycle() {
  const selfIp = primaryIp();
  const [sockets, procs, users, neighbours, gateways] = await Promise.all([
    collectSockets(),
    collectProcessCount(),
    collectUserCount(),
    args.noArp ? Promise.resolve(null) : arpNeighbours(),
    defaultGateways()
  ]);

  const listening = sockets ? sockets.filter(s => /LISTEN/i.test(s.state)).length : null;
  const established = sockets ? sockets.filter(s => /ESTAB/i.test(s.state)).length : null;

  /**
   * Flows, ordered by how much a defender cares before the cap is applied.
   *
   * A plain slice was wrong and the first live run proved it: on a workstation the
   * socket table is dominated by loopback, so taking the first N shipped forty
   * 127.0.0.1 entries and silently discarded every genuine external connection — the
   * only ones that represent exposure. Public remotes go first, then private RFC1918,
   * then loopback, so the cap costs the least informative flows instead of the most.
   */
  const flows = sockets
    ? sockets
        .map(s => socketToFlow(s, selfIp))
        .filter(Boolean)
        .sort((a, b) => remotePriority(a.sourceIP) - remotePriority(b.sourceIP))
        .slice(0, args.maxFlows)
    : [];

  if (sockets == null) {
    log('WARN: no socket collector available on this host (ss/netstat missing or blocked).');
    log('      posture will omit connection counts rather than report zero.');
  }

  if (args.dryRun) {
    log(`dry run — sockets:${sockets?.length ?? 'unavailable'} listening:${listening ?? '—'} established:${established ?? '—'} processes:${procs ?? '—'} users:${users ?? '—'} flows:${flows.length} neighbours:${neighbours === null ? 'unavailable' : neighbours.length}`);
    if (flows[0]) log('sample flow:', JSON.stringify(flows[0]));
    for (const n of (neighbours ?? []).slice(0, 8)) {
      log(`  neighbour ${n.ip.padEnd(16)} ${n.mac} ${n.vendor ?? 'unknown vendor'}`);
    }
    log('local segments:', localSegments().map(x => x.cidr).join(' '));
    return;
  }

  // Flows first, so a heartbeat reporting N flows is never sent before they arrive.
  let sent = 0;
  if (flows.length > 0) {
    try {
      await post('/api/v1/soc/ingest-telemetry/batch', { payloads: flows });
      sent = flows.length;
    } catch (err) {
      log('flow ingestion failed:', err.message);
    }
  }

  const posture = {
    uptimeSec: Math.round(os.uptime()),
    extra: { loadAvg1: Number(os.loadavg()[0].toFixed(2)), freeMemMb: Math.round(os.freemem() / 1048576) },
    flowsSent: sent
  };
  // Neighbours travel with the heartbeat. Omitted entirely when the ARP collector could
  // not run, so the server can tell "no neighbours" from "did not look".
  if (neighbours !== null) {
    posture.neighbours = neighbours;
    posture.extra.lanNeighbours = neighbours.length;
  }
  posture.segments = localSegments();
  // Omitted when the route table could not be read, so the platform reports ARP-spoof
  // detection as unavailable rather than silently checking nothing.
  if (gateways !== null) posture.gateways = gateways;

  // Omitted, not zeroed, when the collector could not run.
  if (listening != null) posture.listeningPorts = listening;
  if (established != null) posture.establishedConnections = established;
  if (procs != null) posture.processes = procs;
  if (users != null) posture.loggedInUsers = users;

  try {
    await post(`/api/v1/assets/${assetId}/heartbeat`, posture);
    vlog(`heartbeat ok — flows:${sent} listening:${listening ?? '—'} established:${established ?? '—'}`);
  } catch (err) {
    log('heartbeat failed:', err.message);
    // A 404 means the asset was removed from the registry; re-enrol rather than
    // heartbeating into a void for the rest of the process lifetime.
    if (/404/.test(err.message)) {
      log('asset no longer registered — re-enrolling');
      try {
        await enroll();
      } catch (e) {
        log('re-enrolment failed:', e.message);
      }
    }
  }
}

async function main() {
  log(`Sovereign Defender host sensor v${VERSION} on ${os.hostname()} (${os.platform()}/${os.arch()})`);

  if (!args.dryRun) {
    try {
      await enroll();
    } catch (err) {
      console.error('[sensor] enrolment failed:', err.message);
      process.exit(1);
    }
  } else {
    log('dry run: no enrolment, no transmission');
  }

  // An active sweep runs once at startup, never on the heartbeat cadence. A repeating
  // connect-scan is sustained traffic against a network the operator has to keep
  // re-authorising, and a sensor that quietly scans every thirty seconds is a sensor
  // that will get itself blocked and its findings distrusted.
  if (args.sweep) {
    const ports = args.sweepPorts
      ? args.sweepPorts.split(',').map(n => Number(n.trim())).filter(n => Number.isInteger(n) && n > 0 && n < 65536)
      : DEFAULT_PORTS.slice(0, 12);

    log(`ACTIVE SWEEP of ${args.sweep} on ${ports.length} ports — this opens real connections`);
    const result = await sweepRange({ cidr: args.sweep, ports, onProgress: (d, t) => vlog(`  sweep ${d}/${t}`) });

    if (result.error) {
      log('sweep refused:', result.error);
    } else {
      log(`sweep done — ${result.respondedCount} responded, ${result.silentCount} silent, ${result.addressesProbed} probed`);
      for (const h of result.hosts) log(`  ${h.ip.padEnd(16)} open:${h.openPorts.join(',') || '(none)'}`);
      if (!args.dryRun) {
        try {
          await post(`/api/v1/assets/${assetId}/discovery`, result);
          log('sweep reported to the platform');
        } catch (err) {
          log('sweep report failed:', err.message);
        }
      }
    }
  }

  await cycle();

  // A dry run is a one-shot check that the collectors work on this host, so it exits
  // rather than entering the loop. A diagnostic that never returns is a diagnostic
  // nobody runs twice.
  if (args.dryRun) {
    log('dry run complete');
    return;
  }

  const timer = setInterval(() => void cycle(), args.interval * 1000);

  const stop = () => {
    clearInterval(timer);
    log('stopped');
    process.exit(0);
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

main().catch(err => {
  console.error('[sensor] fatal:', err);
  process.exit(1);
});
