/**
 * NETWORK DISCOVERY — the sensor's view of the LAN around it.
 *
 * Two collectors, and the distinction between them is the whole safety model:
 *
 *   PASSIVE (arpNeighbours)   reads the kernel's ARP cache. Every device this host has
 *                             already exchanged frames with on its local segments,
 *                             with vendor resolved from the MAC prefix. Sends nothing.
 *                             No packet leaves the machine, nothing appears in anyone
 *                             else's logs, and no permission question arises.
 *
 *   ACTIVE (sweepRange)       opens real TCP connections to real addresses. This is an
 *                             intrusive act: it appears in the target's logs and can
 *                             trip its intrusion detection. It is therefore gated on an
 *                             operator-declared range, refuses anything outside RFC1918,
 *                             and is rate-limited.
 *
 * The active scan refuses public address space outright. Not as a configuration default
 * that can be flipped, but in code, because a port scan against an address the operator
 * does not own is unauthorised access in most jurisdictions regardless of intent, and a
 * defence platform must not be the instrument of that. Scanning your own RFC1918 network
 * is the case this was authorised for, and the only case it will do.
 *
 * Every result is an observation with a method attached. A host that answered a TCP
 * handshake is `RESPONDED`; one that did not is `NO_RESPONSE`, never `DOWN` — a silent
 * host may be firewalled, asleep, or filtering, and reporting absence of evidence as
 * evidence of absence is how an inventory grows confident holes.
 */

import net from 'node:net';
import os from 'node:os';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const exec = promisify(execFile);

/** Ports worth probing first: the services that actually carry risk on a LAN. */
export const DEFAULT_PORTS = [
  22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 587, 993, 1433, 1521,
  3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017
];

/**
 * A small, honest OUI table.
 *
 * Deliberately small. The IEEE registry has tens of thousands of entries and fetching it
 * would break zero-egress; shipping a stale copy would let the sensor assert a wrong
 * vendor with full confidence. So this covers prefixes common on a corporate LAN and
 * every other MAC reports `vendor: null`, which the UI renders as unknown rather than
 * guessing. An unknown vendor is information; a wrong one is a false lead an analyst
 * will chase.
 */
const OUI = {
  '00:50:56': 'VMware', '00:0c:29': 'VMware', '00:05:69': 'VMware', '00:1c:14': 'VMware',
  '08:00:27': 'VirtualBox / Oracle',
  '00:15:5d': 'Microsoft Hyper-V', '00:03:ff': 'Microsoft',
  '52:54:00': 'QEMU / KVM',
  '00:16:3e': 'Xen',
  'ec:a1:d1': 'Huawei', '00:e0:fc': 'Huawei', '00:25:9e': 'Huawei',
  '00:1a:11': 'Google', 'f4:f5:e8': 'Google',
  '3c:5a:b4': 'Google', 'd8:3a:dd': 'Raspberry Pi', 'b8:27:eb': 'Raspberry Pi',
  'dc:a6:32': 'Raspberry Pi', 'e4:5f:01': 'Raspberry Pi',
  '00:1b:63': 'Apple', 'a4:83:e7': 'Apple', 'f0:18:98': 'Apple', '3c:07:54': 'Apple',
  '00:1d:7e': 'Cisco-Linksys', '00:26:b8': 'Cisco-Linksys', '00:0f:66': 'Cisco-Linksys',
  '00:18:39': 'Cisco-Linksys', '00:1a:2b': 'Cisco', '00:1e:13': 'Cisco',
  '00:24:b2': 'Netgear', '20:4e:7f': 'Netgear', 'a0:40:a0': 'Netgear',
  '00:1f:3f': 'D-Link', '14:d6:4d': 'D-Link', '00:24:01': 'D-Link',
  '50:c7:bf': 'TP-Link', 'a4:2b:b0': 'TP-Link', 'c0:25:e9': 'TP-Link',
  '00:1c:c0': 'Intel', '00:1b:21': 'Intel', '3c:97:0e': 'Intel', '00:15:17': 'Intel',
  '00:17:88': 'Philips Hue', '00:12:17': 'Cisco-Linksys',
  '00:21:9b': 'Dell', '18:03:73': 'Dell', 'd0:67:e5': 'Dell',
  '00:23:24': 'HP', '3c:d9:2b': 'HP', '98:e7:f4': 'HP',
  '00:24:81': 'HP', 'ac:16:2d': 'HP',
  '00:e0:4c': 'Realtek', '52:54:ab': 'Realtek'
};

function vendorFor(mac) {
  if (!mac) return null;
  const key = mac.toLowerCase().replace(/-/g, ':').split(':').slice(0, 3).join(':');
  return OUI[key] ?? null;
}

/** Broadcast, multicast and unspecified addresses are plumbing, not devices. */
function isRealHost(ip, mac) {
  if (!ip) return false;
  if (/^(0\.0\.0\.0|255\.255\.255\.255)$/.test(ip)) return false;
  // 224.0.0.0/4 multicast
  const first = Number(ip.split('.')[0]);
  if (first >= 224) return false;
  if (ip.endsWith('.255')) return false;
  if (mac && /^(ff-ff-ff-ff-ff-ff|ff:ff:ff:ff:ff:ff)$/i.test(mac)) return false;
  if (mac && /^(01-00-5e|01:00:5e|33-33|33:33)/i.test(mac)) return false;
  return true;
}

export function isPrivateIpv4(ip) {
  return (
    /^10\./.test(ip) ||
    /^192\.168\./.test(ip) ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(ip) ||
    /^169\.254\./.test(ip) ||
    /^127\./.test(ip)
  );
}

async function tryExec(cmd, args) {
  try {
    const { stdout } = await exec(cmd, args, { timeout: 15000, maxBuffer: 4 * 1024 * 1024, windowsHide: true });
    return stdout;
  } catch {
    return null;
  }
}

/* ── PASSIVE: ARP neighbours ───────────────────────────────────────────────── */

/**
 * Every device on the local segments this host has spoken to.
 *
 * Returns null when no ARP tool is available, so the caller can distinguish "no
 * neighbours found" from "could not look". Those are different facts and collapsing
 * them would report an empty network where the truth is a blind sensor.
 */
export async function arpNeighbours() {
  const out = (await tryExec('arp', ['-a'])) ?? (await tryExec('ip', ['neigh', 'show']));
  if (out == null) return null;

  const seen = new Map();
  let currentIface = null;

  for (const line of out.split(/\r?\n/)) {
    // Windows: "Interface: 192.168.1.139 --- 0x8"
    const ifm = /^Interface:\s+((?:\d{1,3}\.){3}\d{1,3})/.exec(line);
    if (ifm) {
      currentIface = ifm[1];
      continue;
    }

    // Windows: "  192.168.1.1   ec-a1-d1-20-1d-83   dynamic"
    // BSD/mac: "? (192.168.1.1) at ec:a1:d1:20:1d:83 on en0 ifscope [ethernet]"
    // iproute2: "192.168.1.1 dev eth0 lladdr ec:a1:d1:20:1d:83 REACHABLE"
    const m =
      /^\s*((?:\d{1,3}\.){3}\d{1,3})\s+((?:[0-9a-f]{2}[-:]){5}[0-9a-f]{2})\s*(\w*)/i.exec(line) ||
      /\(((?:\d{1,3}\.){3}\d{1,3})\)\s+at\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})/i.exec(line) ||
      /^((?:\d{1,3}\.){3}\d{1,3})\s+dev\s+\S+\s+lladdr\s+((?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s*(\w*)/i.exec(line);

    if (!m) continue;
    const ip = m[1];
    const mac = m[2].toLowerCase().replace(/-/g, ':');
    const type = (m[3] || '').toUpperCase() || null;
    if (!isRealHost(ip, mac)) continue;

    // First sighting wins; ARP can list the same address under two interfaces.
    if (!seen.has(ip)) {
      seen.set(ip, {
        ip,
        mac,
        vendor: vendorFor(mac),
        arpType: type,
        viaInterface: currentIface,
        method: 'ARP_CACHE',
        discoveredAt: new Date().toISOString()
      });
    }
  }

  return [...seen.values()];
}

/**
 * This host's default gateway(s), read from the routing table.
 *
 * The platform needs the real gateway to detect ARP poisoning: a man-in-the-middle
 * answers ARP for the gateway's address with its own MAC. Guessing the gateway from a
 * .1 or .254 address would raise false alarms on any network laid out differently, so
 * this reads the route instead, and returns null when no route tool answered — "could
 * not look" is reported as such, never as "no gateway".
 */
export async function defaultGateways() {
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/;
  const found = new Set();

  if (process.platform === 'win32') {
    // "  0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.139     25"
    const out = await tryExec('route', ['print', '-4', '0.0.0.0']);
    if (out == null) return null;
    for (const line of out.split(/\r?\n/)) {
      const cols = line.trim().split(/\s+/);
      if (cols[0] === '0.0.0.0' && cols[1] === '0.0.0.0' && ipv4.test(cols[2] ?? '')) found.add(cols[2]);
    }
  } else {
    // iproute2: "default via 192.168.1.1 dev eth0 proto dhcp metric 100"
    const ip = await tryExec('ip', ['route', 'show', 'default']);
    if (ip != null) {
      for (const m of ip.matchAll(/default via ((?:\d{1,3}\.){3}\d{1,3})/g)) found.add(m[1]);
    } else {
      // BSD / macOS: "   gateway: 192.168.1.1"
      const bsd = await tryExec('route', ['-n', 'get', 'default']);
      if (bsd == null) return null;
      const m = /gateway:\s*((?:\d{1,3}\.){3}\d{1,3})/.exec(bsd);
      if (m) found.add(m[1]);
    }
  }
  return [...found];
}

/** The host's own local segments, as CIDRs, so the UI can offer them for a sweep. */
export function localSegments() {
  const out = [];
  for (const [name, addrs] of Object.entries(os.networkInterfaces())) {
    for (const a of addrs ?? []) {
      if (a.internal || a.family !== 'IPv4') continue;
      const bits = maskToBits(a.netmask);
      if (bits == null || bits < 16) continue; // refuse to offer a /8 sweep
      out.push({ interface: name, address: a.address, netmask: a.netmask, cidr: `${networkBase(a.address, bits)}/${bits}` });
    }
  }
  return out;
}

function maskToBits(mask) {
  if (!mask) return null;
  const parts = mask.split('.').map(Number);
  if (parts.length !== 4 || parts.some(n => !Number.isFinite(n))) return null;
  return parts.reduce((s, n) => s + ((n >>> 0).toString(2).match(/1/g)?.length ?? 0), 0);
}

function networkBase(ip, bits) {
  const n = ip.split('.').map(Number).reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  const base = (n & mask) >>> 0;
  return [base >>> 24, (base >>> 16) & 255, (base >>> 8) & 255, base & 255].join('.');
}

export function enumerateCidr(cidr, cap = 512) {
  const m = /^((?:\d{1,3}\.){3}\d{1,3})\/(\d{1,2})$/.exec(cidr.trim());
  if (!m) return { error: 'CIDR must look like 192.168.1.0/24' };
  const bits = Number(m[2]);
  // /22 is 1024 addresses. Beyond that a connect-sweep stops being a quick check and
  // becomes sustained traffic against a network, so it is refused rather than throttled.
  if (bits < 22) return { error: 'Refusing a sweep wider than /22. Narrow the range.' };
  if (!isPrivateIpv4(m[1])) return { error: 'Refusing to sweep public address space.' };

  const base = m[1].split('.').map(Number).reduce((acc, o) => (acc << 8) | o, 0) >>> 0;
  const mask = (0xffffffff << (32 - bits)) >>> 0;
  const network = (base & mask) >>> 0;
  const size = 2 ** (32 - bits);

  const ips = [];
  // Skip the network and broadcast addresses: neither is a host.
  for (let i = 1; i < size - 1 && ips.length < cap; i++) {
    const a = (network + i) >>> 0;
    ips.push([a >>> 24, (a >>> 16) & 255, (a >>> 8) & 255, a & 255].join('.'));
  }
  return { ips, truncated: size - 2 > cap };
}

/* ── ACTIVE: TCP connect sweep ─────────────────────────────────────────────── */

function probePort(ip, port, timeoutMs) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    const done = result => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(result);
    };
    socket.setTimeout(timeoutMs);
    socket.once('connect', () => done('OPEN'));
    // A refusal proves the host is alive and the port closed, which is a finding in
    // itself: it distinguishes a live host from a silent one.
    socket.once('error', err => done(err && err.code === 'ECONNREFUSED' ? 'REFUSED' : 'ERROR'));
    socket.once('timeout', () => done('TIMEOUT'));
    socket.connect(port, ip);
  });
}

/** Bounded concurrency. A thousand parallel sockets exhausts file handles, not speed. */
async function pool(items, size, worker) {
  const results = [];
  let index = 0;
  const runners = Array.from({ length: Math.min(size, items.length) }, async () => {
    while (index < items.length) {
      const i = index++;
      results[i] = await worker(items[i]);
    }
  });
  await Promise.all(runners);
  return results;
}

/**
 * Connect-sweep a private range.
 *
 * `RESPONDED` means the host completed or refused a handshake. `NO_RESPONSE` means it
 * did not answer — never `DOWN`, because a silent host may be firewalled, asleep or
 * filtering, and calling that "down" puts a hole in the inventory that looks like a fact.
 */
export async function sweepRange({
  cidr,
  ports = DEFAULT_PORTS.slice(0, 12),
  timeoutMs = 700,
  concurrency = 64,
  hostCap = 512,
  onProgress
}) {
  const en = enumerateCidr(cidr, hostCap);
  if (en.error) return { error: en.error };

  const startedAt = new Date().toISOString();
  const targets = [];
  for (const ip of en.ips) for (const port of ports) targets.push({ ip, port });

  let completed = 0;
  const byHost = new Map();

  await pool(targets, concurrency, async ({ ip, port }) => {
    const verdict = await probePort(ip, port, timeoutMs);
    completed++;
    if (onProgress && completed % 100 === 0) onProgress(completed, targets.length);

    if (!byHost.has(ip)) byHost.set(ip, { ip, openPorts: [], refusedPorts: [], responded: false });
    const h = byHost.get(ip);
    if (verdict === 'OPEN') {
      h.openPorts.push(port);
      h.responded = true;
    } else if (verdict === 'REFUSED') {
      h.refusedPorts.push(port);
      h.responded = true;
    }
  });

  const hosts = [...byHost.values()]
    .filter(h => h.responded)
    .map(h => ({
      ip: h.ip,
      openPorts: h.openPorts.sort((a, b) => a - b),
      refusedPortCount: h.refusedPorts.length,
      state: 'RESPONDED',
      method: 'TCP_CONNECT',
      discoveredAt: new Date().toISOString()
    }));

  return {
    cidr,
    startedAt,
    finishedAt: new Date().toISOString(),
    portsProbed: ports,
    addressesProbed: en.ips.length,
    truncated: Boolean(en.truncated),
    respondedCount: hosts.length,
    silentCount: en.ips.length - hosts.length,
    hosts,
    // Stated in the payload so any consumer carries the caveat with the data.
    note: 'Silent addresses are reported as counts only and are NOT claimed to be down: a host may be firewalled, asleep or filtering.'
  };
}
