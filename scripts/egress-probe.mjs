// ZERO-EGRESS PROBE — records every outbound connection this Node process attempts.
//
//   SD_EGRESS_LOG=egress.jsonl node --import ./scripts/egress-probe.mjs --import tsx server.ts
//
// Preloaded before the application, so it sees connections made during start-up as well as
// at run time. It observes and never blocks: a probe that changed behaviour would be
// measuring a different program.
//
// What it sees: every TCP/TLS client socket (http, https, fetch/undici, ws) through the
// `net.client.socket` diagnostics channel, every DNS lookup those sockets perform, and every
// UDP datagram sent with node:dgram.
// What it cannot see: traffic from child processes (bpftool, arp, curl) and anything a native
// module sends without going through node:net. A packet capture on the host is the
// independent check for those; this probe is the cheap, always-available one.
import dc from 'node:diagnostics_channel';
import dgram from 'node:dgram';
import fs from 'node:fs';
import net from 'node:net';

const LOG = process.env.SD_EGRESS_LOG || 'egress.jsonl';
const started = Date.now();
fs.writeFileSync(LOG, '');

const isLocal = (addr) => {
  if (!addr) return false;
  const a = String(addr).replace(/^::ffff:/, '');
  return a === '::1' || a === 'localhost' || a.startsWith('127.') || a === '0.0.0.0' || a === '::';
};
/** RFC 1918 / link-local / ULA: on the LAN, so not internet egress, but still reported. */
const isPrivate = (addr) => {
  const a = String(addr || '').replace(/^::ffff:/, '');
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/.test(a) || /^(fe80|fc|fd)/i.test(a);
};
const record = (e) => {
  const scope = isLocal(e.address ?? e.host) ? 'LOOPBACK' : isPrivate(e.address) ? 'LAN' : 'EXTERNAL';
  if (scope === 'LOOPBACK') return;
  const stack = (new Error().stack || '').split('\n').slice(2)
    .filter(l => !l.includes('node:') && !l.includes('egress-probe')).slice(0, 3).map(l => l.trim());
  try { fs.appendFileSync(LOG, JSON.stringify({ tMs: Date.now() - started, scope, ...e, stack }) + '\n'); } catch { /* observing only */ }
};

dc.subscribe('net.client.socket', ({ socket }) => {
  if (!(socket instanceof net.Socket)) return;
  socket.once('lookup', (err, address, _family, host) => record({ kind: 'dns', host, address: address ?? null, error: err?.code }));
  socket.once('connect', () => record({ kind: 'tcp', address: socket.remoteAddress, port: socket.remotePort }));
});

const udpSend = dgram.Socket.prototype.send;
dgram.Socket.prototype.send = function (...args) {
  const nums = args.filter(a => typeof a === 'number');
  const address = args.find((a, i) => typeof a === 'string' && i > 0);
  record({ kind: 'udp', address: address ?? null, port: nums[nums.length - 1] ?? null });
  return udpSend.apply(this, args);
};
