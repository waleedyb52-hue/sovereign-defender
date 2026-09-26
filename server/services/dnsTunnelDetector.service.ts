import { shannonEntropy } from './payloadForensics.js';

/**
 * DNS TUNNEL DETECTOR + TCP TARPIT — T1048 exfiltration over an alternative protocol
 *
 * Built because the capability report found T1048 at 1/3 sensors: no tunnelling
 * heuristic and no tarpit existed anywhere in the tree.
 *
 * Why DNS tunnelling is detectable at all
 *   A resolver is not supposed to carry payload. Exfiltration over DNS has to
 *   encode data into names or TXT answers, and that leaves four marks that normal
 *   resolution does not:
 *
 *     1. Label length. Legitimate hostnames are short and human-chosen; an
 *        encoded chunk runs to the 63-byte label limit.
 *     2. Entropy. `www.example.com` is low-entropy English. Base32 of ciphertext
 *        is close to uniform.
 *     3. Query rate to one zone. A browser resolves a domain and caches it. A
 *        tunnel queries continuously because each query is a packet.
 *     4. Record-type skew. TXT and NULL carry the most bytes per answer, so a
 *        tunnel over-uses them relative to A and AAAA.
 *
 *   No single mark is sufficient — a CDN hostname is long, a DNSSEC record is
 *   high-entropy, a monitoring probe is frequent. So this scores the marks and
 *   requires a combination, and it reports each contribution so an analyst can
 *   see which mark carried the decision rather than a bare verdict.
 *
 * On the tarpit
 *   Tarpitting is the correct response here rather than dropping: a drop tells the
 *   implant immediately to switch channel, while a slow accept holds the session
 *   and costs the operator nothing. The implementation below is userspace — it
 *   holds a socket with delayed, minimal writes. A kernel-side tarpit would need
 *   XDP and is not claimed here; `mode` reports which one is active.
 */

export type DnsRecordType = 'A' | 'AAAA' | 'TXT' | 'NULL' | 'CNAME' | 'MX' | 'SRV' | 'OTHER';

export interface DnsQueryObservation {
  /** Fully qualified name queried. */
  name: string;
  recordType: DnsRecordType;
  /** Byte length of the answer or encoded payload, when known. */
  payloadLength?: number | null;
  srcIp: string;
  at?: number;
}

interface ZoneState {
  queries: Array<{ at: number; name: string; type: DnsRecordType; len: number | null; entropy: number }>;
}

/** Window over which query rate to one zone is measured. */
const RATE_WINDOW_MS = 10_000;
const MAX_PER_ZONE = 512;

/** Label length above which a label stops looking human-chosen. */
export const LONG_LABEL_BYTES = 40;
/** Entropy (bits/byte) above which a label looks encoded rather than named. */
export const HIGH_LABEL_ENTROPY = 3.6;
/** Queries/sec to a single zone above which caching is clearly not happening. */
export const HIGH_ZONE_QPS = 5;
/** Share of TXT/NULL records above which the record mix is skewed toward payload. */
export const PAYLOAD_TYPE_SHARE = 0.5;

export interface TunnelAssessment {
  tunnelSuspected: boolean;
  /** 0-100, from the marks below. Not a probability — a weighted score. */
  score: number;
  zone: string;
  /** Each mark's contribution, so the decision is inspectable. */
  marks: {
    longLabels: { hit: boolean; maxLabelBytes: number; weight: number };
    highEntropy: { hit: boolean; meanLabelEntropy: number; weight: number };
    highRate: { hit: boolean; queriesPerSec: number; weight: number };
    payloadTypeSkew: { hit: boolean; txtNullShare: number; weight: number };
  };
  queriesInWindow: number;
  mitreTechnique: 'T1048';
  recommendedAction: 'TCP_TARPIT_ENGAGEMENT' | 'MONITOR' | 'NONE';
  classification: 'DNS_TUNNELING_EXFILTRATION' | 'BENIGN_RESOLUTION' | 'INDETERMINATE';
}

/** Registrable zone, approximated by the last two labels. Enough to group a tunnel's traffic. */
function zoneOf(name: string): string {
  const parts = String(name).toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  return parts.length <= 2 ? parts.join('.') : parts.slice(-2).join('.');
}

/** Labels excluding the registrable zone — where an encoder puts its payload. */
function payloadLabels(name: string): string[] {
  const parts = String(name).toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  return parts.length <= 2 ? [] : parts.slice(0, -2);
}

export class DnsTunnelDetector {
  private zones = new Map<string, ZoneState>();
  private detections = 0;
  private observed = 0;

  record(obs: DnsQueryObservation): void {
    const at = obs.at ?? Date.now();
    const zone = zoneOf(obs.name);
    const labels = payloadLabels(obs.name);
    const encoded = labels.join('');
    // Entropy of the payload labels only. Including the zone would dilute the
    // signal with a fixed low-entropy string on every query.
    const entropy = encoded.length >= 8 ? Number(shannonEntropy(encoded).toFixed(3)) : 0;

    const st = this.zones.get(zone) ?? { queries: [] };
    st.queries.push({
      at,
      name: obs.name,
      type: obs.recordType,
      len: obs.payloadLength ?? (encoded.length || null),
      entropy
    });
    if (st.queries.length > MAX_PER_ZONE) st.queries.splice(0, st.queries.length - MAX_PER_ZONE);
    this.zones.set(zone, st);
    this.observed++;
  }

  assess(zoneName: string, now = Date.now()): TunnelAssessment {
    const zone = zoneOf(zoneName);
    const st = this.zones.get(zone);
    const inWindow = (st?.queries ?? []).filter(q => q.at >= now - RATE_WINDOW_MS);

    const maxLabelBytes = inWindow.reduce((m, q) => {
      const longest = Math.max(0, ...payloadLabels(q.name).map(l => l.length));
      return Math.max(m, longest);
    }, 0);

    const entropies = inWindow.map(q => q.entropy).filter(e => e > 0);
    const meanLabelEntropy = entropies.length
      ? Number((entropies.reduce((a, b) => a + b, 0) / entropies.length).toFixed(3))
      : 0;

    const earliest = inWindow.length ? Math.min(...inWindow.map(q => q.at)) : now;
    const spanMs = Math.max(1, now - earliest);
    const queriesPerSec = inWindow.length ? Number(((inWindow.length / spanMs) * 1000).toFixed(2)) : 0;

    const payloadTypes = inWindow.filter(q => q.type === 'TXT' || q.type === 'NULL').length;
    const txtNullShare = inWindow.length ? Number((payloadTypes / inWindow.length).toFixed(3)) : 0;

    const marks = {
      longLabels: { hit: maxLabelBytes >= LONG_LABEL_BYTES, maxLabelBytes, weight: 30 },
      highEntropy: { hit: meanLabelEntropy >= HIGH_LABEL_ENTROPY, meanLabelEntropy, weight: 30 },
      highRate: { hit: queriesPerSec >= HIGH_ZONE_QPS, queriesPerSec, weight: 25 },
      payloadTypeSkew: { hit: txtNullShare >= PAYLOAD_TYPE_SHARE, txtNullShare, weight: 15 }
    };

    const score = Object.values(marks).reduce((s, m) => s + (m.hit ? m.weight : 0), 0);
    const hits = Object.values(marks).filter(m => m.hit).length;

    // Two independent marks minimum. Any single one has a legitimate explanation:
    // a CDN hostname is long, DNSSEC is high-entropy, a health check is frequent.
    const tunnelSuspected = score >= 55 && hits >= 2;

    if (tunnelSuspected) this.detections++;

    return {
      tunnelSuspected,
      score,
      zone,
      marks,
      queriesInWindow: inWindow.length,
      mitreTechnique: 'T1048',
      recommendedAction: tunnelSuspected ? 'TCP_TARPIT_ENGAGEMENT' : hits >= 1 ? 'MONITOR' : 'NONE',
      classification: tunnelSuspected
        ? 'DNS_TUNNELING_EXFILTRATION'
        : inWindow.length === 0
          ? 'INDETERMINATE'
          : 'BENIGN_RESOLUTION'
    };
  }

  getStatistics() {
    return {
      zonesTracked: this.zones.size,
      queriesObserved: this.observed,
      tunnelsSuspected: this.detections,
      rateWindowMs: RATE_WINDOW_MS,
      thresholds: {
        longLabelBytes: LONG_LABEL_BYTES,
        highLabelEntropy: HIGH_LABEL_ENTROPY,
        highZoneQps: HIGH_ZONE_QPS,
        payloadTypeShare: PAYLOAD_TYPE_SHARE
      },
      provenance: { mode: 'MEASURED_FROM_OBSERVED_QUERIES', seeded: false }
    };
  }

  reset() {
    this.zones.clear();
    this.detections = 0;
    this.observed = 0;
  }
}

/* ── TCP tarpit ──────────────────────────────────────────────────────────── */

export interface TarpitSession {
  id: string;
  targetIp: string;
  reason: string;
  engagedAt: number;
  /** Cumulative time the peer has been held, in ms. */
  heldMs: number;
  bytesTrickled: number;
  active: boolean;
}

/**
 * Userspace TCP tarpit.
 *
 * Holds a hostile peer in a slow conversation instead of dropping it. A drop is a
 * clean signal to switch channel; being held costs the implant its session and
 * costs the defender one idle socket.
 *
 * `mode` is USERSPACE here, and says so. A kernel tarpit — shrinking the window
 * from XDP — is a different capability and is not claimed by this class.
 */
export class TcpTarpit {
  private sessions = new Map<string, TarpitSession>();
  private totalEngagements = 0;

  engage(targetIp: string, reason = 'DNS_TUNNELING_EXFILTRATION'): TarpitSession {
    const existing = [...this.sessions.values()].find(s => s.targetIp === targetIp && s.active);
    if (existing) return existing;

    const session: TarpitSession = {
      id: `TARPIT-${Date.now().toString(36).toUpperCase()}`,
      targetIp,
      reason,
      engagedAt: Date.now(),
      heldMs: 0,
      bytesTrickled: 0,
      active: true
    };
    this.sessions.set(session.id, session);
    this.totalEngagements++;
    return session;
  }

  /**
   * Record a trickle. Called by whatever holds the socket, so `heldMs` reflects
   * time actually elapsed rather than a timer this class runs on its own.
   */
  trickle(sessionId: string, bytes = 1): TarpitSession | null {
    const s = this.sessions.get(sessionId);
    if (!s || !s.active) return null;
    s.bytesTrickled += bytes;
    s.heldMs = Date.now() - s.engagedAt;
    return s;
  }

  release(sessionId: string): boolean {
    const s = this.sessions.get(sessionId);
    if (!s) return false;
    s.active = false;
    s.heldMs = Date.now() - s.engagedAt;
    return true;
  }

  getSessions(): TarpitSession[] {
    return [...this.sessions.values()]
      .map(s => (s.active ? { ...s, heldMs: Date.now() - s.engagedAt } : s))
      .sort((a, b) => b.engagedAt - a.engagedAt);
  }

  getStatistics() {
    const sessions = this.getSessions();
    const active = sessions.filter(s => s.active);
    return {
      mode: 'USERSPACE' as const,
      activeSessions: active.length,
      totalEngagements: this.totalEngagements,
      /** Aggregate attacker time held. Summed from real elapsed clocks. */
      totalHeldMs: sessions.reduce((a, s) => a + s.heldMs, 0),
      totalBytesTrickled: sessions.reduce((a, s) => a + s.bytesTrickled, 0),
      kernelTarpitAvailable: false,
      note: 'Userspace hold. A kernel-side window-shrink tarpit would require XDP and is not implemented.',
      provenance: { mode: 'MEASURED_FROM_SESSION_CLOCKS', seeded: false }
    };
  }

  reset() {
    this.sessions.clear();
    this.totalEngagements = 0;
  }
}

export const globalDnsTunnelDetector = new DnsTunnelDetector();
export const globalTcpTarpit = new TcpTarpit();
