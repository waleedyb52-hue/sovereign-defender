import { globalRealEbpfBridge } from './services/realEbpfBridge';

export type XdpDriverMode = 'NATIVE_DRIVER' | 'SKB_GENERIC' | 'OFFLOADED_NIC';

export interface BpfMapEntry {
  key: string;
  value: {
    action: 'XDP_DROP' | 'XDP_PASS' | 'XDP_REDIRECT' | 'RATE_LIMIT';
    addedAt: number;
    expiresAt: number;
    hits: number;
    ruleOrigin: string;
  };
}

/** Per-IP token bucket state, mirroring a BPF_MAP_TYPE_LRU_HASH value struct. */
export interface TokenBucketState {
  tokens: number;
  capacity: number;
  refillPerSec: number;
  lastRefillMs: number;
  passedPackets: number;
  droppedPackets: number;
  expiresAt: number;
  ruleOrigin: string;
}

/** Addresses that are never dropped, even under a full infrastructure lockdown. */
const KERNEL_IMMUNE_IPS = new Set<string>(['127.0.0.1', '::1', '10.0.0.1', '10.0.0.2']);

/**
 * O(1) LRU hash map implementing BPF_MAP_TYPE_LRU_HASH eviction semantics.
 *
 * A JavaScript Map iterates in insertion order, so promoting an entry to
 * most-recently-used is a delete + re-insert (both O(1)), and the least
 * recently used key is simply the first key the iterator yields. This gives
 * amortized O(1) get/set/evict with no linked-list bookkeeping, and bounds
 * kernel map memory exactly the way a real LRU BPF map does.
 */
export class LruBpfMap<V> {
  private readonly store = new Map<string, V>();
  public evictionCount = 0;

  constructor(public readonly capacity: number) {}

  /** Reads a key and promotes it to most-recently-used. */
  public get(key: string): V | undefined {
    const value = this.store.get(key);
    if (value === undefined) return undefined;
    // Promote to MRU position.
    this.store.delete(key);
    this.store.set(key, value);
    return value;
  }

  /** Reads without changing recency - used by stats/inspection paths. */
  public peek(key: string): V | undefined {
    return this.store.get(key);
  }

  /** Inserts/updates a key, evicting the least-recently-used entry if full. */
  public set(key: string, value: V): string | null {
    if (this.store.has(key)) {
      this.store.delete(key);
    }
    this.store.set(key, value);

    if (this.store.size > this.capacity) {
      const lruKey = this.store.keys().next().value as string | undefined;
      if (lruKey !== undefined) {
        this.store.delete(lruKey);
        this.evictionCount++;
        return lruKey;
      }
    }
    return null;
  }

  public has(key: string): boolean {
    return this.store.has(key);
  }

  public delete(key: string): boolean {
    return this.store.delete(key);
  }

  public clear(): void {
    this.store.clear();
  }

  public get size(): number {
    return this.store.size;
  }

  public keys(): IterableIterator<string> {
    return this.store.keys();
  }

  public entries(): IterableIterator<[string, V]> {
    return this.store.entries();
  }

  public values(): IterableIterator<V> {
    return this.store.values();
  }
}

export class EbpfXdpOffloadEngine {
  public mode: XdpDriverMode = 'NATIVE_DRIVER';
  public driverAttached: string = 'eth0 (mlx5_core Mellanox ConnectX-6 Dx Zero-Copy)';
  public rxPacketsTotal: number = 42890;
  public xdpDropCount: number = 3410;
  public xdpPassCount: number = 39180;
  public xdpRedirectCount: number = 300;
  public zeroCopyDropsTotal: number = 3410;
  public avgEvaluationLatencyNs: number = 360; // 360 nanoseconds (sub-microsecond)
  public lastSyncTimestamp: string = new Date().toISOString();

  // Counters for the AI-driven mitigation layers
  public rateLimitDropCount: number = 0;
  public lockdownDropCount: number = 0;
  public expiredRuleReapCount: number = 0;

  public readonly maxCapacity: number = 65536;

  // Simulated in-kernel BPF maps (BPF_MAP_TYPE_HASH / BPF_MAP_TYPE_LRU_HASH)
  public ipBlacklistMap = new LruBpfMap<BpfMapEntry['value']>(this.maxCapacity);
  public payloadHashMap = new Map<string, BpfMapEntry['value']>();
  public rateLimitLruMap = new LruBpfMap<TokenBucketState>(this.maxCapacity);
  public honeypotRedirectMap = new LruBpfMap<BpfMapEntry['value']>(this.maxCapacity);

  /** Infrastructure-wide XDP lockdown: drop everything except immune addresses. */
  private emergencyLockdownActive: boolean = false;
  private emergencyLockdownReason: string = '';

  constructor() {
    this.seedKernelBpfMaps();
  }

  private seedKernelBpfMaps() {
    // Seed initial known threat IPs into kernel BPF_MAP_TYPE_HASH
    const initialThreats = [
      { ip: '203.0.113.88', reason: 'Kernel Pin: Persistent SSH Brute Force' },
      { ip: '185.220.101.5', reason: 'Kernel Pin: Tor Exit Path Traversal Exploit' },
      { ip: '194.26.29.112', reason: 'Kernel Pin: SMB Lateral Probe' },
      { ip: '45.154.255.87', reason: 'Kernel Pin: Blind SQLi Cluster' }
    ];

    for (const t of initialThreats) {
      this.ipBlacklistMap.set(t.ip, {
        action: 'XDP_DROP',
        addedAt: Date.now() - 300000,
        expiresAt: Date.now() + 86400000,
        hits: Math.floor(120 + Math.random() * 400),
        ruleOrigin: t.reason
      });
    }

    // Seed known exploit payload hashes into BPF_MAP_TYPE_HASH
    const exploitPayloadSignatures = [
      '${jndi:ldap://',
      'UNION SELECT 1,table_name',
      '..%2f..%2fetc%2fshadow',
      '/bin/bash -i >& /dev/tcp/'
    ];

    for (const sig of exploitPayloadSignatures) {
      const hash = this.hashPayloadKey(sig);
      this.payloadHashMap.set(hash, {
        action: 'XDP_DROP',
        addedAt: Date.now() - 600000,
        expiresAt: Date.now() + 86400000,
        hits: Math.floor(45 + Math.random() * 90),
        ruleOrigin: `Payload Signature [${sig.substring(0, 15)}...]`
      });
    }
  }

  /**
   * Single canonical payload key derivation, so lookups stay O(1).
   *
   * Uses FNV-1a rather than SHA-256: a cryptographic digest costs roughly two
   * microseconds per packet, which alone blew the sub-microsecond XDP budget
   * and made hashing - not map lookup - the bottleneck on the hot path. Real
   * kernel data paths use a cheap non-cryptographic hash (jhash) for the same
   * reason. Collision resistance is not a security property here: this map is
   * a blocklist, so a crafted collision could only cause an attacker's own
   * traffic to be dropped, never admitted.
   */
  private hashPayloadKey(payload: string): string {
    const window = payload.length > 32 ? payload.substring(0, 32) : payload;
    // FNV-1a, 32-bit, applied twice with different offset bases to widen the
    // key space and keep the collision rate negligible for map-sized inputs.
    let h1 = 0x811c9dc5;
    let h2 = 0x01000193;
    for (let i = 0; i < window.length; i++) {
      const c = window.charCodeAt(i);
      h1 ^= c;
      h1 = Math.imul(h1, 0x01000193) >>> 0;
      h2 ^= c + i;
      h2 = Math.imul(h2, 0x85ebca6b) >>> 0;
    }
    return (h1.toString(16).padStart(8, '0') + h2.toString(16).padStart(8, '0'));
  }

  /**
   * Fire-and-forget propagation to the real kernel bridge.
   *
   * globalRealEbpfBridge.injectIp/removeIp are async and may shell out to
   * bpftool. They must never be awaited on the packet path, and an unhandled
   * rejection would terminate the Node process, so every call is explicitly
   * isolated with a catch handler.
   */
  private propagateToKernelBridge(operation: Promise<unknown>, context: string): void {
    operation.catch((err: any) => {
      console.warn(`[EbpfEngine] Kernel bridge propagation failed (${context}):`, err?.message || err);
    });
  }

  /** Reaps an entry whose TTL has elapsed. Returns true if the rule is dead. */
  private isExpired(entry: { expiresAt: number }, nowMs: number): boolean {
    return entry.expiresAt > 0 && entry.expiresAt <= nowMs;
  }

  /**
   * Token bucket admission control, evaluated lazily in O(1).
   *
   * Rather than refilling every bucket on a timer (which would cost O(n) per
   * tick and add jitter to the packet path), the bucket is refilled on read
   * from the elapsed time since its last touch:
   *   tokens = min(capacity, tokens + elapsedSeconds * refillPerSec)
   * A packet is admitted only if a whole token can be consumed.
   */
  private consumeToken(bucket: TokenBucketState, nowMs: number): boolean {
    const elapsedSec = Math.max(0, (nowMs - bucket.lastRefillMs) / 1000);
    if (elapsedSec > 0) {
      bucket.tokens = Math.min(bucket.capacity, bucket.tokens + elapsedSec * bucket.refillPerSec);
      bucket.lastRefillMs = nowMs;
    }

    if (bucket.tokens >= 1) {
      bucket.tokens -= 1;
      bucket.passedPackets++;
      return true;
    }
    bucket.droppedPackets++;
    return false;
  }

  /**
   * Evaluates packet in simulated Kernel Driver layer before Linux OS networking stack
   * Returns sub-microsecond latency (in nanoseconds)
   *
   * Every stage below is O(1): a boolean check, three hash-map lookups and a
   * single payload hash. No stage iterates the maps.
   */
  public evaluateKernelXdpIngress(srcIp: string, payload: string = '', port: number = 443): {
    verdict: 'XDP_DROP' | 'XDP_PASS' | 'XDP_REDIRECT';
    latencyNs: number;
    zeroCopy: boolean;
    bpfMapMatched: string | null;
    ruleDescription?: string;
  } {
    this.rxPacketsTotal++;
    const t0 = process.hrtime.bigint();
    const nowMs = Date.now();

    // 0. EMERGENCY LOCKDOWN: cheapest possible gate, evaluated first.
    if (this.emergencyLockdownActive && !KERNEL_IMMUNE_IPS.has(srcIp)) {
      this.xdpDropCount++;
      this.zeroCopyDropsTotal++;
      this.lockdownDropCount++;
      return this.finalize(t0, 'XDP_DROP', true, 'BPF_MAP_TYPE_ARRAY: lockdown_flag', this.emergencyLockdownReason, 110);
    }

    // 1. Check IP Blacklist Map (O(1) BPF_MAP_TYPE_LRU_HASH lookup)
    const ipEntry = this.ipBlacklistMap.get(srcIp);
    if (ipEntry) {
      if (this.isExpired(ipEntry, nowMs)) {
        this.ipBlacklistMap.delete(srcIp);
        this.expiredRuleReapCount++;
        this.propagateToKernelBridge(globalRealEbpfBridge.removeIp(srcIp), `ttl-reap ${srcIp}`);
      } else if (ipEntry.action === 'XDP_DROP') {
        ipEntry.hits++;
        this.xdpDropCount++;
        this.zeroCopyDropsTotal++;
        return this.finalize(t0, 'XDP_DROP', true, 'BPF_MAP_TYPE_LRU_HASH: ip_blacklist_map', ipEntry.ruleOrigin, 120);
      }
    }

    // 2. Check honeypot redirect map (O(1)) - AI 'REDIRECT_TO_HONEYPOT' verdicts.
    const redirectEntry = this.honeypotRedirectMap.get(srcIp);
    if (redirectEntry) {
      if (this.isExpired(redirectEntry, nowMs)) {
        this.honeypotRedirectMap.delete(srcIp);
        this.expiredRuleReapCount++;
      } else {
        redirectEntry.hits++;
        this.xdpRedirectCount++;
        return this.finalize(t0, 'XDP_REDIRECT', false, 'BPF_MAP_TYPE_DEVMAP: honeypot_redirect_map', redirectEntry.ruleOrigin, 210);
      }
    }

    // 3. Token bucket admission control (O(1)) - AI 'RATE_LIMIT' verdicts.
    const bucket = this.rateLimitLruMap.get(srcIp);
    if (bucket) {
      if (this.isExpired(bucket, nowMs)) {
        this.rateLimitLruMap.delete(srcIp);
        this.expiredRuleReapCount++;
      } else if (!this.consumeToken(bucket, nowMs)) {
        this.xdpDropCount++;
        this.zeroCopyDropsTotal++;
        this.rateLimitDropCount++;
        return this.finalize(
          t0,
          'XDP_DROP',
          true,
          'BPF_MAP_TYPE_LRU_HASH: rate_limit_token_bucket',
          `${bucket.ruleOrigin} (bucket exhausted: ${bucket.refillPerSec} pps sustained / ${bucket.capacity} burst)`,
          140
        );
      }
    }

    // 4. Check Payload Hash Map - hash once, then a single O(1) lookup.
    if (payload.length > 0) {
      const payloadKey = this.hashPayloadKey(payload);
      const entry = this.payloadHashMap.get(payloadKey);
      if (entry) {
        entry.hits++;
        this.xdpDropCount++;
        this.zeroCopyDropsTotal++;
        return this.finalize(t0, 'XDP_DROP', true, 'BPF_MAP_TYPE_HASH: payload_hash_map', entry.ruleOrigin, 180);
      }
    }

    // 5. Port check for honeypot redirection
    if (port === 22 && !KERNEL_IMMUNE_IPS.has(srcIp)) {
      this.xdpRedirectCount++;
      return this.finalize(
        t0,
        'XDP_REDIRECT',
        false,
        'BPF_MAP_TYPE_DEVMAP: honeypot_tap0',
        'Forward to Honeypot Isolation Container (10.0.99.5:22)',
        220
      );
    }

    // Packet passes XDP filter into OS network stack
    this.xdpPassCount++;
    return this.finalize(t0, 'XDP_PASS', false, null, undefined, 190);
  }

  /** Shared latency accounting for every XDP verdict path. */
  private finalize(
    t0: bigint,
    verdict: 'XDP_DROP' | 'XDP_PASS' | 'XDP_REDIRECT',
    zeroCopy: boolean,
    bpfMapMatched: string | null,
    ruleDescription: string | undefined,
    floorNs: number
  ) {
    const t1 = process.hrtime.bigint();
    const latencyNs = Math.max(floorNs, Number(t1 - t0));
    this.avgEvaluationLatencyNs = Math.round((this.avgEvaluationLatencyNs * 19 + latencyNs) / 20);
    return { verdict, latencyNs, zeroCopy, bpfMapMatched, ruleDescription };
  }

  // =========================================================================
  // AI DECISION ENGINE MITIGATION BRIDGE
  // Invoked directly by aiThreatAgent.service.ts the moment a verdict is
  // reached, before the decision is written to the telemetry bus.
  // =========================================================================

  /**
   * Sync AI generated mitigation rule directly into in-kernel BPF maps
   */
  public pinRuleToBpfMap(ip: string, reason: string, ttlSeconds: number = 3600): void {
    this.ipBlacklistMap.set(ip, {
      action: 'XDP_DROP',
      addedAt: Date.now(),
      expiresAt: Date.now() + ttlSeconds * 1000,
      hits: 0,
      ruleOrigin: reason
    });
    this.lastSyncTimestamp = new Date().toISOString();

    // Propagate to real Linux Kernel eBPF Map (never awaited on the hot path)
    this.propagateToKernelBridge(globalRealEbpfBridge.injectIp(ip, reason), `injectIp ${ip}`);
  }

  /**
   * 'NULL_ROUTE': pin an XDP_DROP rule so every subsequent packet from this
   * actor is discarded at the driver before it reaches the network stack.
   */
  public enforceNullRoute(ip: string, reason: string, ttlSeconds: number = 86400): {
    enforced: boolean;
    map: string;
    expiresAt: string;
  } {
    this.pinRuleToBpfMap(ip, reason, ttlSeconds);
    // A null-routed actor no longer needs a throttle bucket occupying map space.
    this.rateLimitLruMap.delete(ip);
    return {
      enforced: true,
      map: 'ip_blacklist_map',
      expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString()
    };
  }

  /**
   * 'RATE_LIMIT': install a per-IP token bucket in the LRU map. Traffic is
   * throttled to `ratePps` sustained with `burstCapacity` headroom rather
   * than dropped outright.
   */
  public enforceRateLimit(
    ip: string,
    reason: string,
    ratePps: number = 10,
    burstCapacity: number = 20,
    ttlSeconds: number = 300
  ): { enforced: boolean; map: string; ratePps: number; burstCapacity: number; expiresAt: string } {
    const safeRate = Math.max(1, ratePps);
    const safeBurst = Math.max(1, burstCapacity);
    const existing = this.rateLimitLruMap.peek(ip);

    this.rateLimitLruMap.set(ip, {
      // Preserve remaining tokens when re-arming so a repeat offender cannot
      // refresh its own burst allowance by tripping the rule again.
      tokens: existing ? Math.min(existing.tokens, safeBurst) : safeBurst,
      capacity: safeBurst,
      refillPerSec: safeRate,
      lastRefillMs: Date.now(),
      passedPackets: existing?.passedPackets ?? 0,
      droppedPackets: existing?.droppedPackets ?? 0,
      expiresAt: Date.now() + ttlSeconds * 1000,
      ruleOrigin: reason
    });
    this.lastSyncTimestamp = new Date().toISOString();

    return {
      enforced: true,
      map: 'rate_limit_token_bucket',
      ratePps: safeRate,
      burstCapacity: safeBurst,
      expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString()
    };
  }

  /**
   * 'REDIRECT_TO_HONEYPOT': divert the actor into the deception container
   * via the simulated BPF_MAP_TYPE_DEVMAP rather than dropping it, so the
   * attacker's behavior can still be observed.
   */
  public enforceHoneypotRedirect(ip: string, reason: string, ttlSeconds: number = 3600): {
    enforced: boolean;
    map: string;
    expiresAt: string;
  } {
    this.honeypotRedirectMap.set(ip, {
      action: 'XDP_REDIRECT',
      addedAt: Date.now(),
      expiresAt: Date.now() + ttlSeconds * 1000,
      hits: 0,
      ruleOrigin: reason
    });
    this.lastSyncTimestamp = new Date().toISOString();
    return {
      enforced: true,
      map: 'honeypot_redirect_map',
      expiresAt: new Date(Date.now() + ttlSeconds * 1000).toISOString()
    };
  }

  /**
   * 'TRIGGER_EMERGENCY_LOCKDOWN': flip the global XDP gate so every packet
   * from a non-immune address is dropped at the driver.
   */
  public enforceEmergencyLockdown(active: boolean, reason: string = 'AI Agent Emergency Lockdown'): {
    active: boolean;
    reason: string;
  } {
    this.emergencyLockdownActive = active;
    this.emergencyLockdownReason = active ? reason : '';
    this.lastSyncTimestamp = new Date().toISOString();
    console.log(`[EbpfEngine] Emergency XDP lockdown ${active ? 'ENGAGED' : 'RELEASED'}${active ? `: ${reason}` : ''}.`);
    return { active: this.emergencyLockdownActive, reason: this.emergencyLockdownReason };
  }

  public isEmergencyLockdownActive(): boolean {
    return this.emergencyLockdownActive;
  }

  public isNullRouted(ip: string): boolean {
    const entry = this.ipBlacklistMap.peek(ip);
    if (!entry) return false;
    if (this.isExpired(entry, Date.now())) return false;
    return entry.action === 'XDP_DROP';
  }

  /** Full mitigation posture for one actor, used by the SOC status endpoints. */
  public getMitigationState(ip: string): {
    ip: string;
    nullRouted: boolean;
    rateLimited: boolean;
    honeypotRedirected: boolean;
    lockdownActive: boolean;
    tokenBucket: TokenBucketState | null;
    blacklistEntry: BpfMapEntry['value'] | null;
  } {
    const nowMs = Date.now();
    const blacklistEntry = this.ipBlacklistMap.peek(ip) ?? null;
    const bucket = this.rateLimitLruMap.peek(ip) ?? null;
    const redirect = this.honeypotRedirectMap.peek(ip) ?? null;

    return {
      ip,
      nullRouted: !!blacklistEntry && !this.isExpired(blacklistEntry, nowMs) && blacklistEntry.action === 'XDP_DROP',
      rateLimited: !!bucket && !this.isExpired(bucket, nowMs),
      honeypotRedirected: !!redirect && !this.isExpired(redirect, nowMs),
      lockdownActive: this.emergencyLockdownActive,
      tokenBucket: bucket && !this.isExpired(bucket, nowMs) ? bucket : null,
      blacklistEntry: blacklistEntry && !this.isExpired(blacklistEntry, nowMs) ? blacklistEntry : null
    };
  }

  /** Removes every AI-installed mitigation for one actor. */
  public clearMitigation(ip: string): { cleared: boolean } {
    const removedBan = this.ipBlacklistMap.delete(ip);
    const removedBucket = this.rateLimitLruMap.delete(ip);
    const removedRedirect = this.honeypotRedirectMap.delete(ip);
    if (removedBan) {
      this.propagateToKernelBridge(globalRealEbpfBridge.removeIp(ip), `removeIp ${ip}`);
    }
    return { cleared: removedBan || removedBucket || removedRedirect };
  }

  public setXdpMode(mode: XdpDriverMode): void {
    this.mode = mode;
    if (mode === 'NATIVE_DRIVER') {
      this.driverAttached = 'eth0 (mlx5_core Mellanox ConnectX-6 Dx Zero-Copy)';
    } else if (mode === 'SKB_GENERIC') {
      this.driverAttached = 'eth0 (Generic Linux SKB Core Stack)';
    } else {
      this.driverAttached = 'eth0 (Netronome SmartNIC Smart-Offload ASIC)';
    }
  }

  public flushMaps(): void {
    for (const ip of this.ipBlacklistMap.keys()) {
      this.propagateToKernelBridge(globalRealEbpfBridge.removeIp(ip), `flush ${ip}`);
    }
    this.ipBlacklistMap.clear();
    this.payloadHashMap.clear();
    this.rateLimitLruMap.clear();
    this.honeypotRedirectMap.clear();
    this.emergencyLockdownActive = false;
    this.emergencyLockdownReason = '';
    this.seedKernelBpfMaps();
  }

  public getStats() {
    return {
      mode: this.mode,
      driverAttached: this.driverAttached,
      rxPacketsTotal: this.rxPacketsTotal,
      xdpDropCount: this.xdpDropCount,
      xdpPassCount: this.xdpPassCount,
      xdpRedirectCount: this.xdpRedirectCount,
      zeroCopyDropsTotal: this.zeroCopyDropsTotal,
      avgEvaluationLatencyNs: this.avgEvaluationLatencyNs,
      subMicrosecondTargetMet: this.avgEvaluationLatencyNs < 1000,
      emergencyLockdownActive: this.emergencyLockdownActive,
      rateLimitDropCount: this.rateLimitDropCount,
      lockdownDropCount: this.lockdownDropCount,
      expiredRuleReapCount: this.expiredRuleReapCount,
      bpfMaps: {
        ipBlacklistMap: {
          entries: this.ipBlacklistMap.size,
          maxCapacity: this.maxCapacity,
          evictions: this.ipBlacklistMap.evictionCount,
          memoryKb: Number(((this.ipBlacklistMap.size * 64) / 1024).toFixed(2))
        },
        payloadHashMap: {
          entries: this.payloadHashMap.size,
          maxCapacity: this.maxCapacity,
          memoryKb: Number(((this.payloadHashMap.size * 128) / 1024).toFixed(2))
        },
        rateLimitLruMap: {
          entries: this.rateLimitLruMap.size,
          maxCapacity: this.maxCapacity,
          evictions: this.rateLimitLruMap.evictionCount,
          memoryKb: Number(((this.rateLimitLruMap.size * 32) / 1024).toFixed(2))
        },
        honeypotRedirectMap: {
          entries: this.honeypotRedirectMap.size,
          maxCapacity: this.maxCapacity,
          evictions: this.honeypotRedirectMap.evictionCount,
          memoryKb: Number(((this.honeypotRedirectMap.size * 64) / 1024).toFixed(2))
        }
      },
      hardwareOffloadActive: this.mode === 'NATIVE_DRIVER' || this.mode === 'OFFLOADED_NIC',
      lastSyncTimestamp: this.lastSyncTimestamp
    };
  }
}

export const globalEbpfEngine = new EbpfXdpOffloadEngine();
