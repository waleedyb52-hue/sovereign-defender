import dns from 'dns';
import net from 'net';

// =============================================================================
// LIVE THREAT INTELLIGENCE ENRICHMENT (v1.0)
//
// Performs real network operations: real reverse DNS via the OS resolver,
// real HTTPS calls to public threat feeds, and a real TTL cache that keeps
// upstream rate limits intact.
//
// HONEST SCOPE NOTE
// -----------------
// AbuseIPDB requires an API key. Without ABUSEIPDB_API_KEY set, this service
// does NOT invent a reputation score - it reports the source as
// UNAVAILABLE_NO_CREDENTIAL and the result is marked partial. The Tor exit
// directory is genuinely public and is fetched for real. Every result states
// exactly which sources answered, so an operator can never mistake a degraded
// lookup for a confirmed clean verdict.
// =============================================================================

const resolver = dns.promises;

export type IntelSourceId = 'REVERSE_DNS' | 'TOR_EXIT_DIRECTORY' | 'ABUSEIPDB_V2' | 'LOCAL_HEURISTICS';
export type SourceStatus = 'OK' | 'MISS' | 'TIMEOUT' | 'ERROR' | 'UNAVAILABLE_NO_CREDENTIAL' | 'SKIPPED_PRIVATE';

export interface SourceOutcome {
  source: IntelSourceId;
  status: SourceStatus;
  latencyMs: number;
  detail: string | null;
}

export interface LiveIntelResult {
  ip: string;
  /** True when the address is RFC1918/loopback and never sent upstream. */
  isPrivate: boolean;
  reverseDns: string[] | null;
  /** Forward-confirmed reverse DNS: the PTR name resolves back to this IP. */
  fcrdnsValid: boolean | null;
  isTorExitNode: boolean | null;
  abuseConfidenceScore: number | null;
  abuseTotalReports: number | null;
  countryCode: string | null;
  usageType: string | null;
  isp: string | null;
  asn: number | null;
  /** 0-100 composite from whatever really answered. */
  compositeRisk: number;
  sources: SourceOutcome[];
  /** True when at least one source failed or was unavailable. */
  partial: boolean;
  cacheHit: boolean;
  resolvedAt: number;
  totalLatencyMs: number;
}

/** Upstream budget. Beyond this a source is abandoned, never blocking. */
const UPSTREAM_TIMEOUT_MS = 4000;
const DNS_TIMEOUT_MS = 2500;

const CACHE_TTL_MS = 30 * 60_000; // 30 minutes
const CACHE_MAX_ENTRIES = 5000;
/** Tor list is large and slow-moving; refresh hourly, not per lookup. */
const TOR_LIST_TTL_MS = 60 * 60_000;

const TOR_EXIT_LIST_URL = 'https://check.torproject.org/torbulkexitlist';
const ABUSEIPDB_URL = 'https://api.abuseipdb.com/api/v2/check';

/**
 * Real TTL cache.
 *
 * Expiry is enforced lazily on read rather than by a sweep timer: a timer
 * would keep the event loop busy for entries nobody asks about, and the read
 * path has to check freshness anyway.
 */
class TtlCache<V> {
  private readonly store = new Map<string, { value: V; expiresAt: number }>();
  public hits = 0;
  public misses = 0;
  public evictions = 0;

  constructor(private readonly ttlMs: number, private readonly maxEntries: number) {}

  get(key: string): V | undefined {
    const e = this.store.get(key);
    if (!e) { this.misses++; return undefined; }
    if (e.expiresAt <= Date.now()) { this.store.delete(key); this.misses++; return undefined; }
    // Promote to most-recently-used.
    this.store.delete(key); this.store.set(key, e);
    this.hits++;
    return e.value;
  }

  set(key: string, value: V): void {
    if (this.store.has(key)) this.store.delete(key);
    this.store.set(key, { value, expiresAt: Date.now() + this.ttlMs });
    while (this.store.size > this.maxEntries) {
      const oldest = this.store.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.store.delete(oldest);
      this.evictions++;
    }
  }

  get size(): number { return this.store.size; }
  clear(): void { this.store.clear(); }
  get hitRatePercent(): number {
    const t = this.hits + this.misses;
    return t === 0 ? 0 : Number(((this.hits / t) * 100).toFixed(2));
  }
}

/** Races a promise against a real timeout so one slow feed cannot stall a lookup. */
function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(label + ' timed out after ' + ms + 'ms')), ms);
    p.then(v => { clearTimeout(timer); resolve(v); },
           e => { clearTimeout(timer); reject(e); });
  });
}

function isPrivateAddress(ip: string): boolean {
  if (!net.isIP(ip)) return true; // not routable, treat as internal
  if (/^(10\.|127\.|169\.254\.|192\.168\.)/.test(ip)) return true;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(ip)) return true;
  if (ip === '::1' || ip.startsWith('fc') || ip.startsWith('fd')) return true;
  return false;
}

export class LiveThreatIntelService {
  private readonly cache = new TtlCache<LiveIntelResult>(CACHE_TTL_MS, CACHE_MAX_ENTRIES);
  private torExitSet: Set<string> | null = null;
  private torFetchedAt = 0;
  private torFetchInFlight: Promise<Set<string> | null> | null = null;

  public totalLookups = 0;
  public totalUpstreamCalls = 0;
  public totalPartial = 0;

  // -------------------------------------------------------------------
  // Real reverse DNS
  // -------------------------------------------------------------------

  /**
   * Real PTR lookup through the OS resolver, then forward-confirmation.
   *
   * A PTR record alone is attacker-controllable: whoever owns the reverse
   * zone can claim any name. FCrDNS resolves the returned hostname back to A
   * records and only trusts it if the original IP is among them, which is the
   * check that makes reverse DNS meaningful rather than decorative.
   */
  public async reverseLookup(ip: string): Promise<{ names: string[] | null; fcrdns: boolean | null; detail: string }> {
    try {
      const names = await withTimeout(resolver.reverse(ip), DNS_TIMEOUT_MS, 'reverse DNS');
      if (!names || names.length === 0) return { names: null, fcrdns: null, detail: 'no PTR record' };

      let fcrdns = false;
      try {
        const forward = await withTimeout(resolver.resolve4(names[0]), DNS_TIMEOUT_MS, 'forward DNS');
        fcrdns = Array.isArray(forward) && forward.includes(ip);
      } catch {
        fcrdns = false;
      }
      return { names, fcrdns, detail: names[0] + (fcrdns ? ' (forward-confirmed)' : ' (NOT forward-confirmed)') };
    } catch (err: any) {
      const code = err?.code || err?.message || 'unknown';
      // ENOTFOUND simply means no PTR exists, which is normal, not an error.
      return { names: null, fcrdns: null, detail: String(code) };
    }
  }

  // -------------------------------------------------------------------
  // Real Tor exit directory
  // -------------------------------------------------------------------

  /**
   * Fetches the genuine public Tor exit-node list.
   *
   * Public and unauthenticated, so this works with no credential. The list is
   * cached for an hour and concurrent callers share one in-flight fetch,
   * because a burst of lookups must never become a burst of downloads.
   */
  public async loadTorExitNodes(force = false): Promise<Set<string> | null> {
    const fresh = this.torExitSet && (Date.now() - this.torFetchedAt) < TOR_LIST_TTL_MS;
    if (fresh && !force) return this.torExitSet;
    if (this.torFetchInFlight) return this.torFetchInFlight;

    this.torFetchInFlight = (async () => {
      try {
        this.totalUpstreamCalls++;
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
        const res = await fetch(TOR_EXIT_LIST_URL, {
          signal: controller.signal,
          headers: { 'User-Agent': 'SovereignDefender/4.0 (threat-intel)' }
        });
        clearTimeout(timer);
        if (!res.ok) throw new Error('HTTP ' + res.status);

        const text = await res.text();
        const set = new Set<string>();
        for (const line of text.split('\n')) {
          const t = line.trim();
          if (t && net.isIP(t)) set.add(t);
        }
        this.torExitSet = set;
        this.torFetchedAt = Date.now();
        console.log('[LiveIntel] Loaded ' + set.size + ' real Tor exit nodes from the public directory.');
        return set;
      } catch (err: any) {
        console.warn('[LiveIntel] Tor exit directory unavailable:', err?.message || err);
        // Keep any previously loaded list rather than dropping to null: stale
        // intelligence beats no intelligence, and staleness is reported.
        return this.torExitSet;
      } finally {
        this.torFetchInFlight = null;
      }
    })();

    return this.torFetchInFlight;
  }

  // -------------------------------------------------------------------
  // Real AbuseIPDB v2
  // -------------------------------------------------------------------

  /**
   * Queries the real AbuseIPDB v2 endpoint when a credential is configured.
   *
   * Returns an explicit UNAVAILABLE_NO_CREDENTIAL rather than a fabricated
   * score when the key is absent. Reporting a synthetic reputation as if it
   * were live intelligence is precisely the failure mode this stage exists to
   * eliminate.
   */
  public async queryAbuseIpDb(ip: string): Promise<{
    status: SourceStatus;
    detail: string;
    data: { abuseConfidenceScore: number; totalReports: number; countryCode: string | null; usageType: string | null; isp: string | null; isTor: boolean } | null;
  }> {
    const key = process.env.ABUSEIPDB_API_KEY;
    if (!key) {
      return {
        status: 'UNAVAILABLE_NO_CREDENTIAL',
        detail: 'ABUSEIPDB_API_KEY is not set; no live reputation was retrieved.',
        data: null
      };
    }

    try {
      this.totalUpstreamCalls++;
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
      const url = ABUSEIPDB_URL + '?ipAddress=' + encodeURIComponent(ip) + '&maxAgeInDays=90&verbose';
      const res = await fetch(url, {
        signal: controller.signal,
        headers: { Key: key, Accept: 'application/json', 'User-Agent': 'SovereignDefender/4.0' }
      });
      clearTimeout(timer);

      if (res.status === 429) return { status: 'ERROR', detail: 'rate limited by upstream (HTTP 429)', data: null };
      if (!res.ok) return { status: 'ERROR', detail: 'upstream HTTP ' + res.status, data: null };

      const json: any = await res.json();
      const d = json?.data;
      if (!d) return { status: 'MISS', detail: 'no data object in upstream response', data: null };

      return {
        status: 'OK',
        detail: 'abuseConfidenceScore=' + d.abuseConfidenceScore,
        data: {
          abuseConfidenceScore: Number(d.abuseConfidenceScore) || 0,
          totalReports: Number(d.totalReports) || 0,
          countryCode: d.countryCode ?? null,
          usageType: d.usageType ?? null,
          isp: d.isp ?? null,
          isTor: Boolean(d.isTor)
        }
      };
    } catch (err: any) {
      const aborted = err?.name === 'AbortError';
      return {
        status: aborted ? 'TIMEOUT' : 'ERROR',
        detail: aborted ? 'aborted after ' + UPSTREAM_TIMEOUT_MS + 'ms' : String(err?.message || err),
        data: null
      };
    }
  }

  // -------------------------------------------------------------------
  // Composite lookup
  // -------------------------------------------------------------------

  /**
   * Full enrichment for one address.
   *
   * Sources are queried concurrently and each is individually timeout-guarded,
   * so total latency is bounded by the slowest single source rather than by
   * their sum, and one dead feed cannot hold up the others.
   */
  public async enrich(ip: string): Promise<LiveIntelResult> {
    const started = Date.now();
    this.totalLookups++;
    const clean = String(ip ?? '').trim();

    const cached = this.cache.get(clean);
    if (cached) {
      return { ...cached, cacheHit: true, totalLatencyMs: Date.now() - started };
    }

    const sources: SourceOutcome[] = [];
    const priv = isPrivateAddress(clean);

    // Private space is never sent to a third party: doing so would leak
    // internal topology to an external service for no analytical gain.
    if (priv) {
      sources.push({ source: 'ABUSEIPDB_V2', status: 'SKIPPED_PRIVATE', latencyMs: 0, detail: 'RFC1918/loopback not sent upstream' });
      sources.push({ source: 'TOR_EXIT_DIRECTORY', status: 'SKIPPED_PRIVATE', latencyMs: 0, detail: 'not applicable to private space' });
    }

    const t0 = Date.now();
    const [dnsRes, torRes, abuseRes] = await Promise.all([
      this.reverseLookup(clean).then(r => ({ ok: true as const, r }), e => ({ ok: false as const, e })),
      priv ? Promise.resolve(null) : this.loadTorExitNodes().catch(() => null),
      priv ? Promise.resolve(null) : this.queryAbuseIpDb(clean).catch(() => null)
    ]);

    // --- Reverse DNS -----------------------------------------------
    let reverseDns: string[] | null = null;
    let fcrdnsValid: boolean | null = null;
    if (dnsRes.ok) {
      reverseDns = dnsRes.r.names;
      fcrdnsValid = dnsRes.r.fcrdns;
      sources.push({
        source: 'REVERSE_DNS',
        status: reverseDns ? 'OK' : 'MISS',
        latencyMs: Date.now() - t0,
        detail: dnsRes.r.detail
      });
    } else {
      sources.push({ source: 'REVERSE_DNS', status: 'ERROR', latencyMs: Date.now() - t0, detail: 'resolver failure' });
    }

    // --- Tor exit directory ----------------------------------------
    let isTorExitNode: boolean | null = null;
    if (!priv) {
      if (torRes) {
        isTorExitNode = torRes.has(clean);
        const ageMin = Math.round((Date.now() - this.torFetchedAt) / 60000);
        sources.push({
          source: 'TOR_EXIT_DIRECTORY',
          status: 'OK',
          latencyMs: Date.now() - t0,
          detail: torRes.size + ' exit nodes loaded (' + ageMin + ' min old)'
        });
      } else {
        sources.push({ source: 'TOR_EXIT_DIRECTORY', status: 'ERROR', latencyMs: Date.now() - t0, detail: 'directory unreachable' });
      }
    }

    // --- AbuseIPDB --------------------------------------------------
    let abuseConfidenceScore: number | null = null;
    let abuseTotalReports: number | null = null;
    let countryCode: string | null = null;
    let usageType: string | null = null;
    let isp: string | null = null;
    if (!priv) {
      if (abuseRes) {
        sources.push({ source: 'ABUSEIPDB_V2', status: abuseRes.status, latencyMs: Date.now() - t0, detail: abuseRes.detail });
        if (abuseRes.data) {
          abuseConfidenceScore = abuseRes.data.abuseConfidenceScore;
          abuseTotalReports = abuseRes.data.totalReports;
          countryCode = abuseRes.data.countryCode;
          usageType = abuseRes.data.usageType;
          isp = abuseRes.data.isp;
          if (abuseRes.data.isTor) isTorExitNode = true;
        }
      } else {
        sources.push({ source: 'ABUSEIPDB_V2', status: 'ERROR', latencyMs: Date.now() - t0, detail: 'connector failure' });
      }
    }

    // --- Local heuristics on what genuinely resolved ----------------
    const heuristics = this.localHeuristics(clean, reverseDns, fcrdnsValid);
    sources.push({ source: 'LOCAL_HEURISTICS', status: 'OK', latencyMs: 0, detail: heuristics.detail });

    const compositeRisk = this.composeRisk({ abuseConfidenceScore, isTorExitNode, fcrdnsValid, heuristicRisk: heuristics.risk });
    const partial = sources.some(s => s.status === 'ERROR' || s.status === 'TIMEOUT' || s.status === 'UNAVAILABLE_NO_CREDENTIAL');
    if (partial) this.totalPartial++;

    const result: LiveIntelResult = {
      ip: clean,
      isPrivate: priv,
      reverseDns,
      fcrdnsValid,
      isTorExitNode,
      abuseConfidenceScore,
      abuseTotalReports,
      countryCode,
      usageType,
      isp,
      asn: null, // Requires a BGP/WHOIS feed; not fabricated here.
      compositeRisk,
      sources,
      partial,
      cacheHit: false,
      resolvedAt: Date.now(),
      totalLatencyMs: Date.now() - started
    };

    // Only cache results that at least one live source contributed to.
    if (!partial || reverseDns !== null || isTorExitNode !== null) {
      this.cache.set(clean, result);
    }
    return result;
  }

  /** Signals derivable without any upstream call. */
  private localHeuristics(ip: string, reverseDns: string[] | null, fcrdns: boolean | null): { risk: number; detail: string } {
    const notes: string[] = [];
    let risk = 0;

    if (reverseDns === null) {
      // Most residential and cloud addresses have PTR records; bare IPs with
      // none skew toward bulletproof hosting.
      risk += 12; notes.push('no PTR record');
    } else if (fcrdns === false) {
      risk += 20; notes.push('PTR not forward-confirmed');
    } else if (fcrdns === true) {
      risk -= 5; notes.push('forward-confirmed PTR');
    }

    const host = reverseDns?.[0]?.toLowerCase() ?? '';
    if (/(vps|vultr|digitalocean|linode|hetzner|ovh|contabo|colo|dedi)/.test(host)) {
      risk += 15; notes.push('hosting/VPS reverse name');
    }
    if (/(tor|exit|relay)/.test(host)) { risk += 25; notes.push('tor-suggestive hostname'); }
    if (/(comcast|verizon|bt\.net|telecom|broadband|dsl|cable)/.test(host)) {
      risk -= 5; notes.push('residential ISP name');
    }

    return { risk: Math.max(0, Math.min(60, risk)), detail: notes.join('; ') || 'no local signal' };
  }

  /**
   * Composite risk from sources that actually answered.
   *
   * A missing source contributes nothing rather than a default, so an
   * unreachable feed lowers confidence instead of silently manufacturing a
   * clean verdict.
   */
  private composeRisk(input: {
    abuseConfidenceScore: number | null;
    isTorExitNode: boolean | null;
    fcrdnsValid: boolean | null;
    heuristicRisk: number;
  }): number {
    let risk = input.heuristicRisk;
    if (typeof input.abuseConfidenceScore === 'number') {
      risk = Math.max(risk, input.abuseConfidenceScore);
    }
    if (input.isTorExitNode === true) risk = Math.max(risk, 70);
    return Math.max(0, Math.min(100, Math.round(risk)));
  }

  public getStats() {
    return {
      totalLookups: this.totalLookups,
      totalUpstreamCalls: this.totalUpstreamCalls,
      totalPartial: this.totalPartial,
      cache: {
        entries: this.cache.size,
        hits: this.cache.hits,
        misses: this.cache.misses,
        evictions: this.cache.evictions,
        hitRatePercent: this.cache.hitRatePercent,
        ttlMs: CACHE_TTL_MS
      },
      torDirectory: {
        loaded: this.torExitSet !== null,
        nodeCount: this.torExitSet?.size ?? 0,
        ageMinutes: this.torFetchedAt ? Math.round((Date.now() - this.torFetchedAt) / 60000) : null,
        ttlMs: TOR_LIST_TTL_MS
      },
      abuseIpDb: {
        credentialConfigured: Boolean(process.env.ABUSEIPDB_API_KEY),
        endpoint: ABUSEIPDB_URL
      }
    };
  }

  public clearCache(): void { this.cache.clear(); }
}

export const globalLiveThreatIntel = new LiveThreatIntelService();
