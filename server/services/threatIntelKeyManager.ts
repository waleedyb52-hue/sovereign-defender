import dns from 'dns';
import net from 'net';
import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalLiveThreatIntel } from './liveThreatIntel.service.js';

const resolver = dns.promises;

// =============================================================================
// THREAT INTEL KEY ORCHESTRATOR & FALLBACK RESILIENCE (v1.0)
//
// Removes the missing-API-key bottleneck two ways:
//
//   1. Keys can be injected at runtime (env at boot, or the SOC admin route)
//      with quota accounting and automatic cooldown when a provider throttles.
//
//   2. When no key is usable, intelligence does NOT degrade to nothing. The
//      resolver falls through to sources that need no credential at all:
//      real DNSBL lookups over DNS, and the Tor exit directory already synced
//      by the live intel service.
//
// KEY HANDLING
// ------------
// Injected keys are held in memory only. They are never written to disk, never
// logged, and never returned by any read API - only a fingerprint (first 6
// characters of a SHA-256) and the last four characters are exposed, which is
// enough for an operator to confirm which key is loaded without the value
// itself becoming recoverable from telemetry or a screenshot.
// =============================================================================

export type IntelProvider = 'ABUSEIPDB' | 'VIRUSTOTAL' | 'OTX' | 'GREYNOISE';
export type ResolutionTier = 'PRIMARY_API' | 'DNSBL' | 'TOR_DIRECTORY' | 'LOCAL_ONLY';

export interface KeyRecord {
  provider: IntelProvider;
  /** Never the key itself. */
  fingerprint: string;
  lastFour: string;
  installedAt: number;
  installedBy: string;
  /** Requests made in the current quota window. */
  usedThisWindow: number;
  windowStartedAt: number;
  quotaLimit: number;
  /** Set when the provider throttled us; no calls until it passes. */
  cooldownUntil: number | null;
  lastError: string | null;
  healthy: boolean;
}

export interface DnsblVerdict {
  zone: string;
  listed: boolean;
  /** Return codes the zone answered with, which encode the listing reason. */
  codes: string[];
  meaning: string | null;
  latencyMs: number;
  error: string | null;
}

export interface ResolvedIntel {
  ip: string;
  tier: ResolutionTier;
  /** 0-100. */
  riskScore: number;
  listedOn: string[];
  dnsbl: DnsblVerdict[];
  isTorExit: boolean | null;
  abuseConfidence: number | null;
  reverseDns: string[] | null;
  /** Human-readable account of which sources actually contributed. */
  provenance: string[];
  degraded: boolean;
  latencyMs: number;
}

const DNSBL_TIMEOUT_MS = 2500;
const DEFAULT_QUOTA = 1000;
const QUOTA_WINDOW_MS = 24 * 60 * 60_000;
const COOLDOWN_MS = 15 * 60_000;

/**
 * Public DNS blocklists queried over plain DNS.
 *
 * These need no account and no key, which is exactly what makes them a
 * dependable floor: when a commercial API is missing or throttled, the system
 * still gets real, externally-sourced reputation rather than falling back to
 * guesswork.
 */
const DNSBL_ZONES: Array<{ zone: string; meanings: Record<string, string> }> = [
  {
    zone: 'zen.spamhaus.org',
    meanings: {
      '127.0.0.2': 'SBL - direct spam source',
      '127.0.0.3': 'SBL CSS - snowshoe spam',
      '127.0.0.4': 'XBL - exploited machine or open proxy',
      '127.0.0.9': 'DROP - hijacked or leased by criminals',
      '127.0.0.10': 'PBL - end-user address, should not send mail directly',
      '127.0.0.11': 'PBL - ISP-declared dynamic space'
    }
  },
  {
    zone: 'dnsbl.dronebl.org',
    meanings: {
      '127.0.0.3': 'IRC drone',
      '127.0.0.8': 'open proxy',
      '127.0.0.9': 'compromised router or gateway',
      '127.0.0.13': 'brute-force attacker',
      '127.0.0.17': 'automated dictionary attacker'
    }
  },
  {
    zone: 'b.barracudacentral.org',
    meanings: { '127.0.0.2': 'Barracuda reputation block' }
  }
];

export class ThreatIntelKeyManager {
  private readonly keys = new Map<IntelProvider, { value: string; record: KeyRecord }>();
  private readonly dnsblCache = new Map<string, { verdicts: DnsblVerdict[]; expiresAt: number }>();

  public totalResolutions = 0;
  public totalPrimaryApi = 0;
  public totalDnsblFallback = 0;
  public totalLocalOnly = 0;

  constructor() {
    // Adopt any key already present in the environment at boot.
    this.adoptFromEnv();
  }

  private adoptFromEnv(): void {
    const map: Array<[IntelProvider, string | undefined]> = [
      ['ABUSEIPDB', process.env.ABUSEIPDB_API_KEY],
      ['VIRUSTOTAL', process.env.VIRUSTOTAL_API_KEY],
      ['OTX', process.env.OTX_API_KEY],
      ['GREYNOISE', process.env.GREYNOISE_API_KEY]
    ];
    for (const [provider, value] of map) {
      if (value && value.trim()) this.installKey(provider, value.trim(), 'environment');
    }
  }

  // -------------------------------------------------------------------
  // Key lifecycle
  // -------------------------------------------------------------------

  /**
   * Installs or rotates a provider key at runtime.
   *
   * Also pushes ABUSEIPDB into process.env so the existing live intel service
   * picks it up without a restart - that service reads the variable per call
   * by design, precisely so a key can arrive mid-flight.
   */
  public installKey(provider: IntelProvider, key: string, installedBy: string): KeyRecord {
    const value = String(key ?? '').trim();
    const fingerprint = crypto.createHash('sha256').update(value).digest('hex').slice(0, 6);

    const record: KeyRecord = {
      provider,
      fingerprint,
      lastFour: value.length >= 4 ? value.slice(-4) : '****',
      installedAt: Date.now(),
      installedBy,
      usedThisWindow: 0,
      windowStartedAt: Date.now(),
      quotaLimit: DEFAULT_QUOTA,
      cooldownUntil: null,
      lastError: null,
      healthy: true
    };

    this.keys.set(provider, { value, record });
    if (provider === 'ABUSEIPDB') process.env.ABUSEIPDB_API_KEY = value;
    if (provider === 'VIRUSTOTAL') process.env.VIRUSTOTAL_API_KEY = value;

    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'SOAR_PLAYBOOK',
        severity: 'INFO',
        title: '[Intel Keys] ' + provider + ' key installed (fingerprint ' + fingerprint + ')',
        titleAr: '[مفاتيح الاستخبارات] تم تركيب مفتاح ' + provider + ' (البصمة ' + fingerprint + ')',
        details: 'Runtime key injection by ' + installedBy + '. The key value is held in memory only and is never logged or persisted.',
        detailsAr: 'حقن مفتاح أثناء التشغيل بواسطة ' + installedBy + '. القيمة تبقى في الذاكرة فقط ولا تُسجل أو تُحفظ.',
        actionTaken: 'INTEL_KEY_INSTALLED',
        actionTakenAr: 'تم تركيب مفتاح استخباراتي',
        metadata: { provider, fingerprint, installedBy, keyValueLogged: false }
      });
    } catch { /* telemetry optional */ }

    return record;
  }

  public revokeKey(provider: IntelProvider): boolean {
    const had = this.keys.delete(provider);
    if (provider === 'ABUSEIPDB') delete process.env.ABUSEIPDB_API_KEY;
    if (provider === 'VIRUSTOTAL') delete process.env.VIRUSTOTAL_API_KEY;
    return had;
  }

  /** True when the provider has a key that is neither exhausted nor cooling down. */
  public isUsable(provider: IntelProvider): { usable: boolean; reason: string } {
    const entry = this.keys.get(provider);
    if (!entry) return { usable: false, reason: 'no key installed' };

    const r = entry.record;
    if (r.cooldownUntil && Date.now() < r.cooldownUntil) {
      return { usable: false, reason: 'cooling down until ' + new Date(r.cooldownUntil).toISOString() + ' after upstream throttling' };
    }
    if (Date.now() - r.windowStartedAt > QUOTA_WINDOW_MS) {
      r.usedThisWindow = 0;
      r.windowStartedAt = Date.now();
    }
    if (r.usedThisWindow >= r.quotaLimit) {
      return { usable: false, reason: 'daily quota of ' + r.quotaLimit + ' exhausted' };
    }
    return { usable: true, reason: 'ready' };
  }

  public noteUsage(provider: IntelProvider, outcome: 'OK' | 'RATE_LIMITED' | 'ERROR', detail?: string): void {
    const entry = this.keys.get(provider);
    if (!entry) return;
    const r = entry.record;
    r.usedThisWindow++;

    if (outcome === 'RATE_LIMITED') {
      // Back off rather than hammering a provider that just throttled us; the
      // fallback tier keeps intelligence flowing meanwhile.
      r.cooldownUntil = Date.now() + COOLDOWN_MS;
      r.healthy = false;
      r.lastError = 'rate limited; cooling down ' + (COOLDOWN_MS / 60000) + ' minutes';
    } else if (outcome === 'ERROR') {
      r.healthy = false;
      r.lastError = (detail ?? 'error').slice(0, 160);
    } else {
      r.healthy = true;
      r.lastError = null;
    }
  }

  // -------------------------------------------------------------------
  // DNSBL: credential-free external reputation
  // -------------------------------------------------------------------

  /**
   * Real DNSBL query.
   *
   * A blocklist is queried by reversing the octets and prefixing the zone:
   * 203.0.113.5 becomes 5.113.0.203.zen.spamhaus.org. An A record means
   * listed, and the returned 127.0.0.x address encodes WHY. NXDOMAIN means
   * not listed, which is a successful answer rather than a failure.
   */
  public async queryDnsbl(ip: string, zone: string, meanings: Record<string, string>): Promise<DnsblVerdict> {
    const started = Date.now();
    if (!net.isIPv4(ip)) {
      return { zone, listed: false, codes: [], meaning: null, latencyMs: 0, error: 'DNSBL supports IPv4 only' };
    }

    const query = ip.split('.').reverse().join('.') + '.' + zone;
    try {
      const codes = await Promise.race([
        resolver.resolve4(query),
        new Promise<string[]>((_, rej) => setTimeout(() => rej(new Error('timeout')), DNSBL_TIMEOUT_MS))
      ]);
      const meaning = codes.map(c => meanings[c]).filter(Boolean).join('; ') || null;
      return { zone, listed: codes.length > 0, codes, meaning, latencyMs: Date.now() - started, error: null };
    } catch (err: any) {
      const code = err?.code ?? err?.message ?? 'unknown';
      // NXDOMAIN is the normal "not listed" answer, not an error condition.
      if (code === 'ENOTFOUND' || code === 'ENODATA') {
        return { zone, listed: false, codes: [], meaning: null, latencyMs: Date.now() - started, error: null };
      }
      return { zone, listed: false, codes: [], meaning: null, latencyMs: Date.now() - started, error: String(code) };
    }
  }

  /** Queries every configured blocklist concurrently. */
  public async queryAllDnsbl(ip: string): Promise<DnsblVerdict[]> {
    const cached = this.dnsblCache.get(ip);
    if (cached && cached.expiresAt > Date.now()) return cached.verdicts;

    const verdicts = await Promise.all(
      DNSBL_ZONES.map(z => this.queryDnsbl(ip, z.zone, z.meanings))
    );
    this.dnsblCache.set(ip, { verdicts, expiresAt: Date.now() + 30 * 60_000 });
    while (this.dnsblCache.size > 3000) {
      const oldest = this.dnsblCache.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.dnsblCache.delete(oldest);
    }
    return verdicts;
  }

  // -------------------------------------------------------------------
  // Tiered resolution
  // -------------------------------------------------------------------

  /**
   * Resolves reputation through the best tier available, never returning
   * nothing.
   *
   * Order: a usable primary API first, then credential-free DNSBL plus the
   * Tor directory, then local-only. The tier that actually answered is always
   * reported, so a degraded answer can never be mistaken for a confirmed one.
   */
  public async resolve(ip: string): Promise<ResolvedIntel> {
    const started = Date.now();
    this.totalResolutions++;
    const clean = String(ip ?? '').trim();
    const provenance: string[] = [];

    const priv = /^(10\.|127\.|192\.168\.|169\.254\.)/.test(clean) || /^172\.(1[6-9]|2\d|3[01])\./.test(clean);
    if (priv) {
      this.totalLocalOnly++;
      return {
        ip: clean, tier: 'LOCAL_ONLY', riskScore: 0, listedOn: [], dnsbl: [],
        isTorExit: null, abuseConfidence: null, reverseDns: null,
        provenance: ['private address space: never sent to any third party'],
        degraded: false, latencyMs: Date.now() - started
      };
    }

    // --- Tier 1: primary commercial API ---------------------------
    const abuse = this.isUsable('ABUSEIPDB');
    let abuseConfidence: number | null = null;
    let tier: ResolutionTier = 'DNSBL';

    if (abuse.usable) {
      const live = await globalLiveThreatIntel.enrich(clean);
      const src = live.sources.find(s => s.source === 'ABUSEIPDB_V2');
      if (src?.status === 'OK' && typeof live.abuseConfidenceScore === 'number') {
        abuseConfidence = live.abuseConfidenceScore;
        tier = 'PRIMARY_API';
        this.totalPrimaryApi++;
        this.noteUsage('ABUSEIPDB', 'OK');
        provenance.push('AbuseIPDB v2 answered: confidence ' + abuseConfidence + '/100');
      } else {
        const rateLimited = (src?.detail ?? '').includes('429') || (src?.detail ?? '').includes('rate limited');
        this.noteUsage('ABUSEIPDB', rateLimited ? 'RATE_LIMITED' : 'ERROR', src?.detail ?? undefined);
        provenance.push('AbuseIPDB unavailable (' + (src?.status ?? 'unknown') + '); falling through to credential-free sources');
      }
    } else {
      provenance.push('AbuseIPDB skipped: ' + abuse.reason);
    }

    // --- Tier 2: credential-free external reputation ---------------
    const [dnsbl, torSet, ptr] = await Promise.all([
      this.queryAllDnsbl(clean),
      globalLiveThreatIntel.loadTorExitNodes().catch(() => null),
      resolver.reverse(clean).catch(() => null)
    ]);

    const listedOn = dnsbl.filter(d => d.listed).map(d => d.zone + (d.meaning ? ' (' + d.meaning + ')' : ''));
    if (dnsbl.some(d => d.error === null)) {
      provenance.push('DNSBL queried ' + dnsbl.length + ' zones; listed on ' + listedOn.length);
      if (tier !== 'PRIMARY_API') this.totalDnsblFallback++;
    }

    const isTorExit = torSet ? torSet.has(clean) : null;
    if (torSet) provenance.push('Tor exit directory checked (' + torSet.size + ' nodes)');
    if (ptr) provenance.push('reverse DNS: ' + ptr[0]);

    // --- Composite ---------------------------------------------------
    let riskScore = 0;
    if (typeof abuseConfidence === 'number') riskScore = Math.max(riskScore, abuseConfidence);
    // Each independent blocklist listing is strong, corroborating evidence.
    if (listedOn.length > 0) riskScore = Math.max(riskScore, Math.min(95, 55 + listedOn.length * 20));
    if (isTorExit) riskScore = Math.max(riskScore, 70);
    if (!ptr) riskScore = Math.max(riskScore, 15);

    const degraded = tier !== 'PRIMARY_API';
    if (tier !== 'PRIMARY_API' && listedOn.length === 0 && isTorExit === null) {
      tier = 'LOCAL_ONLY';
      this.totalLocalOnly++;
    } else if (tier !== 'PRIMARY_API') {
      tier = isTorExit !== null || listedOn.length > 0 ? 'DNSBL' : 'TOR_DIRECTORY';
    }

    return {
      ip: clean, tier,
      riskScore: Math.max(0, Math.min(100, Math.round(riskScore))),
      listedOn, dnsbl, isTorExit, abuseConfidence,
      reverseDns: ptr,
      provenance, degraded,
      latencyMs: Date.now() - started
    };
  }

  // -------------------------------------------------------------------
  // Status
  // -------------------------------------------------------------------

  /** Key metadata only. The key values are never exposed by any API. */
  public getKeyRecords(): KeyRecord[] {
    return Array.from(this.keys.values()).map(e => ({ ...e.record }));
  }

  public getStatus() {
    const providers: Record<string, unknown> = {};
    for (const p of ['ABUSEIPDB', 'VIRUSTOTAL', 'OTX', 'GREYNOISE'] as IntelProvider[]) {
      const usable = this.isUsable(p);
      const rec = this.keys.get(p)?.record;
      providers[p] = {
        keyInstalled: Boolean(rec),
        fingerprint: rec?.fingerprint ?? null,
        lastFour: rec?.lastFour ?? null,
        usable: usable.usable,
        reason: usable.reason,
        usedThisWindow: rec?.usedThisWindow ?? 0,
        quotaLimit: rec?.quotaLimit ?? null,
        healthy: rec?.healthy ?? null,
        lastError: rec?.lastError ?? null
      };
    }

    return {
      providers,
      fallback: {
        dnsblZones: DNSBL_ZONES.map(z => z.zone),
        torDirectorySynced: globalLiveThreatIntel.getStats().torDirectory.nodeCount,
        neverDegradesToNothing: true
      },
      counters: {
        totalResolutions: this.totalResolutions,
        totalPrimaryApi: this.totalPrimaryApi,
        totalDnsblFallback: this.totalDnsblFallback,
        totalLocalOnly: this.totalLocalOnly
      },
      dnsblCacheEntries: this.dnsblCache.size,
      keyValuesExposedByApi: false
    };
  }

  public clearCache(): void { this.dnsblCache.clear(); }
}

export const globalThreatIntelKeyManager = new ThreatIntelKeyManager();
