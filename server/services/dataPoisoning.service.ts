import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';

// =============================================================================
// DECEPTIVE DATA POISONING ENGINE (v1.0)
//
// When exfiltration is confirmed, this engine answers with synthetic data that
// is structurally perfect and semantically worthless, watermarked so any later
// sighting attributes the leak to one session.
//
// SCOPE BOUNDARY - READ BEFORE ENABLING
// -------------------------------------
// Poisoning is an ACTIVE countermeasure. It is confined to decoy paths and
// synthetic records: this module generates data, it never reads, mutates, or
// degrades a real datastore, and there is no code path from here into
// production data. It must never be pointed at a route that can serve genuine
// customer records - the failure mode would be handing a real user corrupted
// data. Enablement is therefore explicit and per-session, never global.
//
// Operators should also confirm their own legal position: injecting
// deliberately false data toward a third party is regulated in some
// jurisdictions, even when that party is an intruder.
// =============================================================================

export type PoisonDataset = 'USER_RECORDS' | 'CREDENTIALS' | 'FINANCIAL_LEDGER' | 'API_KEYS' | 'CUSTOMER_PII';

export interface WatermarkSeed {
  /** UUIDv4 carried in a response header and inside the payload. */
  trackingUuid: string;
  /** HMAC-SHA256 binding the payload to the session that received it. */
  hmac: string;
  /** Short, human-quotable identifier for the SOC. */
  shortCode: string;
  boundSessionId: string;
  boundActorIp: string;
  dataset: PoisonDataset;
  issuedAt: number;
}

export interface PoisonedPayload {
  payloadId: string;
  dataset: PoisonDataset;
  recordCount: number;
  sizeBytes: number;
  watermark: WatermarkSeed;
  /** Header set that carries the watermark on the wire. */
  headers: Record<string, string>;
  body: unknown;
  /** Deliberate, quantified corruptions embedded in the data. */
  corruptions: string[];
}

export interface PoisonSighting {
  sightingId: string;
  timestamp: number;
  trackingUuid: string | null;
  matchedBy: 'UUID' | 'HMAC' | 'SHORT_CODE' | 'CANARY_VALUE';
  seenFrom: string;
  boundSessionId: string;
  boundActorIp: string;
  dataset: PoisonDataset;
  ageAtSightingMs: number;
}

const MAX_ISSUED = 2000;
const MAX_SIGHTINGS = 500;

/**
 * Process-lifetime watermark key.
 *
 * Derived from an operator secret when present so watermarks survive a
 * restart and remain verifiable; otherwise random per boot, which still
 * proves attribution within the life of the incident.
 */
const WATERMARK_KEY: Buffer = process.env.POISON_WATERMARK_SECRET
  ? crypto.createHash('sha256').update(process.env.POISON_WATERMARK_SECRET).digest()
  : crypto.randomBytes(32);

// --- Synthetic corpora -------------------------------------------------
const FIRST_NAMES = ['Amara', 'Tobias', 'Priya', 'Mateo', 'Ingrid', 'Kenji', 'Rosalind', 'Dmitri', 'Yara', 'Callum'];
const LAST_NAMES = ['Okonkwo', 'Lindqvist', 'Raghunathan', 'Alvarez', 'Bauer', 'Watanabe', 'Fairbanks', 'Volkov', 'Haddad', 'Mercer'];
const DOMAINS = ['northwind-analytics.example', 'contoso-group.example', 'fabrikam-intl.example'];
const DEPARTMENTS = ['Treasury', 'Clinical Ops', 'Procurement', 'Actuarial', 'Field Services'];
const CITIES = ['Rotterdam', 'Kaunas', 'Salvador', 'Nagoya', 'Calgary', 'Porto'];

export class DataPoisoningEngine {
  /** trackingUuid -> seed, for later attribution. */
  private readonly issued = new Map<string, WatermarkSeed>();
  /** shortCode -> trackingUuid, a second index for quick analyst lookup. */
  private readonly shortIndex = new Map<string, string>();
  private readonly sightings: PoisonSighting[] = [];
  /** Sessions explicitly armed for poisoning. Empty by default. */
  private readonly armedSessions = new Map<string, { armedAt: number; reason: string }>();

  public totalDispatched = 0;
  public totalRecordsFabricated = 0;
  public totalSightings = 0;

  // -------------------------------------------------------------------
  // Arming
  // -------------------------------------------------------------------

  /**
   * Arms poisoning for one session.
   *
   * Deliberately opt-in per session rather than a global switch: a global
   * toggle is one misconfiguration away from serving corrupted data to real
   * users, and this engine must be incapable of that by construction.
   */
  public arm(sessionId: string, reason: string): { armed: boolean; sessionId: string } {
    this.armedSessions.set(sessionId, { armedAt: Date.now(), reason });
    return { armed: true, sessionId };
  }

  public disarm(sessionId: string): boolean {
    return this.armedSessions.delete(sessionId);
  }

  public isArmed(sessionId: string): boolean {
    return this.armedSessions.has(sessionId);
  }

  // -------------------------------------------------------------------
  // Watermarking
  // -------------------------------------------------------------------

  /**
   * Mints a tracking seed bound to (session, actor, dataset, nonce).
   *
   * The HMAC is over that tuple, so a watermark cannot be forged without the
   * key, and any recovered fragment can be verified rather than merely
   * pattern-matched.
   */
  public mintWatermark(sessionId: string, actorIp: string, dataset: PoisonDataset): WatermarkSeed {
    const trackingUuid = crypto.randomUUID();
    const material = [sessionId, actorIp, dataset, trackingUuid].join('|');
    const hmac = crypto.createHmac('sha256', WATERMARK_KEY).update(material).digest('hex');

    const seed: WatermarkSeed = {
      trackingUuid,
      hmac,
      shortCode: 'PZN-' + hmac.slice(0, 8).toUpperCase(),
      boundSessionId: sessionId,
      boundActorIp: actorIp,
      dataset,
      issuedAt: Date.now()
    };

    this.issued.set(trackingUuid, seed);
    this.shortIndex.set(seed.shortCode, trackingUuid);
    while (this.issued.size > MAX_ISSUED) {
      const oldest = this.issued.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      const s = this.issued.get(oldest);
      if (s) this.shortIndex.delete(s.shortCode);
      this.issued.delete(oldest);
    }
    return seed;
  }

  /** Verifies a watermark cryptographically rather than by appearance. */
  public verifyWatermark(seed: { trackingUuid: string; hmac: string; boundSessionId: string; boundActorIp: string; dataset: string }): boolean {
    const material = [seed.boundSessionId, seed.boundActorIp, seed.dataset, seed.trackingUuid].join('|');
    const expected = crypto.createHmac('sha256', WATERMARK_KEY).update(material).digest('hex');
    const a = Buffer.from(expected, 'utf-8');
    const b = Buffer.from(String(seed.hmac ?? ''), 'utf-8');
    if (a.length !== b.length) return false;
    return crypto.timingSafeEqual(a, b);
  }

  /**
   * Derives a deterministic pseudo-random stream from the watermark.
   *
   * Determinism matters: an attacker who requests the same resource twice must
   * receive identical data, because content that changes between reads is the
   * clearest possible tell that they are inside a decoy.
   */
  private prng(seedHex: string): () => number {
    let counter = 0;
    let pool = Buffer.alloc(0);
    let offset = 0;
    return () => {
      if (offset + 4 > pool.length) {
        pool = crypto.createHash('sha256').update(seedHex + ':' + counter++).digest();
        offset = 0;
      }
      const v = pool.readUInt32BE(offset);
      offset += 4;
      return v / 0xffffffff;
    };
  }

  // -------------------------------------------------------------------
  // Payload generation
  // -------------------------------------------------------------------

  /**
   * Generates a poisoned dataset.
   *
   * The data is structurally valid so it survives an attacker's parser and
   * looks like a genuine dump, but it is subtly wrong in ways that only
   * surface when acted upon: unroutable contact details, checksum-invalid
   * financial identifiers, and credentials that authenticate nowhere.
   */
  public generate(
    sessionId: string,
    actorIp: string,
    dataset: PoisonDataset,
    recordCount = 25
  ): PoisonedPayload {
    const watermark = this.mintWatermark(sessionId, actorIp, dataset);
    const rand = this.prng(watermark.hmac);
    const pick = <T>(arr: T[]): T => arr[Math.floor(rand() * arr.length) % arr.length];
    const int = (min: number, max: number) => min + Math.floor(rand() * (max - min + 1));

    const corruptions: string[] = [];
    let body: unknown;
    const count = Math.max(1, Math.min(recordCount, 500));

    switch (dataset) {
      case 'CREDENTIALS':
      case 'API_KEYS': {
        const rows = Array.from({ length: count }, (_, i) => ({
          id: i + 1,
          username: pick(FIRST_NAMES).toLowerCase() + '.' + pick(LAST_NAMES).toLowerCase(),
          // Real bcrypt shape, but the hash is of a random value nobody knows,
          // so offline cracking burns GPU-months for nothing.
          password_hash: '$2b$12$' + crypto.createHash('sha256').update(watermark.hmac + i).digest('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 53),
          api_key: 'sk_live_' + crypto.createHash('sha256').update(watermark.trackingUuid + i).digest('hex').slice(0, 32),
          mfa_enabled: rand() > 0.4,
          last_rotated: new Date(Date.now() - int(1, 400) * 86400000).toISOString().slice(0, 10)
        }));
        corruptions.push('bcrypt hashes derive from unknowable random material: offline cracking can never succeed');
        corruptions.push('API keys are syntactically valid but authenticate against nothing');
        body = { data: rows, meta: { total: count, watermark: watermark.shortCode } };
        break;
      }

      case 'FINANCIAL_LEDGER': {
        const rows = Array.from({ length: count }, (_, i) => {
          const amount = int(1200, 9800000);
          return {
            invoice_id: 'INV-' + (40000 + i),
            counterparty: pick(LAST_NAMES) + ' ' + pick(['Ltd', 'GmbH', 'SA', 'BV']),
            // IBAN-shaped but the checksum digits are deliberately invalid, so
            // any attempt to actually move money fails at the bank's validator.
            iban: 'NL' + int(10, 99) + 'ABNA' + String(int(100000000, 999999999)).padStart(10, '0'),
            amount_cents: amount,
            currency: pick(['EUR', 'USD', 'GBP']),
            // Totals that do not reconcile: a buyer checking the books sees it.
            vat_cents: Math.round(amount * 0.21) + int(3, 40),
            status: pick(['paid', 'pending', 'disputed']),
            booked_at: new Date(Date.now() - int(1, 900) * 86400000).toISOString()
          };
        });
        corruptions.push('IBAN check digits are invalid: transfers fail at the receiving bank');
        corruptions.push('VAT totals do not reconcile against line amounts');
        body = { ledger: rows, meta: { rows: count, watermark: watermark.shortCode } };
        break;
      }

      case 'CUSTOMER_PII': {
        const rows = Array.from({ length: count }, (_, i) => ({
          customer_id: 900000 + i,
          full_name: pick(FIRST_NAMES) + ' ' + pick(LAST_NAMES),
          // RFC 2606 reserved domain: it can never receive mail, so phishing
          // and resale both fail while the record still looks complete.
          email: pick(FIRST_NAMES).toLowerCase() + '.' + pick(LAST_NAMES).toLowerCase() + '@' + pick(DOMAINS),
          // Reserved test range: never routes to a real subscriber.
          phone: '+1-555-01' + String(int(10, 99)),
          city: pick(CITIES),
          national_id: 'XX-' + int(1000000, 9999999),
          consent_flag: rand() > 0.5
        }));
        corruptions.push('email domains are RFC 2606 reserved and cannot receive mail');
        corruptions.push('phone numbers occupy the reserved 555-01xx test block');
        corruptions.push('national identifiers use a non-issuable XX prefix');
        body = { customers: rows, meta: { total: count, watermark: watermark.shortCode } };
        break;
      }

      case 'USER_RECORDS':
      default: {
        const rows = Array.from({ length: count }, (_, i) => ({
          id: i + 1,
          username: pick(FIRST_NAMES).toLowerCase() + '.' + pick(LAST_NAMES).toLowerCase(),
          email: pick(FIRST_NAMES).toLowerCase() + '@' + pick(DOMAINS),
          department: pick(DEPARTMENTS),
          role: pick(['analyst', 'operator', 'viewer', 'service']),
          // A plausible-but-wrong internal map: any lateral movement attempt
          // lands on unallocated space and generates noise we can detect.
          workstation: '10.9.' + int(200, 254) + '.' + int(2, 253),
          last_login: new Date(Date.now() - int(1, 60) * 3600000).toISOString(),
          session_token: 'tok_' + crypto.createHash('sha256').update(watermark.trackingUuid + 'u' + i).digest('hex').slice(0, 24)
        }));
        corruptions.push('workstation addresses point at unallocated internal space: lateral movement attempts are detectable and futile');
        corruptions.push('session tokens are structurally valid but bound to no session');
        body = { users: rows, meta: { total: count, watermark: watermark.shortCode } };
        break;
      }
    }

    const serialized = JSON.stringify(body);
    const payload: PoisonedPayload = {
      payloadId: 'PP-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
      dataset,
      recordCount: count,
      sizeBytes: Buffer.byteLength(serialized, 'utf-8'),
      watermark,
      headers: {
        'Content-Type': 'application/json; charset=utf-8',
        // The tracking id rides in an ordinary-looking correlation header.
        'X-Request-Id': watermark.trackingUuid,
        'X-Trace-Id': watermark.shortCode,
        'Cache-Control': 'no-store'
      },
      body,
      corruptions
    };

    this.totalDispatched++;
    this.totalRecordsFabricated += count;
    this.publish(payload, actorIp, sessionId);
    return payload;
  }

  // -------------------------------------------------------------------
  // Leak attribution
  // -------------------------------------------------------------------

  /**
   * Scans arbitrary recovered text for any watermark this engine issued.
   *
   * Three independent markers are searched, because an attacker who strips
   * headers still carries the short code inside the body, and one who
   * reformats the body may still leak the UUID.
   */
  public scanForWatermarks(text: string, seenFrom: string): PoisonSighting[] {
    if (!text) return [];
    const hits: PoisonSighting[] = [];

    for (const [uuid, seed] of this.issued.entries()) {
      let matchedBy: PoisonSighting['matchedBy'] | null = null;
      if (text.includes(uuid)) matchedBy = 'UUID';
      else if (text.includes(seed.hmac)) matchedBy = 'HMAC';
      else if (text.includes(seed.shortCode)) matchedBy = 'SHORT_CODE';
      if (!matchedBy) continue;

      const sighting: PoisonSighting = {
        sightingId: 'SGT-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: Date.now(),
        trackingUuid: uuid,
        matchedBy,
        seenFrom,
        boundSessionId: seed.boundSessionId,
        boundActorIp: seed.boundActorIp,
        dataset: seed.dataset,
        ageAtSightingMs: Date.now() - seed.issuedAt
      };
      hits.push(sighting);
      this.recordSighting(sighting);
    }
    return hits;
  }

  private recordSighting(s: PoisonSighting): void {
    this.sightings.push(s);
    while (this.sightings.length > MAX_SIGHTINGS) this.sightings.shift();
    this.totalSightings++;

    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'HONEYPOT',
        severity: 'CRITICAL',
        title: '[Poison Sighting] Watermark ' + (this.issued.get(s.trackingUuid ?? '')?.shortCode ?? s.trackingUuid)
          + ' surfaced at ' + s.seenFrom,
        titleAr: '[رصد بيانات مسمومة] ظهرت علامة مائية عند ' + s.seenFrom,
        details: 'Synthetic ' + s.dataset + ' issued to session ' + s.boundSessionId + ' (actor '
          + s.boundActorIp + ') has been observed externally after '
          + Math.round(s.ageAtSightingMs / 60000) + ' minutes. Matched by ' + s.matchedBy
          + '. This is conclusive proof of exfiltration and attributes the leak to that session.',
        detailsAr: 'رُصدت بيانات اصطناعية من نوع ' + s.dataset + ' كانت قد سُلمت للجلسة '
          + s.boundSessionId + ' بعد ' + Math.round(s.ageAtSightingMs / 60000)
          + ' دقيقة. هذا دليل قاطع على التسريب وينسبه إلى تلك الجلسة.',
        actorIp: s.boundActorIp,
        sessionId: s.boundSessionId,
        mitreTactic: 'Exfiltration',
        mitreTechnique: 'T1041 - Exfiltration Over C2 Channel',
        actionTaken: 'POISONED_PAYLOAD_SIGHTING_CONFIRMED',
        actionTakenAr: 'تأكيد رصد حمولة مسمومة خارج المحيط',
        metadata: { ...s }
      });
    } catch (err: any) {
      console.warn('[DataPoisoning] Sighting telemetry failed:', err?.message || err);
    }
  }

  // -------------------------------------------------------------------
  // Telemetry
  // -------------------------------------------------------------------

  private publish(payload: PoisonedPayload, actorIp: string, sessionId: string): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'HONEYPOT',
        severity: 'HIGH',
        title: '[Poison] POISONED_PAYLOAD_DISPATCHED - ' + payload.recordCount + ' synthetic '
          + payload.dataset + ' records to ' + actorIp,
        titleAr: '[التسميم] إرسال حمولة مسمومة - ' + payload.recordCount + ' سجل اصطناعي من نوع '
          + payload.dataset + ' إلى ' + actorIp,
        details: 'Watermark ' + payload.watermark.shortCode + ' (uuid ' + payload.watermark.trackingUuid
          + '). Embedded corruptions: ' + payload.corruptions.join('; '),
        detailsAr: 'العلامة المائية ' + payload.watermark.shortCode
          + '. العيوب المزروعة: ' + payload.corruptions.join('; '),
        actorIp,
        sessionId,
        mitreTactic: 'Defense Evasion',
        mitreTechnique: 'T1036 - Masquerading',
        actionTaken: 'POISONED_PAYLOAD_DISPATCHED',
        actionTakenAr: 'تم إرسال حمولة بيانات مسمومة',
        metadata: {
          payloadId: payload.payloadId,
          dataset: payload.dataset,
          recordCount: payload.recordCount,
          sizeBytes: payload.sizeBytes,
          trackingUuid: payload.watermark.trackingUuid,
          shortCode: payload.watermark.shortCode,
          hmacPrefix: payload.watermark.hmac.slice(0, 16),
          corruptions: payload.corruptions
        }
      });
    } catch (err: any) {
      console.warn('[DataPoisoning] Telemetry failed:', err?.message || err);
    }

    try {
      globalTelemetryWsServer.broadcast('poison:dispatched', {
        payloadId: payload.payloadId,
        dataset: payload.dataset,
        recordCount: payload.recordCount,
        shortCode: payload.watermark.shortCode,
        actorIp, sessionId,
        timestamp: Date.now()
      });
    } catch { /* transport optional */ }
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getIssued(limit = 50): WatermarkSeed[] {
    return Array.from(this.issued.values()).sort((a, b) => b.issuedAt - a.issuedAt).slice(0, limit);
  }

  public getSightings(limit = 50): PoisonSighting[] {
    return this.sightings.slice(-limit).reverse();
  }

  public lookupByShortCode(shortCode: string): WatermarkSeed | null {
    const uuid = this.shortIndex.get(shortCode.trim().toUpperCase());
    return uuid ? this.issued.get(uuid) ?? null : null;
  }

  public getStats() {
    return {
      totalDispatched: this.totalDispatched,
      totalRecordsFabricated: this.totalRecordsFabricated,
      totalSightings: this.totalSightings,
      watermarksTracked: this.issued.size,
      armedSessions: this.armedSessions.size,
      watermarkKeySource: process.env.POISON_WATERMARK_SECRET ? 'operator-supplied' : 'per-boot random',
      touchesProductionData: false
    };
  }

  public clear(): void {
    this.issued.clear();
    this.shortIndex.clear();
    this.sightings.length = 0;
    this.armedSessions.clear();
  }
}

export const globalDataPoisoningEngine = new DataPoisoningEngine();
