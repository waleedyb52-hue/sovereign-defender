import { globalThreatMemory, type RetrievedContext, type StoredIncident } from './threatMemory.service.js';

/**
 * ITERATIVE RETRIEVE-AND-REASON (Phase 4) AND ACTOR INVESTIGATION (Phase 5)
 *
 * Phase 4 — why iterate at all
 *   Single-shot retrieval asks one question and takes whatever comes back. The
 *   CyberRAG result (Future Generation Computer Systems, 2025) is that iterating —
 *   retrieve, judge whether the evidence answers the question, refine, retrieve
 *   again — beats it, and the mechanism is easy to see: the first query is built
 *   from what the *packet* contained, while the useful query is built from what the
 *   first retrieval *revealed*. An actor IP alone finds nothing; the technique that
 *   actor used last week finds the playbook.
 *
 *   The failure mode iteration introduces is unbounded cost, so every loop here is
 *   capped and the cost is reported. An iterative retriever that cannot state its
 *   own budget is a latency incident waiting to happen.
 *
 * Phase 5 — why the pivot is a first-class operation
 *   The acceptance criterion is that an analyst can answer "what else did this actor
 *   touch" without writing SQL. That sentence is the entire job of a SOC console and
 *   it is usually answered by exporting to a spreadsheet. `investigateActor` walks
 *   the corpus from an indicator outward — incidents, then the techniques in those
 *   incidents, then other actors sharing those techniques — and returns the trail
 *   with the hop count, so a result three hops away is not presented with the same
 *   confidence as a direct hit.
 *
 * On honesty in both
 *   Neither invents a relationship. Where the corpus holds nothing, the response
 *   says the corpus is empty rather than returning a plausible-looking graph. The
 *   confidence attached to each finding is derived from hop distance and corroborating
 *   count, never assigned.
 */

/** Hard ceiling on retrieval rounds. Phase 4's criterion requires a bounded cost. */
export const MAX_ROUNDS = 3;
/**
 * Evidence items above which further rounds are unlikely to add anything.
 *
 * Raised from 6 after measurement: against a 44,000-incident corpus round 1
 * routinely returns 11 items, so the loop terminated immediately and the
 * iteration never engaged. That is itself the finding — iteration earns its cost
 * when the corpus is sparse or the packet uninformative, not universally.
 */
export const SUFFICIENCY_THRESHOLD = 14;

/**
 * A LIMIT ON WHAT PHASE 4 CAN CLAIM HERE
 *
 * The plan's acceptance criterion is a measurable false-positive reduction versus
 * single-shot retrieval. That cannot be measured in the sovereign configuration,
 * and the reason is structural rather than a gap in this file:
 *
 *   Retrieved context reaches only the external model's prompt
 *   (`contextMemory` in server.ts). The sovereign detection path is
 *   `classifyPayload()` alone, and it never consults the corpus. So with no
 *   external model configured — the default, and the configuration the product is
 *   sold on — retrieval quality cannot move the false-positive rate, because
 *   retrieval does not participate in the verdict.
 *
 * Making it participate is a real change to the detection path: corpus evidence
 * would have to adjust a borderline score, which risks blocking everything from an
 * address that once did something bad. That deserves its own measured pass against
 * Set B rather than being appended to this one, so the machinery here is built and
 * bounded, and the criterion is recorded as unmet.
 */

export interface RetrievalRound {
  round: number;
  /** What was asked this round, and why — the refinement is the interesting part. */
  query: { actorIp?: string; mitreTechnique?: string; vector?: string; text?: string };
  rationale: string;
  newIncidents: number;
  newTechniques: number;
  cumulativeEvidence: number;
  elapsedMs: number;
}

export interface IterativeRetrievalResult {
  rounds: RetrievalRound[];
  /** Deduplicated union of everything retrieved. */
  incidents: StoredIncident[];
  techniques: Array<{ id: string; name?: string; source: 'PACKET' | 'DISCOVERED' }>;
  iocHit: unknown | null;
  stoppedBecause: 'SUFFICIENT' | 'NO_NEW_EVIDENCE' | 'ROUND_LIMIT' | 'EMPTY_CORPUS';
  totalElapsedMs: number;
  /** Cost, stated so the bound can be checked rather than trusted. */
  cost: { rounds: number; maxRounds: number; corpusSize: number };
  /** Single-shot equivalent, for the comparison Phase 4's criterion requires. */
  singleShotEvidence: number;
  evidenceGain: number;
}

export interface ActorInvestigation {
  indicator: string;
  /** Empty is a valid answer and is reported as such. */
  corpusEmpty: boolean;
  directIncidents: StoredIncident[];
  /** Techniques this actor used, from its own incidents. */
  techniquesUsed: Array<{ id: string; incidentCount: number }>;
  /** Other actors seen using the same techniques. Hop 2. */
  relatedActors: Array<{ ip: string; sharedTechniques: string[]; incidentCount: number; hops: 2 }>;
  /** Assets or targets named in this actor's incidents. */
  touchedTargets: Array<{ target: string; occurrences: number }>;
  iocRecord: unknown | null;
  timeline: Array<{ at: string; title: string; technique: string | null; action: string | null }>;
  /** Derived from corroborating count and hop distance. Never assigned by hand. */
  confidence: { level: 'HIGH' | 'MEDIUM' | 'LOW' | 'NONE'; basis: string };
  queryElapsedMs: number;
}

function countEvidence(ctx: RetrievedContext): number {
  return (
    ctx.sameActor.length +
    ctx.sameTechnique.length +
    ctx.similar.length +
    (ctx.iocHit ? 1 : 0) +
    (ctx.technique ? 1 : 0)
  );
}

export class IterativeRetrievalService {
  /**
   * Retrieve iteratively, refining the query from what each round reveals.
   *
   * Round 1 asks what the packet allows. Round 2 asks about techniques discovered
   * in round 1 — the refinement that single-shot cannot make, because those
   * techniques were not known when the first query was built. Round 3 follows text
   * similarity from the strongest incident found so far.
   */
  retrieve(seed: { actorIp?: string; vector?: string; mitreTechnique?: string; payload?: string }): IterativeRetrievalResult {
    const t0 = Date.now();
    const rounds: RetrievalRound[] = [];
    const incidents = new Map<string, StoredIncident>();
    const techniques = new Map<string, { id: string; name?: string; source: 'PACKET' | 'DISCOVERED' }>();
    let iocHit: unknown | null = null;

    const corpusSize = globalThreatMemory.count();
    if (corpusSize === 0) {
      return {
        rounds: [],
        incidents: [],
        techniques: [],
        iocHit: null,
        stoppedBecause: 'EMPTY_CORPUS',
        totalElapsedMs: Date.now() - t0,
        cost: { rounds: 0, maxRounds: MAX_ROUNDS, corpusSize: 0 },
        singleShotEvidence: 0,
        evidenceGain: 0
      };
    }

    // Round 1 — everything the packet itself supports. This is also the
    // single-shot baseline, captured for the comparison.
    const r1Start = Date.now();
    const ctx1 = globalThreatMemory.retrieve({
      actorIp: seed.actorIp,
      vector: seed.vector,
      mitreTechnique: seed.mitreTechnique,
      payload: seed.payload
    });
    const singleShotEvidence = countEvidence(ctx1);

    for (const inc of [...ctx1.sameActor, ...ctx1.sameTechnique, ...ctx1.similar]) {
      if (inc?.id) incidents.set(inc.id, inc);
    }
    if (ctx1.iocHit) iocHit = ctx1.iocHit;
    if (seed.mitreTechnique) {
      techniques.set(seed.mitreTechnique, { id: seed.mitreTechnique, source: 'PACKET' });
    }
    if (ctx1.technique?.id) {
      techniques.set(String(ctx1.technique.id), {
        id: String(ctx1.technique.id),
        name: (ctx1.technique as any)?.name,
        source: 'PACKET'
      });
    }

    rounds.push({
      round: 1,
      query: { actorIp: seed.actorIp, mitreTechnique: seed.mitreTechnique, vector: seed.vector },
      rationale: 'What the packet itself supports: this actor, this technique, text similar to this payload.',
      newIncidents: incidents.size,
      newTechniques: techniques.size,
      cumulativeEvidence: incidents.size + techniques.size + (iocHit ? 1 : 0),
      elapsedMs: Date.now() - r1Start
    });

    let stopped: IterativeRetrievalResult['stoppedBecause'] = 'ROUND_LIMIT';

    for (let round = 2; round <= MAX_ROUNDS; round++) {
      const before = incidents.size + techniques.size;
      if (before >= SUFFICIENCY_THRESHOLD) {
        stopped = 'SUFFICIENT';
        break;
      }

      const rStart = Date.now();
      let rationale = '';
      const query: RetrievalRound['query'] = {};

      if (round === 2) {
        // The refinement single-shot cannot make: techniques found in the
        // retrieved incidents were not known when the first query was built.
        const discovered = [...incidents.values()]
          .map(i => (i as any).mitreTechnique ?? (i as any).mitre_technique)
          .filter((t): t is string => typeof t === 'string' && t.length > 0)
          .filter(t => !techniques.has(t));

        if (discovered.length === 0) {
          stopped = 'NO_NEW_EVIDENCE';
          break;
        }
        const pick = discovered[0];
        query.mitreTechnique = pick;
        rationale = `Round 1 surfaced technique ${pick} in a retrieved incident. It was not in the packet, so single-shot retrieval could not have asked for it.`;

        const ctx2 = globalThreatMemory.retrieve({ mitreTechnique: pick, limit: 8 });
        for (const inc of [...ctx2.sameTechnique, ...ctx2.similar]) {
          if (inc?.id) incidents.set(inc.id, inc);
        }
        techniques.set(pick, { id: pick, source: 'DISCOVERED' });
        if (ctx2.technique?.id) {
          techniques.set(String(ctx2.technique.id), {
            id: String(ctx2.technique.id),
            name: (ctx2.technique as any)?.name,
            source: 'DISCOVERED'
          });
        }
      } else {
        // Round 3 — follow text similarity from the richest incident found.
        const best = [...incidents.values()].sort(
          (a, b) => String((b as any).details ?? '').length - String((a as any).details ?? '').length
        )[0];
        const text = String((best as any)?.details ?? (best as any)?.title ?? '').slice(0, 160);
        if (!text) {
          stopped = 'NO_NEW_EVIDENCE';
          break;
        }
        query.text = text.slice(0, 60) + '…';
        rationale = 'Following textual similarity from the most detailed incident retrieved so far.';
        for (const inc of globalThreatMemory.textSearch(text, 6)) {
          if (inc?.id) incidents.set(inc.id, inc);
        }
      }

      const after = incidents.size + techniques.size;
      rounds.push({
        round,
        query,
        rationale,
        newIncidents: after - before,
        newTechniques: 0,
        cumulativeEvidence: after + (iocHit ? 1 : 0),
        elapsedMs: Date.now() - rStart
      });

      if (after === before) {
        stopped = 'NO_NEW_EVIDENCE';
        break;
      }
    }

    const totalEvidence = incidents.size + techniques.size + (iocHit ? 1 : 0);
    return {
      rounds,
      incidents: [...incidents.values()],
      techniques: [...techniques.values()],
      iocHit,
      stoppedBecause: stopped,
      totalElapsedMs: Date.now() - t0,
      cost: { rounds: rounds.length, maxRounds: MAX_ROUNDS, corpusSize },
      singleShotEvidence,
      evidenceGain: totalEvidence - singleShotEvidence
    };
  }

  /**
   * Phase 5's question, answered without SQL: what else did this actor touch?
   */
  investigateActor(indicator: string): ActorInvestigation {
    const t0 = Date.now();
    const corpusSize = globalThreatMemory.count();

    if (corpusSize === 0) {
      return {
        indicator,
        corpusEmpty: true,
        directIncidents: [],
        techniquesUsed: [],
        relatedActors: [],
        touchedTargets: [],
        iocRecord: null,
        timeline: [],
        confidence: { level: 'NONE', basis: 'The threat corpus holds no incidents, so nothing can be said about this actor.' },
        queryElapsedMs: Date.now() - t0
      };
    }

    const ctx = globalThreatMemory.retrieve({ actorIp: indicator, limit: 25 });
    const direct = ctx.sameActor;

    const techMap = new Map<string, number>();
    for (const inc of direct) {
      const t = (inc as any).mitreTechnique ?? (inc as any).mitre_technique;
      if (typeof t === 'string' && t) techMap.set(t, (techMap.get(t) ?? 0) + 1);
    }
    const techniquesUsed = [...techMap.entries()]
      .map(([id, incidentCount]) => ({ id, incidentCount }))
      .sort((a, b) => b.incidentCount - a.incidentCount);

    // Hop 2 — other actors seen using the same techniques.
    const actorMap = new Map<string, { shared: Set<string>; count: number }>();
    for (const { id } of techniquesUsed) {
      const peers = globalThreatMemory.retrieve({ mitreTechnique: id, limit: 25 });
      for (const inc of peers.sameTechnique) {
        const ip = String((inc as any).actorIp ?? (inc as any).actor_ip ?? '');
        if (!ip || ip === indicator) continue;
        const entry = actorMap.get(ip) ?? { shared: new Set<string>(), count: 0 };
        entry.shared.add(id);
        entry.count++;
        actorMap.set(ip, entry);
      }
    }
    const relatedActors = [...actorMap.entries()]
      .map(([ip, v]) => ({ ip, sharedTechniques: [...v.shared], incidentCount: v.count, hops: 2 as const }))
      .sort((a, b) => b.sharedTechniques.length - a.sharedTechniques.length)
      .slice(0, 12);

    // Targets named in this actor's incidents.
    const targetMap = new Map<string, number>();
    for (const inc of direct) {
      for (const key of ['targetAsset', 'target_asset', 'dstIp', 'dst_ip', 'assetId']) {
        const v = (inc as any)[key];
        if (typeof v === 'string' && v) targetMap.set(v, (targetMap.get(v) ?? 0) + 1);
      }
    }
    const touchedTargets = [...targetMap.entries()]
      .map(([target, occurrences]) => ({ target, occurrences }))
      .sort((a, b) => b.occurrences - a.occurrences);

    const timeline = direct
      .map(inc => ({
        at: String((inc as any).timestamp ?? (inc as any).occurredAt ?? ''),
        title: String((inc as any).title ?? ''),
        technique: ((inc as any).mitreTechnique ?? (inc as any).mitre_technique ?? null) as string | null,
        action: ((inc as any).actionTaken ?? (inc as any).action_taken ?? null) as string | null
      }))
      .filter(r => r.at)
      .sort((a, b) => a.at.localeCompare(b.at));

    // Confidence is derived from what was found, not asserted.
    const iocRecord = globalThreatMemory.lookupIoc(indicator);
    let level: ActorInvestigation['confidence']['level'];
    let basis: string;
    if (direct.length === 0 && !iocRecord) {
      level = 'NONE';
      basis = `No incident in a corpus of ${corpusSize} names this indicator, and it is not on the IOC list. Absence of evidence, not evidence of safety.`;
    } else if (direct.length >= 3 && iocRecord) {
      level = 'HIGH';
      basis = `${direct.length} incidents directly name this actor and it is a known IOC.`;
    } else if (direct.length >= 1) {
      level = 'MEDIUM';
      basis = `${direct.length} direct incident${direct.length > 1 ? 's' : ''}${iocRecord ? ' plus an IOC record' : ', no IOC record'}.`;
    } else {
      level = 'LOW';
      basis = 'IOC record only, with no incident in the corpus naming this actor.';
    }

    return {
      indicator,
      corpusEmpty: false,
      directIncidents: direct,
      techniquesUsed,
      relatedActors,
      touchedTargets,
      iocRecord,
      timeline,
      confidence: { level, basis },
      queryElapsedMs: Date.now() - t0
    };
  }
}

export const globalIterativeRetrieval = new IterativeRetrievalService();
