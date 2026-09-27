import { globalThreatMemory } from './threatMemory.service.js';
import { BLOCK_THRESHOLD, type ClassificationResult } from './payloadClassifier.service.js';

/**
 * CORPUS CORROBORATION — letting retrieved history move a borderline verdict
 *
 * Why this exists
 *   Phase 4's acceptance criterion is a measurable false-positive reduction versus
 *   single-shot retrieval. It could not be assessed at all, because retrieval only
 *   ever reached the external model's prompt: the sovereign detection path is
 *   `classifyPayload()` and it never consulted the corpus. With no external model
 *   configured — the default the product ships in — retrieval could not move any
 *   rate, because it took no part in the decision.
 *
 *   So this makes it take part, in the narrowest way that could possibly help.
 *
 * The four constraints, and what each one is protecting against
 *
 *   1. BAND-LIMITED. Corroboration applies only to scores inside
 *      [CORROBORATION_FLOOR, BLOCK_THRESHOLD). A payload the rules already block is
 *      not re-judged, and a payload the rules found nothing in stays clean. This is
 *      the constraint that prevents history from manufacturing detections.
 *
 *   2. NEVER FROM NOTHING. A score of zero is never adjusted, regardless of how bad
 *      the actor's history is. Otherwise every request from a once-hostile address
 *      becomes an incident, which is the "once flagged, always flagged" failure that
 *      makes reputation systems unusable and destroys an analyst's trust faster than
 *      a missed detection does.
 *
 *   3. TWO INDEPENDENT SIGNALS. One signal is a coincidence. An IOC record alone is
 *      not enough, because an address that scanned the perimeter last month is not
 *      thereby sending an attack now.
 *
 *   4. CAPPED AND EXPLAINED. The lift cannot exceed MAX_LIFT, and every adjustment
 *      returns the signals that produced it. An analyst who disagrees needs to see
 *      why, not a score that moved.
 *
 * On measurement
 *   This ships behind a flag and the flag's default is decided by measurement, not
 *   by preference. `audit/corroboration_impact.ts` tests both directions — whether
 *   it catches borderline attacks from known-bad actors, and whether it turns benign
 *   traffic from those same actors into false positives. If the false-positive cost
 *   exceeds the recall gain, the honest outcome is to leave it off and record that
 *   Phase 4's criterion does not hold for a deterministic rule engine.
 */

/** Scores below this are left alone: there is not enough in the payload to corroborate. */
export const CORROBORATION_FLOOR = 40;
/** Maximum points history may add. Enough to cross a borderline, not to invent one. */
export const MAX_LIFT = 18;
/** IOC sightings below this are treated as a single weak observation. */
export const IOC_SIGHTING_FLOOR = 2;

export interface CorroborationSignal {
  id: 'IOC_RECORD' | 'PRIOR_INCIDENTS' | 'TECHNIQUE_CONTINUITY' | 'SIMILAR_PAYLOAD_HISTORY';
  weight: number;
  detail: string;
}

export interface CorroborationResult {
  applied: boolean;
  originalScore: number;
  adjustedScore: number;
  lift: number;
  signals: CorroborationSignal[];
  /** Why it did not apply, when it did not. Makes the non-decision inspectable too. */
  skippedReason?: string;
  verdictChanged: boolean;
}

/**
 * Corroborate a classification against the corpus.
 *
 * Pure with respect to the classifier: it takes the result and returns an adjusted
 * view, and never mutates the input. The caller decides whether to use it.
 */
export function corroborate(
  classification: ClassificationResult,
  actorIp: string,
  payload: string
): CorroborationResult {
  const original = classification.score;
  const base: CorroborationResult = {
    applied: false,
    originalScore: original,
    adjustedScore: original,
    lift: 0,
    signals: [],
    verdictChanged: false
  };

  // Constraint 2 — nothing from nothing.
  if (original <= 0) {
    return { ...base, skippedReason: 'Score is zero; history never creates a detection from an empty payload signal.' };
  }
  // Constraint 1 — band-limited.
  if (original >= BLOCK_THRESHOLD) {
    return { ...base, skippedReason: 'Already at or above the block threshold; the rules decided and history is not asked.' };
  }
  if (original < CORROBORATION_FLOOR) {
    return {
      ...base,
      skippedReason: `Score ${original} is below the corroboration floor ${CORROBORATION_FLOOR}; too little in the payload to corroborate.`
    };
  }

  const signals: CorroborationSignal[] = [];

  // Signal 1 — the actor is a recorded indicator with more than one sighting.
  const ioc = globalThreatMemory.lookupIoc(actorIp);
  const sightings = Number((ioc as any)?.sightings ?? 0);
  if (ioc && sightings >= IOC_SIGHTING_FLOOR) {
    signals.push({
      id: 'IOC_RECORD',
      weight: 7,
      detail: `Actor is a recorded indicator with ${sightings} sightings.`
    });
  }

  const ctx = globalThreatMemory.retrieve({ actorIp, payload, limit: 10 });

  // Signal 2 — prior incidents naming this actor.
  if (ctx.sameActor.length > 0) {
    signals.push({
      id: 'PRIOR_INCIDENTS',
      weight: Math.min(8, 4 + ctx.sameActor.length),
      detail: `${ctx.sameActor.length} prior incident(s) name this actor.`
    });
  }

  // Signal 3 — the family now detected matches a technique this actor used before.
  // Continuity of behaviour is stronger evidence than mere presence on a list.
  const priorTechniques = new Set(
    ctx.sameActor
      .map(i => String((i as any).mitreTechnique ?? (i as any).mitre_technique ?? ''))
      .filter(Boolean)
  );
  const familyToken = classification.family.replace(/_/g, ' ').toLowerCase();
  const continuity = [...priorTechniques].some(t => t.toLowerCase().includes(familyToken.split(' ')[0]));
  if (continuity) {
    signals.push({
      id: 'TECHNIQUE_CONTINUITY',
      weight: 8,
      detail: `Current family ${classification.family} matches a technique this actor used previously.`
    });
  }

  // Signal 4 — a textually similar payload is already on file as an incident.
  if (ctx.similar.length >= 2) {
    signals.push({
      id: 'SIMILAR_PAYLOAD_HISTORY',
      weight: 6,
      detail: `${ctx.similar.length} corpus incidents contain textually similar payloads.`
    });
  }

  // Constraint 3 — two independent signals minimum.
  if (signals.length < 2) {
    return {
      ...base,
      signals,
      skippedReason:
        signals.length === 0
          ? 'No corroborating history for this actor.'
          : `Only one corroborating signal (${signals[0].id}); a single signal is a coincidence, not evidence.`
    };
  }

  // Constraint 4 — capped.
  const lift = Math.min(MAX_LIFT, signals.reduce((a, s) => a + s.weight, 0));
  const adjusted = Math.min(100, original + lift);

  return {
    applied: true,
    originalScore: original,
    adjustedScore: adjusted,
    lift,
    signals,
    verdictChanged: original < BLOCK_THRESHOLD && adjusted >= BLOCK_THRESHOLD
  };
}

/**
 * Whether corroboration is enabled in the running configuration.
 *
 * Default is off. It flips only on evidence from `audit/corroboration_impact.ts`,
 * and the environment variable exists so the measurement can toggle it without
 * editing source — which would make the before/after comparison suspect.
 */
export function corroborationEnabled(): boolean {
  return process.env.SD_CORPUS_CORROBORATION === 'on';
}
