// =============================================================================
// THREAT INTELLIGENCE & AUTOMATED FORENSICS - TYPE ONTOLOGY (v1.0)
// Shared contract between the multi-source intelligence hub, the autonomous
// forensic investigator, and the SOC query endpoints. Modeled on STIX 2.1
// concepts (Indicator, Sighting, Attack Pattern, Observed Data) while staying
// dependency-free so any external tooling can import it.
// =============================================================================

/** Observable classes this platform can resolve against upstream feeds. */
export type IndicatorType = 'IPV4' | 'DOMAIN' | 'HASH_SHA256';

/**
 * STIX 2.1 `indicator` analogue: a single observable asserted as malicious by
 * one or more upstream feeds, carrying the confidence of that assertion.
 */
export interface ThreatFeedIndicator {
  indicator: string;
  type: IndicatorType;
  /** 0-100 confidence that this observable is malicious. */
  maliciousConfidence: number;
  /** Free-form kill-chain / malware family labels (e.g. 'SSH_BRUTE_FORCE'). */
  threatCategory: string[];
  /** Epoch milliseconds of the most recent sighting. */
  lastSeen: number;
}

/**
 * STIX 2.1 `observed-data` analogue: network-level reputation context
 * resolved for a single actor, merged across every healthy feed connector.
 */
export interface ReputationEnrichment {
  asn: number;
  countryCode: string;
  /** 0-100 abuse confidence, AbuseIPDB `abuseConfidenceScore` semantics. */
  abuseConfidenceScore: number;
  knownMaliciousSignatures: string[];
  isTorExitNode: boolean;
  isKnownVPN: boolean;
}

/**
 * STIX 2.1 `attack-pattern` analogue: one rung of a MITRE ATT&CK Enterprise
 * kill chain, resolved from observed packet attributes.
 */
export interface MitreTacticMapping {
  tacticId: string;
  tacticName: string;
  techniqueId: string;
  techniqueName: string;
  subTechniqueId?: string;
}

/**
 * Tamper-evident forensic record emitted by the AutonomousForensicAgent for
 * any incident that crosses the investigation threshold. `integrityHash`
 * seals every other field, so any post-hoc edit is detectable.
 */
export interface ForensicIncidentReport {
  incidentId: string;
  /** Epoch milliseconds the investigation was opened. */
  timestamp: number;
  rootCauseAnalysis: string;
  rootCauseAnalysisAr: string;
  /** Canonical `offset  hex-bytes  ascii` dump of the observed payload. */
  rawPayloadDumpHex: string;
  mitreAttackChain: MitreTacticMapping[];
  evidencePointers: string[];
  remediationsEnforced: string[];
  sourceIP: string;
  compositeThreatScore: number;
  severity: ForensicSeverity;
  reputation: ReputationEnrichment | null;
  networkHops: NetworkHop[];
  memorySnapshot: ForensicMemorySnapshot;
  /** SHA-256 over the canonical serialization of this report. */
  integrityHash: string;
  /** Algorithm identifier so verifiers never have to guess. */
  integrityAlgorithm: 'SHA-256';
}

export type ForensicSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';

/** One resolved layer-3 hop between the actor and the protected asset. */
export interface NetworkHop {
  hop: number;
  address: string;
  rttMs: number;
  asn: number | null;
}

/** Process/heap telemetry captured at the moment of detection. */
export interface ForensicMemorySnapshot {
  capturedAt: number;
  heapUsedBytes: number;
  heapTotalBytes: number;
  rssBytes: number;
  externalBytes: number;
  processUptimeSec: number;
  eventLoopLagMs: number;
  activeHandles: number;
}

// -----------------------------------------------------------------------
// Intelligence hub operational types
// -----------------------------------------------------------------------

/** Upstream connectors the hub can fan out to. */
export type FeedSourceId = 'ABUSEIPDB' | 'VIRUSTOTAL_V3' | 'INTERNAL_SENSOR';

/** Standard three-state circuit breaker. */
export type CircuitState = 'CLOSED' | 'OPEN' | 'HALF_OPEN';

export interface CircuitBreakerSnapshot {
  source: FeedSourceId;
  state: CircuitState;
  consecutiveFailures: number;
  totalFailures: number;
  totalSuccesses: number;
  /** Epoch ms when an OPEN breaker will next admit a trial request. */
  nextTrialAt: number | null;
  lastError: string | null;
}

/**
 * Deterministic decomposition of the weighted reputation score, retained so
 * an analyst can audit exactly how a verdict was reached.
 */
export interface CompositeScoreBreakdown {
  behavioralAnomalyScore: number;
  abuseConfidenceScore: number;
  knownSignatureWeight: number;
  weights: { w1: number; w2: number; w3: number };
  /** Weighted sum, normalized 0-100. */
  compositeScore: number;
}

/** Full result of one intelligence lookup, returned to callers and cached. */
export interface ThreatIntelLookupResult {
  indicator: string;
  type: IndicatorType;
  reputation: ReputationEnrichment;
  indicators: ThreatFeedIndicator[];
  /** Sources that answered successfully for this lookup. */
  sourcesQueried: FeedSourceId[];
  /** Sources skipped because their breaker was OPEN, or that errored. */
  sourcesDegraded: FeedSourceId[];
  /** True when at least one connector was unavailable (partial intelligence). */
  degraded: boolean;
  cacheHit: boolean;
  resolvedAt: number;
  lookupLatencyMs: number;
}

/** Aggregate hub health surfaced to the SOC dashboard. */
export interface ThreatIntelHubStats {
  cache: {
    entries: number;
    maxEntries: number;
    ttlMs: number;
    hits: number;
    misses: number;
    evictions: number;
    expirations: number;
    hitRatePercent: number;
  };
  breakers: CircuitBreakerSnapshot[];
  totalLookups: number;
  degradedLookups: number;
}
