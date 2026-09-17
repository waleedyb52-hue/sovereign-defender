// =============================================================================
// AI COGNITIVE THREAT AGENT - TYPE DEFINITIONS (v1.0)
// Shared contract between the ingestion API, the ThreatAnalyzer, and the
// autonomous DecisionEngine. Kept dependency-free so it can be imported by
// both the analysis service and (in future) any external tooling.
// =============================================================================

/** Supported wire protocols reported by upstream sensors (Scapy/Nmap/etc). */
export type NetworkProtocol = 'TCP' | 'UDP' | 'ICMP' | 'HTTP' | 'HTTPS' | 'DNS';

/**
 * Raw network telemetry payload as reported by an external capture tool
 * (e.g. a Python/Scapy sniffer or Nmap scan correlator) to the ingestion
 * endpoint. This is the untrusted, wire-level shape - always validate
 * before use.
 */
export interface NetworkTelemetryPayload {
  sourceIP: string;
  destinationIP: string;
  protocol: NetworkProtocol;
  port: number;
  packetSize: number;
  /** Raw payload snippet, decoded header, or URI used for signature matching. */
  payloadSignature?: string;
  /** ISO-8601 capture timestamp. Defaults to server ingestion time if absent. */
  timestamp: string;
}

/** Final normalized threat score, 0 (benign) - 100 (critical/zero-day). */
export type ThreatScore = number;

/**
 * Per-signal breakdown of how the final ThreatScore was derived. Each
 * component is independently bounded so the composite score stays
 * interpretable and auditable.
 */
export interface ThreatScoreBreakdown {
  /** 0-40: request-rate / DDoS-style burst analysis. */
  frequencyScore: number;
  /** 0-42: known-malicious payload signature matching. */
  signatureScore: number;
  /** 0-25: distinct-port reconnaissance / scanning behavior. */
  portScanScore: number;
  /** 0-15: tiny-packet + high-rate flood heuristic (SYN-flood style). */
  packetAnomalyScore: number;
  /** Clamped sum of the above, 0-100. */
  finalScore: ThreatScore;
}

/** Autonomous mitigation decisions the DecisionEngine can select. */
export type AgentAction =
  | 'ALLOW'
  | 'RATE_LIMIT'
  | 'NULL_ROUTE'
  | 'REDIRECT_TO_HONEYPOT'
  | 'TRIGGER_EMERGENCY_LOCKDOWN';

/**
 * Full analysis output for one processed telemetry event: the diagnosis,
 * the chosen autonomous action, and the human-readable justification that
 * gets surfaced to the SOC dashboard.
 */
export interface AIAnalysisReport {
  incidentId: string;
  /** incidentIds of prior analyses for the same sourceIP within the correlation window. */
  correlatedEvents: string[];
  threatScore: ThreatScore;
  scoreBreakdown: ThreatScoreBreakdown;
  chosenAction: AgentAction;
  /** 0-1 confidence derived from how many independent signals agreed. */
  confidenceLevel: number;
  reasoning: string;
  reasoningAr: string;
  sourceIP: string;
  timestamp: string;
}
