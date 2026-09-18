// =============================================================================
// ACTIVE INTERCEPTION, LINK ANALYSIS & DLP - DOMAIN CONTRACTS (v1.0)
// Shared, dependency-free contracts between the in-transit stream inspector,
// the file DLP engine, the link-analysis graph builder, and the SOC surface.
// =============================================================================

// -----------------------------------------------------------------------
// 1. In-transit data contracts
// -----------------------------------------------------------------------

export type TamperFlag =
  | 'PAYLOAD_MUTATED'
  | 'LENGTH_DISCREPANCY'
  | 'PARAMETER_POLLUTED'
  | 'OUT_OF_ORDER';

export interface NetworkEndpoint {
  ip: string;
  port: number;
  asn?: number;
}

/**
 * One inspected frame of data in transit.
 *
 * `expectedPayloadHash` is the HMAC-SHA256 the sender committed to (or the
 * session baseline digest); `actualPayloadHash` is what the bytes on the wire
 * actually produce. Divergence between the two is the primary tamper signal.
 */
export interface DataTransitPacket {
  /** UUIDv4. */
  packetId: string;
  sessionToken: string;
  sourceEndpoint: NetworkEndpoint;
  destinationEndpoint: NetworkEndpoint;
  payloadRaw: string;
  /** HMAC-SHA256 (system-derived key) or SHA-256 digest the sender committed to. */
  expectedPayloadHash: string;
  actualPayloadHash: string;
  tamperFlags: TamperFlag[];
  timestamp: number;
}

// -----------------------------------------------------------------------
// 2. File operation contracts
// -----------------------------------------------------------------------

export type FileOperationType =
  | 'FILE_READ_EXFIL'
  | 'FILE_WRITE_INJECT'
  | 'FILE_MODIFY_TAMPER'
  | 'FILE_DELETE_PURGE';

export interface ActorIdentity {
  uid: string;
  sourceIp: string;
  userAgent: string;
  role: string;
}

/**
 * One file operation presented to the DLP engine for adjudication.
 *
 * `entropyScore` is Shannon entropy in bits per byte, so it is bounded to
 * [0.0, 8.0] for byte-valued data. Values above ~7.2 indicate compressed,
 * encrypted, or packed content.
 */
export interface FileOperationVector {
  operationType: FileOperationType;
  targetPath: string;
  fileSizeBytes: number;
  fileMimeType: string;
  /** Leading bytes rendered as uppercase hex pairs, e.g. "4D 5A 90 00". */
  magicBytesHex: string;
  /** Shannon entropy, 0.0 - 8.0 bits per byte. */
  entropyScore: number;
  actorIdentity: ActorIdentity;
  processId: number;
}

// -----------------------------------------------------------------------
// 3. Adjudication contract
// -----------------------------------------------------------------------

export type InterceptionAction =
  | 'ALLOW'
  | 'BLOCK_AND_ISOLATE'
  | 'TERMINATE_SESSION_TCP_RST'
  | 'QUARANTINE_HONEYFILE'
  | 'TRIGGER_SYSTEM_FREEZE';

export interface InterceptionDecision {
  action: InterceptionAction;
  /** 0 - 100, monotonically increasing in severity. */
  threatScore: number;
  /** 0.0 - 1.0, how much independent evidence agreed. */
  confidence: number;
  /** MITRE ATT&CK Enterprise technique id and name. */
  mitreTechnique: string;
  /** SHA-256 over the canonical serialization of the full incident payload. */
  forensicDigest: string;
}

// -----------------------------------------------------------------------
// 4. Link analysis graph
// -----------------------------------------------------------------------

export type GraphNodeType = 'ACTOR' | 'ENDPOINT' | 'FILE_OBJECT' | 'TECHNIQUE' | 'STATE';

export type GraphRelationship =
  | 'ATTACKED'
  | 'TAMPERED_WITH'
  | 'EXFILTRATING'
  | 'MITIGATED_BY';

export interface LinkAnalysisNode {
  id: string;
  label: string;
  type: GraphNodeType;
  /** 0 - 100 contribution of this node to overall incident risk. */
  riskWeight: number;
}

export interface LinkAnalysisEdge {
  source: string;
  target: string;
  relationship: GraphRelationship;
  latencyMs: number;
}

export interface LinkAnalysisGraph {
  nodes: LinkAnalysisNode[];
  edges: LinkAnalysisEdge[];
}

// -----------------------------------------------------------------------
// 5. Aggregate counters surfaced by /status
// -----------------------------------------------------------------------

export interface InterceptionStatusCounters {
  totalPacketsInspected: number;
  tamperedDropped: number;
  tcpResetsIssued: number;
  dlpOperationsEvaluated: number;
  dlpBlocks: number;
  honeyfilesServed: number;
  systemFreezesTriggered: number;
  activeQuarantinedSessions: number;
  activeLockedTokens: number;
  meanInspectionLatencyMicros: number;
}
