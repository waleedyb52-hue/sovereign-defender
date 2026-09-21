export type AppTab =
  // Core operations
  | 'site_inspector'
  | 'blue_team_soc'
  | 'threat_labs'
  | 'fim_forensics'
  | 'threat_heatmap'
  // Network & kernel
  | 'topology'
  | 'kernel_perf'
  // Analytics & intelligence
  | 'soc_analytics'
  | 'threat_intel'
  | 'behavioral'
  // Defense & response
  | 'defense_overview'
  | 'live_protection'
  | 'deception'
  // Simulation & tooling
  | 'attack_sim'
  | 'digital_twin'
  | 'forensics_vault'
  | 'pro_tools'
  // Knowledge base
  | 'threat_corpus';

export type AttackVectorType = 
  | 'SSH_BRUTE_FORCE'
  | 'DNS_EXFILTRATION'
  | 'SQL_INJECTION'
  | 'LATERAL_MOVEMENT'
  | 'XSS_ATTACK'
  | 'DDOS_AMPLIFICATION'
  | 'PATH_TRAVERSAL'
  | 'REMOTE_CODE_EXECUTION'
  | 'CREDENTIAL_STUFFING';

export type PacketStatus = 'BLOCKED' | 'PASSED' | 'ANALYZED' | 'HONEYPOT_DIVERTED' | 'RATE_LIMITED';

export interface AttackVectorConfig {
  id: AttackVectorType;
  nameEn: string;
  nameAr: string;
  mitreId: string;
  category: string;
  defaultPort: number;
  descriptionEn: string;
  descriptionAr: string;
  samplePayloads: string[];
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  cveOrRef: string;
}

export interface TelemetryPacket {
  id: string;
  uuid?: string;
  timestamp: string;
  srcIp: string;
  dstIp: string;
  port: number;
  protocol: 'TCP' | 'UDP' | 'HTTP' | 'HTTPS' | 'DNS' | 'SSH' | 'RDP';
  vector: AttackVectorType;
  vectorNameEn: string;
  vectorNameAr: string;
  payload: string;
  packetSize: number;
  reqRate: number;
  threatScore: number;
  status: PacketStatus;
  actionTaken: string;
  reason: string;
  mitreTactic: string;
  xaiAttribution?: {
    payloadEntropy?: number;
    requestRate?: number;
    failedAuthCount?: number;
    packetSizeAnomaly?: number;
    signatureMatch?: number;
  };
  generatedRules?: {
    iptables?: string;
    suricata?: string;
    ebpf?: string;
    httpResponse?: number;
  };
}

export interface NetworkNode {
  id: string;
  labelEn: string;
  labelAr: string;
  ip: string;
  type: 'GATEWAY' | 'DEFENDER' | 'WEB_SERVER' | 'DATABASE' | 'HONEYPOT' | 'BASTION' | 'ATTACKER';
  status: 'ONLINE' | 'UNDER_ATTACK' | 'COMPROMISED' | 'ISOLATED' | 'PROTECTED';
  activeConnections: number;
  riskScore: number;
  x: number;
  y: number;
  ports: number[];
  os: string;
  firewallRulesCount: number;
}

export interface NetworkEdge {
  id: string;
  source: string;
  target: string;
  active: boolean;
  threatLevel: 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  packetsCount: number;
  lastVector?: string;
}

export interface QuarantinedHost {
  ip: string;
  threatScore: number;
  quarantineStart: number;
  unbanTimestamp: number;
  remainingSeconds: number;
  tier: number;
  actionTaken: string;
  reason: string;
  country?: string;
  attackVector: string;
}

export interface IngestedDataset {
  id: string;
  name: string;
  type: 'NGINX_LOG' | 'WAF_JSON' | 'MODSECURITY' | 'PAYLOAD_SAMPLES' | 'PCAP_JSON';
  uploadedAt: string;
  recordsCount: number;
  parsedAttacks: number;
  topVectors: { vector: string; count: number }[];
  status: 'PROCESSED' | 'ACTIVE_IN_MEMORY';
  sampleRaw: string;
}

export interface ThreatIntelligenceMetrics {
  totalIngestedLogs: number;
  knownMaliciousIps: number;
  zeroDaySignatures: number;
  aiDetectionAccuracy: number;
  falsePositiveRate: number;
  topTargetedUrls: { url: string; hits: number; threatLevel: 'HIGH' | 'CRITICAL' | 'MEDIUM' }[];
  topUserAgents: { ua: string; malicious: boolean; count: number }[];
  ipReputationScores: {
    ip: string;
    reputation: number; // 0-100
    category: string;
    country: string;
    lastSeen: string;
    status: 'ACTIVE_BLOCK' | 'SUSPICIOUS' | 'NEUTRAL';
  }[];
}

export interface LiveProtectionRequest {
  clientIp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD';
  url: string;
  headers: Record<string, string>;
  body?: string;
  userAgent?: string;
  apiKey?: string;
}

export interface LiveProtectionResponse {
  verdict: 'ALLOW' | 'BLOCK' | 'CHALLENGE' | 'DIVERT_HONEYPOT' | 'RATE_LIMIT' | 'QUEUED_APPROVAL';
  statusCode: 200 | 401 | 403 | 429 | 302;
  threatDetected: boolean;
  threatCategory?: AttackVectorType | 'ANOMALOUS_SCANNER' | 'CLEAN_TRAFFIC';
  threatScore: number;
  confidence: number;
  confidenceGatePassed?: boolean;
  confidenceThresholdRequired?: number; // 85%
  isDegradedToChallenge?: boolean;
  isDegradedToRateLimit?: boolean;
  reason: string;
  reasonAr: string;
  incidentId: string;
  latencyMs: number;
  cached?: boolean;
  cacheHit?: boolean;
  cacheTtlRemainingSec?: number;
  promptIsolationActive?: boolean;
  selfDosProtectionActive?: boolean;
  challengePayload?: {
    challengeId: string;
    type: string;
    powDifficulty: number;
    token: string;
    expiresInSec: number;
    /** Interactive-challenge question, emitted by the server for TIER-2. */
    mathPrompt?: string;
  };
  enforcementActions: {
    iptablesRule: string;
    ipsetRule: string;
    suricataRule: string;
    ebpfAction: string;
    httpStatus: number;
    quarantineTtlSec: number;
  };
  aiAnalysisSummary?: string;
}

export interface SimulatorControls {
  selectedVector: AttackVectorType;
  spoofedSrcIp: string;
  targetNodeId: string;
  targetPort: number;
  packetSize: number;
  packetsPerSec: number;
  durationSec: number;
  customPayload?: string;
  isContinuous: boolean;
}

export type TopologyViewMode = 
  | 'ARCHITECTURE' 
  | 'MITRE_KILL_CHAIN' 
  | 'GEO_THREAT_MAP' 
  | 'BLAST_RADIUS_RADAR';

export interface GeoThreatNode {
  id: string;
  ip: string;
  country: string;
  countryCode: string;
  flag: string;
  asn: string;
  city: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  attackType: string;
  packetsSent: number;
  targetAsset: string;
  divertedToHoneypot: boolean;
  x: number;
  y: number;
  latencyMs: number;
}

export interface KillChainStage {
  id: string;
  stepNumber: number;
  titleEn: string;
  titleAr: string;
  mitreTactic: string;
  techniqueId: string;
  status: 'ACTIVE' | 'SEVERED_BY_DEFENDER' | 'DIVERTED_HONEYPOT' | 'BLOCKED_KERNEL';
  executingNodeId: string;
  descriptionEn: string;
  descriptionAr: string;
  mitigationRule: string;
}

export interface PcapDissectionResult {
  packetLengthBytes: number;
  entropy: number;
  entropyLevel: string;
  headers: {
    ethernet: { srcMac: string; dstMac: string; etherType: string };
    ip: { version: number; ihl: number; ttl: number; protocol: string; src: string; dst: string; checksum: string };
    transport: {
      srcPort: number;
      dstPort: number;
      flags: { SYN: boolean; ACK: boolean; FIN: boolean; RST: boolean; PSH: boolean; URG: boolean };
      windowSize: number;
    };
  };
  hexDump: string;
}

export interface EbpfCompileResult {
  compiledBytecodeSize: number;
  instructionsCount: number;
  verifierStatus: string;
  targetHook: string;
  nanosecondLatency: string;
  userspaceComparison: string;
  sourceCode: string;
}

export interface BlastRadiusAssessment {
  selectedNodeId: string;
  compromiseProbability: number;
  directExposureCount: number;
  crownJewelRiskIndex: number;
  containmentPlaybookEn: string[];
  containmentPlaybookAr: string[];
  isolatedSubnets: string[];
  remediationLatencySec: number;
}

export type DefenseFlightMode = 'AUTOPILOT' | 'MANUAL_APPROVAL';

export interface IncidentForensicReport {
  id: string;
  incidentId: string;
  timestamp: string;
  vector: AttackVectorType;
  vectorNameEn: string;
  vectorNameAr: string;
  mitreId: string;
  mitreTactic: string;
  srcIp: string;
  dstIp: string;
  port: number;
  protocol: string;
  threatSeverityScore: number;
  threatTier: 'TIER_1_RATE_LIMIT' | 'TIER_2_CHALLENGE' | 'TIER_3_CRITICAL_DROP';
  country: string;
  asn: string;
  payloadDump: string;
  payloadEntropy: number;
  actionTaken: string;
  generatedRules: {
    iptables?: string;
    suricata?: string;
    ebpf?: string;
  };
  forensicEvidence: {
    pcapHexSample: string;
    rawRequestHeader: string;
    anomalyIndicators: string[];
    threatActorAttribution: string;
    recommendedRemediation: string[];
  };
}

export interface PendingRuleApproval {
  id: string;
  timestamp: string;
  incidentId: string;
  srcIp: string;
  vector: AttackVectorType;
  vectorName: string;
  threatScore: number;
  mitreId: string;
  suggestedRules: {
    iptables: string;
    suricata: string;
    ebpf: string;
  };
  reason: string;
  status: 'PENDING' | 'APPROVED' | 'REJECTED';
}

export interface AlertWebhookConfig {
  provider: 'DISCORD' | 'TELEGRAM' | 'SLACK' | 'GENERIC_WEBHOOK';
  webhookUrl: string;
  telegramBotToken?: string;
  telegramChatId?: string;
  enabled: boolean;
  minSeverity: 'CRITICAL' | 'HIGH' | 'ALL';
  lastDispatchedAt?: string;
  totalDispatchedCount: number;
}

export interface ProgressiveMitigationMetrics {
  tier1RateLimitedCount: number; // 429
  tier2ChallengedCount: number;  // Captcha / verification
  tier3CriticalBlockedCount: number; // 403 / iptables
  activeTier1Sessions: number;
  activeTier2Challenges: number;
  activeTier3HardBans: number;
}

export interface LruCacheStats {
  hits: number;
  misses: number;
  hitRatio: number;
  totalEntries: number;
  capacity: number;
  ttlSeconds: number;
  evictions: number;
}

export interface ProductionSafeguardsState {
  lruCache: LruCacheStats;
  promptIsolation: {
    active: boolean;
    sanitizationStrictness: 'STRICT_XML_TAG_ISOLATED';
    injectionsNeutralizedCount: number;
  };
  confidenceGate: {
    thresholdTier3Drop: number; // 85%
    tier2DegradationCount: number;
    falsePositivesPrevented: number;
  };
  selfDosDefense: {
    active: boolean;
    rateLimitThresholdReqSec: number;
    earlyDropBlockedCount: number;
  };
}

// =============================================================================
// VERSION 4.0 ENTERPRISE SUITE TYPES
// =============================================================================

export interface FederatedIocItem {
  id: string;
  iocHash: string;
  vector: AttackVectorType | string;
  mitreTechnique: string;
  confidence: number;
  peerOrigin: string; // e.g. "NODE-TOKYO-01"
  region: string;
  timestamp: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  verifiedNodes: number;
  autoSynced: boolean;
  samplePattern: string;
}

export interface FederatedShieldStatus {
  isSharingEnabled: boolean;
  activePeerNodes: number;
  totalSynchronizedIocs: number;
  networkTrustScore: number; // 0 - 100%
  lastBroadcastTime: string;
  syncedIocs: FederatedIocItem[];
  peers: {
    nodeId: string;
    region: string;
    status: 'ONLINE' | 'SYNCING' | 'PROTECTED';
    latMs: number;
    contributedIocs: number;
  }[];
}

export interface BreachSimulationScenario {
  id: string;
  nameEn: string;
  nameAr: string;
  category: 'XSS_CSP' | 'RCE_SHELL' | 'EBPF_HEAP_SPRAY' | 'ZERO_DAY_DESERIALIZATION' | 'API_TOKEN_EXFIL' | 'SSH_BRUTE_FORCE';
  descriptionEn: string;
  descriptionAr: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM';
  simulatedPayload: string;
  attackVector: string;
  targetComponent: string;
}

export interface BreachSimulationResult {
  testId: string;
  scenarioId: string;
  scenarioNameEn: string;
  scenarioNameAr: string;
  timestamp: string;
  durationMs: number;
  status: 'BLOCKED_INSTANT' | 'MITIGATED_DEGRADED' | 'HONEYPOT_TRAPPED' | 'BYPASS_DETECTED';
  resilienceScore: number; // 0 - 100%
  evasionResistanceScore: number; // 0 - 100%
  threatScoreDetected: number;
  kernelRuleSynthesized: boolean;
  iptablesRule: string;
  suricataRule: string;
  ebpfFilter: string;
  aiPlaybook: {
    titleEn: string;
    titleAr: string;
    executiveSummaryEn: string;
    executiveSummaryAr: string;
    tacticalRemediations: string[];
    kernelHardeningSteps: string[];
    mitreMitigationCode: string;
  };
}

export interface BehavioralBaseline {
  sampleCount: number;
  meanReqRate: number;
  stdDevReqRate: number;
  meanPacketSize: number;
  stdDevPacketSize: number;
  meanEntropy: number;
  stdDevEntropy: number;
  endpointFrequencies: Record<string, number>;
  activeDriftFlags: {
    id: string;
    flag: string;
    flagAr: string;
    severity: 'HIGH' | 'MEDIUM' | 'LOW';
    deviationZScore: number;
    triggeredAt: string;
    sampleMetric: string;
  }[];
  anomalyThresholdZScore: number;
}

export interface HoneypotSession {
  sessionId: string;
  attackerIp: string;
  decoyService: 'SSH_BAIT' | 'REST_ADMIN_API' | 'MYSQL_DECOY' | 'KUBERNETES_API';
  connectedAt: string;
  lastActivityAt: string;
  keystrokesCount: number;
  capturedCommands: {
    cmd: string;
    time: string;
    decoyResponse: string;
    riskLevel: 'HIGH' | 'CRITICAL' | 'INFO';
  }[];
  decoyCanariesTripped: string[];
  status: 'TRAPPED' | 'INTERACTING' | 'DISCONNECTED';
  baitCredentialsAccessed: string;
  /**
   * Geo/containment enrichment. The core honeypot feed does not carry these,
   * so every consumer must fall back — they are declared optional rather than
   * required to stop the UI reading fields that are simply absent.
   */
  country?: string;
  countryFlag?: string;
  jailContainerId?: string;
  triggerVector?: string;
}

// =============================================================================
// HIGH-THROUGHPUT & ENTERPRISE ENGINE TYPES (OPTIMIZATIONS 1-5)
// =============================================================================

export type XdpDriverMode = 'NATIVE_DRIVER' | 'SKB_GENERIC' | 'OFFLOADED_NIC';

export interface EbpfXdpEngineStats {
  mode: XdpDriverMode;
  driverAttached: string;
  rxPacketsTotal: number;
  xdpDropCount: number;
  xdpPassCount: number;
  xdpRedirectCount: number;
  zeroCopyDropsTotal: number;
  avgEvaluationLatencyNs: number; // e.g. 340ns
  subMicrosecondTargetMet: boolean;
  bpfMaps: {
    ipBlacklistMap: { entries: number; maxCapacity: number; memoryKb: number };
    payloadHashMap: { entries: number; maxCapacity: number; memoryKb: number };
    rateLimitLruMap: { entries: number; maxCapacity: number; memoryKb: number };
  };
  hardwareOffloadActive: boolean;
  lastSyncTimestamp: string;
}

export interface MultiTierCacheStats {
  tier1HotCache: {
    hits: number;
    misses: number;
    hitRatio: number;
    entries: number;
    capacity: number;
    ttlSec: number;
    avgLookupLatencyMicros: number;
    evictions: number;
  };
  tier2BloomFilter: {
    filterSizeBits: number;
    hashFunctionsCount: number;
    totalElementsEstimated: number;
    cleanTrafficBypassedCount: number;
    falsePositiveRateEst: number;
    memoryAllocatedKb: number;
    isPrewarmed: boolean;
  };
  aiQuotaEfficiency: {
    totalTrafficEvaluations: number;
    tier1ResolvedFastPath: number;
    tier2BloomBypassedClean: number;
    geminiAiDeepEvaluations: number;
    apiQuotaSavedPercentage: number;
    savedComputeCyclesScore: number;
  };
}

export interface WorkerPipelineMetrics {
  poolSize: number;
  activeWorkers: number;
  idleWorkers: number;
  tasksCompletedTotal: number;
  queueDepth: number;
  avgTaskExecutionMs: number;
  eventLoopDelayMs: number;
  eventLoopHealth: 'OPTIMAL' | 'DEGRADED' | 'CRITICAL';
  taskDistribution: {
    pcapEntropyDissections: number;
    datasetIngestions: number;
    behavioralModelRecalcs: number;
    cryptoHashGenerations: number;
  };
}

export interface TokenBucketBackpressureState {
  bucketCapacity: number;
  currentTokens: number;
  fillPercentage: number;
  refillRatePerSec: number;
  isLoadSheddingActive: boolean;
  pressureMode: 'NORMAL' | 'ELEVATED_THROTTLE' | 'CRITICAL_LOAD_SHEDDING';
  totalRequestsReceived: number;
  shedTelemetryPacketsCount: number;
  prioritizedSecurityVerdictsCount: number;
  currentSystemPps: number;
}

export interface RealEbpfKernelStats {
  rxPackets: number;
  rxBytes: number;
  droppedPackets: number;
  droppedBytes: number;
  passedPackets: number;
  passedBytes: number;
  activeBlacklistEntries: number;
  throughputGbps: number;
  throughputPps: number;
  avgLatencyNs: number;
  driverMode: 'XDP_NATIVE_DRV' | 'XDP_GENERIC_SKB' | 'XDP_OFFLOAD_NIC' | 'CONTAINER_EMULATION';
  interfaceName: string;
  kernelPinnedMapPath: string;
  lastUpdated: string;
  isKernelNative: boolean;
}

export interface EnterpriseIngressPerformanceState {
  xdpEngine: EbpfXdpEngineStats;
  multiTierCache: MultiTierCacheStats;
  workerPipeline: WorkerPipelineMetrics;
  tokenBucket: TokenBucketBackpressureState;
  realEbpfStats?: RealEbpfKernelStats;
  websocketStream: {
    connectedClients: number;
    broadcastRatePerSec: number;
    streamActive: boolean;
    uptimeSec: number;
  };
}

// =========================================================================
// SOC & BLUE TEAM FORENSICS TYPES (v6.0)
// =========================================================================
export interface AttackChainSession {
  sessionId: string;
  actorIp: string;
  firstSeen: string;
  lastSeen: string;
  threatScore: number;
  stagesCompleted: Array<{
    stage: 'Reconnaissance' | 'Initial Access' | 'Execution' | 'Exploitation' | 'Persistence' | 'Exfiltration';
    timestamp: string;
    description: string;
    technique: string;
  }>;
  status: 'ACTIVE_TRACKING' | 'CONTAINED' | 'NEUTRALIZED';
}

export interface HoneytokenTrap {
  id: string;
  endpointPath: string;
  trapType: string;
  hitsCount: number;
  lastTriggered?: string;
  lastAttackerIp?: string;
  autoBanEnabled: boolean;
  descriptionEn?: string;
  descriptionAr?: string;
}

export interface CredentialStuffingEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  targetEndpoint: string;
  usernameAttempted: string;
  velocityPerMinute: number;
  botnetClusterName?: string;
  actionTaken: string;
}

export interface FimFile {
  relativePath: string;
  fileName: string;
  originalHash: string;
  currentHash: string;
  isModified: boolean;
  isQuarantined: boolean;
  status: 'SECURE' | 'MODIFIED' | 'QUARANTINED' | 'INTACT' | 'TAMPERED' | 'DELETED';
  lastChecked?: string;
  lastModified?: string;
  sizeBytes: number;
  category?: string;
}

export interface FimAlert {
  id: string;
  timestamp: string;
  filePath: string;
  fileName: string;
  changeType: 'CREATE' | 'MODIFY' | 'DELETE' | 'PERMISSION_CHANGE' | string;
  previousHash?: string;
  originalHash?: string;
  currentHash: string;
  diffSnippet?: string;
  threatCategory: string;
  intentClassification: string;
  threatScore: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  mitreTechnique: string;
  analysisEn: string;
  analysisAr: string;
  status: 'DETECTED' | 'QUARANTINED' | 'ROLLEDBACK' | 'DISMISSED' | 'ALERTED' | 'IGNORED';
  aiAnalyzed?: boolean;
}

export interface ForensicProcess {
  pid: number;
  ppid: number;
  name: string;
  user: string;
  cpuPercent: number;
  memoryMb: number;
  command: string;
  sha256: string;
  startTime: string;
  status: 'RUNNING' | 'SUSPICIOUS' | 'INJECTED' | 'TERMINATED';
  loadedModules: string[];
  injectionEvidence?: string;
  threatScore: number;
}

export interface HeaderAuditItem {
  headerName?: string;
  header?: string;
  name?: string;
  present: boolean;
  value?: string | null;
  status?: 'PASS' | 'FAIL' | 'WARN';
  recommendation?: string;
  weight?: number;
}

export interface TargetScanReport {
  id: string;
  targetUrl: string;
  normalizedHost: string;
  ipAddress?: string;
  timestamp: string;
  responseTimeMs?: number;
  latencyMs?: number;
  httpStatus?: number;
  overallScore: number;
  grade: 'A+' | 'A' | 'B' | 'C' | 'D' | 'F';
  executiveSummaryEn: string;
  executiveSummaryAr: string;
  mitreMapping?: string[];
  headersAnalyzed: HeaderAuditItem[];
  headersAudit?: HeaderAuditItem[];
  vulnerabilitiesFound?: string[];
  remediationDirectives?: string[];
  actionableMitigations?: string[];
  remediationConfigSnippet?: string;
  tlsStatus?: {
    isHttps: boolean;
    hstsEnforced: boolean;
    validTls: boolean;
    details: string;
  };
}



