/**
 * ADVANCED GROUND-TRUTH SCENARIOS — a capability probe, not a validation set
 *
 * Four scenarios supplied as authoritative ground truth: APT29 lateral movement,
 * a kernel rootkit syscall hook, a ransomware encryption burst, and DNS tunnel
 * exfiltration. Each carries a MITRE technique, an expected action and an SLA.
 *
 * They are NOT loaded into `eval_harness.ts`, and the instruction to inject them
 * there "to achieve 100% validation" is the one part of the specification this
 * file declines to implement. Two reasons, both load-bearing:
 *
 *   1. It is the original defect. The 100% this project opened with came from
 *      rules and test payloads authored by the same process. TESSERACT (USENIX
 *      Security 2019) states that F1 above 0.99 in security classification is a
 *      signature of experimental bias rather than of a superior detector. A
 *      target of 100% is therefore a target for the wrong thing: reaching it
 *      would mean the harness had stopped measuring.
 *
 *   2. It is a category error. `classifyPayload()` consumes a payload *string*.
 *      These scenarios are structured telemetry — `syscall_id`, `io_rate_ops_sec`,
 *      `shannon_entropy_post`, DNS `query_type` and frequency. Three of the four
 *      domains describe sensors this platform does not have: a repository scan
 *      finds zero files handling DNS tunnelling, zero handling I/O rate, and
 *      `fim.service.ts` computes neither entropy nor write rate. Injecting them
 *      would either fail outright, or force detectors written to match these four
 *      records — which is memorisation wearing the costume of validation.
 *
 * So they are used for what they are genuinely excellent at: defining the target
 * capability surface, and driving the exhibition drill. `npx tsx
 * audit/scenario_capability_report.ts` scores the platform against them and
 * reports honestly which sensors are missing. A low score there is the roadmap,
 * not a failure to hide.
 *
 * Provenance: authored ground truth, supplied with the architecture spec. Marked
 * DRILL / AUTOMATED_IMPORT anywhere it reaches the adjudication store, so it can
 * never raise `operatorGrounded` or stand in for an analyst's ruling.
 */

export type ScenarioDomain = 'eBPF_Network' | 'FIM_Engine_Memory' | 'FIM_Engine_Storage';

export interface GroundTruthScenario {
  scenarioId: string;
  domain: ScenarioDomain;
  mitreTechnique: string;
  /** Short human label for the exhibition timeline. */
  titleEn: string;
  titleAr: string;
  telemetryInput: Record<string, unknown>;
  groundTruth: {
    action: string;
    slaLatencyMicros?: number;
    maxDetectionWindowMs?: number;
    aiConfidenceRequired?: number;
    aiClassification?: string;
    auditFlag: string;
  };
  /**
   * The closest thing to this scenario the platform can actually be fed today.
   * Null where no ingress path exists — which is itself the finding, and is why
   * this field is not allowed to be a plausible-looking approximation.
   */
  probePayload: string | null;
  /** Sensors this scenario requires, for the capability report. */
  requiredSensors: string[];
}

export const GROUND_TRUTH_SCENARIOS: GroundTruthScenario[] = [
  {
    scenarioId: 'APT29_LATERAL_MOVEMENT_001',
    domain: 'eBPF_Network',
    mitreTechnique: 'T1210',
    titleEn: 'APT29 lateral movement over SMB',
    titleAr: 'حركة جانبية لـ APT29 عبر SMB',
    telemetryInput: {
      source_ip: '10.0.0.45',
      target_port: 445,
      protocol: 'SMB',
      anomaly_score: 0.92,
      payload_signature: 'Mimikatz_LSASS_Dump_Heuristic'
    },
    groundTruth: {
      action: 'XDP_DROP_AND_ISOLATE_HOST',
      slaLatencyMicros: 35,
      aiConfidenceRequired: 0.98,
      auditFlag: 'CRITICAL_LATERAL_MOVEMENT_HALTED'
    },
    // A payload-shaped probe exists here because the signature is a string the
    // classifier could in principle recognise.
    probePayload: 'sekurlsa::logonpasswords privilege::debug lsass.exe minidump',
    requiredSensors: ['smb_flow_inspection', 'credential_dump_signature', 'xdp_drop', 'host_isolation']
  },
  {
    scenarioId: 'KERNEL_ROOTKIT_SYSCALL_HOOK_002',
    domain: 'FIM_Engine_Memory',
    mitreTechnique: 'T1014',
    titleEn: 'Kernel rootkit syscall table hook',
    titleAr: 'خطّاف جدول نداءات النظام (روتكِت)',
    telemetryInput: {
      syscall_id: 29,
      process_name: 'kworker/u4:2',
      memory_region: '0xffffffff81000000',
      integrity_hash_mismatch: true
    },
    groundTruth: {
      action: 'SIGKILL_AND_KERNEL_PANIC_PREVENTION',
      maxDetectionWindowMs: 2.5,
      auditFlag: 'ROOTKIT_HOOK_INTERCEPTED'
    },
    // No ingress path takes a syscall id and a kernel address. Leaving this null
    // rather than inventing a string is the honest representation of that gap.
    probePayload: null,
    requiredSensors: ['syscall_table_integrity', 'kernel_memory_hashing', 'process_kill', 'panic_guard']
  },
  {
    scenarioId: 'RANSOMWARE_ENCRYPTION_BURST_003',
    domain: 'FIM_Engine_Storage',
    mitreTechnique: 'T1486',
    titleEn: 'Ransomware encryption burst',
    titleAr: 'انفجار تشفير بفدية',
    telemetryInput: {
      path: '/var/secure_vault/intel.docx',
      io_rate_ops_sec: 24000,
      shannon_entropy_post: 7.99,
      pre_sha256: 'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    },
    groundTruth: {
      action: 'QUARANTINE_PID_AND_ROLLBACK',
      maxDetectionWindowMs: 5.0,
      auditFlag: 'DATA_DESTRUCTION_PREVENTED'
    },
    probePayload: null,
    requiredSensors: ['file_io_rate', 'post_write_entropy', 'pid_quarantine', 'snapshot_rollback']
  },
  {
    scenarioId: 'STEALTH_EXFILTRATION_DNS_TUNNEL_004',
    domain: 'eBPF_Network',
    mitreTechnique: 'T1048',
    titleEn: 'DNS TXT tunnel exfiltration',
    titleAr: 'تسريب عبر نفق DNS TXT',
    telemetryInput: {
      query_type: 'TXT',
      payload_length_avg: 240,
      frequency_per_sec: 85,
      destination_ip: '1.1.1.1'
    },
    groundTruth: {
      action: 'TCP_TARPIT_ENGAGEMENT',
      aiClassification: 'DNS_TUNNELING_EXFILTRATION',
      auditFlag: 'DATA_LEAKAGE_CONTAINED'
    },
    probePayload: null,
    requiredSensors: ['dns_query_flow_stats', 'tunnel_entropy_heuristic', 'tcp_tarpit']
  }
];

/**
 * Sensors the repository actually implements, established by scanning for them
 * rather than asserted here. Kept as a list of probe terms so the capability
 * report derives coverage instead of restating a claim.
 */
export const SENSOR_PROBES: Record<string, { pattern: RegExp; note: string }> = {
  smb_flow_inspection: { pattern: /\bSMB\b|port\s*445/i, note: 'SMB-aware flow inspection' },
  credential_dump_signature: { pattern: /mimikatz|lsass|sekurlsa/i, note: 'credential-dump signatures' },
  xdp_drop: { pattern: /XDP_DROP/, note: 'XDP drop action' },
  host_isolation: { pattern: /contain-ip|containIp|ACTIVE_BLACKHOLE/, note: 'host isolation' },
  syscall_table_integrity: { pattern: /syscall.*(table|hook)|sys_call_table/i, note: 'syscall table integrity' },
  kernel_memory_hashing: { pattern: /kernel.*(hash|integrity)|memory_region/i, note: 'kernel memory hashing' },
  process_kill: { pattern: /SIGKILL|killProcess|process\.kill/, note: 'process termination' },
  panic_guard: { pattern: /kernel_panic|panicGuard|panic_prevention/i, note: 'kernel panic guard' },
  file_io_rate: { pattern: /io_?rate|opsPerSec|writeRate|iops/i, note: 'file I/O rate monitoring' },
  post_write_entropy: { pattern: /shannonEntropy|calculateEntropy|entropy/i, note: 'entropy computation' },
  pid_quarantine: { pattern: /quarantinePid|quarantine.*pid/i, note: 'PID quarantine' },
  snapshot_rollback: { pattern: /rollback|restoreSnapshot|revertFile/i, note: 'snapshot rollback' },
  dns_query_flow_stats: { pattern: /dns.*(query|flow|stats)|queryType/i, note: 'DNS query flow statistics' },
  tunnel_entropy_heuristic: { pattern: /tunnel/i, note: 'tunnelling heuristic' },
  tcp_tarpit: { pattern: /tarpit/i, note: 'TCP tarpit' }
};
