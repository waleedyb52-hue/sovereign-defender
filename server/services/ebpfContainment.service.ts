import { globalUnifiedTelemetryService } from './unifiedTelemetry.service';
import { globalRealEbpfBridge } from './realEbpfBridge';

export interface EbpfContainmentRecord {
  id: string;
  targetIp: string;
  cidrBlock: string;
  reason: string;
  reasonAr: string;
  triggeredByIoc: string;
  severity: 'CRITICAL' | 'HIGH';
  status: 'ACTIVE_BLACKHOLE' | 'RELEASED';
  interceptLatencyUs: number; // e.g. 0.35 microseconds
  packetsDroppedCount: number;
  tcpConnectionsSevered: number;
  isolatedAt: string;
  releasedAt?: string;
  nodeName: string;
  bpfMapKey?: string;
  severedSockets?: SeveredTcpSocket[];
  /** Whether interceptLatencyUs was measured on a kernel path or is a seeded value. */
  interceptLatencySource?: 'MEASURED' | 'SEEDED' | 'SIMULATED';
  /** The operator or key that requested it; absent for autonomous containment. */
  requestedBy?: string;
  releasedBy?: string;
}

export interface SeveredTcpSocket {
  id: string;
  targetIp: string;
  srcPort: number;
  dstIp: string;
  dstPort: number;
  protocol: 'TCP';
  stateBeforeSever: 'ESTABLISHED' | 'SYN_SENT' | 'CLOSE_WAIT';
  rstInjectedAt: string;
  latencyUs: number;
  bytesTransferredBeforeKill: number;
  /** Whether latencyUs was measured on a kernel path or modelled. */
  latencySource?: 'MEASURED' | 'SEEDED' | 'SIMULATED';
}

export interface BehavioralAnomaly {
  id: string;
  type: 'DATA_EXFILTRATION' | 'PERSISTENT_CODE_INJECTION' | 'UNAUTHORIZED_BINARY_EXECUTION' | 'LATERAL_CLUSTER_TRAVERSAL';
  title: string;
  titleAr: string;
  actorIp: string;
  targetNode: string;
  confidenceScore: number; // 0 to 100
  thresholdExceeded: string;
  thresholdExceededAr: string;
  heuristicDetails: {
    samplesAnalyzed: number;
    anomalyMetric: string;
    baselineValue: string;
    observedValue: string;
  };
  detectedAt: string;
  autoContained: boolean;
  containmentRecordId?: string;
}

export interface ClusterNodeIsolationState {
  nodeName: string;
  nodeIp: string;
  clusterRole: 'INGRESS_PROXY' | 'APP_WORKLOAD' | 'DATABASE_CLUSTER' | 'AI_INFERENCE_GATEWAY';
  isolationStatus: 'HEALTHY_ATTACHED' | 'QUARANTINED_EAST_WEST';
  ebpfXdpAttached: boolean;
  ingressPacketsDropped: number;
  egressPacketsDropped: number;
  lastIsolatedAt?: string;
}

export class EbpfContainmentService {
  private containmentRecords: EbpfContainmentRecord[] = [];
  private behavioralAnomalies: BehavioralAnomaly[] = [];
  private severedSockets: SeveredTcpSocket[] = [];
  private clusterNodes: ClusterNodeIsolationState[] = [];
  /**
   * Seeded demo baselines, kept separate from anything observed.
   *
   * These were previously added straight into the reported totals, so a caller
   * received 373,960 "packets dropped" with no way to tell that every one of
   * them was a literal written here. They are now reported apart from observed
   * activity, and `getStatistics()` labels them SEEDED.
   *
   * The values remain because an empty console is hard to review; what changes
   * is that they can no longer be mistaken for measurements.
   */
  private readonly seededPacketsDroppedBaseline: number = 248910;
  private readonly seededTcpResetsBaseline: number = 842;

  /**
   * Last kernel latency actually read, in microseconds.
   *
   * Null until a kernel path reports one. Deliberately not given a default: a
   * default here is how the hardcoded 0.34 reached the console in the first
   * place.
   */
  private measuredKernelLatencyUs: number | null = null;

  /** Counted in this process since boot. Zero until something actually happens. */
  private observedPacketsDropped: number = 0;
  private observedTcpResetsInjected: number = 0;

  constructor() {
    this.initializeClusterNodes();
    this.seedInitialContainments();
    this.seedInitialAnomalies();
  }

  private initializeClusterNodes() {
    this.clusterNodes = [
      {
        nodeName: 'prod-web-frontend-01',
        nodeIp: '10.0.1.10',
        clusterRole: 'INGRESS_PROXY',
        isolationStatus: 'QUARANTINED_EAST_WEST',
        ebpfXdpAttached: true,
        ingressPacketsDropped: 68450,
        egressPacketsDropped: 1240,
        lastIsolatedAt: new Date(Date.now() - 18 * 60 * 1000).toISOString()
      },
      {
        nodeName: 'db-cluster-primary',
        nodeIp: '10.0.2.20',
        clusterRole: 'DATABASE_CLUSTER',
        isolationStatus: 'QUARANTINED_EAST_WEST',
        ebpfXdpAttached: true,
        ingressPacketsDropped: 41200,
        egressPacketsDropped: 890,
        lastIsolatedAt: new Date(Date.now() - 8 * 60 * 1000).toISOString()
      },
      {
        nodeName: 'app-workload-worker-02',
        nodeIp: '10.0.1.15',
        clusterRole: 'APP_WORKLOAD',
        isolationStatus: 'HEALTHY_ATTACHED',
        ebpfXdpAttached: true,
        ingressPacketsDropped: 0,
        egressPacketsDropped: 0
      },
      {
        nodeName: 'ai-inference-gateway-01',
        nodeIp: '10.0.3.5',
        clusterRole: 'AI_INFERENCE_GATEWAY',
        isolationStatus: 'HEALTHY_ATTACHED',
        ebpfXdpAttached: true,
        ingressPacketsDropped: 0,
        egressPacketsDropped: 0
      }
    ];
  }

  private seedInitialContainments() {
    const now = Date.now();
    const minutesAgo = (m: number) => new Date(now - m * 60 * 1000).toISOString();

    const sockets1: SeveredTcpSocket[] = [
      {
        id: 'SOCK-901',
        targetIp: '194.26.29.112',
        srcPort: 4444,
        dstIp: '10.0.2.20',
        dstPort: 5432,
        protocol: 'TCP',
        stateBeforeSever: 'ESTABLISHED',
        rstInjectedAt: minutesAgo(8),
        latencyUs: 0.31,
        latencySource: 'SEEDED' as const,
        bytesTransferredBeforeKill: 1420
      },
      {
        id: 'SOCK-902',
        targetIp: '194.26.29.112',
        srcPort: 4445,
        dstIp: '10.0.2.20',
        dstPort: 22,
        protocol: 'TCP',
        stateBeforeSever: 'SYN_SENT',
        rstInjectedAt: minutesAgo(8),
        latencyUs: 0.29,
        latencySource: 'SEEDED' as const,
        bytesTransferredBeforeKill: 64
      }
    ];

    this.severedSockets.push(...sockets1);

    this.containmentRecords = [
      {
        id: 'EBPF-ISO-401',
        targetIp: '194.26.29.112',
        cidrBlock: '194.26.29.112/32',
        reason: 'Autonomous containment: Persistent reverse TCP stager & lateral exfiltration detected',
        reasonAr: 'عزل ذاتي عبر النواة: رصد محاولة اتصال عكسي مشبوه وتسريب بيانات جانبية',
        triggeredByIoc: 'METERPRETER_C2_TRAVERSAL',
        severity: 'CRITICAL',
        status: 'ACTIVE_BLACKHOLE',
        interceptLatencyUs: 0.32,
        interceptLatencySource: 'SEEDED' as const,
        packetsDroppedCount: 41200,
        tcpConnectionsSevered: 4,
        isolatedAt: minutesAgo(8),
        nodeName: 'db-cluster-primary',
        bpfMapKey: '0xc21a1d70',
        severedSockets: sockets1
      },
      {
        id: 'EBPF-ISO-402',
        targetIp: '185.220.101.5',
        cidrBlock: '185.220.101.5/32',
        reason: 'Autonomous containment: Multiple webshell write violations & unauthorized binary execution',
        reasonAr: 'عزل ذاتي عبر النواة: رصد محاولات متكررة لرفع شل وتنفيذ أوامر بالنظام',
        triggeredByIoc: 'WEBSHELL_RCE_ATTEMPT',
        severity: 'CRITICAL',
        status: 'ACTIVE_BLACKHOLE',
        interceptLatencyUs: 0.28,
        interceptLatencySource: 'SEEDED' as const,
        packetsDroppedCount: 68450,
        tcpConnectionsSevered: 7,
        isolatedAt: minutesAgo(18),
        nodeName: 'prod-web-frontend-01',
        bpfMapKey: '0xb9dc6505'
      },
      {
        id: 'EBPF-ISO-403',
        targetIp: '45.155.205.233',
        cidrBlock: '45.155.205.233/32',
        reason: 'Autonomous containment: High-frequency SQL injection & memory probe scanner',
        reasonAr: 'عزل تلقائي: هجوم حقن قواعد بيانات عالي الكثافة وفحص للذاكرة',
        triggeredByIoc: 'SQLI_PROBE_BURST',
        severity: 'HIGH',
        status: 'RELEASED',
        interceptLatencyUs: 0.41,
        interceptLatencySource: 'SEEDED' as const,
        packetsDroppedCount: 15400,
        tcpConnectionsSevered: 2,
        isolatedAt: minutesAgo(65),
        releasedAt: minutesAgo(15),
        nodeName: 'ingress-proxy-02',
        bpfMapKey: '0x2d9bcd49'
      }
    ];
  }

  private seedInitialAnomalies() {
    const now = Date.now();
    const minutesAgo = (m: number) => new Date(now - m * 60 * 1000).toISOString();

    this.behavioralAnomalies = [
      {
        id: 'ANOM-IOC-301',
        type: 'DATA_EXFILTRATION',
        title: 'Heuristic Alert: Asymmetric Outbound Exfiltration Surge',
        titleAr: 'إنذار سلوكي: تدفق غير متماثل لتسريب بيانات خارجية عبر بروتوكول مشفر',
        actorIp: '194.26.29.112',
        targetNode: 'db-cluster-primary',
        confidenceScore: 96,
        thresholdExceeded: 'Outbound burst: 48.2 MB / 8 sec to unverified external ASN (Threshold: 5 MB)',
        thresholdExceededAr: 'تدفق خارجي: 48.2 ميجابايت خلال 8 ثوانٍ إلى ASN مجهول (الحد الأقصى: 5 ميجابايت)',
        heuristicDetails: {
          samplesAnalyzed: 1400,
          anomalyMetric: 'egress_bytes_rate_per_sec',
          baselineValue: '120 KB/s',
          observedValue: '6.02 MB/s (50x spike)'
        },
        detectedAt: minutesAgo(8),
        autoContained: true,
        containmentRecordId: 'EBPF-ISO-401'
      },
      {
        id: 'ANOM-IOC-302',
        type: 'UNAUTHORIZED_BINARY_EXECUTION',
        title: 'LSM Probe: Web Server Spawned Unauthorized Subshell /bin/sh',
        titleAr: 'فحص نواة LSM: خادم الويب فرّع شل أوامر غير مصرح به /bin/sh',
        actorIp: '185.220.101.5',
        targetNode: 'prod-web-frontend-01',
        confidenceScore: 99,
        thresholdExceeded: 'Syscall execve() invoked /bin/sh from user www-data (Zero-Trust Policy Violation)',
        thresholdExceededAr: 'استدعاء execve() لتشغيل /bin/sh من المستخدم www-data (مخالفة سياسة انعدام الثقة)',
        heuristicDetails: {
          samplesAnalyzed: 85,
          anomalyMetric: 'unauthorized_process_fork',
          baselineValue: '0 forks',
          observedValue: '3 interactive subshell invocations'
        },
        detectedAt: minutesAgo(18),
        autoContained: true,
        containmentRecordId: 'EBPF-ISO-402'
      },
      {
        id: 'ANOM-IOC-303',
        type: 'PERSISTENT_CODE_INJECTION',
        title: 'Heuristic Burst: Cascading Polyglot Injection Attempts',
        titleAr: 'إنذار سلوكي: محاولات متتالية لحقن شيفرات متعددة اللغات في وقت قياسي',
        actorIp: '45.155.205.233',
        targetNode: 'ingress-proxy-02',
        confidenceScore: 88,
        thresholdExceeded: '18 SQLi/RCE payloads detected in a 15-second sliding window',
        thresholdExceededAr: '18 حمولة حقن قواعد وأوامر رُصدت في نافذة زمنية مدتها 15 ثانية',
        heuristicDetails: {
          samplesAnalyzed: 340,
          anomalyMetric: 'injection_signature_frequency',
          baselineValue: '0.05 req/min',
          observedValue: '72 req/min'
        },
        detectedAt: minutesAgo(65),
        autoContained: true,
        containmentRecordId: 'EBPF-ISO-403'
      }
    ];
  }

  /**
   * Autonomous Trigger: Instantly blackholes an IP/CIDR block at kernel level
   */
  public containIpAutonomously(params: {
    targetIp: string;
    reason: string;
    reasonAr: string;
    triggeredByIoc: string;
    nodeName?: string;
    severity?: 'CRITICAL' | 'HIGH';
    requestedBy?: string;
  }): EbpfContainmentRecord {
    const {
      targetIp,
      reason,
      reasonAr,
      triggeredByIoc,
      nodeName = 'k8s-worker-sovereign-01',
      severity = 'CRITICAL'
    } = params;

    // Check if already active
    const existing = this.containmentRecords.find(r => r.targetIp === targetIp && r.status === 'ACTIVE_BLACKHOLE');
    // Already contained: return the live record. This used to add 250 to its drop
    // counter, a number nothing had dropped.
    if (existing) return existing;

    /**
     * Simulated containment effects.
     *
     * XDP is Linux-only and this process has no kernel path, so there is no real
     * intercept latency or socket count to read. These are modelled, and every
     * record produced below carries `latencySource: 'SIMULATED'` so nothing
     * downstream can present them as measurements. The alternative — omitting them
     * — would leave the containment surface blank and tell an operator less.
     */
    const latency = Math.round((0.25 + Math.random() * 0.18) * 100) / 100;
    const tcpSevered = Math.floor(Math.random() * 4 + 2);

    // Generate severed socket records
    const newSeveredSockets: SeveredTcpSocket[] = [];
    for (let i = 0; i < tcpSevered; i++) {
      const sock: SeveredTcpSocket = {
        id: `SOCK-${Math.floor(Math.random() * 9000 + 1000)}`,
        targetIp,
        srcPort: Math.floor(Math.random() * 40000 + 10000),
        dstIp: '10.0.1.10',
        dstPort: [443, 80, 5432, 22, 6379][Math.floor(Math.random() * 5)],
        protocol: 'TCP',
        stateBeforeSever: 'ESTABLISHED',
        rstInjectedAt: new Date().toISOString(),
        latencyUs: Math.round((0.20 + Math.random() * 0.15) * 100) / 100,
        latencySource: 'SIMULATED' as const,
        bytesTransferredBeforeKill: Math.floor(Math.random() * 4000 + 200)
      };
      newSeveredSockets.push(sock);
      this.severedSockets.unshift(sock);
    }

    if (this.severedSockets.length > 50) {
      this.severedSockets = this.severedSockets.slice(0, 50);
    }

    const newRecord: EbpfContainmentRecord = {
      id: `EBPF-ISO-${Math.floor(Math.random() * 9000 + 1000)}`,
      targetIp,
      cidrBlock: targetIp.includes('/') ? targetIp : `${targetIp}/32`,
      reason,
      reasonAr,
      triggeredByIoc,
      severity,
      status: 'ACTIVE_BLACKHOLE',
      interceptLatencyUs: latency,
      interceptLatencySource: 'SIMULATED',
      packetsDroppedCount: 0,
      tcpConnectionsSevered: tcpSevered,
      isolatedAt: new Date().toISOString(),
      nodeName,
      requestedBy: params.requestedBy,
      bpfMapKey: `0x${Math.random().toString(16).substring(2, 10)}`,
      severedSockets: newSeveredSockets
    };

    this.containmentRecords.unshift(newRecord);
    // tcpSevered is modelled above, so it is not added to observedTcpResetsInjected: it was,
    // and the console reported random resets as MEASURED. XDP_DROP sends no RST at all.

    // Direct injection into production Linux Kernel eBPF Map via Bridge
    globalRealEbpfBridge.injectIp(targetIp, reason);

    // Isolate node if critical
    this.quarantineClusterNode(nodeName);

    // Dispatch incident to unified SOC bus
    globalUnifiedTelemetryService.recordEvent({
      source: 'WAF_EBPF',
      severity: 'CRITICAL',
      title: `Autonomous Kernel eBPF Containment: ${targetIp}`,
      titleAr: `عزل شبكي تلقائي بنواة eBPF: ${targetIp}`,
      details: `Drop rule set for ${targetIp} (kernel XDP map where available, otherwise the application gate). Reason: ${reason}. Node ${nodeName} micro-segmented.`,
      detailsAr: `ضُبطت قاعدة إسقاط للعنوان ${targetIp} (في خريطة XDP بالنواة إن توفرت، وإلا في بوابة التطبيق). السبب: ${reason}. تم عزل العقدة ${nodeName} جزئياً لمنع الانتشار الجانبي.`,
      actorIp: targetIp,
      mitreTactic: 'Defense Evasion',
      mitreTechnique: 'T1562 - Impair Defenses Countermeasure',
      actionTaken: 'EBPF_KERNEL_BLACKHOLE_APPLIED',
      actionTakenAr: 'تم تطبيق العزل الشبكي الفوري بنواة النظام'
    });

    return newRecord;
  }

  /**
   * Evaluates behavioral anomaly and triggers zero-trust auto-isolation if confidence >= 80%
   */
  public reportAndEvaluateAnomaly(anomaly: {
    type: BehavioralAnomaly['type'];
    title: string;
    titleAr: string;
    actorIp: string;
    targetNode: string;
    confidenceScore: number;
    thresholdExceeded: string;
    thresholdExceededAr: string;
    metric: string;
    baseline: string;
    observed: string;
  }): { anomaly: BehavioralAnomaly; containmentRecord?: EbpfContainmentRecord } {
    const anomalyId = `ANOM-IOC-${Math.floor(Math.random() * 9000 + 1000)}`;
    const shouldAutoIsolate = anomaly.confidenceScore >= 80;

    let containmentRecord: EbpfContainmentRecord | undefined;

    if (shouldAutoIsolate) {
      containmentRecord = this.containIpAutonomously({
        targetIp: anomaly.actorIp,
        reason: `Autonomous containment triggered by behavioral anomaly: ${anomaly.title}`,
        reasonAr: `عزل شبكي تلقائي إثر رصد سلوك اختراق شاذ: ${anomaly.titleAr}`,
        triggeredByIoc: anomaly.type,
        nodeName: anomaly.targetNode,
        severity: 'CRITICAL'
      });
    }

    const record: BehavioralAnomaly = {
      id: anomalyId,
      type: anomaly.type,
      title: anomaly.title,
      titleAr: anomaly.titleAr,
      actorIp: anomaly.actorIp,
      targetNode: anomaly.targetNode,
      confidenceScore: anomaly.confidenceScore,
      thresholdExceeded: anomaly.thresholdExceeded,
      thresholdExceededAr: anomaly.thresholdExceededAr,
      heuristicDetails: {
        samplesAnalyzed: Math.floor(Math.random() * 500 + 100),
        anomalyMetric: anomaly.metric,
        baselineValue: anomaly.baseline,
        observedValue: anomaly.observed
      },
      detectedAt: new Date().toISOString(),
      autoContained: shouldAutoIsolate,
      containmentRecordId: containmentRecord?.id
    };

    this.behavioralAnomalies.unshift(record);
    if (this.behavioralAnomalies.length > 30) {
      this.behavioralAnomalies.pop();
    }

    return { anomaly: record, containmentRecord };
  }

  /**
   * Micro-segments a compromised cluster node (East-West traffic blackholed)
   */
  public quarantineClusterNode(nodeName: string): boolean {
    const node = this.clusterNodes.find(n => n.nodeName === nodeName);
    if (node) {
      node.isolationStatus = 'QUARANTINED_EAST_WEST';
      node.lastIsolatedAt = new Date().toISOString();
      return true;
    }
    return false;
  }

  public releaseClusterNode(nodeName: string): boolean {
    const node = this.clusterNodes.find(n => n.nodeName === nodeName);
    if (node) {
      node.isolationStatus = 'HEALTHY_ATTACHED';
      return true;
    }
    return false;
  }

  /**
   * Manual or Policy-based Release of an isolated IP
   */
  public releaseIp(targetIp: string, releasedBy?: string): boolean {
    const record = this.containmentRecords.find(r => r.targetIp === targetIp && r.status === 'ACTIVE_BLACKHOLE');
    if (record) {
      record.status = 'RELEASED';
      record.releasedAt = new Date().toISOString();
      record.releasedBy = releasedBy;

      // Direct removal from production Linux Kernel eBPF Map via Bridge
      globalRealEbpfBridge.removeIp(targetIp);

      globalUnifiedTelemetryService.recordEvent({
        source: 'WAF_EBPF',
        severity: 'INFO',
        title: `eBPF Isolation Released for ${targetIp}`,
        titleAr: `تم إلغاء العزل الشبكي للنواة عن ${targetIp}`,
        details: `Operator or policy released eBPF drop rule for IP ${targetIp}.`,
        detailsAr: `تم رفع قاعدة إسقاط الحزم في نواة eBPF عن العنوان ${targetIp}.`,
        actorIp: targetIp,
        actionTaken: 'EBPF_RULE_REMOVED',
        actionTakenAr: 'تمت إزالة قاعدة العزل من النواة'
      });
      return true;
    }
    return false;
  }

  /**
   * Whether requests from `ip` must be refused at the application layer.
   *
   * On a host with no kernel path, contain-ip wrote the address to an in-process list
   * that nothing consulted: a "contained" host could keep talking to this server. The
   * request gate now asks this. Seeded demo records are excluded — they name real public
   * addresses, and blocking those because a fixture mentions them would be a side effect
   * of demo data, not a defensive decision.
   */
  public isEnforced(ip: string): boolean {
    const clean = ip.replace(/^::ffff:/, '').trim();
    return this.containmentRecords.some(
      r => r.status === 'ACTIVE_BLACKHOLE' && r.interceptLatencySource !== 'SEEDED' && r.targetIp === clean
    );
  }

  /** A request actually refused at the gate. Counted as observed, because it was. */
  public recordEnforcedDrop(ip: string): void {
    this.observedPacketsDropped++;
    const rec = this.containmentRecords.find(r => r.status === 'ACTIVE_BLACKHOLE' && r.targetIp === ip);
    if (rec) rec.packetsDroppedCount++;
  }

  /**
   * Seeded records are demo fixtures for a host with no kernel path. Where the kernel is
   * readable they claimed blackholes the XDP map did not hold — on Linux the console showed
   * two "active" seeds against an empty blacklist_map — so they are withheld there.
   */
  private get showSeeds(): boolean {
    return !globalRealEbpfBridge.countersReadable;
  }

  private visibleRecords(): EbpfContainmentRecord[] {
    return this.showSeeds
      ? this.containmentRecords
      : this.containmentRecords.filter(r => r.interceptLatencySource !== 'SEEDED');
  }

  public getContainmentRecords(): EbpfContainmentRecord[] {
    return [...this.visibleRecords()];
  }

  public getBehavioralAnomalies(): BehavioralAnomaly[] {
    return [...this.behavioralAnomalies];
  }

  public getSeveredSockets(): SeveredTcpSocket[] {
    return this.showSeeds ? [...this.severedSockets] : this.severedSockets.filter(s => s.latencySource !== 'SEEDED');
  }

  public getClusterNodes(): ClusterNodeIsolationState[] {
    return [...this.clusterNodes];
  }

  public getStatistics() {
    const records = this.visibleRecords();
    // Enforced ones only, as isEnforced() defines them: a seeded "active" record blocks
    // nothing on any host, so counting it reported two blackholes that did not exist.
    const active = records.filter(r => r.status === 'ACTIVE_BLACKHOLE' && r.interceptLatencySource !== 'SEEDED');
    // Seeded drops are the baseline plus the seeded records' own counts. The old total added
    // every record's count and then observedPacketsDropped again, so a gate drop was counted
    // twice and half of it was reported as seeded.
    const seededDropped = this.showSeeds
      ? records
          .filter(r => r.interceptLatencySource === 'SEEDED')
          .reduce((acc, r) => acc + r.packetsDroppedCount, this.seededPacketsDroppedBaseline)
      : 0;
    // Gate refusals counted here, plus what the XDP program itself dropped (stats_map).
    const observedDropped = this.observedPacketsDropped + (globalRealEbpfBridge.kernelDroppedPackets ?? 0);
    const seededResets = this.showSeeds ? this.seededTcpResetsBaseline : 0;
    const quarantinedNodes = this.clusterNodes.filter(n => n.isolationStatus === 'QUARANTINED_EAST_WEST');
    const originOf = (seeded: number, observed: number) =>
      seeded > 0 ? (observed > 0 ? 'MIXED_SEEDED_AND_MEASURED' : 'SEEDED') : 'MEASURED';

    const kernelNative = globalRealEbpfBridge.kernelNative;
    const countersReadable = globalRealEbpfBridge.countersReadable;
    const toolingPresent = globalRealEbpfBridge.toolingPresent;
    // The latency value first, then the tag derived FROM it. Tagging from a
    // capability flag is what produced `meanKernelLatencyUs: null` labelled
    // MEASURED: the flag was true and the value was absent.
    const latencyValue = countersReadable ? this.measuredKernelLatencyUs : null;

    return {
      // Counted from real state: these are lengths of arrays this process owns.
      activeBlackholesCount: active.length,
      totalHistoricIsolations: records.length,
      anomaliesDetectedCount: this.behavioralAnomalies.length,
      quarantinedNodesCount: quarantinedNodes.length,
      totalClusterNodesCount: this.clusterNodes.length,

      // Packet and reset counters, split by origin so a consumer cannot blend
      // them by accident.
      totalPacketsDropped: seededDropped + observedDropped,
      observedPacketsDropped: observedDropped,
      seededPacketsDropped: seededDropped,
      totalTcpResetsInjected: seededResets + this.observedTcpResetsInjected,
      observedTcpResetsInjected: this.observedTcpResetsInjected,

      /**
       * Kernel latency.
       *
       * This was the literal 0.34, returned unconditionally and rendered in the
       * console as a measured microsecond figure. XDP is Linux-only, so on a
       * host without a kernel path there is nothing to measure and the honest
       * value is null — the UI then shows an em dash instead of a number that
       * was typed by hand.
       */
      meanKernelLatencyUs: latencyValue,

      /**
       * Per-figure provenance. The point of this block is that no consumer has
       * to guess: MEASURED came from the kernel or from real process state,
       * SEEDED is a literal shipped for review, SIMULATED is modelled.
       */
      provenance: {
        kernelNative,
        // Three states, not two. The middle one is the case that was being
        // reported as KERNEL_NATIVE: a Linux host with the toolchain installed but
        // no permission to read anything through it.
        mode: countersReadable
          ? 'KERNEL_NATIVE'
          : toolingPresent
            ? 'KERNEL_TOOLING_PRESENT_UNREADABLE'
            : 'SIMULATED_NO_KERNEL_PATH',
        reason: countersReadable
          ? 'A bpftool read succeeded, so kernel counters are readable on this host.'
          : toolingPresent
            ? 'bpftool and /sys/fs/bpf exist, but a read returned a permission error and no BPF program is pinned. Nothing is being read from the kernel, so packet figures remain seeded and kernel latency is unavailable. Loading an XDP program requires CAP_BPF or root.'
            : 'No bpftool or BPF filesystem on this host (XDP is Linux-only), so packet figures are seeded demo values and kernel latency is unavailable.',
        kernelToolingPresent: toolingPresent,
        kernelCountersReadable: countersReadable,
        fields: {
          activeBlackholesCount: 'MEASURED',
          totalHistoricIsolations: 'MEASURED',
          anomaliesDetectedCount: 'MEASURED',
          quarantinedNodesCount: 'MEASURED',
          totalClusterNodesCount: 'MEASURED',
          observedPacketsDropped: 'MEASURED',
          observedTcpResetsInjected: 'MEASURED',
          seededPacketsDropped: 'SEEDED',
          totalPacketsDropped: originOf(seededDropped, observedDropped),
          totalTcpResetsInjected: originOf(seededResets, this.observedTcpResetsInjected),
          // Derived from whether a number exists, never from a capability flag.
          meanKernelLatencyUs: latencyValue != null ? 'MEASURED' : 'UNAVAILABLE'
        }
      }
    };
  }
}

export const globalEbpfContainmentService = new EbpfContainmentService();

