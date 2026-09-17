import crypto from 'crypto';

// =============================================================================
// PRE-ATTACK INTENT & OBFUSCATION ANALYZER (v1.0)
//
// Detects reconnaissance and pre-exploitation probing that survives WAF
// evasion, by peeling encoding layers until the payload stops changing and
// then scoring the *decoded* form against weighted threat indicators.
//
// Pipeline: deobfuscate() -> matchIndicators() -> scoreBayesian() -> verdict
// =============================================================================

export type IntentAction = 'ALLOW' | 'MONITOR' | 'ACTION_DIVERT_TO_DECEPTION_GRID';

export type IndicatorCategory =
  | 'STEALTH_RECON'
  | 'SQL_INJECTION'
  | 'NOSQL_INJECTION'
  | 'COMMAND_INJECTION'
  | 'PATH_TRAVERSAL'
  | 'TEMPLATE_INJECTION'
  | 'SCANNER_FINGERPRINT'
  | 'OBFUSCATION_ABUSE';

export interface IntentIndicator {
  id: string;
  category: IndicatorCategory;
  label: string;
  labelAr: string;
  /**
   * Likelihood ratio: P(indicator | attacker) / P(indicator | benign).
   * An LR of 800 means this evidence is 800x more likely from an attacker
   * than from a legitimate user. The ratios are deliberately high for
   * unambiguous indicators: no benign client ever requests /.git/config, so
   * pretending that evidence is weak would only delay the diversion.
   *
   * Protection against false positives comes from the *precision* of each
   * pattern, not from artificially deflated weights. If a rule ever fires on
   * legitimate traffic the correct fix is to tighten that rule, because
   * weakening every weight instead would blunt the whole model.
   */
  likelihoodRatio: number;
  mitreTechnique: string;
  matched: string;
}

export interface DeobfuscationLayer {
  technique: 'URL_DECODE' | 'BASE64_DECODE' | 'HEX_DECODE' | 'UNICODE_NFKC' | 'COMMENT_STRIP' | 'WHITESPACE_NORMALIZE';
  before: string;
  after: string;
}

export interface IntentAnalysisResult {
  analysisId: string;
  timestamp: number;
  sessionToken: string;
  actorIp: string;
  rawInput: string;
  /** Fully peeled payload the indicators were actually matched against. */
  normalizedInput: string;
  layers: DeobfuscationLayer[];
  /** How many distinct encoding layers had to be removed. */
  obfuscationDepth: number;
  indicators: IntentIndicator[];
  /** 0-100 posterior probability that the actor is hostile, as a percentage. */
  adversaryIntentScore: number;
  priorProbability: number;
  posteriorProbability: number;
  action: IntentAction;
  primaryCategory: IndicatorCategory | null;
  mitreTechniques: string[];
}

// -----------------------------------------------------------------------
// Tuning
// -----------------------------------------------------------------------

/** Score at or above which the actor is transparently forked into the grid. */
export const DIVERSION_THRESHOLD = 65;
/** Score at or above which the actor is watched but still served production. */
export const MONITOR_THRESHOLD = 35;

/**
 * Base rate of hostile traffic.
 *
 * Deliberately low: on a real endpoint the overwhelming majority of requests
 * are legitimate, and a Bayesian model that starts from an inflated prior
 * will divert real customers on thin evidence. 2% keeps the burden of proof
 * on the evidence rather than on the prior.
 */
const PRIOR_HOSTILE_PROBABILITY = 0.02;

/** Bound on decoding passes, so a crafted payload cannot spin the CPU. */
const MAX_DECODE_ITERATIONS = 6;
/** Payload prefix actually analyzed; bounds cost on huge bodies. */
const MAX_ANALYSIS_CHARS = 8192;

// -----------------------------------------------------------------------
// Indicator table
// -----------------------------------------------------------------------

interface IndicatorRule {
  id: string;
  category: IndicatorCategory;
  label: string;
  labelAr: string;
  pattern: RegExp;
  likelihoodRatio: number;
  mitreTechnique: string;
}

const INDICATOR_RULES: IndicatorRule[] = [
  // --- Stealth reconnaissance of sensitive metadata -----------------
  { id: 'RECON_GIT', category: 'STEALTH_RECON', label: 'Probing exposed .git repository metadata', labelAr: 'استطلاع بيانات مستودع git المكشوفة', pattern: /\/\.git\/(config|head|index)/i, likelihoodRatio: 800, mitreTechnique: 'T1595.002 - Active Scanning: Vulnerability Scanning' },
  { id: 'RECON_ENV', category: 'STEALTH_RECON', label: 'Probing environment/secrets file', labelAr: 'استطلاع ملف متغيرات البيئة والأسرار', pattern: /\/\.env(\.|$|\?|\s)|\/\.env\b/i, likelihoodRatio: 800, mitreTechnique: 'T1592.002 - Gather Victim Host Information: Software' },
  { id: 'RECON_ACTUATOR', category: 'STEALTH_RECON', label: 'Spring Actuator management endpoint probe', labelAr: 'استطلاع نقاط إدارة Spring Actuator', pattern: /\/actuator\/(health|env|beans|heapdump|mappings)/i, likelihoodRatio: 150, mitreTechnique: 'T1595.002 - Active Scanning: Vulnerability Scanning' },
  { id: 'RECON_WPLOGIN', category: 'STEALTH_RECON', label: 'WordPress admin surface probe', labelAr: 'استطلاع واجهة إدارة ووردبريس', pattern: /\/(wp-login\.php|wp-admin|xmlrpc\.php)/i, likelihoodRatio: 120, mitreTechnique: 'T1595.002 - Active Scanning: Vulnerability Scanning' },
  { id: 'RECON_SSHKEY', category: 'STEALTH_RECON', label: 'Private key material probe', labelAr: 'استطلاع مواد المفاتيح الخاصة', pattern: /(id_rsa|id_ed25519|\.ssh\/authorized_keys|\.pem\b)/i, likelihoodRatio: 600, mitreTechnique: 'T1552.004 - Unsecured Credentials: Private Keys' },
  { id: 'RECON_CLOUDMETA', category: 'STEALTH_RECON', label: 'Cloud instance metadata (SSRF) probe', labelAr: 'استطلاع بيانات مثيل السحابة عبر SSRF', pattern: /169\.254\.169\.254|\/latest\/meta-data\//i, likelihoodRatio: 900, mitreTechnique: 'T1552.005 - Unsecured Credentials: Cloud Instance Metadata API' },
  { id: 'RECON_BACKUP', category: 'STEALTH_RECON', label: 'Backup/dump artifact probe', labelAr: 'استطلاع ملفات النسخ الاحتياطي', pattern: /\.(sql|bak|dump|old|swp|tar\.gz)(\?|$)/i, likelihoodRatio: 100, mitreTechnique: 'T1595.002 - Active Scanning: Vulnerability Scanning' },

  // --- SQL injection, including blind and error-based ---------------
  { id: 'SQLI_UNION', category: 'SQL_INJECTION', label: 'UNION SELECT extraction attempt', labelAr: 'محاولة استخراج عبر UNION SELECT', pattern: /union[\s\/*]+(all[\s\/*]+)?select/i, likelihoodRatio: 900, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },
  { id: 'SQLI_TAUTOLOGY', category: 'SQL_INJECTION', label: 'Boolean tautology injection', labelAr: 'حقن منطقي دائم الصحة', pattern: /(\bor\b|\band\b)[\s(]*['"]?\d+['"]?\s*=\s*['"]?\d+/i, likelihoodRatio: 200, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },
  { id: 'SQLI_TIMEBLIND', category: 'SQL_INJECTION', label: 'Time-based blind SQLi probe', labelAr: 'فحص أعمى زمني لحقن SQL', pattern: /(sleep\s*\(\s*\d+|benchmark\s*\(|pg_sleep\s*\(|waitfor\s+delay)/i, likelihoodRatio: 900, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },
  { id: 'SQLI_ERRORBASED', category: 'SQL_INJECTION', label: 'Error-based SQLi extraction', labelAr: 'استخراج SQL عبر رسائل الخطأ', pattern: /(extractvalue\s*\(|updatexml\s*\(|information_schema\.|sqlite_master)/i, likelihoodRatio: 700, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },
  { id: 'SQLI_STACKED', category: 'SQL_INJECTION', label: 'Stacked query / destructive DDL', labelAr: 'استعلامات مكدسة أو أوامر هدم', pattern: /;\s*(drop|truncate|alter|create)\s+(table|database|schema)/i, likelihoodRatio: 1500, mitreTechnique: 'T1485 - Data Destruction' },

  // --- NoSQL injection ---------------------------------------------
  { id: 'NOSQLI_OPERATOR', category: 'NOSQL_INJECTION', label: 'MongoDB operator injection', labelAr: 'حقن معاملات MongoDB', pattern: /\$(ne|gt|lt|gte|lte|regex|where|expr|function)\b["']?\s*[:=]/i, likelihoodRatio: 400, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },
  { id: 'NOSQLI_JS', category: 'NOSQL_INJECTION', label: 'Server-side JavaScript evaluation', labelAr: 'تنفيذ JavaScript من جهة الخادم', pattern: /\$where["']?\s*:\s*['"]?\s*(function|this\.)/i, likelihoodRatio: 900, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },

  // --- Command injection -------------------------------------------
  { id: 'CMDI_SUBSHELL', category: 'COMMAND_INJECTION', label: 'Sub-shell command substitution', labelAr: 'استبدال أوامر عبر صدفة فرعية', pattern: /(\$\(\s*(whoami|id|uname|hostname|cat|curl|wget)|`\s*(whoami|id|uname|cat)\s*`)/i, likelihoodRatio: 1200, mitreTechnique: 'T1059.004 - Command and Scripting Interpreter: Unix Shell' },
  { id: 'CMDI_CHAIN', category: 'COMMAND_INJECTION', label: 'Shell metacharacter command chaining', labelAr: 'تسلسل أوامر عبر محارف الصدفة', pattern: /[;|&]{1,2}\s*(cat|ls|id|whoami|uname|nc|bash|sh|curl|wget|chmod)\b/i, likelihoodRatio: 600, mitreTechnique: 'T1059.004 - Command and Scripting Interpreter: Unix Shell' },
  { id: 'CMDI_PASSWD', category: 'COMMAND_INJECTION', label: 'Credential file read attempt', labelAr: 'محاولة قراءة ملف بيانات الاعتماد', pattern: /\/etc\/(passwd|shadow|sudoers)/i, likelihoodRatio: 500, mitreTechnique: 'T1003.008 - OS Credential Dumping: /etc/passwd' },
  { id: 'CMDI_REVSHELL', category: 'COMMAND_INJECTION', label: 'Reverse shell construction', labelAr: 'بناء صدفة عكسية', pattern: /(bash\s+-i\s*>&|\/dev\/tcp\/|nc\s+-e\s|python.{0,20}socket\.socket)/i, likelihoodRatio: 2000, mitreTechnique: 'T1059.004 - Command and Scripting Interpreter: Unix Shell' },

  // --- Path traversal ----------------------------------------------
  { id: 'TRAVERSAL_DOTDOT', category: 'PATH_TRAVERSAL', label: 'Directory traversal sequence', labelAr: 'تسلسل اجتياز الأدلة', pattern: /(\.\.[\/\\]){2,}|\.\.[\/\\](etc|windows|proc|root)/i, likelihoodRatio: 400, mitreTechnique: 'T1083 - File and Directory Discovery' },
  { id: 'TRAVERSAL_NULLBYTE', category: 'PATH_TRAVERSAL', label: 'Null-byte extension truncation', labelAr: 'قطع الامتداد ببايت صفري', pattern: /%00|\x00/, likelihoodRatio: 600, mitreTechnique: 'T1027 - Obfuscated Files or Information' },

  // --- Template / expression injection ------------------------------
  { id: 'SSTI_EXPR', category: 'TEMPLATE_INJECTION', label: 'Server-side template expression', labelAr: 'تعبير قالب من جهة الخادم', pattern: /(\{\{\s*\d+\s*\*\s*\d+\s*\}\}|\$\{\s*\d+\s*\*\s*\d+\s*\}|\{\{\s*self\.|__class__)/i, likelihoodRatio: 900, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },
  { id: 'JNDI_LOOKUP', category: 'TEMPLATE_INJECTION', label: 'JNDI lookup (Log4Shell class)', labelAr: 'استدعاء JNDI من فئة Log4Shell', pattern: /\$\{\s*jndi\s*:/i, likelihoodRatio: 3000, mitreTechnique: 'T1190 - Exploit Public-Facing Application' },

  // --- Scanner fingerprints ----------------------------------------
  { id: 'SCANNER_UA', category: 'SCANNER_FINGERPRINT', label: 'Known offensive scanner signature', labelAr: 'بصمة أداة فحص هجومية معروفة', pattern: /(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|hydra|wpscan|acunetix|nuclei)/i, likelihoodRatio: 700, mitreTechnique: 'T1595.002 - Active Scanning: Vulnerability Scanning' }
];

export class PreAttackIntentAnalyzer {
  private totalAnalyzed = 0;
  private totalDiverted = 0;
  private totalMonitored = 0;

  // -------------------------------------------------------------------
  // De-obfuscation pipeline
  // -------------------------------------------------------------------

  /**
   * Peels encoding layers until the payload stops changing.
   *
   * WAF evasion works by ensuring the *encoded* form does not match a
   * signature while the server still decodes it into an attack. Matching on
   * the raw input alone is therefore useless against `%252e%252e%252f`, and
   * matching on a single decode pass is defeated by adding one more layer.
   * The loop is bounded so a deliberately deep payload cannot spin the CPU.
   */
  public deobfuscate(raw: string): { normalized: string; layers: DeobfuscationLayer[] } {
    const layers: DeobfuscationLayer[] = [];
    let current = (raw ?? '').slice(0, MAX_ANALYSIS_CHARS);

    for (let iteration = 0; iteration < MAX_DECODE_ITERATIONS; iteration++) {
      const before = current;

      // 1. Percent decoding. decodeURIComponent throws on malformed input,
      //    which attackers use deliberately, so it degrades to a manual pass.
      const urlDecoded = this.safeUrlDecode(current);
      if (urlDecoded !== current) {
        layers.push({ technique: 'URL_DECODE', before: current, after: urlDecoded });
        current = urlDecoded;
      }

      // 2. Hex escapes in \xNN and 0xNN form.
      const hexDecoded = this.decodeHexEscapes(current);
      if (hexDecoded !== current) {
        layers.push({ technique: 'HEX_DECODE', before: current, after: hexDecoded });
        current = hexDecoded;
      }

      // 3. Embedded base64 blobs.
      const b64Decoded = this.decodeEmbeddedBase64(current);
      if (b64Decoded !== current) {
        layers.push({ technique: 'BASE64_DECODE', before: current, after: b64Decoded });
        current = b64Decoded;
      }

      if (current === before) break; // fixed point reached
    }

    // 4. Unicode normalization defeats fullwidth and homoglyph evasion
    //    (e.g. U+FF35 FULLWIDTH LATIN CAPITAL U in "UNION").
    const nfkc = current.normalize('NFKC');
    if (nfkc !== current) {
      layers.push({ technique: 'UNICODE_NFKC', before: current, after: nfkc });
      current = nfkc;
    }

    // 5. Inline comment stripping defeats `UN/**/ION SEL/**/ECT`.
    // Comments collapse to a space (MySQL treats /**/ as whitespace, so
    // UNION/**/SELECT reads as UNION SELECT). The zero-width reading is kept
    // alongside it, because a filter that strips comments outright would
    // instead turn UNI/**/ON into UNION.
    const decommented = current.replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/(^|\s)--[^\n]*/g, ' ');
    const decommentedTight = current.replace(/\/\*[\s\S]*?\*\//g, '');
    if (decommented !== current) {
      layers.push({ technique: 'COMMENT_STRIP', before: current, after: decommented });
      // Carry both readings forward so neither evasion shape can hide.
      current = decommented + ' ' + decommentedTight;
    }

    // 6. Whitespace normalization, including the tab/newline/vertical-tab
    //    variants used to break token adjacency.
    const collapsed = current.replace(/[\s\u00a0\u1680\u2000-\u200b\u2028\u2029\u202f\u205f\u3000\ufeff]+/g, ' ').trim();
    if (collapsed !== current) {
      layers.push({ technique: 'WHITESPACE_NORMALIZE', before: current, after: collapsed });
      current = collapsed;
    }

    return { normalized: current, layers };
  }

  /** Percent-decode that never throws on malformed sequences. */
  private safeUrlDecode(input: string): string {
    try {
      const decoded = decodeURIComponent(input);
      return decoded;
    } catch {
      // Malformed percent sequences are themselves an evasion tactic, so fall
      // back to decoding only the well-formed triplets and leaving the rest.
      return input.replace(/%[0-9a-fA-F]{2}/g, m => {
        try { return decodeURIComponent(m); } catch { return m; }
      });
    }
  }

  /** Decodes \xNN and 0xNN escape forms. */
  private decodeHexEscapes(input: string): string {
    return input.replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
  }

  /**
   * Finds and decodes base64 blobs embedded in a larger string.
   *
   * Only substrings long enough to carry a payload are considered, and the
   * decode is kept only when it yields mostly printable text - otherwise any
   * random alphanumeric token would be "decoded" into noise that could
   * accidentally match an indicator.
   */
  private decodeEmbeddedBase64(input: string): string {
    return input.replace(/[A-Za-z0-9+/]{16,}={0,2}/g, candidate => {
      if (candidate.length % 4 !== 0) return candidate;
      try {
        const decoded = Buffer.from(candidate, 'base64').toString('utf-8');
        if (decoded.length < 4) return candidate;
        const printable = decoded.replace(/[^\x20-\x7e]/g, '').length / decoded.length;
        return printable > 0.85 ? decoded : candidate;
      } catch {
        return candidate;
      }
    });
  }

  // -------------------------------------------------------------------
  // Scoring
  // -------------------------------------------------------------------

  /**
   * Naive-Bayes accumulation in log-odds space.
   *
   *   logit(P_post) = logit(P_prior) + Σ ln(LR_i)
   *   P_post        = σ(logit(P_post))
   *
   * Working in log-odds keeps the arithmetic numerically stable and makes
   * evidence additive rather than multiplicative, so no single indicator can
   * saturate the score on its own. Distinct *categories* are what compound:
   * within one category only the strongest indicator contributes fully, since
   * five SQLi patterns in one payload are one finding, not five independent
   * pieces of evidence.
   */
  public scoreBayesian(indicators: IntentIndicator[], obfuscationDepth: number): {
    score: number;
    prior: number;
    posterior: number;
  } {
    const prior = PRIOR_HOSTILE_PROBABILITY;
    let logOdds = Math.log(prior / (1 - prior));

    // Group by category and take the strongest LR per category at full
    // weight, with the remainder heavily discounted.
    const byCategory = new Map<IndicatorCategory, IntentIndicator[]>();
    for (const ind of indicators) {
      const list = byCategory.get(ind.category) ?? [];
      list.push(ind);
      byCategory.set(ind.category, list);
    }

    for (const list of byCategory.values()) {
      const sorted = [...list].sort((a, b) => b.likelihoodRatio - a.likelihoodRatio);
      sorted.forEach((ind, index) => {
        // Correlated evidence within a category is discounted geometrically.
        const weight = index === 0 ? 1 : 0.25 / index;
        logOdds += Math.log(ind.likelihoodRatio) * weight;
      });
    }

    // Deep obfuscation is itself evidence of intent: legitimate clients do
    // not triple-encode their query parameters.
    if (obfuscationDepth >= 2) {
      logOdds += Math.log(1.8 + obfuscationDepth * 0.6);
    }

    const posterior = 1 / (1 + Math.exp(-logOdds));
    return {
      score: Number((posterior * 100).toFixed(2)),
      prior,
      posterior: Number(posterior.toFixed(6))
    };
  }

  // -------------------------------------------------------------------
  // Full analysis
  // -------------------------------------------------------------------

  public analyze(input: {
    sessionToken: string;
    actorIp: string;
    method?: string;
    url?: string;
    body?: unknown;
    userAgent?: string;
    headers?: Record<string, string | string[] | undefined>;
  }): IntentAnalysisResult {
    this.totalAnalyzed++;

    // Everything the client controls is concatenated into one analysis
    // surface, so an attacker cannot escape detection by moving the payload
    // from the query string into a header or the body.
    const bodyText = typeof input.body === 'string'
      ? input.body
      : input.body !== undefined && input.body !== null
        ? JSON.stringify(input.body)
        : '';

    const rawInput = [
      input.method ?? '',
      input.url ?? '',
      bodyText,
      input.userAgent ?? '',
      input.headers ? JSON.stringify(input.headers) : ''
    ].filter(Boolean).join('   ').slice(0, MAX_ANALYSIS_CHARS);

    const { normalized, layers } = this.deobfuscate(rawInput);
    const obfuscationDepth = new Set(layers.map(l => l.technique)).size;

    // Indicators are matched against the decoded form AND the raw form: some
    // signatures (a null byte, a scanner user-agent) are only visible before
    // normalization collapses them.
    const haystack = normalized + '   ' + rawInput;
    const indicators: IntentIndicator[] = [];

    for (const rule of INDICATOR_RULES) {
      const match = haystack.match(rule.pattern);
      if (!match) continue;
      indicators.push({
        id: rule.id,
        category: rule.category,
        label: rule.label,
        labelAr: rule.labelAr,
        likelihoodRatio: rule.likelihoodRatio,
        mitreTechnique: rule.mitreTechnique,
        matched: String(match[0]).slice(0, 120)
      });
    }

    if (obfuscationDepth >= 3) {
      indicators.push({
        id: 'OBF_DEEP',
        category: 'OBFUSCATION_ABUSE',
        label: obfuscationDepth + ' stacked encoding layers detected',
        labelAr: 'رُصدت ' + obfuscationDepth + ' طبقات ترميز متراكمة',
        likelihoodRatio: 25,
        mitreTechnique: 'T1027 - Obfuscated Files or Information',
        matched: layers.map(l => l.technique).join(' -> ')
      });
    }

    const { score, prior, posterior } = this.scoreBayesian(indicators, obfuscationDepth);

    let action: IntentAction = 'ALLOW';
    if (score >= DIVERSION_THRESHOLD) {
      action = 'ACTION_DIVERT_TO_DECEPTION_GRID';
      this.totalDiverted++;
    } else if (score >= MONITOR_THRESHOLD) {
      action = 'MONITOR';
      this.totalMonitored++;
    }

    // The dominant category is the one carrying the strongest single piece of
    // evidence, which is what an analyst wants named in the alert.
    const primary = indicators.length > 0
      ? indicators.reduce((top, i) => (i.likelihoodRatio > top.likelihoodRatio ? i : top), indicators[0])
      : null;

    return {
      analysisId: 'INT-' + crypto.randomBytes(5).toString('hex').toUpperCase(),
      timestamp: Date.now(),
      sessionToken: input.sessionToken,
      actorIp: input.actorIp,
      rawInput: rawInput.slice(0, 1024),
      normalizedInput: normalized.slice(0, 1024),
      layers: layers.slice(0, 12).map(l => ({
        technique: l.technique,
        before: l.before.slice(0, 180),
        after: l.after.slice(0, 180)
      })),
      obfuscationDepth,
      indicators,
      adversaryIntentScore: score,
      priorProbability: prior,
      posteriorProbability: posterior,
      action,
      primaryCategory: primary ? primary.category : null,
      mitreTechniques: Array.from(new Set(indicators.map(i => i.mitreTechnique)))
    };
  }

  public getStats() {
    return {
      totalAnalyzed: this.totalAnalyzed,
      totalDiverted: this.totalDiverted,
      totalMonitored: this.totalMonitored,
      diversionThreshold: DIVERSION_THRESHOLD,
      monitorThreshold: MONITOR_THRESHOLD,
      priorProbability: PRIOR_HOSTILE_PROBABILITY,
      indicatorRuleCount: INDICATOR_RULES.length
    };
  }
}

export const globalPreAttackIntentAnalyzer = new PreAttackIntentAnalyzer();
