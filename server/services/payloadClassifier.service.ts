import { shannonEntropy } from './payloadForensics.js';

/**
 * LOCAL PAYLOAD CLASSIFIER
 *
 * Decides whether a request payload is hostile by inspecting the payload.
 *
 * Why this exists: the sovereign (cloud-disabled) path previously derived its
 * verdict from `packet.vector` — a label supplied by the caller — so it would
 * BLOCK a one-character payload labelled UNKNOWN and ALLOW a real
 * `DROP TABLE users; --` labelled CLEAN_TRAFFIC. It classified the label, not
 * the traffic. On the default deployment that is the only detection there is,
 * so it had to become real.
 *
 * Design: weighted signatures per attack family, scored additively, with
 * deliberate guards against the false positives that make a WAF untrusted —
 * prose containing SQL keywords, base64 in a legitimate token, version
 * numbers with dots in a path. Every verdict carries the signatures that
 * produced it, so an analyst can see why rather than trusting a number.
 */

export type AttackFamily =
  | 'SQL_INJECTION' | 'XSS_ATTACK' | 'PATH_TRAVERSAL' | 'REMOTE_CODE_EXECUTION'
  | 'SSH_BRUTE_FORCE' | 'CREDENTIAL_STUFFING' | 'DNS_EXFILTRATION' | 'CLEAN_TRAFFIC';

export interface ClassificationResult {
  family: AttackFamily;
  /** 0-100. Above BLOCK_THRESHOLD the payload is treated as hostile. */
  score: number;
  malicious: boolean;
  /** Human-readable signatures that fired, in the order they contributed. */
  signatures: string[];
  entropy: number;
}

export const BLOCK_THRESHOLD = 55;

interface Rule {
  re: RegExp;
  weight: number;
  label: string;
  family: AttackFamily;
}

/**
 * Weights are calibrated so a single unambiguous signature (a script tag, a
 * PHP open tag, a traversal sequence) clears the threshold alone, while
 * individually-weak signals (a bare SQL keyword) need corroboration.
 */
const RULES: Rule[] = [
  // ---- SQL injection ----
  { re: /'\s*(or|and)\s*'?\d*'?\s*=\s*'?\d*/i, weight: 60, label: "SQL tautology ('OR 1=1)", family: 'SQL_INJECTION' },
  { re: /\bunion\s+(all\s+)?select\b/i, weight: 65, label: 'UNION SELECT', family: 'SQL_INJECTION' },
  { re: /\b(drop|truncate)\s+table\b/i, weight: 65, label: 'DROP/TRUNCATE TABLE', family: 'SQL_INJECTION' },
  { re: /;\s*(drop|delete|update|insert)\b/i, weight: 55, label: 'stacked SQL statement', family: 'SQL_INJECTION' },
  { re: /\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(/i, weight: 60, label: 'time-based blind SQLi', family: 'SQL_INJECTION' },
  { re: /(--|#|\/\*)\s*$/, weight: 20, label: 'SQL comment terminator', family: 'SQL_INJECTION' },
  { re: /\b(information_schema|sysobjects|pg_catalog)\b/i, weight: 45, label: 'schema enumeration', family: 'SQL_INJECTION' },

  // ---- Cross-site scripting ----
  { re: /<\s*script[\s>]/i, weight: 65, label: '<script> tag', family: 'XSS_ATTACK' },
  { re: /\bon(error|load|click|mouseover|focus)\s*=/i, weight: 60, label: 'inline event handler', family: 'XSS_ATTACK' },
  { re: /javascript\s*:/i, weight: 50, label: 'javascript: URI', family: 'XSS_ATTACK' },
  { re: /<\s*(svg|img|iframe|object|embed)[^>]*\bon\w+\s*=/i, weight: 65, label: 'tag with event handler', family: 'XSS_ATTACK' },
  { re: /document\s*\.\s*(cookie|domain)/i, weight: 45, label: 'document.cookie/domain access', family: 'XSS_ATTACK' },
  { re: /\balert\s*\(|\bprompt\s*\(/i, weight: 30, label: 'alert()/prompt()', family: 'XSS_ATTACK' },

  // ---- Path traversal ----
  { re: /(\.\.[\/\\]){2,}/, weight: 65, label: 'repeated ../ traversal', family: 'PATH_TRAVERSAL' },
  { re: /(\.\.%2f|%2e%2e[\/\\%])/i, weight: 65, label: 'encoded traversal', family: 'PATH_TRAVERSAL' },
  { re: /\/etc\/(passwd|shadow)\b/i, weight: 70, label: 'sensitive unix path', family: 'PATH_TRAVERSAL' },
  { re: /\b(win\.ini|boot\.ini|system32\\config)\b/i, weight: 65, label: 'sensitive windows path', family: 'PATH_TRAVERSAL' },

  // ---- Remote code execution / webshell ----
  { re: /<\?php/i, weight: 70, label: 'PHP open tag', family: 'REMOTE_CODE_EXECUTION' },
  { re: /\b(system|shell_exec|passthru|popen|proc_open)\s*\(/i, weight: 65, label: 'command execution primitive', family: 'REMOTE_CODE_EXECUTION' },
  { re: /\beval\s*\(/i, weight: 55, label: 'eval()', family: 'REMOTE_CODE_EXECUTION' },
  { re: /\bbase64_decode\s*\(/i, weight: 50, label: 'base64_decode()', family: 'REMOTE_CODE_EXECUTION' },
  { re: /\$\{jndi:(ldap|rmi|dns):/i, weight: 75, label: 'JNDI lookup (Log4Shell)', family: 'REMOTE_CODE_EXECUTION' },
  { re: /;\s*(curl|wget)\s+https?:\/\/[^\s|]+\s*\|\s*(sh|bash)/i, weight: 75, label: 'download-and-execute chain', family: 'REMOTE_CODE_EXECUTION' },
  { re: /powershell\s+-(enc|e|encodedcommand)\b/i, weight: 65, label: 'encoded PowerShell', family: 'REMOTE_CODE_EXECUTION' },
  { re: /\bRuntime\.getRuntime\(\)\.exec/i, weight: 65, label: 'Java runtime exec', family: 'REMOTE_CODE_EXECUTION' },

  // ---- Credential attacks ----
  { re: /\broot\s*:\s*\S+\s+root\s*:/i, weight: 60, label: 'credential list', family: 'SSH_BRUTE_FORCE' },
  { re: /\b\d{2,}\s+(distinct\s+)?accounts?\b/i, weight: 45, label: 'multi-account attempt volume', family: 'CREDENTIAL_STUFFING' },
  { re: /\b(admin|root|administrator)\s*[:\/]\s*(admin|root|toor|password|123456|letmein)\b/i, weight: 55, label: 'default credential pair', family: 'SSH_BRUTE_FORCE' },

  // ---- Server-side template injection (found missing by the held-out set) ----
  { re: /\{\{\s*[\w.]*\s*[*+\-/]\s*[\w.]+\s*\}\}/, weight: 60, label: 'template expression {{expr}}', family: 'REMOTE_CODE_EXECUTION' },
  { re: /<%=?[^%>]*[*+\-/][^%>]*%>/, weight: 55, label: 'ERB/JSP template expression', family: 'REMOTE_CODE_EXECUTION' },
  { re: /\$\{\s*[\w.]+\s*[*+\-/]\s*[\w.]+\s*\}/, weight: 55, label: 'EL/template expression', family: 'REMOTE_CODE_EXECUTION' },

  // ---- XML external entity ----
  { re: /<!ENTITY\s+\S+\s+SYSTEM\s+["']/i, weight: 75, label: 'XXE external entity', family: 'REMOTE_CODE_EXECUTION' },
  { re: /<!DOCTYPE[^>]*\[<!ENTITY/i, weight: 70, label: 'inline DTD with entity', family: 'REMOTE_CODE_EXECUTION' },

  // ---- NoSQL injection ----
  { re: /["']\s*\$(ne|gt|lt|gte|lte|regex|where|expr)\s*["']?\s*:/i, weight: 65, label: 'NoSQL operator injection', family: 'SQL_INJECTION' },

  // ---- Server-side request forgery ----
  { re: /https?:\/\/(169\.254\.169\.254|metadata\.google\.internal)/i, weight: 75, label: 'cloud metadata endpoint', family: 'REMOTE_CODE_EXECUTION' },
  { re: /https?:\/\/(127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(:\d+)?/i, weight: 40, label: 'loopback URL in parameter', family: 'REMOTE_CODE_EXECUTION' },
  { re: /(file|gopher|dict):\/\//i, weight: 60, label: 'dangerous URI scheme', family: 'REMOTE_CODE_EXECUTION' },

  // ---- Header / CRLF injection ----
  { re: /(%0d%0a|[\r\n])\s*(set-cookie|location|content-length)\s*:/i, weight: 70, label: 'CRLF header injection', family: 'REMOTE_CODE_EXECUTION' },

  // ---- Exfiltration ----
  { re: /\b[A-Za-z0-9+/]{16,}={0,2}\.[A-Za-z0-9+/]{16,}={0,2}\./, weight: 55, label: 'base64 chunks in DNS labels', family: 'DNS_EXFILTRATION' },
  { re: /\b(attacker|exfil|c2)[-.][a-z0-9-]*\.(com|net|io|xyz)\b/i, weight: 50, label: 'suspicious exfil domain', family: 'DNS_EXFILTRATION' }
];

/**
 * Contexts that make an otherwise-suspicious token benign.
 *
 * Without these the classifier flags a blog post about SQL, a JWT in a query
 * string, or a documentation path containing a version number — the exact
 * false positives that teach analysts to ignore a WAF.
 */
const BENIGN_GUARDS: Array<{ re: RegExp; label: string }> = [
  { re: /^\s*(GET|HEAD|OPTIONS)\s+\/[\w\-./]*(\?[\w=&%\-.,+]*)?\s*$/i, label: 'plain read request, no payload' },
  { re: /\beyJ[A-Za-z0-9_-]{8,}\./, label: 'JWT (structured token, not exfil)' },
  { re: /\/[\w-]+\.v\d+(\.\d+)*\/\.\.\/[\w-]+\.v\d+/, label: 'version-segment path, single level' }
];

/** A bare SQL keyword inside a sentence is prose, not an injection. */
function looksLikeProse(payload: string): boolean {
  const words = payload.split(/\s+/).filter(Boolean);
  if (words.length < 6) return false;
  const punctuation = (payload.match(/[.,!?]/g) || []).length;
  const hasInjectionSyntax = /['";]|--\s*$|\/\*|\bunion\b.*\bselect\b/i.test(payload);
  return punctuation >= 1 && !hasInjectionSyntax;
}

/**
 * Canonicalises a payload before matching.
 *
 * Signature detection fails on obfuscation, not on novelty: a held-out test
 * showed MySQL executable comments splitting a UNION SELECT, and
 * double-encoded traversal (%252e%252e%252f), slipping through untouched
 * while the plain forms were caught. Decoding and comment-stripping fixes the
 * whole class at once, which is cheaper and more durable than writing a rule
 * per evasion trick.
 */
function canonicalisePayload(raw: string): string {
  let s = raw;
  // Bounded recursive URL-decode: catches %252e (double-encoded) without
  // looping forever on adversarial input.
  for (let i = 0; i < 3; i++) {
    let next: string;
    try { next = decodeURIComponent(s.replace(/\+/g, ' ')); } catch { break; }
    if (next === s) break;
    s = next;
  }
  // MySQL executable comments and inline comments used to break up keywords.
  s = s.replace(/\/\*![\d]*([^*]*)\*\//g, '$1');
  s = s.replace(/\/\*[^*]*\*\//g, ' ');
  // HTML entity forms of the characters that matter most.
  s = s.replace(/&#x?([0-9a-f]+);?/gi, (_m, c) => {
    const n = parseInt(c, /^[0-9]+$/.test(c) ? 10 : 16);
    return Number.isFinite(n) && n < 0x110000 ? String.fromCodePoint(n) : ' ';
  });
  return s;
}

export function classifyPayload(rawPayload: unknown): ClassificationResult {
  const original = String(rawPayload ?? '');
  // Match against BOTH forms: canonicalisation can dissolve a signature that
  // was only present in the raw text, so a hit in either counts.
  const canonical = canonicalisePayload(original);
  const payload = original === canonical ? original : original + '\n' + canonical;
  const entropy = payload ? shannonEntropy(payload) : 0;

  if (!payload.trim()) {
    return { family: 'CLEAN_TRAFFIC', score: 0, malicious: false, signatures: [], entropy };
  }

  const guard = BENIGN_GUARDS.find(g => g.re.test(payload));
  const prose = looksLikeProse(payload);

  // Accumulate per family so the dominant family wins rather than a blend.
  const byFamily = new Map<AttackFamily, { score: number; sigs: string[] }>();
  for (const rule of RULES) {
    if (!rule.re.test(payload)) continue;
    // Prose suppresses the weak SQL signals only; a UNION SELECT in a sentence
    // is still a UNION SELECT.
    if (prose && rule.family === 'SQL_INJECTION' && rule.weight < 50) continue;
    const cur = byFamily.get(rule.family) ?? { score: 0, sigs: [] };
    cur.score += rule.weight;
    cur.sigs.push(rule.label);
    byFamily.set(rule.family, cur);
  }

  // Very high entropy in a short payload suggests packing/encoding, but it is
  // corroboration only — it never convicts on its own.
  if (entropy >= 5.2 && payload.length >= 40 && byFamily.size > 0) {
    const top = [...byFamily.entries()].sort((a, b) => b[1].score - a[1].score)[0];
    top[1].score += 10;
    top[1].sigs.push(`high entropy (${entropy.toFixed(2)})`);
  }

  if (byFamily.size === 0) {
    return { family: 'CLEAN_TRAFFIC', score: 0, malicious: false, signatures: guard ? [guard.label] : [], entropy };
  }

  const [family, agg] = [...byFamily.entries()].sort((a, b) => b[1].score - a[1].score)[0];
  let score = Math.min(100, agg.score);
  const signatures = [...agg.sigs];

  if (guard) {
    // A guard halves the score rather than clearing it: a benign-looking
    // wrapper should not be able to launder an unambiguous payload.
    score = Math.round(score / 2);
    signatures.push(`benign context: ${guard.label}`);
  }

  return {
    family: score >= BLOCK_THRESHOLD ? family : 'CLEAN_TRAFFIC',
    score,
    malicious: score >= BLOCK_THRESHOLD,
    signatures,
    entropy
  };
}
