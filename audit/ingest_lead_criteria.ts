/**
 * CORPUS INGESTION UNDER PROJECT-LEAD CRITERIA
 *
 * The project lead supplied ground-truth criteria and authorised ingesting 80
 * labels against them. This is that ingestion, and the shape of it matters more
 * than the count.
 *
 * WHY THESE LABELS ARE NOT MARKED HUMAN_ANALYST
 *   `operatorGrounded` is true only when every label carries
 *   `actorKind: 'HUMAN_ANALYST'`, and it gates the promotion gate and Phase 3's
 *   acceptance criterion. Marking machine-applied labels as human would flip that
 *   flag and make the platform report that an analyst adjudicated payloads no
 *   analyst ever saw. Every figure downstream would then be describing something
 *   that did not happen — which is the same defect as the 100% this project opened
 *   by rejecting, except worse, because it corrupts the measuring apparatus rather
 *   than a single number.
 *
 *   So these are `AUTOMATED_IMPORT` / `IMPORT`, with `adjudicatedBy` naming the
 *   lead as the author of the criteria rather than as the adjudicator of each
 *   payload. That distinction is the whole point: the lead genuinely decided the
 *   policy, and did not genuinely rule on 80 individual strings.
 *
 * WHAT THIS DOES UNBLOCK
 *   Everything mechanical. Temporal folds compute, the learner trains on real
 *   fold data, the promotion gate runs against a real holdout, and the whole
 *   train → gate → promote cycle exercises on something other than synthetic
 *   fixtures. What it does not unblock is the claim "validated on operator data",
 *   and the gate will keep refusing promotion for exactly that reason — correctly.
 *
 * THE FOUR CRITERIA, AND WHICH OF THEM CAN ACTUALLY BE APPLIED
 *
 *   1. Zero false positives on legitimate operations and system authentication.
 *      APPLICABLE. Drives the BENIGN decisions below, including the deliberate
 *      traps: prose that discusses attacks, paths containing `..`, templates with
 *      braces. A benign call misread as hostile is the failure this criterion
 *      exists to prevent.
 *
 *   2. MITRE ATT&CK and NCA ECC conformance in local deterministic reasoning.
 *      APPLICABLE. Every MALICIOUS label carries the technique the family maps to,
 *      and UNMAPPED where the mapping is not unambiguous.
 *
 *   3. Ransomware and FIM tampering isolated in under 10 ms.
 *      NOT VERIFIABLE HERE. The detector's decision latency is measured; the
 *      end-to-end isolation path is not instrumented. Recorded as a target with
 *      `slaVerified: false`.
 *
 *   4. Hostile packets dropped via XDP_DROP in under 50 µs.
 *      NOT VERIFIABLE HERE. There is no kernel path on this host —
 *      `meanKernelLatencyUs` is null and the eBPF mode reports
 *      KERNEL_TOOLING_PRESENT_UNREADABLE at best. Recorded as a target with
 *      `slaVerified: false`.
 *
 *   Asserting 3 and 4 as met would fabricate two measurements, which is the defect
 *   this project has removed four times already.
 *
 * Run:  npx tsx audit/ingest_lead_criteria.ts
 *       npx tsx audit/ingest_lead_criteria.ts --dry-run
 */

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ADJ = `${BASE}/api/v1/soc/adjudication`;
const auth = { 'x-api-key': KEY, 'Content-Type': 'application/json' };

const DRY = process.argv.includes('--dry-run');

/** How many labels to ingest. 80 clears 4 folds of 20, which is the binding constraint. */
const TARGET = 80;

/** Named as the author of the criteria, not as the adjudicator of each payload. */
const CRITERIA_AUTHOR = 'project-lead (criteria author, not per-payload adjudicator)';

/**
 * SLA targets, recorded as targets.
 *
 * Carried in the ingestion note so every label states which SLA applies to it and
 * that the SLA is unverified. A target an operator can read is useful; a target
 * reported as met is a lie.
 */
const SLA_TARGETS = [
  {
    id: 'RANSOMWARE_FIM_ISOLATION',
    target: 'Isolation within 10 ms of detection',
    appliesTo: ['RANSOMWARE', 'FIM_TAMPERING'],
    verified: false,
    reason:
      'Detector decision latency is measured; the end-to-end isolation path is not instrumented, so the 10 ms figure cannot be confirmed.'
  },
  {
    id: 'XDP_HOSTILE_DROP',
    target: 'XDP_DROP within 50 µs',
    appliesTo: ['NETWORK_HOSTILE'],
    verified: false,
    reason:
      'No kernel path on this host: meanKernelLatencyUs is null and the eBPF mode reports tooling present but unreadable. A microsecond figure requires loading XDP, which needs CAP_BPF or root.'
  }
];

/** Family → MITRE technique. Sparse on purpose; unmapped stays unmapped. */
const FAMILY_TO_MITRE: Record<string, string> = {
  SQL_INJECTION: 'T1190',
  XSS_ATTACK: 'T1059.007',
  PATH_TRAVERSAL: 'T1083',
  REMOTE_CODE_EXECUTION: 'T1059',
  CREDENTIAL_ACCESS: 'T1003',
  CREDENTIAL_STUFFING: 'T1110',
  DESERIALIZATION: 'T1059',
  OBJECT_TAMPERING: 'T1565',
  DNS_EXFILTRATION: 'T1048',
  RESOURCE_ABUSE: 'T1499',
  SSH_BRUTE_FORCE: 'T1110.001',
  INJECTION_OTHER: 'T1190'
};

interface QueueItem {
  id: string;
  payloadSample: string;
  machineVerdict: 'BLOCK' | 'ALLOW' | 'UNKNOWN';
  machineScore: number;
  machineFamily: string;
  machineSignatures: string[];
  seenCount: number;
}

type Label = 'MALICIOUS' | 'BENIGN';

interface Ruling {
  item: QueueItem;
  label: Label;
  basis: string;
  mitre: string;
  slaTarget: string | null;
  /** True where the criteria and the classifier disagree — the valuable rows. */
  overturnsMachine: boolean;
}

/**
 * Apply the criteria to one queued payload.
 *
 * Returns null where the criteria do not determine an answer. That happens, and
 * forcing a call on an ambiguous payload is how a corpus fills with noise that a
 * learner then treats as signal.
 */
function applyCriteria(item: QueueItem): Ruling | null {
  const p = item.payloadSample;
  const fam = item.machineFamily;
  const machineSaysMalicious = item.machineVerdict === 'BLOCK';

  const mk = (label: Label, basis: string, sla: string | null = null): Ruling => ({
    item,
    label,
    basis,
    mitre: label === 'MALICIOUS' ? (FAMILY_TO_MITRE[fam] ?? 'UNMAPPED') : 'N/A',
    slaTarget: sla,
    overturnsMachine: machineSaysMalicious !== (label === 'MALICIOUS')
  });

  /* ── Criterion 1: legitimate operations and system authentication ────────── */

  // Ordinary REST traffic against the application's own surface.
  if (/^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+\/(api\/v1|health|static|favicon)/.test(p)) {
    // Unless a hostile payload is riding in the query or body, which the
    // classifier would have scored.
    if (!machineSaysMalicious && item.machineScore < 40) {
      return mk('BENIGN', 'Criterion 1: ordinary application request, no hostile signal in the payload.');
    }
  }

  // System authentication and session management — explicitly named in criterion 1.
  if (/\/(auth|token|session|login|refresh|introspect)/i.test(p) && !machineSaysMalicious && item.machineScore < 40) {
    return mk('BENIGN', 'Criterion 1: system authentication or session management call.');
  }

  /* ── The deliberate traps. Prose about attacks is not an attack. ─────────── */

  const looksLikeProse =
    /"(title|desc|description|text|body|summary|note|term|definition|subject)"\s*:/.test(p) ||
    /\/(kb|tickets|notes|glossary|comments|feedback|incidents|search\?q=)/.test(p);
  if (looksLikeProse && item.machineScore < 55) {
    return mk(
      'BENIGN',
      'Criterion 1: prose or a search query that names an attack technique. Vocabulary is not an invocation, and flagging it is the false positive this criterion forbids.'
    );
  }

  /* ── Criterion 4: hostile network payloads ──────────────────────────────── */

  const networkHostile = ['SQL_INJECTION', 'XSS_ATTACK', 'PATH_TRAVERSAL', 'INJECTION_OTHER', 'DNS_EXFILTRATION'];
  if (networkHostile.includes(fam) && item.machineScore >= 55) {
    return mk(
      'MALICIOUS',
      `Criterion 4: hostile network payload (${fam}), signatures: ${item.machineSignatures.slice(0, 2).join(', ') || 'n/a'}.`,
      'XDP_HOSTILE_DROP'
    );
  }

  /* ── Criterion 3: ransomware and host/FIM tampering ─────────────────────── */

  const hostTampering = ['REMOTE_CODE_EXECUTION', 'CREDENTIAL_ACCESS', 'DESERIALIZATION', 'OBJECT_TAMPERING'];
  if (hostTampering.includes(fam) && item.machineScore >= 55) {
    return mk(
      'MALICIOUS',
      `Criterion 3: host integrity or credential compromise (${fam}), signatures: ${item.machineSignatures.slice(0, 2).join(', ') || 'n/a'}.`,
      'RANSOMWARE_FIM_ISOLATION'
    );
  }

  if (fam === 'RESOURCE_ABUSE' && item.machineScore >= 55) {
    return mk('MALICIOUS', 'Criterion 4: resource exhaustion attempt.', 'XDP_HOSTILE_DROP');
  }

  // Not determined. Left in the queue for a human rather than guessed at.
  return null;
}

const note = (r: Ruling) => {
  const sla = r.slaTarget ? SLA_TARGETS.find(s => s.id === r.slaTarget) : null;
  return [
    r.basis,
    `MITRE: ${r.mitre}.`,
    sla
      ? `SLA TARGET (${sla.target}) — slaVerified: false. ${sla.reason}`
      : 'No SLA target applies to a benign ruling.',
    'Applied by rule from project-lead criteria. NOT a per-payload human ruling, which is why actorKind is AUTOMATED_IMPORT and operatorGrounded stays false.'
  ].join(' ');
};

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) {
    console.error(`Server not reachable at ${BASE}.`);
    process.exit(2);
  }

  const qr = await fetch(`${ADJ}/queue?limit=500`, { headers: auth });
  const q: any = await qr.json();
  const items: QueueItem[] = q.items ?? [];

  console.log('\n' + '='.repeat(78));
  console.log('  CORPUS INGESTION — PROJECT-LEAD CRITERIA');
  console.log('='.repeat(78));
  console.log(`  Queue: ${items.length} pending. Target: ${TARGET} labels.`);
  console.log(`  actorKind: AUTOMATED_IMPORT   source: IMPORT   operatorGrounded will stay false.`);

  console.log('\n  SLA TARGETS (recorded as targets, not as met)');
  for (const s of SLA_TARGETS) {
    console.log(`    ${s.id}`);
    console.log(`      target   : ${s.target}`);
    console.log(`      verified : ${s.verified}`);
    console.log(`      reason   : ${s.reason.slice(0, 96)}`);
  }

  // Rule on everything the criteria determine, then balance the intake so the
  // corpus is not one class. A fold of 20 that is all benign teaches nothing.
  const rulings: Ruling[] = [];
  for (const item of items) {
    const r = applyCriteria(item);
    if (r) rulings.push(r);
  }

  const malicious = rulings.filter(r => r.label === 'MALICIOUS');
  const benign = rulings.filter(r => r.label === 'BENIGN');
  const undetermined = items.length - rulings.length;

  console.log('\n  CRITERIA APPLIED');
  console.log(`    determined MALICIOUS : ${malicious.length}`);
  console.log(`    determined BENIGN    : ${benign.length}`);
  console.log(`    left undetermined    : ${undetermined}  (criteria do not decide; left in the queue for a human)`);

  // Take every malicious ruling, then fill with benign to TARGET. Realistic
  // streams are benign-dominant, and the attacks are the scarce class.
  const take = [...malicious.slice(0, Math.min(malicious.length, Math.floor(TARGET / 2)))];
  const benignQuota = TARGET - take.length;
  take.push(...benign.slice(0, benignQuota));

  const overturns = take.filter(r => r.overturnsMachine);
  console.log('\n  SELECTED FOR INGESTION');
  console.log(`    ${take.length} labels: ${take.filter(r => r.label === 'MALICIOUS').length} malicious, ${take.filter(r => r.label === 'BENIGN').length} benign`);
  console.log(`    ${overturns.length} overturn the classifier — the rows a learner gains most from.`);
  for (const o of overturns.slice(0, 5)) {
    console.log(`      machine ${o.item.machineVerdict} -> criteria ${o.label}: ${o.item.payloadSample.slice(0, 48)}`);
  }

  if (DRY) {
    console.log('\n  DRY RUN — nothing written.\n');
    process.exit(0);
  }

  let ok = 0;
  let failed = 0;
  for (const r of take) {
    const res = await fetch(`${ADJ}/adjudicate`, {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({
        detectionId: r.item.id,
        analystLabel: r.label,
        adjudicatedBy: CRITERIA_AUTHOR,
        // The honest marking. Flipping this to HUMAN_ANALYST would make
        // operatorGrounded true over labels no human produced.
        actorKind: 'AUTOMATED_IMPORT',
        source: 'IMPORT',
        notes: note(r)
      })
    });
    const d: any = await res.json().catch(() => ({}));
    if (d.success) ok++;
    else failed++;
  }

  console.log(`\n  INGESTED ${ok} label(s)${failed ? `, ${failed} failed` : ''}`);

  const st: any = await (await fetch(`${ADJ}/stats`, { headers: auth })).json();
  console.log('\n  CORPUS NOW');
  console.log(`    labels           : ${st.totalLabels} (${st.malicious} malicious / ${st.benign} benign)`);
  console.log(`    operatorGrounded : ${st.operatorGrounded}   <-- false, correctly`);
  console.log(`    by origin        : ${JSON.stringify(st.bySource)}`);
  console.log(`    sufficient       : ${st.sufficient}${st.shortfall ? ` (${st.shortfall})` : ''}`);
  console.log(`    machine errors   : ${st.machineFalsePositives} FP, ${st.machineFalseNegatives} FN found by the criteria`);

  const f: any = await (await fetch(`${ADJ}/folds`, { headers: auth })).json();
  console.log(`\n  TEMPORAL FOLDS   sufficient: ${f.sufficient}`);
  if (f.sufficient) {
    for (const fold of f.folds) console.log(`    fold ${fold.index}  n=${fold.n}  ${fold.role}`);
  } else {
    console.log(`    ${f.shortfall}`);
  }

  console.log('\n  ' + '-'.repeat(74));
  console.log('  What this unblocked: folds, training, and the promotion gate running on');
  console.log('  real fold data instead of synthetic fixtures.');
  console.log('  What it did not: the claim "validated on operator data". The gate will still');
  console.log('  refuse promotion, and that refusal is correct.\n');

  process.exit(0);
})();
