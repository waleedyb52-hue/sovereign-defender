/**
 * INTERACTIVE ADJUDICATION — terminal triage for the analyst
 *
 * The corpus has 80 machine-applied labels and none of them disagree with the
 * classifier, because the rules that produced them used the classifier's own
 * thresholds. A learner trained on that can approximate the detector and cannot
 * exceed it. The labels that carry information are the DISAGREEMENTS, and only a
 * human produces those.
 *
 * This is the surface for producing them. Every ruling made here is recorded as
 * `HUMAN_ANALYST`, which is what `operatorGrounded` requires, which is what the
 * promotion gate requires, which is what Phase 3's acceptance criterion requires.
 * Nothing else in the codebase may write that provenance — the machine-applied
 * ingestion deliberately did not.
 *
 * ON THE VOCABULARY
 *   Allow / Drop / Quarantine are RESPONSE ACTIONS. The corpus stores a LABEL:
 *   was this payload hostile or not. They are different questions and conflating
 *   them corrupts the ground truth, because two payloads can share a label and
 *   warrant different responses.
 *
 *     Allow      -> label BENIGN
 *     Drop       -> label MALICIOUS, recommended action DROP
 *     Quarantine -> label MALICIOUS, recommended action QUARANTINE
 *
 *   The action is recorded in the note so the operator's intent survives, while
 *   the label stays the single binary fact a detector can be scored against.
 *
 * ON ORDERING
 *   Cases are sorted by information value, not by arrival. A payload the classifier
 *   scored in the borderline band, or one seen many times, teaches more per ruling
 *   than an obvious one. The point is to spend the analyst's attention where a
 *   disagreement is plausible.
 *
 * USAGE
 *   npx tsx audit/adjudicate_cli.ts --peek           # show the next case, no prompt
 *   npx tsx audit/adjudicate_cli.ts --peek --count 5 # show the next five
 *   npx tsx audit/adjudicate_cli.ts --as "waleed"    # interactive session
 *
 *   Interactive keys:  a = allow (benign)   d = drop (malicious)
 *                      q = quarantine (malicious)   s = skip
 *                      ? = why this case ranks here   x = save and exit
 */

import readline from 'node:readline';

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ADJ = `${BASE}/api/v1/soc/adjudication`;
const auth = { 'x-api-key': KEY, 'Content-Type': 'application/json' };

const argv = process.argv.slice(2);
const PEEK = argv.includes('--peek');
const countIdx = argv.indexOf('--count');
const PEEK_COUNT = countIdx >= 0 ? Math.max(1, Number(argv[countIdx + 1]) || 1) : 1;
const asIdx = argv.indexOf('--as');
const ANALYST = asIdx >= 0 ? argv[asIdx + 1] : process.env.SD_ANALYST || '';

interface QueueItem {
  id: string;
  payloadSample: string;
  machineVerdict: 'BLOCK' | 'ALLOW' | 'UNKNOWN';
  machineScore: number;
  machineFamily: string;
  machineSignatures: string[];
  srcIp: string;
  detectedAt: string;
  seenCount: number;
}

/** Family → MITRE, sparse. Shown as context, never asserted where ambiguous. */
const MITRE: Record<string, string> = {
  SQL_INJECTION: 'T1190 Exploit Public-Facing Application',
  XSS_ATTACK: 'T1059.007 Command and Scripting Interpreter: JavaScript',
  PATH_TRAVERSAL: 'T1083 File and Directory Discovery',
  REMOTE_CODE_EXECUTION: 'T1059 Command and Scripting Interpreter',
  CREDENTIAL_ACCESS: 'T1003 OS Credential Dumping',
  CREDENTIAL_STUFFING: 'T1110 Brute Force',
  DESERIALIZATION: 'T1059 Command and Scripting Interpreter',
  OBJECT_TAMPERING: 'T1565 Data Manipulation',
  DNS_EXFILTRATION: 'T1048 Exfiltration Over Alternative Protocol',
  RESOURCE_ABUSE: 'T1499 Endpoint Denial of Service',
  SSH_BRUTE_FORCE: 'T1110.001 Password Guessing',
  INJECTION_OTHER: 'T1190 Exploit Public-Facing Application'
};

/**
 * Information value of ruling on this case.
 *
 * Highest for payloads in the borderline band, because that is where the
 * classifier is least certain and a human is most likely to disagree. Repeat
 * sightings add value because one ruling then covers recurring traffic. An
 * obvious clean GET adds almost nothing.
 */
function informationValue(i: QueueItem): { score: number; why: string[] } {
  const why: string[] = [];
  let v = 0;

  if (i.machineScore >= 40 && i.machineScore < 55) {
    v += 50;
    why.push(`score ${i.machineScore} sits in the borderline band [40,55) where the classifier is least certain`);
  } else if (i.machineScore > 0 && i.machineScore < 40) {
    v += 25;
    why.push(`score ${i.machineScore} is a weak signal the rules did not act on`);
  } else if (i.machineScore >= 55) {
    v += 10;
    why.push(`score ${i.machineScore} is a confident block; a ruling mainly confirms it`);
  } else {
    v += 5;
    why.push('score 0; the rules found nothing, so a ruling is only valuable if they were wrong');
  }

  if (i.seenCount > 1) {
    v += Math.min(20, i.seenCount * 3);
    why.push(`seen ${i.seenCount} times, so one ruling covers recurring traffic`);
  }

  // Prose and template shapes are where false positives hide.
  if (/"(title|desc|text|body|note|term|summary)"\s*:/.test(i.payloadSample) || /\{\{|\bq=/.test(i.payloadSample)) {
    v += 15;
    why.push('contains prose or template syntax, the shapes where false positives hide');
  }

  if (i.machineFamily !== 'CLEAN_TRAFFIC') {
    v += 8;
    why.push(`classifier assigned family ${i.machineFamily}`);
  }

  return { score: v, why };
}

function render(i: QueueItem, rank: number, total: number) {
  const iv = informationValue(i);
  const bar = '─'.repeat(74);
  console.log('\n┌' + bar + '┐');
  console.log(`│ CASE ${rank}/${total}`.padEnd(75) + '│');
  console.log('├' + bar + '┤');

  // The payload, wrapped. This is the thing being judged, so it gets room.
  const p = i.payloadSample;
  for (let x = 0; x < p.length && x < 444; x += 72) {
    console.log('│ ' + p.slice(x, x + 72).padEnd(72) + ' │');
  }
  if (p.length > 444) console.log('│ ' + `… ${p.length - 444} more characters`.padEnd(72) + ' │');

  console.log('├' + bar + '┤');
  const line = (k: string, v: string) => console.log('│ ' + `${k.padEnd(18)} ${v}`.slice(0, 72).padEnd(72) + ' │');
  line('classifier says', `${i.machineVerdict}  score ${i.machineScore}  ${i.machineFamily}`);
  line('signatures', i.machineSignatures.length ? i.machineSignatures.slice(0, 2).join(', ') : '(none fired)');
  line('MITRE (context)', MITRE[i.machineFamily] ?? 'UNMAPPED — no unambiguous mapping');
  line('source', `${i.srcIp}   seen ${i.seenCount}x   ${i.detectedAt.slice(0, 19)}`);
  line('information value', String(iv.score));
  console.log('└' + bar + '┘');

  // The question, phrased as the label rather than the action, because that is
  // what the corpus stores.
  console.log('\n  Was this payload hostile?');
  console.log('    [a] allow      → label BENIGN     (legitimate traffic)');
  console.log('    [d] drop       → label MALICIOUS  (hostile, drop the packet)');
  console.log('    [q] quarantine → label MALICIOUS  (hostile, isolate the source)');
  console.log('    [s] skip       → leave in the queue, decide later');
  console.log('    [?] why this case ranks here      [x] save and exit');
  return iv;
}

async function fetchQueue(): Promise<QueueItem[]> {
  const r = await fetch(`${ADJ}/queue?limit=500`, { headers: auth });
  const d: any = await r.json();
  const items: QueueItem[] = d.items ?? [];
  return items.sort((a, b) => informationValue(b).score - informationValue(a).score);
}

async function submit(item: QueueItem, label: 'MALICIOUS' | 'BENIGN', action: string, analyst: string) {
  const res = await fetch(`${ADJ}/adjudicate`, {
    method: 'POST',
    headers: auth,
    body: JSON.stringify({
      detectionId: item.id,
      analystLabel: label,
      adjudicatedBy: analyst,
      // The one place in this repository that writes HUMAN_ANALYST. A human made
      // this call, looking at this payload.
      actorKind: 'HUMAN_ANALYST',
      source: 'LIVE_TRAFFIC',
      notes: `Human ruling in terminal triage. Recommended action: ${action}. Classifier said ${item.machineVerdict} at score ${item.machineScore} (${item.machineFamily}). ${
        (item.machineVerdict === 'BLOCK') !== (label === 'MALICIOUS')
          ? 'OVERTURNS the classifier — this is the informative case.'
          : 'Upholds the classifier.'
      }`
    })
  });
  const d: any = await res.json().catch(() => ({}));
  return { ok: Boolean(d.success), overturned: Boolean(d.overturnedMachine), error: d.error as string | undefined };
}

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) {
    console.error(`\n  Server not reachable at ${BASE}. Start it with:\n    ADMIN_API_KEY=<key> npx tsx server.ts\n`);
    process.exit(2);
  }

  const queue = await fetchQueue();
  const st: any = await (await fetch(`${ADJ}/stats`, { headers: auth })).json();

  console.log('\n' + '='.repeat(76));
  console.log('  ADJUDICATION TRIAGE');
  console.log('='.repeat(76));
  console.log(`  corpus: ${st.totalLabels} labels   operatorGrounded: ${st.operatorGrounded}   queue: ${queue.length}`);
  console.log('  Ordered by information value: borderline scores and repeat sightings first,');
  console.log('  because a disagreement is most likely — and most useful — there.');

  if (queue.length === 0) {
    console.log('\n  Queue is empty. Nothing to rule on.\n');
    process.exit(0);
  }

  if (PEEK) {
    for (let n = 0; n < Math.min(PEEK_COUNT, queue.length); n++) {
      const iv = render(queue[n], n + 1, queue.length);
      if (PEEK_COUNT > 1) console.log(`  why: ${iv.why[0]}`);
    }
    console.log('\n  Peek only — nothing recorded.');
    console.log(`  To rule interactively:  npx tsx audit/adjudicate_cli.ts --as "your-name"\n`);
    process.exit(0);
  }

  if (!ANALYST.trim()) {
    console.error('\n  --as "<your name>" is required. Provenance is not optional: a label without');
    console.error('  an identified adjudicator is an assertion, not a measurement.\n');
    process.exit(2);
  }

  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const ask = (q: string) => new Promise<string>(res => rl.question(q, a => res(a.trim().toLowerCase())));

  let ruled = 0;
  let overturns = 0;
  let idx = 0;

  while (idx < queue.length) {
    const item = queue[idx];
    const iv = render(item, idx + 1, queue.length);

    let handled = false;
    while (!handled) {
      const k = await ask('\n  > ');
      if (k === 'x') {
        handled = true;
        idx = queue.length;
      } else if (k === 's') {
        handled = true;
        idx++;
      } else if (k === '?') {
        console.log('\n  This case ranks here because:');
        for (const w of iv.why) console.log(`    - ${w}`);
      } else if (k === 'a' || k === 'd' || k === 'q') {
        const label = k === 'a' ? 'BENIGN' : 'MALICIOUS';
        const action = k === 'a' ? 'ALLOW' : k === 'd' ? 'DROP' : 'QUARANTINE';
        const r = await submit(item, label as 'MALICIOUS' | 'BENIGN', action, ANALYST);
        if (r.ok) {
          ruled++;
          if (r.overturned) overturns++;
          console.log(
            `  recorded ${label} (${action})${r.overturned ? '  ** OVERTURNS the classifier — informative **' : ''}`
          );
        } else {
          console.log(`  failed: ${r.error ?? 'unknown'}`);
        }
        handled = true;
        idx++;
      } else {
        console.log('  keys: a allow · d drop · q quarantine · s skip · ? why · x exit');
      }
    }
  }

  rl.close();

  const after: any = await (await fetch(`${ADJ}/stats`, { headers: auth })).json();
  console.log('\n' + '='.repeat(76));
  console.log(`  SESSION: ${ruled} ruling(s), ${overturns} overturning the classifier`);
  console.log(`  corpus now: ${after.totalLabels} labels   operatorGrounded: ${after.operatorGrounded}`);
  console.log(`  by adjudicator kind: ${JSON.stringify(after.byActorKind)}`);
  if (!after.operatorGrounded) {
    console.log('\n  operatorGrounded is still false because the corpus also holds machine-applied');
    console.log('  labels. It becomes true only when every active label is a human ruling — so');
    console.log('  either rule on the rest, or supersede the imported ones.');
  }
  console.log('');
  process.exit(0);
})();
