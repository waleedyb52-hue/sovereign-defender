// ReDoS SCAN — every regular expression in the server, timed against adversarial input
//
//   node audit/redos_scan.mjs [out.json]
//
// Why: a traversal rule added in the 48-hour pass backtracked quadratically (80 KB of dots
// blocked the event loop for 5 s), and a pre-existing DNS-exfiltration rule did the same on
// "/bin/bin/…". Both passed every functional test. Reading patterns by eye missed them, so
// this measures instead.
//
// What it does
//   1. Parses server.ts and every .ts file under server/ with the TypeScript compiler and
//      collects every regex literal and every `new RegExp('…', '…')` with literal arguments.
//      Nothing is copied by hand, so a new rule is covered the day it is written.
//   2. Runs each regex (without g/y, so each run is a full search) against inputs built from
//      every printable character, common separator pairs, and the words in the pattern itself
//      in several shapes ("union union …", "<img on <img on …", "host: x\n…", "eyJ-eyJ-…").
//   3. Times each input at 4,000 and 16,000 characters. Linear work grows ~4x; quadratic
//      ~16x. Suspects are re-run at 64,000 characters and confirmed if they exceed the budget.
//   4. Each file runs in a worker with a deadline, so exponential backtracking cannot hang the
//      scan; a regex that hits the deadline is reported as a timeout.
//
// Exit status 1 when any regex is confirmed super-linear or times out. CI runs this.
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import fs from 'node:fs';
import path from 'node:path';
import { performance } from 'node:perf_hooks';
import { fileURLToPath } from 'node:url';

const SMALL = 4_000;
const LARGE = 16_000;
const CONFIRM = 64_000;
/** A confirmed regex takes longer than this on CONFIRM characters. Linear ones take ~1 ms. */
const CONFIRM_BUDGET_MS = 150;
const PER_REGEX_DEADLINE_MS = 20_000;

if (isMainThread) {
  const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const files = ['server.ts', ...walk(path.join(ROOT, 'server')).map(f => path.relative(ROOT, f))]
    .filter(f => f.endsWith('.ts') && !f.endsWith('.test.ts'))
    .map(f => f.split(path.sep).join('/'))
    .sort();

  const { default: ts } = await import('typescript');
  const jobs = [];
  for (const file of files) {
    const src = fs.readFileSync(path.join(ROOT, file), 'utf-8');
    const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true);
    const found = [];
    const visit = node => {
      if (ts.isRegularExpressionLiteral(node)) {
        const text = node.text;
        const cut = text.lastIndexOf('/');
        found.push({ source: text.slice(1, cut), flags: text.slice(cut + 1), line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1 });
      } else if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'RegExp') {
        const [a, b] = node.arguments ?? [];
        if (a && (ts.isStringLiteral(a) || ts.isNoSubstitutionTemplateLiteral(a))) {
          const flags = b && (ts.isStringLiteral(b) || ts.isNoSubstitutionTemplateLiteral(b)) ? b.text : '';
          found.push({ source: a.text, flags, line: sf.getLineAndCharacterOfPosition(node.getStart()).line + 1 });
        }
      }
      ts.forEachChild(node, visit);
    };
    visit(sf);
    if (found.length) jobs.push({ file, regexes: found });
  }

  const total = jobs.reduce((n, j) => n + j.regexes.length, 0);
  console.error(`[redos] ${total} regexes in ${jobs.length} files`);
  const t0 = performance.now();
  const findings = [];
  let scanned = 0;
  for (const job of jobs) {
    let start = 0;
    while (start < job.regexes.length) {
      const res = await runWorker(job, start);
      scanned += res.done;
      findings.push(...res.findings);
      if (res.timedOutAt != null) {
        const r = job.regexes[res.timedOutAt];
        findings.push({ file: job.file, line: r.line, source: r.source, flags: r.flags, verdict: 'TIMEOUT', detail: `no result within ${PER_REGEX_DEADLINE_MS / 1000} s` });
        scanned++;
        start = res.timedOutAt + 1;
      } else start = job.regexes.length;
    }
  }

  const confirmed = findings.filter(f => f.verdict !== 'LINEAR');
  const report = {
    finishedAt: new Date().toISOString(), node: process.version, platform: process.platform,
    method: { sizes: [SMALL, LARGE, CONFIRM], confirmBudgetMs: CONFIRM_BUDGET_MS, perRegexDeadlineMs: PER_REGEX_DEADLINE_MS },
    files: jobs.length, regexes: total, scanned, seconds: +((performance.now() - t0) / 1000).toFixed(1),
    superLinear: confirmed
  };
  if (process.argv[2]) fs.writeFileSync(process.argv[2], JSON.stringify(report, null, 2) + '\n');
  for (const f of confirmed) console.log(`${f.verdict.padEnd(12)} ${f.file}:${f.line}  /${f.source.slice(0, 90)}/${f.flags}\n             ${f.detail}`);
  console.log(`\n[redos] ${scanned}/${total} regexes scanned in ${report.seconds} s — ${confirmed.length} super-linear or timed out`);
  process.exit(confirmed.length ? 1 : 0);
} else {
  const { job, start } = workerData;
  for (let i = start; i < job.regexes.length; i++) {
    parentPort.postMessage({ type: 'progress', i });
    const r = job.regexes[i];
    let re;
    try { re = new RegExp(r.source, r.flags.replace(/[gy]/g, '')); } catch { parentPort.postMessage({ type: 'done-one', i, finding: null }); continue; }
    parentPort.postMessage({ type: 'done-one', i, finding: probe(re, r) });
  }
  parentPort.postMessage({ type: 'finished' });
}

function runWorker(job, start) {
  return new Promise(resolve => {
    const w = new Worker(fileURLToPath(import.meta.url), { workerData: { job, start } });
    const findings = [];
    let current = start, done = 0, timer = null;
    const arm = () => { clearTimeout(timer); timer = setTimeout(() => { w.terminate(); resolve({ findings, done, timedOutAt: current }); }, PER_REGEX_DEADLINE_MS); };
    arm();
    w.on('message', m => {
      if (m.type === 'progress') { current = m.i; arm(); }
      else if (m.type === 'done-one') { done++; if (m.finding) findings.push({ file: job.file, ...m.finding }); }
      else if (m.type === 'finished') { clearTimeout(timer); w.terminate(); resolve({ findings, done, timedOutAt: null }); }
    });
    w.on('error', () => { clearTimeout(timer); resolve({ findings, done, timedOutAt: current }); });
  });
}

function probe(re, r) {
  const units = new Set();
  for (let c = 32; c < 127; c++) units.add(String.fromCharCode(c));
  for (const u of ['\n', '\t', '\r\n', 'a ', 'a.', '. ', '; ', '| ', '&& ', '/bin/', '0x2e', '..', '../', '%2e', '%25', '{a', '{ a ', '<a ', 'a=', "a'", '"a', '\\x', '-a', 'a-', '=a', 'a:', 'a\n', 'a/', '/a', 'a@', '@a', 'aa', 'a1', '1a', '1.', 'a,', 'a;', 'a(', '(a', 'a)', '<', '>a', 'a b ', 'A ', 'Aa', 'a\t']) units.add(u);
  const words = [...new Set((r.source.match(/[A-Za-z_][A-Za-z0-9_]{1,}/g) || []).filter(w => !/^[a-z]$/.test(w)))].slice(0, 30);
  for (const w of words) for (const shape of [w, w + ' ', w + '-', w + '.', w + '/', w + '\n', '<' + w + ' ', w + ': x\n', w + '(', w + '=', w + '{', w + "'", w + '_', ' ' + w + ' x', w.toUpperCase() + ' ']) units.add(shape);

  const time = (unit, n) => {
    const s = unit.repeat(Math.ceil(n / unit.length)).slice(0, n);
    const t = performance.now();
    re.test(s);
    return performance.now() - t;
  };
  let worst = null;
  for (const u of units) {
    const a = Math.max(time(u, SMALL), 0.05);
    const b = time(u, LARGE);
    if (b < 4 || b / a < 6) continue;
    const c = time(u, CONFIRM);
    if (c > CONFIRM_BUDGET_MS && (!worst || c > worst.ms)) worst = { unit: u, ms: c, small: a, large: b };
  }
  if (!worst) return null;
  return {
    line: r.line, source: r.source, flags: r.flags, verdict: 'SUPER_LINEAR',
    detail: `input ${JSON.stringify(worst.unit)} repeated: ${worst.small.toFixed(1)} ms @${SMALL}, ${worst.large.toFixed(1)} ms @${LARGE}, ${worst.ms.toFixed(0)} ms @${CONFIRM}`
  };
}

function walk(dir) {
  const out = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) out.push(...walk(p));
    else out.push(p);
  }
  return out;
}
