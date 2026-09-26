/**
 * SCENARIO CAPABILITY REPORT
 *
 * Scores the platform against the four supplied ground-truth scenarios and states
 * plainly which sensors exist and which do not.
 *
 * This is the artefact the specification actually needed. It was asked for as
 * "inject the dataset to achieve 100% validation", but a score of 100% against
 * author-supplied records measures nothing — and three of the four scenarios
 * describe sensors this repository does not contain, so the only route to 100%
 * would be writing detectors keyed to these exact four rows.
 *
 * What this reports instead:
 *   - Sensor coverage, established by scanning the repository rather than asserted.
 *   - Whether a scenario can even be fed to the platform today.
 *   - For those that can, the verdict and the measured latency against the SLA.
 *   - A per-scenario readiness verdict: READY, PARTIAL or NO_SENSOR.
 *
 * A low score is the roadmap. It is the most useful thing this file can produce
 * before a judging panel, because it is the thing the panel will otherwise find.
 *
 * Run:  npx tsx audit/scenario_capability_report.ts
 */

import fs from 'fs';
import path from 'path';
import { GROUND_TRUTH_SCENARIOS, SENSOR_PROBES } from './ground_truth_scenarios.js';

const BASE = 'http://127.0.0.1:3000';
const KEY = process.env.ADMIN_API_KEY || 'test_admin_key_123';
const ROOT = process.cwd();

/** Directories scanned for sensor implementations. */
const SCAN_DIRS = ['server', 'ebpf'];

function walk(dir: string, out: string[] = []): string[] {
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out);
    else if (/\.(ts|c|h)$/.test(e.name)) out.push(p);
  }
  return out;
}

function scanSensors() {
  const files = SCAN_DIRS.flatMap(d => walk(path.join(ROOT, d)));
  const corpus = files
    .map(f => {
      try {
        return fs.readFileSync(f, 'utf-8');
      } catch {
        return '';
      }
    })
    .join('\n');

  const coverage: Record<string, { present: boolean; note: string }> = {};
  for (const [sensor, { pattern, note }] of Object.entries(SENSOR_PROBES)) {
    coverage[sensor] = { present: pattern.test(corpus), note };
  }
  return { coverage, fileCount: files.length };
}

async function probe(payload: string, nonce: number) {
  const started = Date.now();
  const res = await fetch(`${BASE}/api/v1/agent/ai-analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': KEY },
    body: JSON.stringify({
      packet: {
        srcIp: `10.0.0.${45 + nonce}`,
        dstIp: '10.0.1.10',
        port: 445,
        protocol: 'SMB',
        vector: 'UNKNOWN',
        payload
      }
    })
  });
  const wallMs = Date.now() - started;
  const d: any = await res.json().catch(() => ({}));
  return {
    verdict: String(d?.verdict ?? 'UNKNOWN'),
    score: Number(d?.detection?.score ?? 0),
    family: String(d?.detection?.family ?? 'UNKNOWN'),
    signatures: (d?.detection?.signatures ?? []) as string[],
    detectionLatencyMs: Number(d?.detectionLatencyMs ?? NaN),
    wallMs
  };
}

(async () => {
  const health = await fetch(`${BASE}/api/health`).catch(() => null);
  if (!health?.ok) {
    console.error(`Server not reachable at ${BASE}.`);
    process.exit(2);
  }

  const { coverage, fileCount } = scanSensors();

  console.log('\n' + '='.repeat(74));
  console.log('  GROUND-TRUTH SCENARIO CAPABILITY REPORT');
  console.log('='.repeat(74));
  console.log(`  Scanned ${fileCount} source files across ${SCAN_DIRS.join(', ')} for sensor implementations.`);
  console.log('  Coverage is detected, not declared.');

  let ready = 0;
  let partial = 0;
  let missing = 0;
  const gaps = new Set<string>();

  for (const [i, sc] of GROUND_TRUTH_SCENARIOS.entries()) {
    const have = sc.requiredSensors.filter(s => coverage[s]?.present);
    const lack = sc.requiredSensors.filter(s => !coverage[s]?.present);
    lack.forEach(l => gaps.add(l));

    const verdictTag =
      lack.length === 0 ? 'READY' : have.length === 0 ? 'NO_SENSOR' : 'PARTIAL';
    if (verdictTag === 'READY') ready++;
    else if (verdictTag === 'PARTIAL') partial++;
    else missing++;

    console.log('\n' + '-'.repeat(74));
    console.log(`  ${sc.scenarioId}`);
    console.log(`    ${sc.titleEn}  ·  ${sc.mitreTechnique}  ·  ${sc.domain}`);
    console.log(`    expected action : ${sc.groundTruth.action}`);
    const sla =
      sc.groundTruth.slaLatencyMicros != null
        ? `${sc.groundTruth.slaLatencyMicros} µs`
        : sc.groundTruth.maxDetectionWindowMs != null
          ? `${sc.groundTruth.maxDetectionWindowMs} ms`
          : 'none stated';
    console.log(`    SLA             : ${sla}`);
    console.log(`    readiness       : ${verdictTag}   (${have.length}/${sc.requiredSensors.length} sensors present)`);
    if (lack.length) {
      console.log(`    MISSING SENSORS : ${lack.map(l => coverage[l]?.note ?? l).join(', ')}`);
    }

    if (sc.probePayload) {
      const r = await probe(sc.probePayload, i);
      const detected = r.verdict !== 'ALLOW';
      console.log(`    probe           : fed a payload-shaped approximation`);
      console.log(`      verdict ${r.verdict}  score ${r.score}  family ${r.family}`);
      if (r.signatures.length) console.log(`      signatures ${JSON.stringify(r.signatures.slice(0, 3))}`);
      console.log(`      detection latency ${Number.isFinite(r.detectionLatencyMs) ? r.detectionLatencyMs + ' ms' : 'not reported'} (wall ${r.wallMs} ms)`);
      if (!detected) {
        console.log(`      NOT DETECTED — the approximation passed as benign.`);
      }
      // The SLA is stated in microseconds for a kernel path. Nothing here runs in
      // the kernel on this host, so the comparison is reported rather than judged.
      if (sc.groundTruth.slaLatencyMicros != null) {
        console.log(
          `      SLA note: ${sc.groundTruth.slaLatencyMicros} µs is a kernel-path budget; this measurement is a` +
            ` userspace round trip and is not comparable.`
        );
      }
    } else {
      console.log(`    probe           : NONE — no ingress path accepts this telemetry shape.`);
      console.log(`      This scenario carries ${Object.keys(sc.telemetryInput).join(', ')},`);
      console.log(`      which no endpoint consumes. No approximation is invented for it.`);
    }
  }

  console.log('\n' + '='.repeat(74));
  console.log('  SUMMARY');
  console.log(`    READY      ${ready}/${GROUND_TRUTH_SCENARIOS.length}`);
  console.log(`    PARTIAL    ${partial}/${GROUND_TRUTH_SCENARIOS.length}`);
  console.log(`    NO_SENSOR  ${missing}/${GROUND_TRUTH_SCENARIOS.length}`);

  if (gaps.size) {
    console.log(`\n  SENSORS TO BUILD  (${gaps.size})`);
    for (const g of [...gaps].sort()) {
      console.log(`    - ${coverage[g]?.note ?? g}`);
    }
  }

  console.log('\n  ' + '-'.repeat(70));
  console.log('  These scenarios are NOT in eval_harness.ts. Injecting author-supplied');
  console.log('  ground truth into the harness to reach 100% would stop the harness');
  console.log('  measuring anything — which is the defect this project opened with.');
  console.log('  Read this report as the build order, not as a score.\n');

  process.exit(0);
})();
