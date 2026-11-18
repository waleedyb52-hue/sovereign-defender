/**
 * Detection regression gate shared by the harnesses.
 *
 * Every harness used to end with process.exit(0) whatever it measured, so the CI steps that
 * ran them could only fail if the server was down — a recall collapse would have passed. With
 * --gate on the command line, a harness compares what it measured against the floors in
 * audit/regression_gate.json and exits 1, naming each figure that fell below its floor.
 * Without --gate the harnesses behave exactly as before.
 */
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'regression_gate.json');

export const gateRequested = process.argv.includes('--gate');

export function gateFloors(section: string): any {
  const all = JSON.parse(fs.readFileSync(FILE, 'utf-8'));
  if (!all[section]) throw new Error(`regression_gate.json has no section "${section}"`);
  return all[section];
}

/** Each check: [description, measured, floor or ceiling, 'min' | 'max']. */
export function enforceGate(section: string, checks: Array<[string, number, number, 'min' | 'max']>): void {
  if (!gateRequested) return;
  const failures = checks.filter(([, measured, bound, kind]) => (kind === 'min' ? measured < bound : measured > bound));
  console.log(`\n  REGRESSION GATE (${section}, audit/regression_gate.json)`);
  for (const [name, measured, bound, kind] of checks) {
    const ok = kind === 'min' ? measured >= bound : measured <= bound;
    console.log(`    ${ok ? 'ok  ' : 'FAIL'}  ${name.padEnd(34)} ${String(measured).padStart(8)}  ${kind === 'min' ? '>=' : '<='} ${bound}`);
  }
  if (failures.length) {
    console.log(`\n  GATE: FAIL — ${failures.length} figure(s) regressed`);
    process.exit(1);
  }
  console.log('\n  GATE: PASS');
}
