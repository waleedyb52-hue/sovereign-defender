import { describe, expect, it } from 'vitest';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';

/**
 * The pending-review queue is written behind the request path. These tests prove, against a
 * real SQLite file in a separate process, that a stop signal writes what is buffered — and,
 * as a control, that a hard kill does not, so the positive cases cannot pass by timing luck.
 *
 * On Linux (CI) the parent sends a real OS signal. On Windows, where one process cannot send
 * SIGTERM/SIGINT to another, the child raises the signal on itself on request; that exercises
 * the same handler but not the OS delivery, which only the Linux run proves.
 */

const FIXTURE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'shutdownChild.ts');
const ROWS = 25;
const realSignals = process.platform !== 'win32';

function pendingRows(dbPath: string): number {
  if (!fs.existsSync(dbPath)) return 0;
  const db = new DatabaseSync(dbPath);
  try {
    return Number((db.prepare('SELECT COUNT(*) AS n FROM pending_detections').get() as any).n);
  } finally {
    db.close();
  }
}

async function runChild(stop: 'SIGTERM' | 'SIGINT' | 'SIGKILL') {
  const dbPath = path.join(os.tmpdir(), `sd-shutdown-${process.pid}-${Date.now()}-${stop}.db`);
  const child = spawn(process.execPath, ['--import', 'tsx', FIXTURE, dbPath, String(ROWS)], {
    env: { ...process.env, SD_ADJUDICATION_FLUSH_MS: '600000' },
    stdio: ['ignore', 'pipe', 'pipe', 'ipc']
  });
  let stderr = '';
  child.stderr!.on('data', d => { stderr += d; });
  await new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('child never became ready: ' + stderr)), 20_000);
    child.stdout!.on('data', d => { if (String(d).includes('READY')) { clearTimeout(t); resolve(); } });
    child.on('exit', code => { clearTimeout(t); reject(new Error(`child exited early (${code}): ${stderr}`)); });
  });

  const rowsBefore = pendingRows(dbPath);
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>(resolve =>
    child.on('exit', (code, signal) => resolve({ code, signal })));
  if (stop === 'SIGKILL' || realSignals) child.kill(stop);
  else child.send(stop);
  const result = await exited;
  const rowsAfter = pendingRows(dbPath);
  for (const f of [dbPath, dbPath + '-wal', dbPath + '-shm']) { try { fs.unlinkSync(f); } catch { /* gone */ } }
  return { ...result, rowsBefore, rowsAfter };
}

describe('graceful shutdown flushes the write-behind review queue', () => {
  it('the rows are still buffered when the signal arrives (precondition)', async () => {
    const r = await runChild('SIGKILL');
    expect(r.rowsBefore).toBe(0);
  }, 40_000);

  it(`SIGTERM writes all ${ROWS} buffered rows and exits 0${realSignals ? ' (real OS signal)' : ' (in-process signal)'}`, async () => {
    const r = await runChild('SIGTERM');
    expect(r.rowsBefore).toBe(0);
    expect(r.rowsAfter).toBe(ROWS);
    expect(r.code).toBe(0);
  }, 40_000);

  it(`SIGINT (Ctrl+C) writes all ${ROWS} buffered rows and exits 0${realSignals ? ' (real OS signal)' : ' (in-process signal)'}`, async () => {
    const r = await runChild('SIGINT');
    expect(r.rowsAfter).toBe(ROWS);
    expect(r.code).toBe(0);
  }, 40_000);

  it('a hard kill loses the buffer — the documented limit of write-behind', async () => {
    const r = await runChild('SIGKILL');
    expect(r.rowsAfter).toBe(0);
  }, 40_000);
});
