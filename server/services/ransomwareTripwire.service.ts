import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { shannonEntropyOfBuffer, LIVE_ENTROPY_THRESHOLD } from './liveHostCanary.service.js';

/**
 * RANSOMWARE TRIPWIRE — decoy files in folders the operator chooses.
 *
 * WHY NOT THE EXISTING CANARY ENGINE. liveHostCanary adds every new file in its tree to
 * a ledger and, on any later change, writes the old bytes back and sets the file
 * read-only. That is right for the platform's own sensitive_store; pointed at a real
 * working folder it would silently revert every edit a person makes. This service never
 * writes, moves, restores or chmods anything it did not create.
 *
 * WHAT IT DOES in each protected folder:
 *
 *   Tripwires  Two decoy files it plants and owns: one named to sort first, one to sort
 *              last, because encryptors walk directories in order and either direction
 *              reaches one early. Any change, rename or deletion of a decoy is a CRITICAL
 *              incident — no legitimate process has a reason to touch them. The decoy's
 *              altered bytes are kept as evidence, then the decoy is re-planted.
 *
 *   Burst      Every other file is only read (first 64 KB) when it changes. A burst of
 *              high-entropy rewrites of normally low-entropy files — or files renamed to
 *              known ransomware extensions — inside one folder is a CRITICAL incident.
 *              Nothing is touched: in someone's working folder the only safe automatic
 *              action is to raise the alarm fast.
 *
 * LIMITS, stated. It watches this server's own filesystem; a remote host needs the
 * sensor. It cannot stop the encrypting process — Node has no portable way to — so its
 * value is detection within seconds, while most of the folder is still intact.
 */

export interface TripwireIncident {
  id: string;
  at: string;
  kind: 'TRIPWIRE_MODIFIED' | 'TRIPWIRE_ENCRYPTED' | 'TRIPWIRE_REMOVED' | 'ENCRYPTION_BURST';
  dir: string;
  file: string | null;
  entropy: number | null;
  count: number | null;
  evidencePath: string | null;
  mitre: string;
  detail: string;
}

interface Protected {
  dir: string;
  addedAt: string;
  addedBy: string;
  source: 'OPERATOR' | 'ENV';
  decoys: Array<{ path: string; sha256: string; bytes: Buffer }>;
  watcher: fs.FSWatcher | null;
  burst: number[];
  lastBurstAlert: number;
}

const DECOY_NAMES = ['!000-sovereign-tripwire-do-not-edit.txt', 'zzz-sovereign-tripwire-do-not-edit.txt'];

/** Formats that are high-entropy by design; excluded from the burst signal. */
const HIGH_ENTROPY_EXT = new Set([
  '.zip', '.gz', '.tgz', '.7z', '.rar', '.bz2', '.xz', '.zst', '.cab', '.pdf',
  '.docx', '.xlsx', '.pptx', '.odt', '.ods', '.odp', '.epub', '.jar', '.apk', '.msi',
  '.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif', '.heic', '.bmp', '.ico',
  '.mp3', '.mp4', '.m4a', '.mkv', '.mov', '.avi', '.webm', '.ogg', '.flac', '.wav',
  '.woff', '.woff2', '.iso', '.dmg', '.kdbx', '.gpg', '.pgp', '.p12', '.pfx', '.crt'
]);

/** Extensions encryptors append. Seen on a changed file, it counts toward a burst. */
const RANSOM_EXT = /\.(locked|encrypted|enc|crypt|crypted|crypto|lockbit|ryk|conti|akira|blackcat|alphv|royal|play|hive|clop|basta|wncry|wnry|cerber|zepto|locky|djvu)$/i;

const BURST_WINDOW_MS = 30_000;
const BURST_THRESHOLD = 8;
const BURST_COOLDOWN_MS = 60_000;
const SAMPLE_BYTES = 65_536;
const MAX_DIRS = 16;
const MAX_INCIDENTS = 300;

function refusePath(dir: string): string | null {
  const resolved = path.resolve(dir);
  if (!path.isAbsolute(dir)) return 'use an absolute path';
  if (path.parse(resolved).root === resolved) return 'a whole drive or filesystem root is too broad to watch';
  const lower = resolved.toLowerCase().replace(/\\/g, '/');
  const system = ['c:/windows', 'c:/program files', 'c:/program files (x86)', 'c:/programdata', '/etc', '/usr', '/bin', '/sbin', '/lib', '/proc', '/sys', '/dev', '/boot', '/var/lib'];
  if (system.some(s => lower === s || lower.startsWith(s + '/'))) return 'system directories are not protected folders';
  const own = path.resolve(process.cwd()).toLowerCase().replace(/\\/g, '/');
  if (lower === own || lower.startsWith(own + '/')) return "that is inside the platform's own directory";
  try {
    if (!fs.statSync(resolved).isDirectory()) return 'not a directory';
  } catch {
    return 'the folder does not exist or cannot be read';
  }
  return null;
}

export class RansomwareTripwireService {
  private dirs = new Map<string, Protected>();
  private incidents: TripwireIncident[] = [];
  private readonly stateFile: string;
  private readonly evidenceDir: string;
  public totals = { events: 0, tripwires: 0, bursts: 0 };

  constructor() {
    this.stateFile = path.join(process.cwd(), 'data', 'tripwire.json');
    this.evidenceDir = path.join(process.cwd(), 'data', 'tripwire_evidence');
  }

  /** Re-arms every persisted folder and every CANARY_DIRS entry; checks decoys for tampering while down. */
  public start() {
    const persisted: Array<{ dir: string; addedAt: string; addedBy: string }> = [];
    try {
      persisted.push(...JSON.parse(fs.readFileSync(this.stateFile, 'utf8')).dirs);
    } catch {
      /* first run */
    }
    for (const p of persisted) this.arm(p.dir, p.addedBy, 'OPERATOR', p.addedAt);
    for (const d of (process.env.CANARY_DIRS ?? '').split(/[;,]/).map(s => s.trim()).filter(Boolean)) {
      const why = refusePath(d);
      if (why) console.warn(`[tripwire] CANARY_DIRS entry refused (${d}): ${why}`);
      else this.arm(d, 'env', 'ENV');
    }
    if (this.dirs.size) console.log(`[tripwire] armed in ${this.dirs.size} folder(s)`);
  }

  private persist() {
    try {
      fs.mkdirSync(path.dirname(this.stateFile), { recursive: true });
      const dirs = [...this.dirs.values()].filter(p => p.source === 'OPERATOR').map(p => ({ dir: p.dir, addedAt: p.addedAt, addedBy: p.addedBy }));
      fs.writeFileSync(this.stateFile, JSON.stringify({ dirs }, null, 2));
    } catch (err: any) {
      console.warn('[tripwire] could not persist protected folders:', err?.message);
    }
  }

  private decoyContent(dir: string, name: string): Buffer {
    const token = crypto.createHash('sha256').update(dir + '|' + name).digest('hex');
    const lines = [
      'Sovereign Defender ransomware tripwire.',
      '',
      'This file is monitored. Editing, encrypting, renaming or deleting it raises a',
      'CRITICAL alert on the security console. It holds no data and needs no action.',
      'Please leave it in place.',
      '',
      'هذا الملف فخّ لكشف برامج الفدية. أي تعديل أو تشفير أو حذف له يطلق تنبيهًا حرجًا.',
      'لا يحتوي بيانات ولا يحتاج إلى أي إجراء. يُرجى تركه في مكانه.',
      '',
      `token: ${token}`
    ];
    // Padding of plain prose keeps the decoy's entropy low, so an encrypted copy stands out.
    for (let i = 0; i < 24; i++) lines.push(`ledger line ${String(i).padStart(2, '0')}: quarterly reconciliation record, retained for audit.`);
    return Buffer.from(lines.join('\n') + '\n', 'utf8');
  }

  private arm(dirIn: string, addedBy: string, source: Protected['source'], addedAt = new Date().toISOString()): Protected | null {
    const dir = path.resolve(dirIn);
    if (this.dirs.has(dir)) return this.dirs.get(dir)!;
    const p: Protected = { dir, addedAt, addedBy, source, decoys: [], watcher: null, burst: [], lastBurstAlert: 0 };

    for (const name of DECOY_NAMES) {
      const file = path.join(dir, name);
      const bytes = this.decoyContent(dir, name);
      try {
        if (fs.existsSync(file)) {
          const onDisk = fs.readFileSync(file);
          if (!onDisk.equals(bytes)) {
            // Tampered while the server was down: report it, keep it, re-plant.
            this.tripped(p, file, onDisk, 'found altered at start-up');
          }
        }
        fs.writeFileSync(file, bytes);
        p.decoys.push({ path: file, sha256: crypto.createHash('sha256').update(bytes).digest('hex'), bytes });
      } catch (err: any) {
        console.warn(`[tripwire] could not plant ${file}:`, err?.message);
      }
    }

    try {
      p.watcher = fs.watch(dir, { recursive: true }, (_e, name) => name && this.onEvent(p, String(name)));
    } catch {
      try {
        p.watcher = fs.watch(dir, (_e, name) => name && this.onEvent(p, String(name)));
      } catch (err: any) {
        console.warn(`[tripwire] could not watch ${dir}:`, err?.message);
      }
    }
    p.watcher?.on('error', err => console.warn('[tripwire] watcher error:', err?.message));
    this.dirs.set(dir, p);
    return p;
  }

  private debounce = new Map<string, NodeJS.Timeout>();

  private onEvent(p: Protected, rel: string) {
    this.totals.events++;
    const abs = path.resolve(p.dir, rel);
    const prev = this.debounce.get(abs);
    if (prev) clearTimeout(prev);
    const t = setTimeout(() => {
      this.debounce.delete(abs);
      try {
        this.inspect(p, abs);
      } catch (err: any) {
        console.warn('[tripwire] inspect failed:', err?.message);
      }
    }, 150);
    t.unref?.();
    this.debounce.set(abs, t);
  }

  private inspect(p: Protected, abs: string) {
    const decoy = p.decoys.find(d => d.path === abs);
    if (decoy) {
      let now: Buffer | null = null;
      try {
        now = fs.readFileSync(abs);
      } catch {
        now = null;
      }
      if (now && crypto.createHash('sha256').update(now).digest('hex') === decoy.sha256) return; // our own re-plant
      this.tripped(p, abs, now, null);
      try {
        fs.writeFileSync(abs, decoy.bytes); // re-arm; the decoy is ours to rewrite
      } catch (err: any) {
        console.warn('[tripwire] re-plant failed:', err?.message);
      }
      return;
    }

    // Anyone else's file: read-only observation.
    let st: fs.Stats;
    try {
      st = fs.statSync(abs);
    } catch {
      return; // deleted or moved away; a burst of these is not scored here
    }
    if (!st.isFile() || st.size < 256) return;
    const ext = path.extname(abs).toLowerCase();
    let suspicious = RANSOM_EXT.test(abs);
    if (!suspicious && !HIGH_ENTROPY_EXT.has(ext)) {
      try {
        const fd = fs.openSync(abs, 'r');
        const buf = Buffer.alloc(Math.min(SAMPLE_BYTES, st.size));
        fs.readSync(fd, buf, 0, buf.length, 0);
        fs.closeSync(fd);
        suspicious = shannonEntropyOfBuffer(buf) > LIVE_ENTROPY_THRESHOLD;
      } catch {
        return;
      }
    }
    if (!suspicious) return;

    const now = Date.now();
    p.burst = p.burst.filter(t => now - t < BURST_WINDOW_MS);
    p.burst.push(now);
    if (p.burst.length >= BURST_THRESHOLD && now - p.lastBurstAlert > BURST_COOLDOWN_MS) {
      p.lastBurstAlert = now;
      this.totals.bursts++;
      this.record({
        kind: 'ENCRYPTION_BURST',
        dir: p.dir,
        file: abs,
        entropy: null,
        count: p.burst.length,
        evidencePath: null,
        mitre: 'T1486 - Data Encrypted for Impact',
        detail: `${p.burst.length} files in ${p.dir} were rewritten as high-entropy data or renamed to ransomware extensions within ${BURST_WINDOW_MS / 1000}s. Latest: ${abs}. No file was modified by the platform.`
      });
    }
  }

  private tripped(p: Protected, file: string, bytes: Buffer | null, note: string | null) {
    this.totals.tripwires++;
    let evidencePath: string | null = null;
    if (bytes) {
      try {
        fs.mkdirSync(this.evidenceDir, { recursive: true });
        evidencePath = path.join(this.evidenceDir, `${path.basename(file)}.${Date.now().toString(36)}.evidence`);
        fs.writeFileSync(evidencePath, bytes);
      } catch {
        evidencePath = null;
      }
    }
    const entropy = bytes ? shannonEntropyOfBuffer(bytes.subarray(0, SAMPLE_BYTES)) : null;
    const kind: TripwireIncident['kind'] = !bytes ? 'TRIPWIRE_REMOVED' : (entropy ?? 0) > LIVE_ENTROPY_THRESHOLD ? 'TRIPWIRE_ENCRYPTED' : 'TRIPWIRE_MODIFIED';
    this.record({
      kind,
      dir: p.dir,
      file,
      entropy,
      count: null,
      evidencePath,
      mitre: kind === 'TRIPWIRE_ENCRYPTED' ? 'T1486 - Data Encrypted for Impact' : kind === 'TRIPWIRE_REMOVED' ? 'T1485 - Data Destruction' : 'T1565.001 - Stored Data Manipulation',
      detail:
        (kind === 'TRIPWIRE_ENCRYPTED'
          ? `A decoy in ${p.dir} was overwritten with encrypted-looking data (H=${entropy} bits/byte).`
          : kind === 'TRIPWIRE_REMOVED'
            ? `A decoy in ${p.dir} was deleted or renamed away.`
            : `A decoy in ${p.dir} was modified.`) +
        (note ? ` (${note})` : '') +
        ' No legitimate process touches these files. The decoy has been re-planted.'
    });
  }

  private record(i: Omit<TripwireIncident, 'id' | 'at'>) {
    const inc: TripwireIncident = { id: 'TRW-' + crypto.randomBytes(4).toString('hex').toUpperCase(), at: new Date().toISOString(), ...i };
    this.incidents.push(inc);
    while (this.incidents.length > MAX_INCIDENTS) this.incidents.shift();
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'FIM',
        severity: 'CRITICAL',
        title:
          i.kind === 'ENCRYPTION_BURST'
            ? `Ransomware behaviour: ${i.count} files encrypted in ${i.dir}`
            : `Ransomware tripwire tripped (${i.kind.replace('TRIPWIRE_', '')}) in ${i.dir}`,
        titleAr:
          i.kind === 'ENCRYPTION_BURST'
            ? `سلوك برنامج فدية: تشفير ${i.count} ملف في ${i.dir}`
            : `انطلق فخّ برامج الفدية في ${i.dir}`,
        details: i.detail,
        mitreTactic: 'Impact',
        mitreTechnique: i.mitre,
        actionTaken: 'ALERT_RAISED',
        actionTakenAr: 'تم رفع تنبيه حرج',
        metadata: { tripwire: true, kind: i.kind, dir: i.dir, file: i.file, entropy: i.entropy, evidencePath: i.evidencePath }
      });
    } catch (err: any) {
      console.warn('[tripwire] telemetry publish failed:', err?.message);
    }
  }

  /** Protect a folder: plant two decoys and start watching. */
  public protect(dir: string, by: string): { ok: true; dir: string; decoys: string[] } | { ok: false; reason: string } {
    if (typeof dir !== 'string' || !dir.trim()) return { ok: false, reason: 'a folder path is required' };
    const resolved = path.resolve(dir.trim());
    // The raw input, so a relative path is refused rather than resolved against the cwd.
    const why = refusePath(dir.trim());
    if (why) return { ok: false, reason: why };
    for (const d of this.dirs.keys()) {
      const a = d.toLowerCase(), b = resolved.toLowerCase();
      if (a === b) return { ok: false, reason: 'already protected' };
      if (b.startsWith(a + path.sep.toLowerCase())) return { ok: false, reason: `already covered by ${d}` };
    }
    if (this.dirs.size >= MAX_DIRS) return { ok: false, reason: `at most ${MAX_DIRS} folders` };
    const p = this.arm(resolved, by, 'OPERATOR');
    if (!p) return { ok: false, reason: 'could not arm the folder' };
    this.persist();
    return { ok: true, dir: p.dir, decoys: p.decoys.map(d => d.path) };
  }

  /** Stop protecting a folder and remove the decoys it planted — only if they are still its own bytes. */
  public unprotect(dir: string): { ok: true; removed: string[]; kept: string[] } | { ok: false; reason: string } {
    const p = this.dirs.get(path.resolve(String(dir ?? '')));
    if (!p) return { ok: false, reason: 'not a protected folder' };
    if (p.source === 'ENV') return { ok: false, reason: 'set by CANARY_DIRS; remove it from the environment' };
    try {
      p.watcher?.close();
    } catch {
      /* already closed */
    }
    const removed: string[] = [];
    const kept: string[] = [];
    for (const d of p.decoys) {
      try {
        const now = fs.readFileSync(d.path);
        if (crypto.createHash('sha256').update(now).digest('hex') === d.sha256) {
          fs.unlinkSync(d.path);
          removed.push(d.path);
        } else kept.push(d.path);
      } catch {
        /* already gone */
      }
    }
    this.dirs.delete(p.dir);
    this.persist();
    return { ok: true, removed, kept };
  }

  public status() {
    return {
      entropyThreshold: LIVE_ENTROPY_THRESHOLD,
      burstRule: { files: BURST_THRESHOLD, windowSec: BURST_WINDOW_MS / 1000 },
      dirs: [...this.dirs.values()].map(p => ({
        dir: p.dir,
        addedAt: p.addedAt,
        addedBy: p.addedBy,
        source: p.source,
        watching: Boolean(p.watcher),
        decoys: p.decoys.map(d => {
          let intact = false;
          try {
            intact = crypto.createHash('sha256').update(fs.readFileSync(d.path)).digest('hex') === d.sha256;
          } catch {
            intact = false;
          }
          return { path: d.path, intact };
        })
      })),
      totals: this.totals,
      incidents: this.incidents.slice(-100).reverse()
    };
  }
}

export const globalRansomwareTripwire = new RansomwareTripwireService();
