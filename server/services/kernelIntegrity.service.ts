import crypto from 'crypto';
import fs from 'fs';
import { exec } from 'child_process';
import { promisify } from 'util';

const execp = promisify(exec);

/**
 * KERNEL INTEGRITY — syscall table verification and a kill-safety guard
 *
 * Built for T1014, which the capability report found missing both sensors.
 *
 * The rule this file exists to not break
 *   A syscall-integrity checker that returns "verified" on a host where it cannot
 *   read the kernel is worse than having no checker. It converts an unknown into a
 *   false assurance, and an operator who trusts it will stop looking. This is the
 *   same failure as the hardcoded `meanKernelLatencyUs: 0.34` that this project
 *   already had to remove, so the status enum here has no happy default:
 *
 *     VERIFIED    — a table was actually read and hashed this run.
 *     TAMPERED    — a read succeeded and the hash moved.
 *     UNAVAILABLE — nothing was read. Says why, and never implies health.
 *
 *   On Windows and on any Linux host without the required interfaces, every check
 *   returns UNAVAILABLE. That is the honest answer, and the UI shows it as a gap
 *   rather than a green tick.
 *
 * What a real check needs, and what it reads
 *   The syscall table lives at `sys_call_table` in kernel memory. Userspace cannot
 *   read it directly, so verification uses what the kernel exposes:
 *
 *     - /proc/kallsyms for the symbol addresses, which shift on every boot under
 *       KASLR, so the baseline is per-boot and comparing across reboots is
 *       meaningless. This class records the boot id alongside the baseline and
 *       refuses a cross-boot comparison.
 *     - bpftool, to read a BPF map populated by a tracepoint program that samples
 *       the table. That program is Linux-only and not shipped here.
 *     - /sys/kernel/security/lockdown and Secure Boot state, because on a locked
 *       down kernel the tampering this checks for is largely prevented upstream —
 *       which is more useful to report than a hash.
 *
 * The kill-safety guard
 *   Terminating a suspected rootkit thread can panic the kernel if it holds a lock
 *   or is a kernel worker. `assessKillSafety` is a userspace policy check that
 *   refuses the kill for process classes where SIGKILL is either impossible or
 *   dangerous — kernel threads in particular, which the scenario's `kworker/u4:2`
 *   is an example of. Refusing is the correct answer there: the containment path
 *   is isolating the host, not killing PID 0's children.
 */

export type IntegrityStatus = 'VERIFIED' | 'TAMPERED' | 'UNAVAILABLE';

export interface SyscallIntegrityResult {
  status: IntegrityStatus;
  /** Present only when status is VERIFIED or TAMPERED. */
  tableHash?: string;
  /** Baseline this run was compared against, if one existed for this boot. */
  baselineHash?: string;
  symbolsRead?: number;
  /** Populated when UNAVAILABLE: precisely what is missing. */
  unavailableReason?: string;
  missingInterfaces?: string[];
  /** Boot identity. A baseline from another boot is not comparable under KASLR. */
  bootId?: string | null;
  kernelLockdown?: string | null;
  checkedAt: string;
  durationMs: number;
  mitreTechnique: 'T1014';
}

export interface KillSafetyAssessment {
  safe: boolean;
  processName: string;
  pid: number | null;
  classification: 'KERNEL_THREAD' | 'SYSTEM_CRITICAL' | 'USER_PROCESS' | 'UNKNOWN';
  reason: string;
  recommendedAction: 'SIGKILL' | 'ISOLATE_HOST_INSTEAD' | 'INVESTIGATE_ONLY';
  mitreTechnique: 'T1014';
}

/**
 * Kernel thread names. A process in square brackets in ps output, or matching one
 * of these, cannot be SIGKILLed — the kernel owns it, and asking is at best a
 * no-op and at worst a panic on a patched kernel.
 */
const KERNEL_THREAD_PATTERNS = [
  /^\[.*\]$/,
  /^kworker\//,
  /^ksoftirqd\//,
  /^migration\//,
  /^rcu_/,
  /^watchdog\//,
  /^kthreadd$/,
  /^kswapd\d*$/,
  /^kcompactd\d*$/,
  /^khugepaged$/,
  /^irq\//
];

/** Userspace processes whose death takes the host down with them. */
const SYSTEM_CRITICAL = ['systemd', 'init', 'launchd', 'wininit.exe', 'csrss.exe', 'services.exe', 'smss.exe'];

export class KernelIntegrityService {
  private baseline: { hash: string; bootId: string | null; recordedAt: string } | null = null;
  private checks = 0;
  private tamperEvents = 0;

  /** Interfaces present on this host, probed rather than assumed. */
  async probeInterfaces(): Promise<{ available: string[]; missing: string[] }> {
    const wanted: Array<{ name: string; test: () => Promise<boolean> }> = [
      { name: '/proc/kallsyms', test: async () => fs.existsSync('/proc/kallsyms') },
      { name: '/proc/sys/kernel/random/boot_id', test: async () => fs.existsSync('/proc/sys/kernel/random/boot_id') },
      { name: '/sys/kernel/security/lockdown', test: async () => fs.existsSync('/sys/kernel/security/lockdown') },
      {
        name: 'bpftool',
        test: async () => {
          try {
            const { stdout } = await execp('which bpftool');
            return stdout.trim().length > 0;
          } catch {
            return false;
          }
        }
      }
    ];

    const available: string[] = [];
    const missing: string[] = [];
    for (const w of wanted) {
      let ok = false;
      try {
        ok = await w.test();
      } catch {
        ok = false;
      }
      (ok ? available : missing).push(w.name);
    }
    return { available, missing };
  }

  private readBootId(): string | null {
    try {
      return fs.readFileSync('/proc/sys/kernel/random/boot_id', 'utf-8').trim();
    } catch {
      return null;
    }
  }

  private readLockdown(): string | null {
    try {
      return fs.readFileSync('/sys/kernel/security/lockdown', 'utf-8').trim();
    } catch {
      return null;
    }
  }

  /**
   * Hash the syscall symbol region of /proc/kallsyms.
   *
   * Only the `__x64_sys_*` / `sys_*` entries are hashed: the full symbol table
   * changes whenever a module loads, which would produce tamper alerts on every
   * legitimate modprobe and train the operator to ignore them.
   */
  private hashSyscallSymbols(): { hash: string; count: number } | null {
    try {
      const raw = fs.readFileSync('/proc/kallsyms', 'utf-8');
      const rows = raw
        .split('\n')
        .map(l => l.trim())
        .filter(l => /\b(__x64_sys_|__ia32_sys_|sys_call_table\b)/.test(l))
        .sort();
      if (rows.length === 0) return null;
      return {
        hash: crypto.createHash('sha256').update(rows.join('\n')).digest('hex'),
        count: rows.length
      };
    } catch {
      return null;
    }
  }

  async checkIntegrity(): Promise<SyscallIntegrityResult> {
    const started = Date.now();
    this.checks++;
    const base = {
      checkedAt: new Date().toISOString(),
      mitreTechnique: 'T1014' as const
    };

    const { missing } = await this.probeInterfaces();
    const hashed = this.hashSyscallSymbols();

    if (!hashed) {
      // Nothing was read, so nothing is known. This is the branch that runs on
      // Windows, and it must never imply health.
      return {
        ...base,
        status: 'UNAVAILABLE',
        unavailableReason:
          process.platform !== 'linux'
            ? `Syscall table verification requires Linux. This host reports platform "${process.platform}", where /proc/kallsyms does not exist. No integrity claim is made.`
            : 'Could not read syscall symbols from /proc/kallsyms. It may be restricted (kptr_restrict) or the process lacks privilege. No integrity claim is made.',
        missingInterfaces: missing,
        bootId: this.readBootId(),
        kernelLockdown: this.readLockdown(),
        durationMs: Date.now() - started
      };
    }

    const bootId = this.readBootId();

    // KASLR moves every address on reboot, so a baseline from another boot would
    // read as tampering. Re-baseline instead of raising a false alarm.
    if (!this.baseline || this.baseline.bootId !== bootId) {
      this.baseline = { hash: hashed.hash, bootId, recordedAt: base.checkedAt };
      return {
        ...base,
        status: 'VERIFIED',
        tableHash: hashed.hash,
        symbolsRead: hashed.count,
        bootId,
        kernelLockdown: this.readLockdown(),
        durationMs: Date.now() - started
      };
    }

    const tampered = hashed.hash !== this.baseline.hash;
    if (tampered) this.tamperEvents++;

    return {
      ...base,
      status: tampered ? 'TAMPERED' : 'VERIFIED',
      tableHash: hashed.hash,
      baselineHash: this.baseline.hash,
      symbolsRead: hashed.count,
      bootId,
      kernelLockdown: this.readLockdown(),
      durationMs: Date.now() - started
    };
  }

  /**
   * Whether a suspected process can be safely terminated.
   *
   * The scenario's example is `kworker/u4:2`, a kernel worker. SIGKILL does not
   * apply to it, and a containment path that tries anyway either silently fails or
   * destabilises the host. Refusing and isolating instead is the correct answer,
   * so this returns it explicitly rather than leaving the caller to find out.
   */
  assessKillSafety(processName: string, pid: number | null = null): KillSafetyAssessment {
    const name = String(processName ?? '').trim();

    if (KERNEL_THREAD_PATTERNS.some(p => p.test(name))) {
      return {
        safe: false,
        processName: name,
        pid,
        classification: 'KERNEL_THREAD',
        reason:
          'Kernel thread. SIGKILL does not apply to kernel-owned tasks; attempting it is at best a no-op and can destabilise the host. A rootkit presenting as a kernel worker is contained by isolating the host, not by killing the thread.',
        recommendedAction: 'ISOLATE_HOST_INSTEAD',
        mitreTechnique: 'T1014'
      };
    }

    if (SYSTEM_CRITICAL.includes(name.toLowerCase())) {
      return {
        safe: false,
        processName: name,
        pid,
        classification: 'SYSTEM_CRITICAL',
        reason: 'Terminating this process takes the host down with it. Containment must not be self-inflicted denial of service.',
        recommendedAction: 'ISOLATE_HOST_INSTEAD',
        mitreTechnique: 'T1014'
      };
    }

    if (!name) {
      return {
        safe: false,
        processName: name,
        pid,
        classification: 'UNKNOWN',
        reason: 'No process name supplied, so no safety determination can be made. Defaulting to refuse.',
        recommendedAction: 'INVESTIGATE_ONLY',
        mitreTechnique: 'T1014'
      };
    }

    return {
      safe: true,
      processName: name,
      pid,
      classification: 'USER_PROCESS',
      reason: 'Ordinary user-space process. SIGKILL applies and does not risk kernel stability.',
      recommendedAction: 'SIGKILL',
      mitreTechnique: 'T1014'
    };
  }

  getStatistics() {
    return {
      checksPerformed: this.checks,
      tamperEventsDetected: this.tamperEvents,
      hasBaseline: this.baseline !== null,
      baselineBootId: this.baseline?.bootId ?? null,
      baselineRecordedAt: this.baseline?.recordedAt ?? null,
      platform: process.platform,
      /**
       * Whether this sensor can do anything on this host. False on Windows, and
       * reported so the capability is never counted as present when it is not.
       */
      operational: process.platform === 'linux' && fs.existsSync('/proc/kallsyms'),
      provenance: { mode: 'MEASURED_OR_DECLARED_UNAVAILABLE', seeded: false }
    };
  }

  reset() {
    this.baseline = null;
    this.checks = 0;
    this.tamperEvents = 0;
  }
}

export const globalKernelIntegrity = new KernelIntegrityService();
