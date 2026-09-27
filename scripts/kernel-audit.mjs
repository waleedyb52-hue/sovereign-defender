#!/usr/bin/env node
/**
 * KERNEL AUDIT — real kernel measurements, taken where a kernel exists
 *
 * The platform's core claim is kernel-level defence, and on a Windows host it
 * cannot be verified at all: XDP is Linux-only, so `kernelIntegrity` returns
 * UNAVAILABLE and `meanKernelLatencyUs` is null. Those are honest answers, but
 * they are not measurements.
 *
 * This script takes the measurements on a host that has a kernel — WSL2, a VM, or
 * the deployment target — and hands them back to the platform tagged as what they
 * are. It deliberately has ZERO dependencies and imports nothing outside node's
 * standard library, so it runs under a bare `node` with no `npm ci`, no build step
 * and no native modules. That matters because `npm ci` across /mnt/c is slow and
 * breaks native builds, and the measurement does not need any of it.
 *
 * What it verifies, and why each one is not rhetoric
 *
 *   1. Syscall table integrity. Hashes the __x64_sys_* symbol region of
 *      /proc/kallsyms. This is the sensor that returns UNAVAILABLE on Windows;
 *      here it returns a real hash over a real symbol count.
 *
 *   2. That the XDP program actually compiles. The repository ships
 *      ebpf/xdp_drop.c and the product claims kernel-level packet dropping. Until
 *      this script existed, nothing had ever compiled that file — so the claim
 *      rested on a .c file nobody had put through a compiler. This builds it with
 *      clang -target bpf and inspects the resulting object for an `xdp` section, a
 *      `.maps` section and a license, which is what the loader will require.
 *
 *   3. BPF runtime surface. bpftool on PATH, /sys/fs/bpf mounted, and whether this
 *      process could load a program at all — reported as a capability, not assumed.
 *
 * What it deliberately cannot do
 *   Attaching an XDP program to an interface and reading live drop counters needs
 *   CAP_BPF or root. Where this script runs unprivileged it says so and reports
 *   `xdpAttach: 'REQUIRES_PRIVILEGE'` rather than producing a drop figure. A
 *   fabricated packet counter is the exact defect this project spent its history
 *   removing.
 *
 * Usage
 *   node scripts/kernel-audit.mjs                     # print the report
 *   node scripts/kernel-audit.mjs --json              # machine-readable
 *   node scripts/kernel-audit.mjs --post http://host:3000 --key KEY
 *
 *   From Windows:  wsl.exe -e node scripts/kernel-audit.mjs
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { execFileSync, execSync } from 'node:child_process';

const args = process.argv.slice(2);
const asJson = args.includes('--json');
const postIdx = args.indexOf('--post');
const postTo = postIdx >= 0 ? args[postIdx + 1] : null;
const keyIdx = args.indexOf('--key');
const apiKey = keyIdx >= 0 ? args[keyIdx + 1] : process.env.ADMIN_API_KEY;

const ok = (p) => {
  try {
    return fs.existsSync(p);
  } catch {
    return false;
  }
};
const readOr = (p, fallback = null) => {
  try {
    return fs.readFileSync(p, 'utf-8').trim();
  } catch {
    return fallback;
  }
};
const which = (bin) => {
  try {
    return execSync(`command -v ${bin}`, { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim() || null;
  } catch {
    return null;
  }
};

/* ── 1. Platform ─────────────────────────────────────────────────────────── */

const platform = {
  os: process.platform,
  kernelRelease: os.release(),
  isLinux: process.platform === 'linux',
  isWsl: /microsoft|WSL/i.test(os.release()),
  nodeVersion: process.version,
  hostname: os.hostname(),
  uid: typeof process.getuid === 'function' ? process.getuid() : null,
  privileged: typeof process.getuid === 'function' ? process.getuid() === 0 : false
};

if (!platform.isLinux) {
  const out = {
    ok: false,
    reason: `This audit requires Linux. Running on "${process.platform}", where /proc/kallsyms and XDP do not exist. Run it under WSL2, a VM, or the deployment host.`,
    platform,
    capturedAt: new Date().toISOString()
  };
  console.log(asJson ? JSON.stringify(out, null, 2) : `\n  ${out.reason}\n`);
  process.exit(2);
}

/* ── 2. Syscall table integrity ──────────────────────────────────────────── */

let syscall = { status: 'UNAVAILABLE', reason: 'Could not read /proc/kallsyms.' };
try {
  const raw = fs.readFileSync('/proc/kallsyms', 'utf-8');
  const rows = raw
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => /\b(__x64_sys_|__ia32_sys_|sys_call_table\b)/.test(l))
    .sort();
  if (rows.length > 0) {
    syscall = {
      status: 'VERIFIED',
      symbolsRead: rows.length,
      // Only the syscall region is hashed. Hashing all of kallsyms would change on
      // every legitimate modprobe and train an operator to ignore the alert.
      tableHash: crypto.createHash('sha256').update(rows.join('\n')).digest('hex'),
      kptrRestricted: readOr('/proc/sys/kernel/kptr_restrict'),
      bootId: readOr('/proc/sys/kernel/random/boot_id'),
      lockdown: readOr('/sys/kernel/security/lockdown')
    };
  } else {
    syscall = {
      status: 'UNAVAILABLE',
      reason: 'kallsyms readable but no syscall symbols matched; kptr_restrict may be hiding addresses.',
      kptrRestricted: readOr('/proc/sys/kernel/kptr_restrict')
    };
  }
} catch (e) {
  syscall = { status: 'UNAVAILABLE', reason: `read failed: ${e.message}` };
}

/* ── 3. Does the shipped XDP program actually build? ─────────────────────── */

function auditXdpProgram() {
  const clang = which('clang');
  const objdump = which('llvm-objdump');
  const srcCandidates = [
    path.join(process.cwd(), 'ebpf', 'xdp_drop.c'),
    path.join(process.cwd(), '..', 'ebpf', 'xdp_drop.c')
  ];
  const src = srcCandidates.find(ok);

  if (!src) return { status: 'NOT_FOUND', reason: 'ebpf/xdp_drop.c not found relative to the working directory.' };
  if (!clang) return { status: 'NO_TOOLCHAIN', reason: 'clang not on PATH; cannot verify the program compiles.' };

  const out = path.join(os.tmpdir(), `xdp_audit_${process.pid}.o`);
  try {
    // The arch include dir is required for asm/types.h, which linux/bpf.h pulls in.
    execFileSync(
      clang,
      ['-O2', '-g', '-target', 'bpf', '-D__TARGET_ARCH_x86', '-I/usr/include/x86_64-linux-gnu', '-c', src, '-o', out],
      { stdio: ['ignore', 'pipe', 'pipe'] }
    );
  } catch (e) {
    return {
      status: 'COMPILE_FAILED',
      reason: (e.stderr?.toString() || e.message || '').split('\n').slice(0, 6).join(' | ')
    };
  }

  const size = ok(out) ? fs.statSync(out).size : 0;
  if (size === 0) {
    try { fs.unlinkSync(out); } catch {}
    return { status: 'COMPILE_FAILED', reason: 'clang produced no object.' };
  }

  // Sections the loader will require. Their presence is what makes this a real
  // BPF object rather than a file that merely compiled.
  let sections = [];
  let instructionSample = null;
  if (objdump) {
    try {
      const h = execFileSync(objdump, ['-h', out], { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      sections = [...h.matchAll(/^\s*\d+\s+(\S+)\s+([0-9a-f]+)/gm)].map((m) => ({
        name: m[1],
        bytes: parseInt(m[2], 16)
      }));
      const d = execFileSync(objdump, ['-d', out], { stdio: ['ignore', 'pipe', 'ignore'] }).toString();
      instructionSample = d
        .split('\n')
        .filter((l) => /^\s+\d+:\s+[0-9a-f]{2}/.test(l))
        .slice(0, 3)
        .map((l) => l.trim());
    } catch {
      /* objdump is optional; absence does not invalidate the compile */
    }
  }

  try { fs.unlinkSync(out); } catch {}

  const has = (n) => sections.some((s) => s.name === n || s.name.startsWith(n));
  const xdpSection = sections.find((s) => s.name === 'xdp');

  return {
    status: 'COMPILES',
    objectBytes: size,
    sections: sections.filter((s) => ['xdp', '.maps', 'license', '.text', '.relxdp'].includes(s.name)),
    hasXdpSection: has('xdp'),
    hasMapsSection: has('.maps'),
    hasLicense: has('license'),
    xdpProgramBytes: xdpSection?.bytes ?? null,
    instructionSample,
    // The loader needs all three. Reporting them separately means a partial build
    // cannot pass as a whole one.
    loadable: has('xdp') && has('.maps') && has('license')
  };
}

const xdp = auditXdpProgram();

/* ── 4. BPF runtime surface ──────────────────────────────────────────────── */

const bpftoolPath = which('bpftool');
let bpftoolVersion = null;
if (bpftoolPath) {
  try {
    bpftoolVersion = execFileSync(bpftoolPath, ['version'], { stdio: ['ignore', 'pipe', 'ignore'] })
      .toString()
      .split('\n')[0]
      .trim();
  } catch {
    /* present but not runnable unprivileged */
  }
}

const runtime = {
  bpftool: bpftoolPath,
  bpftoolVersion,
  bpffsMounted: ok('/sys/fs/bpf'),
  pinnedMaps: (() => {
    try {
      return fs.readdirSync('/sys/fs/bpf');
    } catch {
      return [];
    }
  })(),
  unprivilegedBpfDisabled: readOr('/proc/sys/kernel/unprivileged_bpf_disabled'),
  // Attaching and reading live counters needs privilege. Saying so beats
  // producing a drop figure that was never counted.
  xdpAttach: platform.privileged ? 'AVAILABLE' : 'REQUIRES_PRIVILEGE',
  xdpAttachNote: platform.privileged
    ? 'Running privileged; a program could be loaded and attached.'
    : 'Unprivileged: the program can be compiled and inspected but not loaded, so no live packet or latency figure is produced.'
};

/* ── 5. Report ───────────────────────────────────────────────────────────── */

const report = {
  ok: true,
  capturedAt: new Date().toISOString(),
  platform,
  syscallIntegrity: syscall,
  xdpProgram: xdp,
  bpfRuntime: runtime,
  /** What this run can and cannot support, stated rather than inferred. */
  claims: {
    kernelReadable: syscall.status === 'VERIFIED',
    xdpProgramValid: xdp.status === 'COMPILES' && xdp.loadable === true,
    liveKernelCountersAvailable: platform.privileged && runtime.bpffsMounted,
    note:
      'Live packet and latency counters require loading the program, which needs privilege. Where this report says liveKernelCountersAvailable is false, the platform must continue to report those figures as UNAVAILABLE rather than seeded.'
  }
};

if (asJson) {
  console.log(JSON.stringify(report, null, 2));
} else {
  const line = (k, v) => console.log(`    ${String(k).padEnd(26)} ${v}`);
  console.log('\n' + '='.repeat(72));
  console.log('  KERNEL AUDIT');
  console.log('='.repeat(72));
  console.log('\n  PLATFORM');
  line('kernel', platform.kernelRelease);
  line('wsl', platform.isWsl);
  line('node', platform.nodeVersion);
  line('privileged', platform.privileged);

  console.log('\n  SYSCALL TABLE INTEGRITY');
  line('status', syscall.status);
  if (syscall.status === 'VERIFIED') {
    line('symbols read', syscall.symbolsRead);
    line('table hash', syscall.tableHash.slice(0, 32) + '…');
    line('boot id', syscall.bootId);
    line('kptr_restrict', syscall.kptrRestricted);
    line('lockdown', syscall.lockdown ?? '(not exposed)');
  } else {
    line('reason', syscall.reason);
  }

  console.log('\n  SHIPPED XDP PROGRAM (ebpf/xdp_drop.c)');
  line('status', xdp.status);
  if (xdp.status === 'COMPILES') {
    line('object bytes', xdp.objectBytes);
    line('xdp section bytes', xdp.xdpProgramBytes);
    line('has .maps', xdp.hasMapsSection);
    line('has license', xdp.hasLicense);
    line('loadable', xdp.loadable);
    if (xdp.instructionSample?.length) {
      console.log('    first instructions');
      for (const i of xdp.instructionSample) console.log(`      ${i}`);
    }
  } else {
    line('reason', xdp.reason);
  }

  console.log('\n  BPF RUNTIME');
  line('bpftool', runtime.bpftool ?? '(absent)');
  line('bpftool version', runtime.bpftoolVersion ?? '(not runnable)');
  line('bpffs mounted', runtime.bpffsMounted);
  line('pinned maps', runtime.pinnedMaps.length ? runtime.pinnedMaps.join(', ') : '(none)');
  line('xdp attach', runtime.xdpAttach);

  console.log('\n  ' + '-'.repeat(68));
  console.log(`  kernel readable       : ${report.claims.kernelReadable}`);
  console.log(`  xdp program valid     : ${report.claims.xdpProgramValid}`);
  console.log(`  live counters available : ${report.claims.liveKernelCountersAvailable}`);
  console.log(`\n  ${report.claims.note}\n`);
}

/* ── 6. Optionally hand the reading back to the platform ─────────────────── */

if (postTo) {
  const url = `${postTo.replace(/\/$/, '')}/api/v1/soc/sensors/kernel-audit`;
  try {
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(apiKey ? { 'x-api-key': apiKey } : {}) },
      body: JSON.stringify(report)
    });
    const body = await res.json().catch(() => ({}));
    console.log(`  posted to ${url} -> HTTP ${res.status} ${JSON.stringify(body).slice(0, 160)}`);
  } catch (e) {
    console.error(`  post failed: ${e.message}`);
    process.exit(1);
  }
}
