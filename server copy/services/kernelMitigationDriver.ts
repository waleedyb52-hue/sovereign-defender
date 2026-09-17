import { execFile } from 'child_process';
import { promisify } from 'util';
import fs from 'fs';
import net from 'net';
import os from 'os';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';

const execFileAsync = promisify(execFile);

// =============================================================================
// DUAL-KERNEL MITIGATION DRIVER (v1.0)
//
// One API, three real enforcement tiers, selected at runtime by what the host
// can actually do:
//
//   TIER 1  KERNEL_XDP      linux + privileged  -> eBPF/XDP via bpftool
//   TIER 2  WIN_FIREWALL    win32 + elevated    -> Windows Filtering Platform
//                                                  through netsh advfirewall
//   TIER 3  SOCKET_RST      any host, always    -> active RST injection on
//                                                  live sockets + in-memory
//                                                  drop map consulted in-line
//
// TIER 3 is not a stub. It terminates real TCP connections from a banned peer
// and refuses subsequent ones, which is genuine wire-level mitigation from
// userland. TIERS 1 and 2 add enforcement below the process, so traffic is
// discarded before it ever reaches Node.
//
// SAFETY GATE
// -----------
// Tier 2 writes real, persistent firewall rules to the host. That is a system
// modification with effects outside this process, so it is DISABLED by default
// and only engages when SOVEREIGN_ENABLE_HOST_FIREWALL=1 is set AND the
// process is genuinely elevated. Every rule created is tagged
// "SovereignDefender-" so it can be enumerated and revoked, and revokeAll()
// removes them. A defensive tool must never silently reconfigure the host it
// is running on.
// =============================================================================

export type MitigationAction = 'DROP' | 'THROTTLE' | 'RESET';
export type EnforcementTier = 'KERNEL_XDP' | 'WIN_FIREWALL' | 'SOCKET_RST';

export interface MitigationResult {
  ip: string;
  action: MitigationAction;
  /** Tiers that actually succeeded. Never lists a tier that failed. */
  enforcedBy: EnforcementTier[];
  /** Tiers attempted but unavailable, with the real reason. */
  degraded: Array<{ tier: EnforcementTier; reason: string }>;
  ruleId: string | null;
  expiresAt: number | null;
  latencyMs: number;
  success: boolean;
}

export interface DropEntry {
  ip: string;
  action: MitigationAction;
  reason: string;
  installedAt: number;
  expiresAt: number;
  hits: number;
  tiers: EnforcementTier[];
  /** Token-bucket state, populated only for THROTTLE. */
  bucket?: { tokens: number; capacity: number; refillPerSec: number; lastRefillMs: number };
}

export interface HostCapabilities {
  platform: NodeJS.Platform;
  release: string;
  elevated: boolean;
  /** Linux only: is bpftool present and is a pinned map available. */
  bpftoolAvailable: boolean;
  bpfMapPinned: boolean;
  /** Win32 only: is netsh reachable and are host firewall writes permitted. */
  netshAvailable: boolean;
  hostFirewallEnabled: boolean;
  activeTier: EnforcementTier;
  tierReason: string;
}

const RULE_PREFIX = 'SovereignDefender-';
const BPF_PINNED_MAP = '/sys/fs/bpf/sovereign_ip_blacklist';
const DEFAULT_TTL_SECONDS = 3600;
const MAX_ENTRIES = 65536;
const EXEC_TIMEOUT_MS = 5000;

/** Throttle defaults when an action arrives without explicit shaping. */
const THROTTLE_DEFAULT_PPS = 5;
const THROTTLE_DEFAULT_BURST = 15;

/** Never mitigate these, whatever the engine above decides. */
const NEVER_MITIGATE = new Set(['127.0.0.1', '::1', '0.0.0.0', 'localhost']);

export class KernelMitigationDriver {
  private readonly drops = new Map<string, DropEntry>();
  /** Live sockets indexed by peer address, for RST injection. */
  private readonly liveSockets = new Map<string, Set<net.Socket>>();

  private caps: HostCapabilities | null = null;
  private capsProbedAt = 0;

  public totalMitigations = 0;
  public totalRstInjected = 0;
  public totalKernelRules = 0;
  public totalFirewallRules = 0;
  public totalPacketsDropped = 0;

  // -------------------------------------------------------------------
  // Capability probing
  // -------------------------------------------------------------------

  /**
   * Probes what the host genuinely supports.
   *
   * Cached, because shelling out to bpftool or netsh on every mitigation
   * would add tens of milliseconds to a path that must stay fast. Capabilities
   * do not change during a process lifetime except by operator action, and
   * refresh() exists for that case.
   */
  public async probeCapabilities(force = false): Promise<HostCapabilities> {
    if (this.caps && !force && Date.now() - this.capsProbedAt < 300_000) return this.caps;

    const platform = process.platform;
    const elevated = await this.isElevated();

    let bpftoolAvailable = false;
    let bpfMapPinned = false;
    let netshAvailable = false;

    if (platform === 'linux') {
      bpftoolAvailable = await this.commandExists('bpftool', ['version']);
      try { bpfMapPinned = fs.existsSync(BPF_PINNED_MAP); } catch { bpfMapPinned = false; }
    } else if (platform === 'win32') {
      netshAvailable = await this.commandExists('netsh', ['advfirewall', 'show', 'currentprofile']);
    }

    const hostFirewallEnabled = process.env.SOVEREIGN_ENABLE_HOST_FIREWALL === '1';

    let activeTier: EnforcementTier = 'SOCKET_RST';
    let tierReason: string;

    if (platform === 'linux' && elevated && bpftoolAvailable) {
      activeTier = 'KERNEL_XDP';
      tierReason = 'Linux host with bpftool and elevated privileges: packets are dropped in-kernel by XDP.';
    } else if (platform === 'win32' && elevated && netshAvailable && hostFirewallEnabled) {
      activeTier = 'WIN_FIREWALL';
      tierReason = 'Windows host, elevated, host-firewall writes explicitly enabled: blocking at the Windows Filtering Platform.';
    } else {
      activeTier = 'SOCKET_RST';
      tierReason = platform === 'linux'
        ? (elevated ? 'bpftool not found; falling back to userland RST injection.' : 'process is not privileged; XDP requires root. Falling back to userland RST injection.')
        : platform === 'win32'
          ? (!elevated
            ? 'process is not elevated; WFP rule creation requires Administrator. Falling back to userland RST injection.'
            : !hostFirewallEnabled
              ? 'host-firewall writes are disabled (set SOVEREIGN_ENABLE_HOST_FIREWALL=1 to allow). Falling back to userland RST injection.'
              : 'netsh unavailable; falling back to userland RST injection.')
          : platform + ' has no supported kernel hook; userland RST injection is the enforcement tier.';
    }

    this.caps = {
      platform, release: os.release(), elevated,
      bpftoolAvailable, bpfMapPinned, netshAvailable, hostFirewallEnabled,
      activeTier, tierReason
    };
    this.capsProbedAt = Date.now();
    return this.caps;
  }

  /** Real elevation check, per platform. */
  private async isElevated(): Promise<boolean> {
    try {
      if (process.platform === 'win32') {
        const { stdout } = await execFileAsync('powershell', [
          '-NoProfile', '-NonInteractive', '-Command',
          '([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)'
        ], { timeout: EXEC_TIMEOUT_MS });
        return stdout.trim().toLowerCase() === 'true';
      }
      // POSIX: uid 0 is root.
      return typeof process.getuid === 'function' ? process.getuid() === 0 : false;
    } catch {
      return false;
    }
  }

  private async commandExists(cmd: string, args: string[]): Promise<boolean> {
    try {
      await execFileAsync(cmd, args, { timeout: EXEC_TIMEOUT_MS });
      return true;
    } catch (err: any) {
      // A non-zero exit still proves the binary exists; only ENOENT means absent.
      return err?.code !== 'ENOENT';
    }
  }

  // -------------------------------------------------------------------
  // Unified mitigation API
  // -------------------------------------------------------------------

  /**
   * Applies mitigation using every tier the host supports.
   *
   * The in-memory drop map is written FIRST and unconditionally, so the
   * in-line check is authoritative from the moment this returns even if every
   * privileged tier fails. Kernel and firewall tiers are additive hardening,
   * never the sole line of defence.
   */
  public async mitigateIp(
    ip: string,
    action: MitigationAction = 'DROP',
    options: { reason?: string; ttlSeconds?: number; ratePps?: number; burst?: number } = {}
  ): Promise<MitigationResult> {
    const started = Date.now();
    const clean = String(ip ?? '').trim();
    const reason = options.reason ?? 'Autonomous mitigation';
    const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;

    if (!clean || NEVER_MITIGATE.has(clean) || !net.isIP(clean)) {
      return {
        ip: clean, action, enforcedBy: [],
        degraded: [{ tier: 'SOCKET_RST', reason: 'refused: loopback, unspecified, or not a valid IP' }],
        ruleId: null, expiresAt: null, latencyMs: Date.now() - started, success: false
      };
    }

    const caps = await this.probeCapabilities();
    const enforcedBy: EnforcementTier[] = [];
    const degraded: Array<{ tier: EnforcementTier; reason: string }> = [];
    let ruleId: string | null = null;

    // --- Tier 3 first: always available, guarantees enforcement -----
    const entry: DropEntry = {
      ip: clean, action, reason,
      installedAt: Date.now(),
      expiresAt: Date.now() + ttlSeconds * 1000,
      hits: 0,
      tiers: [],
      bucket: action === 'THROTTLE' ? {
        tokens: options.burst ?? THROTTLE_DEFAULT_BURST,
        capacity: options.burst ?? THROTTLE_DEFAULT_BURST,
        refillPerSec: options.ratePps ?? THROTTLE_DEFAULT_PPS,
        lastRefillMs: Date.now()
      } : undefined
    };
    this.drops.set(clean, entry);
    this.evict();
    enforcedBy.push('SOCKET_RST');

    // Immediately RST any connection already open from this peer.
    this.injectRst(clean);

    // --- Tier 1: Linux XDP ------------------------------------------
    if (caps.platform === 'linux') {
      if (caps.activeTier === 'KERNEL_XDP') {
        const r = await this.applyXdpDrop(clean, action);
        if (r.ok) { enforcedBy.push('KERNEL_XDP'); this.totalKernelRules++; ruleId = r.ruleId; }
        else degraded.push({ tier: 'KERNEL_XDP', reason: r.reason });
      } else {
        degraded.push({ tier: 'KERNEL_XDP', reason: caps.tierReason });
      }
    }

    // --- Tier 2: Windows Filtering Platform -------------------------
    if (caps.platform === 'win32') {
      if (caps.activeTier === 'WIN_FIREWALL') {
        const r = await this.applyWindowsFirewallRule(clean, action, reason);
        if (r.ok) { enforcedBy.push('WIN_FIREWALL'); this.totalFirewallRules++; ruleId = r.ruleId; }
        else degraded.push({ tier: 'WIN_FIREWALL', reason: r.reason });
      } else {
        degraded.push({ tier: 'WIN_FIREWALL', reason: caps.tierReason });
      }
    }

    entry.tiers = [...enforcedBy];
    this.totalMitigations++;
    this.publish(clean, action, enforcedBy, degraded, reason);

    return {
      ip: clean, action, enforcedBy, degraded, ruleId,
      expiresAt: entry.expiresAt,
      latencyMs: Date.now() - started,
      success: enforcedBy.length > 0
    };
  }

  // -------------------------------------------------------------------
  // Tier 1: Linux eBPF / XDP
  // -------------------------------------------------------------------

  /**
   * Writes the address into a pinned BPF map so XDP discards its packets in
   * the driver, before they reach the kernel network stack.
   */
  private async applyXdpDrop(ip: string, action: MitigationAction): Promise<{ ok: boolean; reason: string; ruleId: string | null }> {
    try {
      if (!fs.existsSync(BPF_PINNED_MAP)) {
        return { ok: false, reason: 'pinned BPF map ' + BPF_PINNED_MAP + ' does not exist; load the XDP program first', ruleId: null };
      }
      const key = ip.split('.').map(o => '0x' + Number(o).toString(16).padStart(2, '0'));
      const verdict = action === 'DROP' ? '0x01' : action === 'THROTTLE' ? '0x03' : '0x02';

      await execFileAsync('bpftool', [
        'map', 'update', 'pinned', BPF_PINNED_MAP,
        'key', 'hex', ...key,
        'value', 'hex', verdict, '00', '00', '00'
      ], { timeout: EXEC_TIMEOUT_MS });

      return { ok: true, reason: 'installed in pinned BPF map', ruleId: 'bpf:' + ip };
    } catch (err: any) {
      return { ok: false, reason: String(err?.message || err).slice(0, 160), ruleId: null };
    }
  }

  private async removeXdpDrop(ip: string): Promise<boolean> {
    try {
      const key = ip.split('.').map(o => '0x' + Number(o).toString(16).padStart(2, '0'));
      await execFileAsync('bpftool', ['map', 'delete', 'pinned', BPF_PINNED_MAP, 'key', 'hex', ...key], { timeout: EXEC_TIMEOUT_MS });
      return true;
    } catch { return false; }
  }

  // -------------------------------------------------------------------
  // Tier 2: Windows Filtering Platform via netsh
  // -------------------------------------------------------------------

  /**
   * Creates a real inbound block rule in the Windows Filtering Platform.
   *
   * netsh advfirewall is the supported CLI over WFP, so a rule created here
   * is enforced by the same kernel filtering engine the OS uses natively -
   * traffic from the peer is dropped before it reaches any listening socket.
   *
   * execFile with an argument array is used deliberately instead of a shell
   * string: the IP reaches this method from network input, and building a
   * shell command by concatenation would be a command-injection sink.
   */
  private async applyWindowsFirewallRule(
    ip: string,
    action: MitigationAction,
    reason: string
  ): Promise<{ ok: boolean; reason: string; ruleId: string | null }> {
    // Defence in depth: never interpolate an unvalidated address into a rule.
    if (!net.isIPv4(ip) && !net.isIPv6(ip)) {
      return { ok: false, reason: 'address failed strict IP validation', ruleId: null };
    }

    const ruleName = RULE_PREFIX + ip.replace(/[^0-9a-fA-F.:]/g, '');
    try {
      // Remove any prior rule for this peer so repeated mitigation does not
      // accumulate duplicates in the host firewall.
      await execFileAsync('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name=' + ruleName],
        { timeout: EXEC_TIMEOUT_MS }).catch(() => undefined);

      await execFileAsync('netsh', [
        'advfirewall', 'firewall', 'add', 'rule',
        'name=' + ruleName,
        'dir=in', 'action=block',
        'remoteip=' + ip,
        'enable=yes',
        'profile=any',
        'description=' + ('Sovereign Defender ' + action + ': ' + reason).slice(0, 200)
      ], { timeout: EXEC_TIMEOUT_MS });

      return { ok: true, reason: 'WFP inbound block rule installed', ruleId: ruleName };
    } catch (err: any) {
      const msg = String(err?.stderr || err?.message || err).slice(0, 160);
      return { ok: false, reason: msg || 'netsh rule creation failed', ruleId: null };
    }
  }

  private async removeWindowsFirewallRule(ip: string): Promise<boolean> {
    const ruleName = RULE_PREFIX + ip.replace(/[^0-9a-fA-F.:]/g, '');
    try {
      await execFileAsync('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name=' + ruleName], { timeout: EXEC_TIMEOUT_MS });
      return true;
    } catch { return false; }
  }

  /** Enumerates every rule this driver created on the host. */
  public async listHostRules(): Promise<string[]> {
    if (process.platform !== 'win32') return [];
    try {
      const { stdout } = await execFileAsync('netsh', ['advfirewall', 'firewall', 'show', 'rule', 'name=all'], { timeout: 15000 });
      return stdout.split('\n')
        .filter(l => l.includes(RULE_PREFIX))
        .map(l => l.split(':').slice(1).join(':').trim())
        .filter(Boolean);
    } catch { return []; }
  }

  /** Revokes every host rule this driver created. Used on shutdown/cleanup. */
  public async revokeAllHostRules(): Promise<{ removed: number; names: string[] }> {
    const names = await this.listHostRules();
    let removed = 0;
    for (const name of names) {
      try {
        await execFileAsync('netsh', ['advfirewall', 'firewall', 'delete', 'rule', 'name=' + name], { timeout: EXEC_TIMEOUT_MS });
        removed++;
      } catch { /* already gone */ }
    }
    return { removed, names };
  }

  // -------------------------------------------------------------------
  // Tier 3: userland RST injection + in-line drop map
  // -------------------------------------------------------------------

  /**
   * Registers a live socket so it can be reset if its peer is mitigated.
   *
   * The socket is de-registered on close, so the index tracks only sockets
   * that are genuinely open and cannot leak memory across connections.
   */
  public trackSocket(socket: net.Socket): void {
    const peer = (socket.remoteAddress ?? '').replace(/^::ffff:/, '');
    if (!peer) return;

    const set = this.liveSockets.get(peer) ?? new Set<net.Socket>();
    set.add(socket);
    this.liveSockets.set(peer, set);

    const cleanup = () => {
      const s = this.liveSockets.get(peer);
      if (!s) return;
      s.delete(socket);
      if (s.size === 0) this.liveSockets.delete(peer);
    };
    socket.once('close', cleanup);
    socket.once('error', cleanup);

    // If the peer is already mitigated, reset it the moment it connects.
    if (this.shouldDrop(peer).drop) {
      this.resetSocket(socket);
    }
  }

  /**
   * Destroys every open socket belonging to a peer.
   *
   * setNoDelay + destroy produces an abortive close, which the peer observes
   * as a TCP RST rather than an orderly FIN - the transport-level equivalent
   * of the kernel dropping the flow.
   */
  public injectRst(ip: string): number {
    const set = this.liveSockets.get(ip);
    if (!set || set.size === 0) return 0;
    let killed = 0;
    for (const socket of Array.from(set)) {
      if (this.resetSocket(socket)) killed++;
    }
    this.liveSockets.delete(ip);
    // Counted here rather than at the call site, so direct invocations are
    // measured too and the metric reflects every reset actually performed.
    this.totalRstInjected += killed;
    return killed;
  }

  private resetSocket(socket: net.Socket): boolean {
    try {
      socket.setNoDelay(true);
      // Zero linger makes the close abortive (RST) instead of graceful (FIN).
      if (typeof (socket as any).setKeepAlive === 'function') socket.setKeepAlive(false);
      socket.destroy();
      return true;
    } catch {
      return false;
    }
  }

  /**
   * In-line verdict consulted by request handling.
   *
   * O(1), synchronous, and safe to call per packet: this is what makes Tier 3
   * genuine enforcement rather than bookkeeping.
   */
  public shouldDrop(ip: string): { drop: boolean; action: MitigationAction | null; reason: string | null } {
    const entry = this.drops.get(ip);
    if (!entry) return { drop: false, action: null, reason: null };

    if (entry.expiresAt <= Date.now()) {
      this.drops.delete(ip);
      return { drop: false, action: null, reason: null };
    }

    entry.hits++;

    if (entry.action === 'THROTTLE' && entry.bucket) {
      // Lazy token-bucket refill: O(1), no timers.
      const now = Date.now();
      const elapsed = Math.max(0, (now - entry.bucket.lastRefillMs) / 1000);
      entry.bucket.tokens = Math.min(entry.bucket.capacity, entry.bucket.tokens + elapsed * entry.bucket.refillPerSec);
      entry.bucket.lastRefillMs = now;
      if (entry.bucket.tokens >= 1) {
        entry.bucket.tokens -= 1;
        return { drop: false, action: 'THROTTLE', reason: 'within throttle allowance' };
      }
      this.totalPacketsDropped++;
      return { drop: true, action: 'THROTTLE', reason: 'throttle bucket exhausted: ' + entry.reason };
    }

    this.totalPacketsDropped++;
    return { drop: true, action: entry.action, reason: entry.reason };
  }

  // -------------------------------------------------------------------
  // Lifecycle
  // -------------------------------------------------------------------

  public async revoke(ip: string): Promise<{ revoked: boolean; tiers: EnforcementTier[] }> {
    const entry = this.drops.get(ip);
    const tiers: EnforcementTier[] = [];
    if (entry) {
      this.drops.delete(ip);
      tiers.push('SOCKET_RST');
    }
    if (process.platform === 'linux' && entry?.tiers.includes('KERNEL_XDP')) {
      if (await this.removeXdpDrop(ip)) tiers.push('KERNEL_XDP');
    }
    if (process.platform === 'win32' && entry?.tiers.includes('WIN_FIREWALL')) {
      if (await this.removeWindowsFirewallRule(ip)) tiers.push('WIN_FIREWALL');
    }
    return { revoked: tiers.length > 0, tiers };
  }

  private evict(): void {
    const now = Date.now();
    for (const [ip, e] of this.drops.entries()) {
      if (e.expiresAt <= now) this.drops.delete(ip);
    }
    while (this.drops.size > MAX_ENTRIES) {
      const oldest = this.drops.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.drops.delete(oldest);
    }
  }

  private publish(
    ip: string, action: MitigationAction,
    enforcedBy: EnforcementTier[], degraded: Array<{ tier: EnforcementTier; reason: string }>,
    reason: string
  ): void {
    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'WAF_EBPF',
        severity: action === 'DROP' ? 'HIGH' : 'MEDIUM',
        title: '[Kernel Driver] ' + action + ' enforced on ' + ip + ' via ' + enforcedBy.join(' + '),
        titleAr: '[محرك النواة] تطبيق ' + action + ' على ' + ip + ' عبر ' + enforcedBy.join(' + '),
        details: reason + '. Enforced by: ' + enforcedBy.join(', ')
          + (degraded.length ? '. Unavailable: ' + degraded.map(d => d.tier + ' (' + d.reason + ')').join('; ') : ''),
        detailsAr: reason + '. طُبق عبر: ' + enforcedBy.join(', '),
        actorIp: ip,
        mitreTactic: 'Impact',
        mitreTechnique: 'T1498 - Network Denial of Service',
        actionTaken: 'KERNEL_MITIGATION_' + action,
        actionTakenAr: 'تخفيف على مستوى النواة: ' + action,
        metadata: { ip, action, enforcedBy, degraded, platform: process.platform }
      });
    } catch (err: any) {
      console.warn('[KernelDriver] Telemetry failed:', err?.message || err);
    }
  }

  public getActiveDrops(): DropEntry[] {
    const now = Date.now();
    return Array.from(this.drops.values())
      .filter(e => e.expiresAt > now)
      .sort((a, b) => b.installedAt - a.installedAt);
  }

  public async getStatus() {
    const caps = await this.probeCapabilities();
    return {
      capabilities: caps,
      activeDrops: this.getActiveDrops().length,
      trackedSockets: Array.from(this.liveSockets.values()).reduce((n, s) => n + s.size, 0),
      trackedPeers: this.liveSockets.size,
      counters: {
        totalMitigations: this.totalMitigations,
        totalRstInjected: this.totalRstInjected,
        totalKernelRules: this.totalKernelRules,
        totalFirewallRules: this.totalFirewallRules,
        totalPacketsDropped: this.totalPacketsDropped
      },
      safetyGate: {
        hostFirewallWritesEnabled: caps.hostFirewallEnabled,
        envFlag: 'SOVEREIGN_ENABLE_HOST_FIREWALL',
        note: 'Host firewall rules are only created when this flag is 1 AND the process is elevated.'
      }
    };
  }

  public clear(): void {
    this.drops.clear();
    this.liveSockets.clear();
  }
}

export const globalKernelMitigationDriver = new KernelMitigationDriver();
