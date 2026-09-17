import crypto from 'crypto';
import { globalUnifiedTelemetryService } from './unifiedTelemetry.service.js';
import { globalTelemetryWsServer } from '../wsServer.js';

// =============================================================================
// LIVE INTERACTIVE DECEPTION SANDBOX (v1.0)
//
// A stateful pseudo-shell and SQL console that really interprets the
// attacker's input against an isolated in-memory machine, keeps their changes
// between commands, and streams every keystroke to the SOC bus.
//
// EXECUTION SAFETY INVARIANT
// --------------------------
// Nothing here executes anything. There is no child_process import, no eval,
// no vm, no fs write. Every command is parsed and answered from an in-memory
// object graph, so the sandbox cannot become a pivot even if the interpreter
// itself has a bug. That is the single most important property of this file
// and it is enforced structurally, not by policy.
// =============================================================================

export type SandboxMode = 'SHELL' | 'SQL';

export interface SandboxNode {
  name: string;
  type: 'dir' | 'file';
  content?: string;
  mode: string;
  owner: string;
  group: string;
  size: number;
  modified: string;
  children?: Map<string, SandboxNode>;
}

export interface SandboxCommand {
  commandId: string;
  timestamp: number;
  sessionId: string;
  actorIp: string;
  mode: SandboxMode;
  /** Exactly what the attacker typed, unmodified. */
  input: string;
  output: string;
  exitCode: number;
  cwd: string;
  /** Canaries the attacker saw as a result of this command. */
  canariesRevealed: string[];
  /** True when the command mutated the sandbox state. */
  mutatedState: boolean;
  latencyMs: number;
}

export interface SandboxSession {
  sessionId: string;
  actorIp: string;
  mode: SandboxMode;
  cwd: string;
  user: string;
  hostname: string;
  env: Record<string, string>;
  fs: SandboxNode;
  history: string[];
  commands: SandboxCommand[];
  createdAt: number;
  lastActivityAt: number;
  canariesRevealed: Set<string>;
}

const MAX_SESSIONS = 200;
const MAX_HISTORY = 300;
const SESSION_TTL_MS = 60 * 60_000;

/** Deterministic per-session secrets, so a returning attacker sees the same. */
function sessionSecret(sessionId: string, label: string): string {
  return crypto.createHash('sha256').update(label + '|' + sessionId).digest('hex');
}

function nowStamp(): string {
  return new Date().toISOString().slice(0, 16).replace('T', ' ');
}

export class LiveDeceptionSandbox {
  private readonly sessions = new Map<string, SandboxSession>();
  public totalCommands = 0;
  public totalSessions = 0;
  public totalCanaryReveals = 0;

  // -------------------------------------------------------------------
  // Session lifecycle
  // -------------------------------------------------------------------

  public getOrCreate(sessionId: string, actorIp: string, mode: SandboxMode = 'SHELL'): SandboxSession {
    const existing = this.sessions.get(sessionId);
    if (existing) {
      existing.lastActivityAt = Date.now();
      return existing;
    }

    const hostname = 'app-prod-0' + (1 + (parseInt(sessionSecret(sessionId, 'host').slice(0, 4), 16) % 7));
    const session: SandboxSession = {
      sessionId,
      actorIp,
      mode,
      cwd: '/var/www/app',
      user: 'www-data',
      hostname,
      env: {
        USER: 'www-data', HOME: '/var/www', SHELL: '/bin/bash',
        PATH: '/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin',
        HOSTNAME: hostname, PWD: '/var/www/app', LANG: 'en_US.UTF-8',
        NODE_ENV: 'production'
      },
      fs: this.buildFilesystem(sessionId),
      history: [],
      commands: [],
      createdAt: Date.now(),
      lastActivityAt: Date.now(),
      canariesRevealed: new Set<string>()
    };

    this.sessions.set(sessionId, session);
    this.totalSessions++;
    this.evict();
    return session;
  }

  private evict(): void {
    const now = Date.now();
    for (const [id, s] of this.sessions.entries()) {
      if (now - s.lastActivityAt > SESSION_TTL_MS) this.sessions.delete(id);
    }
    while (this.sessions.size > MAX_SESSIONS) {
      const oldest = this.sessions.keys().next().value as string | undefined;
      if (oldest === undefined) break;
      this.sessions.delete(oldest);
    }
  }

  // -------------------------------------------------------------------
  // Synthetic machine
  // -------------------------------------------------------------------

  private dir(name: string, children: SandboxNode[] = [], owner = 'root'): SandboxNode {
    const map = new Map<string, SandboxNode>();
    for (const c of children) map.set(c.name, c);
    return { name, type: 'dir', mode: 'drwxr-xr-x', owner, group: owner, size: 4096, modified: nowStamp(), children: map };
  }

  private file(name: string, content: string, owner = 'root', mode = '-rw-r--r--'): SandboxNode {
    return { name, type: 'file', content, mode, owner, group: owner, size: Buffer.byteLength(content, 'utf-8'), modified: nowStamp() };
  }

  /** Builds the in-memory machine the attacker will explore. */
  private buildFilesystem(sessionId: string): SandboxNode {
    const apiKey = 'sk_live_' + sessionSecret(sessionId, 'stripe').slice(0, 32);
    const dbPass = sessionSecret(sessionId, 'db').slice(0, 24);
    const awsKey = 'AKIA' + sessionSecret(sessionId, 'aws').slice(0, 16).toUpperCase();

    return this.dir('/', [
      this.dir('etc', [
        this.file('passwd', [
          'root:x:0:0:root:/root:/bin/bash',
          'daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin',
          'www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin',
          'postgres:x:112:119:PostgreSQL admin:/var/lib/postgresql:/bin/bash',
          'deploy:x:1001:1001::/home/deploy:/bin/bash',
          'svc_reporting:x:1002:1002::/home/svc_reporting:/bin/bash'
        ].join('\n')),
        this.file('shadow', [
          'root:$6$rounds=656000$' + sessionSecret(sessionId, 'sh1').slice(0, 22) + ':19700:0:99999:7:::',
          'deploy:$6$rounds=656000$' + sessionSecret(sessionId, 'sh2').slice(0, 22) + ':19700:0:99999:7:::'
        ].join('\n'), 'root', '-rw-r-----'),
        this.file('hostname', 'app-prod-07'),
        this.file('hosts', '127.0.0.1 localhost\n10.0.2.14 app-prod-07\n10.0.2.31 db-replica-02\n10.0.2.44 cache-01'),
        this.dir('nginx', [this.file('nginx.conf', 'user www-data;\nworker_processes auto;\nserver {\n  listen 443 ssl;\n  server_name api.internal;\n  root /var/www/app/public;\n}')])
      ]),
      this.dir('var', [
        this.dir('www', [
          this.dir('app', [
            this.file('.env', [
              'NODE_ENV=production',
              'DATABASE_URL=postgres://svc_reporting:' + dbPass + '@db-replica-02:5432/analytics',
              'STRIPE_SECRET_KEY=' + apiKey,
              'AWS_ACCESS_KEY_ID=' + awsKey,
              'SESSION_SECRET=' + sessionSecret(sessionId, 'sess').slice(0, 40),
              'REDIS_URL=redis://cache-01:6379/2'
            ].join('\n'), 'www-data'),
            this.file('server.js', "const express=require('express');\nconst app=express();\napp.listen(3000);\n", 'www-data'),
            this.file('package.json', '{\n  "name": "sovereign-api",\n  "version": "4.0.0"\n}', 'www-data'),
            this.dir('public', [this.file('index.html', '<!doctype html><title>API</title>', 'www-data')]),
            this.dir('logs', [
              this.file('access.log', '10.0.2.9 - - [04/Mar/2026:09:11:02] "GET /api/v1/reports HTTP/1.1" 200 8214\n10.0.2.9 - - [04/Mar/2026:09:11:44] "POST /api/v1/orders HTTP/1.1" 201 412', 'www-data'),
              this.file('error.log', '2026-03-04 09:08:31 ERROR db: connection pool exhausted (max=20)', 'www-data')
            ])
          ], 'www-data')
        ])
      ]),
      this.dir('home', [
        this.dir('deploy', [
          this.file('.bash_history', 'ssh deploy@db-replica-02\npsql -U svc_reporting analytics\nkubectl get pods -n prod\nexit', 'deploy'),
          this.dir('.ssh', [
            this.file('id_rsa', '-----BEGIN OPENSSH PRIVATE KEY-----\n' +
              (sessionSecret(sessionId, 'ssh').repeat(10).match(/.{1,64}/g) ?? []).slice(0, 12).join('\n') +
              '\n-----END OPENSSH PRIVATE KEY-----', 'deploy', '-rw-------'),
            this.file('authorized_keys', 'ssh-rsa AAAAB3NzaC1yc2E' + sessionSecret(sessionId, 'ak').slice(0, 40) + ' deploy@bastion', 'deploy')
          ], 'deploy')
        ], 'deploy')
      ]),
      this.dir('root', [
        this.file('.bash_history', 'systemctl restart sovereign-api\ncat /opt/sovereign/backup.sql | gzip > /backups/db.sql.gz', 'root'),
        this.file('notes.txt', 'Rotate the reporting service credential before Q3 audit.', 'root')
      ]),
      this.dir('opt', [this.dir('sovereign', [this.file('backup.sql', '-- PostgreSQL dump\n-- 48,213 rows\n', 'root')])]),
      this.dir('tmp', [])
    ]);
  }

  // -------------------------------------------------------------------
  // Path resolution
  // -------------------------------------------------------------------

  private normalizePath(cwd: string, target: string): string {
    if (!target || target === '.') return cwd;
    let base = target.startsWith('/') ? [] : cwd.split('/').filter(Boolean);
    for (const part of target.split('/')) {
      if (!part || part === '.') continue;
      if (part === '..') base.pop();
      else base.push(part);
    }
    return '/' + base.join('/');
  }

  private resolve(session: SandboxSession, absPath: string): SandboxNode | null {
    if (absPath === '/' || absPath === '') return session.fs;
    let node: SandboxNode = session.fs;
    for (const part of absPath.split('/').filter(Boolean)) {
      if (node.type !== 'dir' || !node.children) return null;
      const next = node.children.get(part);
      if (!next) return null;
      node = next;
    }
    return node;
  }

  private parentOf(session: SandboxSession, absPath: string): { parent: SandboxNode | null; name: string } {
    const parts = absPath.split('/').filter(Boolean);
    const name = parts.pop() ?? '';
    const parent = this.resolve(session, '/' + parts.join('/'));
    return { parent, name };
  }

  // -------------------------------------------------------------------
  // Command execution (interpretation only)
  // -------------------------------------------------------------------

  /**
   * Interprets one attacker command against the sandbox and returns real
   * output derived from the sandbox's current state.
   */
  public execute(sessionId: string, actorIp: string, input: string, mode?: SandboxMode): SandboxCommand {
    const started = Date.now();
    const session = this.getOrCreate(sessionId, actorIp, mode ?? 'SHELL');
    if (mode && mode !== session.mode) session.mode = mode;

    const raw = String(input ?? '');
    session.history.push(raw);
    while (session.history.length > MAX_HISTORY) session.history.shift();

    const canariesBefore = session.canariesRevealed.size;
    let output: string;
    let exitCode = 0;
    let mutated = false;

    try {
      if (session.mode === 'SQL') {
        const r = this.runSql(session, raw);
        output = r.output; exitCode = r.exitCode; mutated = r.mutated;
      } else {
        const r = this.runShell(session, raw);
        output = r.output; exitCode = r.exitCode; mutated = r.mutated;
      }
    } catch (err: any) {
      // The interpreter must never surface a Node stack trace: that would
      // instantly reveal the sandbox is a JavaScript program.
      output = 'bash: internal error';
      exitCode = 1;
    }

    const revealed = Array.from(session.canariesRevealed).slice(canariesBefore);
    this.totalCanaryReveals += revealed.length;
    this.totalCommands++;
    session.lastActivityAt = Date.now();

    const command: SandboxCommand = {
      commandId: 'CMD-' + crypto.randomBytes(4).toString('hex').toUpperCase(),
      timestamp: Date.now(),
      sessionId, actorIp,
      mode: session.mode,
      input: raw.slice(0, 2048),
      output: output.slice(0, 8192),
      exitCode,
      cwd: session.cwd,
      canariesRevealed: revealed,
      mutatedState: mutated,
      latencyMs: Date.now() - started
    };

    session.commands.push(command);
    while (session.commands.length > MAX_HISTORY) session.commands.shift();

    this.stream(command, session);
    return command;
  }

  /** Marks that the attacker has now seen a given class of planted secret. */
  private revealCanary(session: SandboxSession, id: string): void {
    session.canariesRevealed.add(id);
  }

  private runShell(session: SandboxSession, raw: string): { output: string; exitCode: number; mutated: boolean } {
    const line = raw.trim();
    if (!line) return { output: '', exitCode: 0, mutated: false };

    // Support the pipelines and chains an attacker actually types; each
    // segment is interpreted and only the last segment's output is returned,
    // which matches shell semantics closely enough to be convincing.
    const segments = line.split(/\s*(?:\|\||&&|;|\|)\s*/).filter(Boolean);
    let out = '';
    let code = 0;
    let mutated = false;

    for (const seg of segments) {
      const r = this.runSingle(session, seg);
      out = r.output; code = r.exitCode; mutated = mutated || r.mutated;
    }
    return { output: out, exitCode: code, mutated };
  }

  private runSingle(session: SandboxSession, seg: string): { output: string; exitCode: number; mutated: boolean } {
    const parts = seg.trim().split(/\s+/);
    const cmd = (parts[0] ?? '').toLowerCase();
    const args = parts.slice(1).filter(a => !a.startsWith('-'));
    const flags = parts.slice(1).filter(a => a.startsWith('-'));

    switch (cmd) {
      case 'pwd': return { output: session.cwd, exitCode: 0, mutated: false };
      case 'whoami': return { output: session.user, exitCode: 0, mutated: false };
      case 'id': return { output: 'uid=33(www-data) gid=33(www-data) groups=33(www-data)', exitCode: 0, mutated: false };
      case 'hostname': return { output: session.hostname, exitCode: 0, mutated: false };
      case 'uname': return {
        output: flags.includes('-a')
          ? 'Linux ' + session.hostname + ' 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux'
          : 'Linux',
        exitCode: 0, mutated: false
      };
      case 'date': return { output: new Date().toUTCString(), exitCode: 0, mutated: false };
      case 'echo': return { output: seg.slice(seg.indexOf('echo') + 4).trim().replace(/^["']|["']$/g, ''), exitCode: 0, mutated: false };
      case 'history': return { output: session.history.map((h, i) => String(i + 1).padStart(5) + '  ' + h).join('\n'), exitCode: 0, mutated: false };
      case 'env':
      case 'printenv':
        return { output: Object.entries(session.env).map(([k, v]) => k + '=' + v).join('\n'), exitCode: 0, mutated: false };

      case 'cd': {
        const target = this.normalizePath(session.cwd, args[0] ?? '/var/www');
        const node = this.resolve(session, target);
        if (!node) return { output: 'bash: cd: ' + (args[0] ?? '') + ': No such file or directory', exitCode: 1, mutated: false };
        if (node.type !== 'dir') return { output: 'bash: cd: ' + (args[0] ?? '') + ': Not a directory', exitCode: 1, mutated: false };
        session.cwd = target === '' ? '/' : target;
        session.env.PWD = session.cwd;
        return { output: '', exitCode: 0, mutated: true };
      }

      case 'ls':
      case 'dir': {
        const target = this.normalizePath(session.cwd, args[0] ?? '.');
        const node = this.resolve(session, target);
        if (!node) return { output: "ls: cannot access '" + (args[0] ?? '') + "': No such file or directory", exitCode: 2, mutated: false };
        if (node.type === 'file') return { output: node.name, exitCode: 0, mutated: false };

        const kids = Array.from(node.children?.values() ?? []);
        if (flags.some(f => f.includes('l'))) {
          const rows = kids.map(k =>
            k.mode + ' 1 ' + k.owner.padEnd(9) + k.group.padEnd(9) + String(k.size).padStart(7) + ' ' + k.modified + ' ' + k.name);
          return { output: 'total ' + kids.length * 4 + '\n' + rows.join('\n'), exitCode: 0, mutated: false };
        }
        const showHidden = flags.some(f => f.includes('a'));
        return {
          output: kids.filter(k => showHidden || !k.name.startsWith('.')).map(k => k.name).join('  '),
          exitCode: 0, mutated: false
        };
      }

      case 'cat':
      case 'head':
      case 'tail':
      case 'less':
      case 'more': {
        if (args.length === 0) return { output: '', exitCode: 0, mutated: false };
        const target = this.normalizePath(session.cwd, args[0]);
        const node = this.resolve(session, target);
        if (!node) return { output: cmd + ': ' + args[0] + ': No such file or directory', exitCode: 1, mutated: false };
        if (node.type === 'dir') return { output: cmd + ': ' + args[0] + ': Is a directory', exitCode: 1, mutated: false };

        // Permission realism: www-data genuinely cannot read /etc/shadow.
        if (node.mode.startsWith('-rw-------') || node.mode === '-rw-r-----') {
          if (session.user !== 'root') {
            return { output: cmd + ': ' + args[0] + ': Permission denied', exitCode: 1, mutated: false };
          }
        }

        const content = node.content ?? '';
        if (/STRIPE_SECRET_KEY|AWS_ACCESS_KEY_ID|DATABASE_URL/.test(content)) this.revealCanary(session, 'ENV_CREDENTIALS');
        if (/BEGIN OPENSSH PRIVATE KEY/.test(content)) this.revealCanary(session, 'SSH_PRIVATE_KEY');
        if (/\$6\$rounds/.test(content)) this.revealCanary(session, 'SHADOW_HASHES');

        const lines = content.split('\n');
        if (cmd === 'head') return { output: lines.slice(0, 10).join('\n'), exitCode: 0, mutated: false };
        if (cmd === 'tail') return { output: lines.slice(-10).join('\n'), exitCode: 0, mutated: false };
        return { output: content, exitCode: 0, mutated: false };
      }

      case 'find': {
        const results: string[] = [];
        const walk = (node: SandboxNode, prefix: string) => {
          const full = prefix === '/' ? '/' + node.name : prefix + '/' + node.name;
          if (node !== session.fs) results.push(full);
          if (node.children) for (const k of node.children.values()) walk(k, node === session.fs ? '' : full);
        };
        walk(session.fs, '');
        const needle = args.find(a => !a.startsWith('/'));
        return {
          output: (needle ? results.filter(r => r.includes(needle.replace(/\*/g, ''))) : results).slice(0, 200).join('\n'),
          exitCode: 0, mutated: false
        };
      }

      case 'ps': return {
        output: [
          'USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND',
          'root         1  0.0  0.1 168404 11284 ?        Ss   Mar03   0:14 /sbin/init',
          'www-data   842  0.3  1.8 1284932 74216 ?       Sl   Mar03   2:41 node /var/www/app/server.js',
          'postgres   613  0.1  2.4 421884 98120 ?        Ss   Mar03   1:07 postgres: writer process',
          'www-data  9931  0.0  0.0   7376  3204 ?        R    09:14   0:00 ps aux'
        ].join('\n'), exitCode: 0, mutated: false
      };

      case 'netstat':
      case 'ss': return {
        output: [
          'Proto Recv-Q Send-Q Local Address           Foreign Address         State',
          'tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN',
          'tcp        0      0 10.0.2.14:5432          10.0.2.31:44122         ESTABLISHED',
          'tcp        0      0 10.0.2.14:6379          10.0.2.44:39914         ESTABLISHED'
        ].join('\n'), exitCode: 0, mutated: false
      };

      case 'ifconfig':
      case 'ip': return {
        output: 'eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n        inet 10.0.2.14  netmask 255.255.255.0  broadcast 10.0.2.255',
        exitCode: 0, mutated: false
      };

      case 'mkdir': {
        if (!args[0]) return { output: 'mkdir: missing operand', exitCode: 1, mutated: false };
        const target = this.normalizePath(session.cwd, args[0]);
        const { parent, name } = this.parentOf(session, target);
        if (!parent || parent.type !== 'dir') return { output: "mkdir: cannot create directory '" + args[0] + "': No such file or directory", exitCode: 1, mutated: false };
        parent.children?.set(name, this.dir(name, [], session.user));
        return { output: '', exitCode: 0, mutated: true };
      }

      case 'touch': {
        if (!args[0]) return { output: 'touch: missing file operand', exitCode: 1, mutated: false };
        const target = this.normalizePath(session.cwd, args[0]);
        const { parent, name } = this.parentOf(session, target);
        if (!parent || parent.type !== 'dir') return { output: 'touch: cannot touch ' + args[0] + ': No such file or directory', exitCode: 1, mutated: false };
        if (!parent.children?.has(name)) parent.children?.set(name, this.file(name, '', session.user));
        return { output: '', exitCode: 0, mutated: true };
      }

      case 'rm': {
        if (!args[0]) return { output: 'rm: missing operand', exitCode: 1, mutated: false };
        const target = this.normalizePath(session.cwd, args[0]);
        const { parent, name } = this.parentOf(session, target);
        if (!parent?.children?.has(name)) return { output: 'rm: cannot remove ' + args[0] + ': No such file or directory', exitCode: 1, mutated: false };
        // Root-owned files resist www-data, exactly as they would on a real box.
        const victim = parent.children.get(name)!;
        if (victim.owner === 'root' && session.user !== 'root') {
          return { output: 'rm: cannot remove ' + args[0] + ': Permission denied', exitCode: 1, mutated: false };
        }
        parent.children.delete(name);
        return { output: '', exitCode: 0, mutated: true };
      }

      case 'sudo':
        return { output: session.user + ' is not in the sudoers file.  This incident will be reported.', exitCode: 1, mutated: false };
      case 'su':
        return { output: 'su: Authentication failure', exitCode: 1, mutated: false };
      case 'wget':
      case 'curl':
        this.revealCanary(session, 'EGRESS_ATTEMPT');
        return { output: cmd + ': (6) Could not resolve host: egress blocked by policy', exitCode: 6, mutated: false };
      case 'nc':
      case 'ncat':
        this.revealCanary(session, 'EGRESS_ATTEMPT');
        return { output: 'nc: connect: Network is unreachable', exitCode: 1, mutated: false };
      case 'psql':
        return { output: 'psql (14.10)\nType "help" for help.\n\nanalytics=>', exitCode: 0, mutated: false };
      case 'mysql':
        return { output: 'ERROR 2002 (HY000): Can\'t connect to local MySQL server through socket', exitCode: 1, mutated: false };
      case 'exit':
      case 'logout':
        return { output: 'logout', exitCode: 0, mutated: false };
      case 'clear':
        return { output: '', exitCode: 0, mutated: false };
      default:
        return { output: 'bash: ' + cmd + ': command not found', exitCode: 127, mutated: false };
    }
  }

  // -------------------------------------------------------------------
  // SQL console
  // -------------------------------------------------------------------

  private runSql(session: SandboxSession, raw: string): { output: string; exitCode: number; mutated: boolean } {
    const q = raw.trim().replace(/;+$/, '');
    if (!q) return { output: '', exitCode: 0, mutated: false };
    const lower = q.toLowerCase();

    const tables: Record<string, { cols: string[]; rows: string[][] }> = {
      users: {
        cols: ['id', 'username', 'email', 'role', 'created_at'],
        rows: [
          ['1', 'admin', 'admin@internal.example', 'superuser', '2023-01-14'],
          ['2', 'a.hassan', 'a.hassan@internal.example', 'analyst', '2023-06-02'],
          ['3', 'svc_reporting', 'noreply@internal.example', 'service', '2023-06-11'],
          ['4', 'deploy', 'deploy@internal.example', 'operator', '2024-02-20']
        ]
      },
      credentials: {
        cols: ['user_id', 'password_hash', 'api_token'],
        rows: [
          ['1', '$2b$12$' + sessionSecret(session.sessionId, 'h1').slice(0, 22), 'tok_' + sessionSecret(session.sessionId, 't1').slice(0, 24)],
          ['2', '$2b$12$' + sessionSecret(session.sessionId, 'h2').slice(0, 22), 'tok_' + sessionSecret(session.sessionId, 't2').slice(0, 24)]
        ]
      },
      invoices: {
        cols: ['id', 'customer', 'amount_cents', 'status'],
        rows: [
          ['4471', 'Northwind Ltd', '1284900', 'paid'],
          ['4472', 'Contoso GmbH', '746500', 'pending'],
          ['4473', 'Fabrikam SA', '2210000', 'paid']
        ]
      }
    };

    if (/^show\s+tables/.test(lower)) {
      return { output: this.renderTable(['Tables_in_analytics'], Object.keys(tables).map(t => [t])), exitCode: 0, mutated: false };
    }
    if (/^show\s+databases/.test(lower)) {
      return { output: this.renderTable(['Database'], [['analytics'], ['reporting'], ['information_schema']]), exitCode: 0, mutated: false };
    }
    if (/^(describe|desc)\s+/.test(lower)) {
      const t = lower.replace(/^(describe|desc)\s+/, '').trim();
      const table = tables[t];
      if (!table) return { output: 'ERROR:  relation "' + t + '" does not exist', exitCode: 1, mutated: false };
      return { output: this.renderTable(['Field', 'Type'], table.cols.map(c => [c, c.endsWith('_at') ? 'timestamp' : 'text'])), exitCode: 0, mutated: false };
    }
    if (/information_schema\.tables/.test(lower)) {
      return { output: this.renderTable(['table_name'], Object.keys(tables).map(t => [t])), exitCode: 0, mutated: false };
    }

    if (/^select/.test(lower)) {
      const from = lower.match(/from\s+([a-z_][a-z0-9_]*)/);
      const name = from?.[1] ?? '';
      const table = tables[name];
      if (!table) {
        return { output: 'ERROR:  relation "' + (name || '?') + '" does not exist\nLINE 1: ' + q.slice(0, 60), exitCode: 1, mutated: false };
      }
      if (name === 'credentials') this.revealCanary(session, 'DB_CREDENTIAL_TABLE');

      // Tautologies dump everything, which is the payoff a SQLi operator expects.
      const dumpAll = /or\s+['"]?1['"]?\s*=\s*['"]?1|--|\bunion\b/.test(lower);
      const rows = dumpAll ? table.rows : table.rows.slice(0, 3);
      return { output: this.renderTable(table.cols, rows) + '\n(' + rows.length + ' rows)', exitCode: 0, mutated: false };
    }

    if (/^(insert|update|delete|drop|alter|create)/.test(lower)) {
      return { output: 'ERROR:  permission denied for relation\nHINT:  role "svc_reporting" has only SELECT privileges.', exitCode: 1, mutated: false };
    }
    if (/sleep\s*\(|pg_sleep\s*\(/.test(lower)) {
      // Answer as if the delay really occurred - the attacker is timing this.
      return { output: this.renderTable(['pg_sleep'], [['']]), exitCode: 0, mutated: false };
    }

    return { output: 'ERROR:  syntax error at or near "' + q.split(/\s+/)[0] + '"\nLINE 1: ' + q.slice(0, 60), exitCode: 1, mutated: false };
  }

  private renderTable(cols: string[], rows: string[][]): string {
    const widths = cols.map((c, i) => Math.max(c.length, ...rows.map(r => (r[i] ?? '').length)));
    const line = '+' + widths.map(w => '-'.repeat(w + 2)).join('+') + '+';
    const header = '|' + cols.map((c, i) => ' ' + c.padEnd(widths[i]) + ' ').join('|') + '|';
    const body = rows.map(r => '|' + widths.map((w, i) => ' ' + (r[i] ?? '').padEnd(w) + ' ').join('|') + '|');
    return [line, header, line, ...body, line].join('\n');
  }

  // -------------------------------------------------------------------
  // Live telemetry
  // -------------------------------------------------------------------

  private stream(command: SandboxCommand, session: SandboxSession): void {
    // Per-keystroke/per-command push to the SOC grid.
    try {
      globalTelemetryWsServer.broadcast('sandbox:command', {
        commandId: command.commandId,
        sessionId: command.sessionId,
        actorIp: command.actorIp,
        mode: command.mode,
        cwd: command.cwd,
        input: command.input,
        output: command.output.slice(0, 1200),
        exitCode: command.exitCode,
        canariesRevealed: command.canariesRevealed,
        timestamp: command.timestamp,
        totalCommands: session.commands.length
      });
    } catch (err: any) {
      console.warn('[Sandbox] WS broadcast failed:', err?.message || err);
    }

    // Only escalate to the audit bus for commands that matter, so a trapped
    // actor typing `ls` fifty times cannot flood the shared ring buffer.
    const notable = command.canariesRevealed.length > 0
      || /passwd|shadow|id_rsa|\.env|credentials|sudo|curl|wget|nc\b/i.test(command.input);
    if (!notable) return;

    try {
      globalUnifiedTelemetryService.recordEvent({
        source: 'HONEYPOT',
        severity: command.canariesRevealed.length > 0 ? 'HIGH' : 'MEDIUM',
        title: '[Live Sandbox] ' + command.mode + ' command from ' + command.actorIp + ': ' + command.input.slice(0, 60),
        titleAr: '[الصندوق الحي] أمر ' + command.mode + ' من ' + command.actorIp + ': ' + command.input.slice(0, 60),
        details: 'cwd=' + command.cwd + ' exit=' + command.exitCode
          + (command.canariesRevealed.length ? ' | canaries revealed: ' + command.canariesRevealed.join(', ') : '')
          + ' | output: ' + command.output.slice(0, 160).replace(/\n/g, ' / '),
        detailsAr: 'المسار=' + command.cwd + ' رمز الخروج=' + command.exitCode
          + (command.canariesRevealed.length ? ' | طُعوم مكشوفة: ' + command.canariesRevealed.join(', ') : ''),
        actorIp: command.actorIp,
        sessionId: command.sessionId,
        mitreTactic: command.canariesRevealed.includes('SSH_PRIVATE_KEY') || command.canariesRevealed.includes('ENV_CREDENTIALS')
          ? 'Credential Access' : 'Discovery',
        mitreTechnique: command.canariesRevealed.length > 0
          ? 'T1552.001 - Unsecured Credentials: Credentials In Files'
          : 'T1083 - File and Directory Discovery',
        actionTaken: 'LIVE_SANDBOX_COMMAND_CAPTURED',
        actionTakenAr: 'تم التقاط أمر داخل الصندوق الحي',
        metadata: {
          commandId: command.commandId,
          input: command.input,
          output: command.output.slice(0, 600),
          exitCode: command.exitCode,
          cwd: command.cwd,
          mode: command.mode,
          canariesRevealed: command.canariesRevealed,
          interactiveSandbox: true
        }
      });
    } catch (err: any) {
      console.warn('[Sandbox] Telemetry failed:', err?.message || err);
    }
  }

  // -------------------------------------------------------------------
  // Query surface
  // -------------------------------------------------------------------

  public getSession(sessionId: string): SandboxSession | null {
    return this.sessions.get(sessionId) ?? null;
  }

  public getSessions() {
    return Array.from(this.sessions.values()).map(s => ({
      sessionId: s.sessionId, actorIp: s.actorIp, mode: s.mode, cwd: s.cwd,
      user: s.user, hostname: s.hostname,
      commandCount: s.commands.length,
      canariesRevealed: Array.from(s.canariesRevealed),
      createdAt: s.createdAt, lastActivityAt: s.lastActivityAt
    })).sort((a, b) => b.lastActivityAt - a.lastActivityAt);
  }

  public getTranscript(sessionId?: string, limit = 100): SandboxCommand[] {
    if (sessionId) {
      const s = this.sessions.get(sessionId);
      return s ? s.commands.slice(-limit).reverse() : [];
    }
    const all: SandboxCommand[] = [];
    for (const s of this.sessions.values()) all.push(...s.commands);
    return all.sort((a, b) => b.timestamp - a.timestamp).slice(0, limit);
  }

  public getStats() {
    return {
      activeSessions: this.sessions.size,
      totalSessions: this.totalSessions,
      totalCommands: this.totalCommands,
      totalCanaryReveals: this.totalCanaryReveals,
      executesRealCommands: false,
      sessionTtlMs: SESSION_TTL_MS
    };
  }

  public destroy(sessionId: string): boolean { return this.sessions.delete(sessionId); }
  public clear(): void { this.sessions.clear(); }
}

export const globalLiveDeceptionSandbox = new LiveDeceptionSandbox();
