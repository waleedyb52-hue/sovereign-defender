/**
 * GRACEFUL SHUTDOWN
 *
 * Node's default reaction to SIGINT (Ctrl+C) and SIGTERM (docker stop, systemd, Kubernetes)
 * is to end the process at once, without emitting 'exit'. Anything held in memory for a
 * later write is lost. The adjudication queue is written behind the request path (batched
 * every 50 ms), so before this module every normal stop could drop up to 50 ms — at most 256
 * rows — of detections awaiting analyst review.
 *
 * On a stop signal this:
 *   1. runs every flush step immediately, before waiting on anything, so buffered rows are
 *      on disk even if what follows hangs or the orchestrator escalates to SIGKILL;
 *   2. stops accepting connections and closes idle keep-alive sockets;
 *   3. runs the flush steps again once in-flight requests have finished, since those can
 *      buffer more rows;
 *   4. exits 0, or exits 1 after `timeoutMs` if connections (e.g. WebSockets) did not close,
 *      flushing once more first.
 * A second signal during shutdown flushes and exits immediately.
 *
 * What it cannot cover — documented, not hidden: SIGKILL, `taskkill /F`, Windows
 * TerminateProcess (which is what child.kill() does on Windows), an out-of-memory kill, a
 * crash of the runtime itself, or power loss. Those lose whatever is still in the buffer:
 * at most FLUSH_INTERVAL (50 ms) or 256 pending-review rows. Labels, the audit trail and
 * every other store are written synchronously and are not affected.
 */

export interface FlushStep {
  name: string;
  run: () => void;
}

/** The parts of an http/https server this module uses, described structurally. */
export interface ClosableServer {
  close(callback?: (err?: Error) => void): unknown;
  closeIdleConnections?(): void;
  closeAllConnections?(): void;
}

export interface GracefulShutdownOptions {
  server?: ClosableServer;
  flush: FlushStep[];
  /** How long to wait for open connections before exiting anyway. */
  timeoutMs?: number;
  log?: (message: string) => void;
  /** Injected by tests; defaults to process.exit. */
  exit?: (code: number) => void;
}

const SIGNALS: NodeJS.Signals[] =
  process.platform === 'win32' ? ['SIGINT', 'SIGTERM', 'SIGBREAK'] : ['SIGINT', 'SIGTERM', 'SIGHUP'];

export function installGracefulShutdown(opts: GracefulShutdownOptions): { shutdown: (reason: string) => void } {
  const log = opts.log ?? ((m: string) => console.log(m));
  const exit = opts.exit ?? ((code: number) => process.exit(code));
  const timeoutMs = opts.timeoutMs ?? 5000;
  let stopping = false;

  const flushAll = (stage: string) => {
    for (const step of opts.flush) {
      try { step.run(); } catch (err: any) { log(`[shutdown] ${step.name} flush failed at ${stage}: ${err?.message}`); }
    }
  };

  const shutdown = (reason: string) => {
    if (stopping) {
      log(`[shutdown] ${reason} again — flushing and exiting now`);
      flushAll('forced');
      exit(1);
      return;
    }
    stopping = true;
    log(`[shutdown] ${reason} received — flushing buffered writes and closing connections`);
    flushAll('signal');

    const server = opts.server;
    if (!server) { flushAll('final'); exit(0); return; }

    const timer = setTimeout(() => {
      log(`[shutdown] connections still open after ${timeoutMs} ms — exiting anyway`);
      flushAll('timeout');
      server.closeAllConnections?.();
      exit(1);
    }, timeoutMs);
    server.close(() => {
      clearTimeout(timer);
      flushAll('final');
      log('[shutdown] clean');
      exit(0);
    });
    server.closeIdleConnections?.();
  };

  for (const sig of SIGNALS) process.on(sig, () => shutdown(sig));
  return { shutdown };
}
