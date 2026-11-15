---
name: performance-optimization
description: Use when measuring or improving classifier throughput and latency - profiling the /api/v1/agent/ai-analyze path, investigating event-loop blocking, CPU, memory, caching or concurrency, or comparing requests/sec and p50/p95/p99 before and after a change.
---

# Performance optimization

## Profile before choosing a fix

The server is a single Node process. Throughput plateaus near 170 req/s on the reference laptop
while one classification takes about 15 ms end to end, so the limit is per-request work on the
event loop, not the regex rules themselves (a comment in `server.ts` measures the classifier at
about 0.1 ms). Find where the rest goes before changing anything.

```bash
# CPU profile of the server under load
node --cpu-prof --cpu-prof-dir=prof --import tsx server.ts        # shell 1
ADMIN_API_KEY=... node audit/perf_benchmark.mjs out.json          # shell 2, then stop shell 1
# open prof/*.cpuprofile in Chrome DevTools, or summarise top self-time functions
```

Also check `perf_hooks.monitorEventLoopDelay()` if tail latency is the question.

## Suspects found by reading the request path (hypotheses, not findings)

Each must be confirmed in a profile before it is touched:

- `globalAdjudication.recordPending()` - synchronous SQLite write on every uncached request.
- `globalDriftDetector.observe()` - calls `classifyPayload()` a second time per request.
- `globalStrategicRetention.admit()` and `globalSocMetrics.record()` on the hot path.
- `express.json({ limit: '50mb', verify })` raw-body capture for every request.
- Dev mode (`tsx`) versus the built bundle (`npm run build && npm start`).

## Constraints

- Detection must not change. Re-run the dev-half evaluation after any hot-path edit; identical
  confusion matrix or the change is not a pure optimisation.
- Deferring a write (batching adjudication inserts) must not lose records on shutdown and must
  keep the append-only and provenance guarantees tested by audit cases 51-60.
- `node:cluster` / `worker_threads` only after checking shared state: in-memory rate limiters,
  the LRU cache, WebSocket clients, containment and eBPF services, and SQLite writers are all
  per-process today. Multiple processes would split or duplicate them. Prefer moving pure CPU
  work to a worker pool over forking the whole server, and only if the profile says CPU-bound.
- Caching must never be what a benchmark times: `perf_benchmark.mjs` uses unique payloads.
- Do not present simulated XDP figures as kernel performance.

## Measurement protocol

Same machine, same power state, same Node version, same server mode, server freshly restarted,
nothing else running. Run the benchmark twice and keep both files; if the two baselines differ
by more than 10%, the machine is too noisy to prove a 20% gain and that must be reported.

```bash
ADMIN_API_KEY=... node audit/perf_benchmark.mjs audit/results/perf_<commit>.json
node scripts/compare-perf.mjs audit/results/baseline_perf_2ab323e.json audit/results/perf_<commit>.json --min-throughput-gain=20
```

## Success criterion

Throughput at 100 clients up by at least 20% relative to the same-machine baseline, p95 not
worse, zero non-200 responses, detection results unchanged, audit suite still at zero failures.

## Examples

- "Make it faster" → profile, report the top three self-time frames with percentages, propose
  the one change with the best gain-to-risk ratio.
- "Add cluster mode" → first list every piece of per-process state it would break.
