# Improvement evidence — before / after

**Status on 2026-11-15: baseline only. No detector or server code has been changed yet, so
there is no "after".** Every "after" cell below reads NOT MEASURED until a result file exists.
Nothing in this document may be filled in by hand; each figure is copied from the JSON file
named beside it, produced by the command shown.

Protocol and data rules: [`48H_IMPROVEMENT_ROADMAP.md`](48H_IMPROVEMENT_ROADMAP.md).
Baseline details and environment: [`BASELINE_METRICS.md`](BASELINE_METRICS.md).

## 1. Detection — sealed half (the independent figure)

`node scripts/compare-detection.mjs audit/results/baseline_external_sealed_2ab323e.json audit/results/sealed_<commit>.json --min-recall-gain=20`

| | Before (`2ab323e`) | After | Change |
|---|---|---|---|
| TP / FN / FP / TN | 2,397 / 3,515 / 0 / 9,664 | NOT MEASURED | — |
| Recall (95% CI) | 40.54% (39.30 – 41.80) | NOT MEASURED | — |
| Precision | 100.00% | NOT MEASURED | — |
| F1 / MCC | 57.70% / 0.5453 | NOT MEASURED | — |
| SQL injection | 39.25% | NOT MEASURED | — |
| XSS | 83.27% | NOT MEASURED | — |
| Path traversal | 23.42% | NOT MEASURED | — |
| Command injection | 6.82% | NOT MEASURED | — |

Sealed runs performed on a candidate so far: **0**.

## 2. Detection — dev half (regression figure once rules are written from it)

| | Before (`2ab323e`) | After | Change |
|---|---|---|---|
| TP / FN / FP / TN | 2,416 / 3,435 / 0 / 9,640 | NOT MEASURED | — |
| Recall (95% CI) | 41.29% (40.04 – 42.56) | NOT MEASURED | — |
| SQL injection | 39.46% | NOT MEASURED | — |

## 3. Detection — in-repo sets

| | Before | After |
|---|---|---|
| Set A misses | 2 | NOT MEASURED |
| Set B overall recall / benign FP | 66.7% / 0 of 22 | NOT MEASURED |
| Set B Tier 2 (must not be targeted) | 3 / 12 | NOT MEASURED |

## 4. Performance — same machine, same mode

`node scripts/compare-perf.mjs audit/results/baseline_perf_2ab323e.json audit/results/perf_<commit>.json --min-throughput-gain=20`

| At 100 clients | Before (`2ab323e`) | After | Change |
|---|---|---|---|
| Throughput | 172.8 req/s | NOT MEASURED | — |
| p50 / p95 / p99 | 543.7 / 583.2 / 1,145.6 ms | NOT MEASURED | — |
| Single-request classify p50 | 15.3 ms | NOT MEASURED | — |
| Non-200 responses | 0 | NOT MEASURED | — |

## 5. Zero egress

| | Before | After |
|---|---|---|
| External attempts (45 s soak, in-process probe) | 0 | NOT MEASURED |

## 6. Change log

One row per kept change. A change without a measured effect is not kept.

| Commit | Change | Dev recall | Dev FP | Set B benign FP | Throughput @100 | Result file |
|---|---|---|---|---|---|---|
| `2ab323e` | baseline | 41.29% | 0 | 0 / 22 | 172.8 req/s | `baseline_*_2ab323e.json` |

## 7. Tooling added on this branch (no behaviour change to the detector)

| File | Purpose |
|---|---|
| `audit/split_external.ts` | deterministic dev / sealed split with SHA-256 manifest |
| `audit/eval_external_httpparams.ts` | added `SD_EVAL_SEALED=1`: aggregate output only |
| `audit/analyze_dev_misses.ts` | structural bucketing of dev-half misses; refuses sealed files |
| `scripts/compare-detection.mjs`, `scripts/compare-perf.mjs` | before/after tables and gates |
| `scripts/egress-probe.mjs`, `scripts/zero-egress-check.mjs` | outbound-connection probe and check |
| `.github/workflows/ci.yml` | lint, unit tests, build, Set A and Set B on push / PR — **not yet run on GitHub** |
| `.claude/skills/*` | five project skills |
