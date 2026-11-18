# 48-hour improvement roadmap

**Status (end of pass): executed. Results in FINAL_ENGINEERING_REPORT.md. The sections below are the plan as written at the start.**

**Start:** 2026-11-15 · **Branch:** `improvement/48h-detection-performance` · **Baseline:**
[`BASELINE_METRICS.md`](BASELINE_METRICS.md) · **Evidence log:** [`IMPROVEMENT_EVIDENCE.md`](IMPROVEMENT_EVIDENCE.md)

## Goals (targets, not results)

| Goal | Baseline (measured 15 Nov) | Target | Where it is proven |
|---|---|---|---|
| External recall | 40.54% on the sealed half | ≥ 60.54% (+20 pp) | sealed half, one run on the frozen candidate |
| Throughput at 100 clients | 172.8 req/s, this machine, dev mode | ≥ 207.4 req/s (+20%) | `scripts/compare-perf.mjs`, same machine |
| p95 at 100 clients | 583 ms | not worse | same |
| False positives | 0 / 9,664 sealed benign, 0 / 22 Set B | 0, or every one listed | sealed half + Set B |
| Existing tests | lint clean, 53/53 unit | unchanged | `npm run lint`, `npx vitest run`, audit suite |

Detection and throughput are reported separately. There is no combined "efficiency" figure.

## Why the detection target is reachable — and what could stop it

Dev-half analysis (`audit/analyze_dev_misses.ts`, result in
`audit/results/dev_miss_analysis_2ab323e.json`), classifier called in-process:

- 3,320 SQLi samples missed. **3,275 of them (98.6%) carry at least one generic SQL-structure
  feature** from a list of 14; only 45 carry none.
- Across 9,640 benign dev values, **1** carries any of those features.
- Largest buckets (overlapping): `select` followed by a function/case/subquery 1,800 · SQL
  function call (`char(`, `concat(`, `elt(`, `extractvalue(` …) 1,668 · trailing SQL comment
  1,650 · quote/paren break then `or`/`and` 1,532 · numeric comparison after
  `or`/`and`/`where`/`having` 1,493 · `select … from` 1,459 · system catalog names 783 ·
  stacked statement 686.
- 1,644 of the misses already score above zero: a rule fired but stayed under the threshold.
- XSS (97 missed in-process), command injection (42) and path traversal (84) match none of the
  SQL features; they need their own analysis and are worth at most ~3 pp together.

SQLi is 92% of all attacks in the set. Lifting SQLi recall from 39% to 62% alone meets the goal.

**What this does not show.** These are counts on the half that was read. The features are
hypotheses, not rules; real rules will be narrower. The benign side of this dataset is CSIC
2010 parameter values (names, addresses, short strings) — it contains almost no SQL-like or
code-like benign text, so "1 benign match" understates false-positive risk on real API
traffic. Set B benign and hand-written look-alike tests are the guard for that.

## Priorities

- **P0** — must land or the goal fails.
- **P1** — lands if P0 is green by H+24.
- **P2** — only with time left; otherwise recorded as future work.

| # | Pri | Work | Files |
|---|---|---|---|
| 1 | P0 | SQLi structural rules: numeric tautology without quotes, quote/paren break + boolean, `select` + function/subquery, SQL function calls in value position, stacked statements beyond the four verbs covered today, catalog names | `server/services/payloadClassifier.service.ts`, new `server/services/payloadClassifier.sqli.test.ts` |
| 2 | P0 | Weight/corroboration fix for near misses (1,644 score > 0): pairs of weak SQL signals convict together | same |
| 3 | P0 | Look-alike benign test corpus (prose about SQL, `o'brien`, arithmetic, search queries, Arabic/Spanish text, JSON bodies) | new test file |
| 4 | P0 | Frozen-candidate sealed run + Set A + Set B + audit suite | `audit/results/` |
| 5 | P1 | Normalisation hardening: input length cap, Unicode NFKC for full-width traversal, `%u00xx`; base64 decoded **only** when a decode primitive is present (`base64 -d`, `base64_decode(`, `atob(`, `-enc`) | `canonicalisePayload()` |
| 6 | P1 | Performance: CPU profile, then the single best hot-path fix | `server.ts` (`/ai-analyze`), possibly `adjudication.service.ts` |
| 7 | P1 | Command injection and path traversal: bucket dev misses, one class-level rule each | classifier + tests |
| 8 | P2 | Built-bundle performance figure; 5-minute egress soak; packet capture on Linux | scripts, docs |
| 9 | P2 | `libinjection` evaluation | — |

`libinjection` is P2 on evidence: there is no npm package (`npm view libinjection` → 404), so
it means building C to WASM or a native addon, plus licence and FP measurement, inside the
window. The dev-half data says in-house structural rules are sufficient for the 20 pp goal.

## Hour-by-hour

Times are offsets from start. Each block ends with its acceptance check; a failed check
triggers the rollback listed, not an extension.

### Day 1 — detection

| Hours | Block | Acceptance | Rollback |
|---|---|---|---|
| H+0 – H+1 | **Done:** audit, branch, baseline, split, tooling. Second perf baseline run. Clear or avoid the local adjudication queue. | Two perf baselines within 10% of each other | If not, state that the host is too noisy for a 20% claim and take perf on a quieter boot |
| H+1 – H+3 | Bucket dev SQLi misses properly (mutually exclusive buckets, top 8). Write the benign look-alike corpus **first**, as failing-safe tests. | Bucket table in the evidence log; look-alike tests pass on the unchanged classifier | — |
| H+3 – H+7 | Rules for the three largest buckets, one commit each, unit tests both directions. | After each commit: dev recall up, 0 FP on 9,640 dev benign, 0 / 22 Set B benign, Set B Tier 1 still 15/15 | `git revert` the commit whose FP cannot be fixed in 30 min |
| H+7 – H+9 | Near-miss corroboration (item 2). ReDoS timing of every new regex on a 1 MB input. | Each rule < 50 ms on adversarial input; dev SQLi recall ≥ 70% | Drop corroboration, keep rules |
| H+9 – H+11 | Remaining SQLi buckets; `security-code-review` checklist on the diff. | Dev recall ≥ 65% overall (margin above the 60.9% goal) | Stop adding rules; freeze what passes |
| H+11 – H+12 | Full gate on the dev candidate: lint, vitest, build, Set A, Set B, audit suite. | All green | Fix or revert the offending commit |
| — | Sleep. No rule is written tired. | | |

### Day 2 — normalisation, performance, proof

| Hours | Block | Acceptance | Rollback |
|---|---|---|---|
| H+24 – H+27 | Normalisation hardening (item 5). | Set A reaches 0 misses; dev benign FP still 0; classify p50 at 1 client not worse by more than 1 ms | Revert normalisation only |
| H+27 – H+31 | Profile under load, apply one hot-path fix (item 6). Candidates to confirm, in order of suspicion: synchronous SQLite insert per request (`recordPending`), second `classifyPayload` in drift observation, dev-mode overhead. | `compare-perf.mjs --min-throughput-gain=20` passes; dev-half confusion matrix identical before and after the perf change; audit cases 51–60 pass | Revert; report the profile and the measured gain honestly |
| H+31 – H+34 | Command injection + path traversal (item 7), if P0 is green. | No class regresses > 1 pp; 0 new FP | Revert |
| H+34 – H+36 | **Freeze.** Tag the candidate commit. No rule change after this point. | Clean tree, all gates green | — |
| H+36 – H+38 | Sealed run (once), whole-file run, Set A, Set B, audit suite, perf ×2, egress check with 300 s soak. | Numbers recorded whatever they are | — |
| H+38 – H+42 | Fill `IMPROVEMENT_EVIDENCE.md` from the result files. Regenerate report/poster figures from JSON. | Every number traceable to a file in `audit/results/` | — |
| H+42 – H+48 | Buffer: PR, review, one re-run if a run was disturbed. | | |

## Release gate

A change is kept only if all of these hold:

```bash
npm run lint && npx vitest run && npm run build
ADMIN_API_KEY=... npx tsx audit/eval_harness.ts
ADMIN_API_KEY=... npx tsx audit/eval_holdout_b.ts
ADMIN_API_KEY=... npx tsx audit/audit_suite.ts
node scripts/compare-detection.mjs audit/results/baseline_external_dev_2ab323e.json <dev_candidate.json>
node scripts/compare-perf.mjs audit/results/baseline_perf_2ab323e.json <perf_candidate.json>
```

and it has a measured effect written in the evidence log. A change with no measurable effect
is reverted, not kept "in case".

## Integrity rules for this pass

1. The sealed half is not opened. It is scored once on the frozen candidate with
   `SD_EVAL_SEALED=1`. If a rule changes afterwards, the next sealed figure is labelled a
   re-evaluation.
2. Set B Tier 2 misses are not used to write rules. A Tier 2 class that starts being detected
   as a side effect is reported as a side effect.
3. Evaluation requests keep `vector: 'UNKNOWN'` and send no score, as before, so before and
   after are the same measurement (see baseline finding 1).
4. The dev half becomes regression data the moment rules are written from it. The whole-file
   figure after this pass is therefore **half regression, half independent**, and is reported
   with that label beside the sealed-half figure. The poster headline should use the sealed half.
5. A second, untouched external dataset is the stronger proof and is out of reach in 48 hours;
   it is listed as the first item of future work.

## Risks to the 20-point goal

| Risk | Likelihood | Effect | Mitigation |
|---|---|---|---|
| New rules flag benign text that the CSIC-derived benign set does not contain | **High** | Precision claim becomes untested rather than false — worse for the project's thesis | Look-alike corpus written first; rules require SQL syntax, never a bare keyword; report FP on every set |
| Dev-half gains do not transfer to the sealed half | Low — same generator, hash split | Miss the goal | Margin: aim for ≥ 65% on dev |
| Regex backtracking on large payloads | Medium | Throughput collapse or DoS vector | 1 MB timing test per rule; length cap |
| Perf baseline noise on a laptop | Medium | 20% gain not provable | Two baselines, AC power, nothing else running |
| Hot-path fix weakens adjudication guarantees | Medium | Audit cases 51–60 fail | Batch, do not drop; flush on shutdown |
| Team rewrites rules after seeing the sealed number | Medium under deadline | Loses the only independent figure | Freeze at H+34, written here |
| `Data` / `data/` case collision blocks merging to `main` on Windows | Certain until fixed | Cannot fast-forward locally | Rename `Data` upstream |

## Not in this pass

Machine-learned component (Phase 3), Set C, native XDP, IPv6 in the XDP filter, multi-process
serving. Each needs more than 48 hours to do without breaking a guarantee.
