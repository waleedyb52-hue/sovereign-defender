# Experiment log — 48-hour pass, 2026-11-15

One row per hypothesis that reached code. Every figure is copied from a file in
`audit/results/` or from a command printed beside it. "In-process" means
`audit/eval_dev_inprocess.ts` calling `classifyPayload()` directly; "route" means
`audit/eval_external_httpparams.ts` against a freshly started server, which judges at score 25
because the harness sends `vector: 'UNKNOWN'` (see BASELINE_METRICS.md, finding 1).

Only development data was read during cycles 1–3: the HttpParams dev half, Set A, the second
source's benign dev file, and 100,000 further benign-labelled lines from that source outside its
sealed test ranks. The sealed sets were scored once on the baseline and once on the frozen
candidate (cycle 4).

## Cycle 0 — environment and baseline (`1f54c62`, `7a46165`)

| Field | Value |
|---|---|
| Hypothesis | The poster figures reproduce on this machine; the external set can be split before any rule work |
| Changed files | `audit/split_external.ts`, `audit/eval_external_httpparams.ts` (sealed mode), comparison and egress scripts, CI, skills |
| Result | Full file TP 4,813 / FN 6,950 / FP 0 — identical to the poster |
| Git | Local `main` was 3 behind `origin/main`; checkout failed because root file `Data` collides with `data/` on Windows. Merged `origin/main` into the branch with `Data` renamed to `notebooks/cic_ids2018_colab.py` (content unchanged). No reset, no force, nothing deleted. Local `main` fast-forwarded to `989befb` by ref only. |
| Decision | Keep |

## Cycle 1 — structural SQL analysis (`ac9dc78`)

| Field | Value |
|---|---|
| Hypothesis | SQLi misses are ordinary sqlmap output that differs from fixed signatures by a parenthesis or a missing quote; reading the payload as SQL tokens (constant-vs-constant tests, subquery comparisons, SELECT with expression list, stacked statements, context breaks) catches the technique without matching any tool's text |
| Evidence before coding | `audit/analyze_dev_misses.ts`: 3,275 of 3,320 dev SQLi misses carry ≥1 of 14 generic structural features; 1 of 9,640 dev benign values does |
| Changed files | `server/services/sqlStructure.ts` (new), `server/services/payloadClassifier.service.ts`, `src/__tests__/sqlStructure.test.ts` |
| Baseline (in-process, threshold 55) | overall 39.45%, SQLi 38.58%, FP 0 / 9,640 |
| Candidate (in-process, threshold 55) | overall **95.56%**, SQLi **99.26%**, FP 0 / 9,640 |
| Ablation | `--no-structure` reproduces the baseline exactly, so the whole delta is this component |
| Route, dev half | recall 41.29% → 97.01%, FP 0 (`dev_structure_cand1.json`) |
| Second-source benign | dev benign file 9 → 9 flags; 100,000 further lines: **+5 flags**, each a real `or 1=1` injection the source labels "good" (`fp_stress_structure_dev.json`) |
| Runtime cost | in-process 19.3 → 30.7 µs per payload (one run each) |
| Iterations inside the cycle | (a) `count()`/`length()` in prose scored 40 → empty calls no longer count as SQL functions; (b) `all_users` as a URL directory → catalog names only count in table position |
| Tests | unit 53 → 127 pass; lint clean; Set A misses 2 → 1; Set B unchanged (66.7%, 0 / 22 FP, Tier 2 3 / 12) |
| Decision | **Keep** |

## Cycle 2 — command injection, traversal, prose punctuation (`d7ae2a3`)

| Field | Value |
|---|---|
| Hypothesis | Command-injection misses are a separator plus a command (`;id`, `|/usr/bin/id|`, `` `uname` ``) with no rule at all; traversal misses are dot-runs and hex-spelled separators. Separately, `looksLikeProse()` counted the dots of an IP address as sentence punctuation and exempted quoteless injections from SQL/RCE rules |
| Changed files | `payloadClassifier.service.ts`, `src/__tests__/sqlStructure.test.ts` |
| Baseline (in-process, 55) | overall 95.56%, cmdi 6.67%, traversal 36.36% |
| Candidate (in-process, 55) | overall **96.63%**, cmdi **77.78%**, traversal **59.85%**, FP 0 / 9,640 |
| Second-source benign | dev benign file 9 → 10; across 100,000 further lines the new non-SQL rules flag 20, all Nessus command-injection probes (`|id|`, `|ping -w … |rem`) labelled "good" |
| Iterations inside the cycle | 3 failing tests → `ping` needed an argument shape; `&` alone no longer a separator before short names ("tom & cat; dog"); `bash`/`curl` need an argument |
| Tests | unit 167 / 167 |
| Decision | **Keep** |

## Cycle 3 — pending-queue write-behind (`237420e`)

| Field | Value |
|---|---|
| Hypothesis | Throughput is bounded by synchronous per-request work, not by the classifier |
| Evidence before coding | CPU profile under 50-client load: `recordPending` 17.7% of wall time (≈30% of non-idle), drift detection 2.9%, everything else < 2.2% each. Classifier itself ≈ 30 µs |
| Changed files | `server/services/adjudication.service.ts`, `src/__tests__/adjudicationWriteBehind.test.ts`, `scripts/perf-ab.mjs` |
| Design | Pending rows buffered, one transaction per 50 ms or 256 rows; labels still synchronous; every reader flushes first; exit hook flushes. `SD_ADJUDICATION_WRITE_BEHIND=off` restores write-through. 10.40.x added to evaluation sources |
| Measurement | Interleaved A/B, 3 rounds each, fresh server per run, 100 clients, 3,000 unique payloads (`perf_ab_writebehind.json`) |
| Result | median **176.8 → 454.9 req/s**; ranges 140.4–188.5 vs 432.2–550.4 (no overlap); p95 657 → 315 ms; p99 702 → 333 ms; 0 failed; RSS 289 → 284 MB |
| Detection | Unchanged: route dev-half confusion matrix after this commit equals cycle 2's in-process result (TP 5,739) |
| Tests | unit 172 / 172 (write-behind tests also pass with the buffer off); audit suite **92 / 92** |
| Decision | **Keep** |

## Cycle 4 — freeze and sealed evaluation (`candidate-48h-1` → `237420e`)

No code change. Scored once each, `SD_EVAL_SEALED=1`, fresh server. Results in
[`IMPROVEMENT_EVIDENCE.md`](IMPROVEMENT_EVIDENCE.md).

## Considered and not built

| Candidate | Why not |
|---|---|
| libinjection | No npm package (`npm view libinjection` → 404). Needs C → WASM or a native addon, licence review and its own FP run; cycle 1 already met the dev target with a 300-line in-house tokenizer |
| Wider canonicalisation (base64, NFKC) | Existing canonicalisation already decodes URL (3 rounds), SQL comments and HTML entities. Base64 only when a decode primitive is present was planned as P1 and not reached; the one remaining Set A miss is exactly that case |
| `node:cluster` / worker threads | The profile showed I/O on the event loop, not CPU. Rate limiters, LRU cache, WebSockets, containment and SQLite writers are per-process state; forking would split them. Not needed for the goal |
| Machine-learned component | Out of scope for 48 hours; the plan's Phase 3 |
