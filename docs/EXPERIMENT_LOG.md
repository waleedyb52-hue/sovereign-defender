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
| Design | Pending rows buffered, one transaction per 50 ms or 256 rows; labels still synchronous; every reader flushes first; exit hook flushes. `SD_ADJUDICATION_WRITE_BEHIND=off` restores write-through. 10.40.x added to evaluation sources. **Corrected in cycle 6:** the exit hook does not run on SIGINT/SIGTERM (Node ends without emitting `exit`), so this design lost the buffer on every normal stop until graceful shutdown was added; and the 10.40.x range was a caller-supplied address, replaced in cycle 6 by a server-verified flag |
| Measurement | Interleaved A/B, 3 rounds each, fresh server per run, 100 clients, 3,000 unique payloads (`perf_ab_writebehind.json`) |
| Result | median **176.8 → 454.9 req/s**; ranges 140.4–188.5 vs 432.2–550.4 (no overlap); p95 657 → 315 ms; p99 702 → 333 ms; 0 failed; RSS 289 → 284 MB |
| Detection | Unchanged: route dev-half confusion matrix after this commit equals cycle 2's in-process result (TP 5,739) |
| Tests | unit 172 / 172 (write-behind tests also pass with the buffer off); audit suite **92 / 92** |
| Decision | **Keep** |

## Cycle 4 — freeze and sealed evaluation (`candidate-48h-1` → `237420e`)

No code change. Scored once each, `SD_EVAL_SEALED=1`, fresh server. Results in
[`IMPROVEMENT_EVIDENCE.md`](IMPROVEMENT_EVIDENCE.md).

## Cycle 5 — padding bypass and the defects behind it (`c435d2e`, tag `candidate-48h-2`)

| Field | Value |
|---|---|
| Hypothesis | Reading only the first 4 KB lets filler hide an injection; overlapping windows close it at bounded cost |
| Evidence before coding | Injection after 5 KB, 100 KB, 1 MB, 10 MB of letters / JSON / quote / SQL-ish filler: missed in all 16 cases |
| First attempt | Windows over the whole payload, 2 KB overlap. Detection fixed in all cases; cost 2.6–3.2 s on 10 MB of dense filler. **Rejected** as a DoS lever |
| Second attempt | 1 KB overlap, full coverage to 1 MB, head + tail beyond. A new test then exposed an O(n²) scan over `)` runs: 1 MB of `)` = 12.4 s. Fixed (run end once per run → 70 ms). Worst linear cost still ~350 ms per request at 1 MB. **Rejected** |
| Kept | Full coverage to 256 KB, first and last 128 KB beyond. Structural cost ≤ 65 ms on 10 MB adversarial input |
| Found by the new tests | "select one (or two)" read as a call (pre-existing in candidate-48h-1); original `sleep\s*\(` signature flags "sleep (a lot)" (pre-existing in the baseline). Both fixed with adjacency |
| Dev half, in-process | Identical output to candidate-48h-1, every class, both thresholds |
| Sealed sets | Re-scored once on the new tag: identical confusion matrices. Labelled re-evaluation |
| Second-source benign, 100,000 lines | Unchanged: +5 by structure, all real attacks |
| Tests | unit 208 / 208; audit suite 92 / 92; Set A / Set B unchanged |
| Throughput @100 | 637.3 req/s, one run; within noise, no gain claimed |
| Decision | **Keep** |

## Cycle 6 — fixes from the PR #2 review (`c139113` … `27267a2`)

The review of PR #2 returned NOT READY TO MERGE. Each finding was fixed in its own commit, with
the dev half, Set A and Set B as the regression check and the sealed sets left alone.

| Finding | Evidence | Fix | Verified by |
|---|---|---|---|
| **B1** quadratic backtracking in the dot-run traversal rule added in cycle 2 | 80 KB of dots: 5,112 ms in `classifyPayload` | Start only at the beginning of a dot run: `(?<!\.)\.{3,}[\/\\]\.{3,}[\/\\]` | 4 ms on the same input; dev half identical |
| **P1** same defect in the pre-existing DNS base64 rule | 80 KB of `/bin/`: 5,991 ms | Start only at the beginning of a base64 run | 4 ms |
| 11 more super-linear regexes found by the new scanner (`audit/redos_scan.mjs`, 385 regexes) | 5 more in the classifier, 6 in other services; 2 of those take honeypot input and were reachable **without authentication** | Bounded or anchored rewrites; one replaced by two index scans | Scanner: 13 → 0 of 385; each rewrite compared with its original on attack and look-alike samples (`redosFixes.test.ts`, 39 cases) |
| **srcIp** decided two security matters | Rate-limit key and review exclusion both read `packet.srcIp`, which the caller writes | Exclusion only for ADMIN + direct loopback + declared header; limiter keyed on principal + TCP peer, on the model path it protects; payloads above 1 MiB refused with 413 | Audit #102 (claimed 10.20.x is still reviewed; verified evaluation is not), #103 (413; injection at the end of a 1 MiB payload detected) |
| **B2** write-behind lost its buffer on every normal stop | `server.ts` had no SIGINT/SIGTERM handlers | `server/gracefulShutdown.ts`: flush at once, close, flush again, exit 0 | Child process with a real SQLite file: SIGTERM and SIGINT write all 25 rows, SIGKILL writes 0 (control). Real-server SIGTERM check in CI |
| **C1** CI detection steps could not fail | Both harnesses end with `process.exit(0)` | `--gate` with floors in `audit/regression_gate.json`; dev-half gate pinned by SHA-256; audit suite, ReDoS scan and shutdown check added to CI | Each gate passes on the real floors and exits 1 when one floor is raised above the measured value |
| **D1** docs and result files disagreed | A stale 172/172, the exit-hook claim, four result files edited by hand | Docs corrected; `audit/results/PROVENANCE.md`; the four files regenerated without samples | Regenerated baselines identical to the edited ones, figure for figure |

Also found and fixed on the way: `seed_adjudication_drill.ts` had been silently broken by the
10.90.x exclusion (it exists to fill the review queue); verified evaluation traffic no longer
feeds drift statistics or the learner's retention store; a unit test committed in `0c4f9a0`
still asserted the old exclusion and failed — the commit went in because the command chain
checked `grep`'s exit code instead of `vitest`'s (fixed in `c31c91c`).

Detection after all cycle-6 changes: HttpParams dev half in-process, identical to
candidate-48h-2 at both thresholds and every class (gate output, `regression_gate.json`).

## Cycle 7 — follow-ups after the merge (branch `improvement/followups-defense`)

Started from `main` at the merge commit `faad341` (identical tree to the measured `25639a4`).

### 7a. Console honesty (`315b63c`)

The deep-analysis modal rendered any HTTP reply as an analysis, invented a verdict (BLOCK, score
96, "zero-day confirmed") on a network failure, drew four fixed "XAI attribution" bars
(38/32/18/12 %) for every packet, and called every result "Gemini". Transport and zod validation
moved to `src/lib/aiAnalysis.ts`; the modal now shows a result, or an explicit error with the
status and the server's message, names the engine that ran, and lists the rules that fired.
7 unit tests. Not checked in a browser: it needs a signed-in operator session.

### 7b. Per-caller classification budget (`eec3fea`)

| Field | Value |
|---|---|
| Problem | After the srcIp fix the local path had no per-caller bound: one authenticated client could send 1 MiB payloads back to back |
| Change | `server/classificationBudget.ts`: token bucket in characters per minute, keyed on principal + TCP peer; 256-char floor per request; bounded caller map. Default 64 MiB/min; 429 `CLASSIFICATION_BUDGET_EXCEEDED` + `Retry-After`. Verified evaluation exempt |
| Evidence | Real server at 1 MiB/min (`audit/budget_check.mjs`, in CI): 700 KB → 200, next 700 KB → 429 (Retry-After 22 s), verified evaluation → 200. At the default budget: audit suite 94/94, perf benchmark 1–100 clients with zero non-200 |
| Decision | **Keep** |

### 7c. Second-source gaps (`cfda6e8`)

| Field | Value |
|---|---|
| Data | Fwaf attack ranks 5,000–14,999 (dev, read); 15,000–24,999 (validation, never read, scored before and after only); benign-labelled ranks 20,000–119,999 (read for false positives). Sealed ranks untouched until the end |
| Hypothesis | The misses (cycle 4 diagnosis) are shell expansion syntax, Windows command lines, PHP complex-syntax injection, remote file inclusion and HTML injection without `<script>` — classes with no rule, not obfuscations of covered ones |
| Rules | 22 structural rules plus named-entity decoding and Unicode NFKC in canonicalisation. Deliberately not written: payload-less script-path requests, the scanner marker `XXpathXX`, lone quotes |
| Narrowed during the cycle | `rem` alone cannot block; `file`/`url` and `*url/*uri/*href/*link/*src` parameters are not include-named (Swagger's `?configUrl=`); a single trailing `?` is not an RFI terminator (worth 39 of 10,000 dev attacks); `sleep N` must end the command |
| Fwaf dev | 40.57 % → **66.79 %** |
| Fwaf validation (never read) | 40.72 % → **67.38 %** |
| Fwaf benign-labelled 100 k | 131 → 1,565 flags. Every newly flagged line read: all scanner probes the source labels good (192.168.202.x, `cirt.net/rfiinc.txt`, acunetix/vulnweb hosts, Nessus ping/sleep/rem). Genuine false positives: **0** |
| HttpParams dev | 5,739 → 5,750 at 25; XSS 232 → 243; FP 0 |
| Set A / Set B | Set A held-out 13 → 14 of 14. Set B Tier 1 15/15, benign 0/22. **Tier 2 3 → 4 of 12** (unicode-bypass, a side effect of NFKC; the Tier 2 miss list was known when NFKC was chosen, so not counted; floor stays 3) |
| Fwaf sealed test (scored once, end of cycle) | 41.60 % → **67.24 %** recall. Benign-labelled flags 12 → 157 of 10,000 (1.57 %) — the same rate as the dev-side benign-labelled lines (1.57 %), every one of which was a scanner probe. The sealed lines were not opened. **This is now an in-distribution figure for Fwaf**, like the HttpParams sealed half for HttpParams |
| HttpParams sealed half (re-evaluation) | 97.28 % → 97.50 % (XSS 83.27 % → 88.21 %), FP 0 |
| Throughput | Interleaved `faad341` vs `cfda6e8`: medians 804 vs 1,220 req/s, ranges 350–1,473 vs 1,042–1,343 (overlap; the machine varied 4× between runs of the same code). No gain claimed; no regression measured |
| Other checks | ReDoS 0 of 412; unit tests 306/306; audit suite 94/94; zero egress (60 s) |
| Decision | **Keep** |

Found during the cycle: a look-alike test written in cycle 5 ("`?dir=http://10.0.0.5:8080/x`") had
been adapted from a benign-labelled Fwaf line that was in fact a scanner's RFI probe. The new RFI
rule flagged it; the URL was removed from that test.

## Considered and not built

| Candidate | Why not |
|---|---|
| libinjection | No npm package (`npm view libinjection` → 404). Needs C → WASM or a native addon, licence review and its own FP run; cycle 1 already met the dev target with a 300-line in-house tokenizer |
| Wider canonicalisation (base64, NFKC) | Existing canonicalisation already decodes URL (3 rounds), SQL comments and HTML entities. Base64 only when a decode primitive is present was planned as P1 and not reached; the one remaining Set A miss is exactly that case |
| `node:cluster` / worker threads | The profile showed I/O on the event loop, not CPU. Rate limiters, LRU cache, WebSockets, containment and SQLite writers are per-process state; forking would split them. Not needed for the goal |
| Machine-learned component | Out of scope for 48 hours; the plan's Phase 3 |
