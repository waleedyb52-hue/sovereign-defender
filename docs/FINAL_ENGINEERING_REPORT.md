# Sovereign Defender — 48-hour engineering pass, final report

**Dates:** 2026-11-15 (pass), 2026-11-18 (review fixes) · **Branch:** `improvement/48h-detection-performance`
· **Before:** `2ab323e` (code identical to the poster's `989befb`) · **After:** the branch head after
the review fixes (section 4c). Sealed sets first scored on `237420e` (tag `candidate-48h-1`);
later scores are labelled re-evaluations.

Detailed tables: [`IMPROVEMENT_EVIDENCE.md`](IMPROVEMENT_EVIDENCE.md) · per-change record:
[`EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md) · baseline: [`BASELINE_METRICS.md`](BASELINE_METRICS.md).

## 1. Executive summary

| Goal | Result | Met? |
|---|---|---|
| External recall +20 pp, held-out | HttpParams sealed half **40.54% → 97.28%** (+56.7 pp), FP 0 / 9,664 | Yes, in-distribution |
| — on a second, independent source | Fwaf sealed test **38.94% → 41.60%** (+2.7 pp), FP 9 → 12 of 10,000 | **No** |
| Throughput +20% | Final code against the baseline, interleaved on the same machine the same day: median **172.6 → 316.9 req/s (+83.6 %)**, ranges 156–181 vs 306–648, no overlap. (Pass-day figures: 172.8–205.4 → 510.6–555.1.) | Yes |
| p95 at 100 clients not worse | Same interleaved run: median p95 772.5 → 425.1 ms | Yes |
| No regressions | lint 0 errors, unit 251 / 251, build ok, audit suite 94 / 94 (Windows and Linux CI), Set A / Set B unchanged, dev-half gate at its floors | Yes |
| No super-linear regex | 0 of 385 regexes in the server (was 13) | Yes |
| Zero egress | 0 external connection attempts: 300 s soak on `237420e`, 120 s soak on the final code (in-process probe) | Yes, within the probe's limits |

The headline improvement is real and was measured on data no rule was written from. It is also
narrower than the number suggests: it is an improvement against the payload templates of the
tools that generated HttpParamsDataset, chiefly sqlmap. On a second dataset with a different
attack mix it moved recall by under 3 points. Both statements belong next to each other wherever
the 97% figure is quoted.

## 2. Initial weaknesses (measured on the baseline)

- 59% of attacks in the external set missed; SQL injection recall 39.4%, command injection 6.7%.
- Throughput plateaued near 170–205 req/s on one process while the classifier needs ≈ 30 µs.
- `main` could not be checked out on Windows (root file `Data` vs directory `data/`).
- External-harness traffic (10.40.x) was entering the adjudication queue, sealed payloads included.

## 3. Root causes

| Weakness | Cause, with evidence |
|---|---|
| SQLi misses | Signatures matched fixed text. `'\s*(or|and)` fails when a `)` follows the quote; `UNION SELECT` is the only SELECT signature; four stacked verbs; four time functions. 1,644 of 3,320 dev misses scored above zero but below the threshold. 3,275 of 3,320 carried a generic SQL-structure feature that 1 of 9,640 benign values carries (`dev_miss_analysis_2ab323e.json`) |
| Quoteless injections exempted | `looksLikeProse()` counted the dots of an IP address or `schema.table` as sentence punctuation, so payloads with ≥ 6 words skipped SQL/RCE rules |
| Command injection | No rule for a shell separator followed by a command |
| Throughput | CPU profile: `recordPending()` (synchronous SQLite: three statement compilations, an INSERT in its own transaction, a COUNT over the queue) took more event-loop time than the rest of the request path combined |
| Non-transfer to the second source | Its misses are mostly non-SQL: scanner probes without payload, encoded shell, XSS markup, RFI (`fwaf_transfer_diagnosis_237420e.json`) |

## 4. Implemented improvements

| Commit | Change |
|---|---|
| `1f54c62` | Baseline tooling: deterministic dev/sealed split with SHA-256 manifest; sealed mode that prints no samples; before/after gates; egress probe; CI; five project skills |
| `7a46165` | Merge of `origin/main` with `Data` renamed to `notebooks/cic_ids2018_colab.py` |
| `ac9dc78` | `server/services/sqlStructure.ts`: linear SQL tokenizer, tried on the text as given and from inside a single- or double-quoted string, scoring syntax not text. Wired into `classifyPayload()` as SQL-family evidence; prose guard still applies to weak signals |
| `d7ae2a3` | Command-injection shapes requiring a command-line form; dot-run and hex-spelled traversal; sentence-only punctuation in the prose guard |
| `237420e` | Pending-queue write-behind (labels stay synchronous, readers flush first, exit hook — which turned out not to run on SIGINT/SIGTERM; fixed in 4c); 10.40.x reserved as an evaluation source (replaced in 4c by a server-verified flag) |

## 4b. After the sealed runs: padding-bypass fix (`c435d2e`, tag `candidate-48h-2`)

Review of the frozen candidate found that `analyseSqlStructure()` read only the first 4,096
characters. Measured: an injection after 5 KB to 10 MB of filler was missed in every case. Fixed
by reading overlapping 4 KB windows (1 KB overlap) over the whole payload up to 256 KB and the
first and last 128 KB beyond that, keeping the single most incriminating window. Three defects
surfaced while fixing it and were fixed in the same commit:

| Defect | Evidence | Fix |
|---|---|---|
| O(n²) scan over runs of `)` | 1 MB of `)` took 12.4 s once windows covered the whole payload (in the 4 KB version it was hidden: one window, ~30 ms) | Run end computed once per run: 14.5 ms |
| "Please select one (or more) options" scored 50 — blocked at the route's 25 | The tokenizer drops whitespace, so `one (` read as a call. Present in `candidate-48h-1` | Calls need `name(` with no space, except SQL-only names; SELECT-list forms tightened |
| "I need sleep (a lot)", "benchmark (2024)" flagged | Original signature `sleep\s*\(`, present in the poster's baseline | `sleep(` / `benchmark(` adjacent only; `pg_sleep` and `WAITFOR DELAY` unchanged |

Effect on every measured figure: **none.** HttpParams dev half in-process: identical output at
both thresholds, every class. Both sealed sets re-scored on `candidate-48h-2`
(`reeval_sealed_*_c435d2e.json`): identical confusion matrices to `candidate-48h-1`. Because the
sealed sets had already been scored once, this second score is a **re-evaluation**, not new
independent evidence. Structural cost on 10 MB adversarial filler: 37–65 ms. Throughput at 100
clients 637.3 req/s in one run — within the run-to-run noise of this laptop; no gain is claimed.
Zero-egress check not re-run: no network code or dependency changed.

## 4c. Fixes from the PR #2 review (`c139113` … final)

An engineering and security review of PR #2 returned **NOT READY TO MERGE**. What it found, and
what was done:

| # | Finding | Severity | Fix | Evidence |
|---|---|---|---|---|
| B1 | The dot-run traversal rule added in `d7ae2a3` backtracked quadratically | High, introduced by this PR | Anchored to the start of a dot run | 80 KB of dots: 5,112 ms → 4 ms |
| P1 | Same defect in the pre-existing DNS base64 rule | High, pre-existing | Anchored to the start of a base64 run | 80 KB of `/bin/`: 5,991 ms → 4 ms |
| — | 11 further super-linear regexes, found by a new scanner over all 385 regexes in the server | 2 reachable **without authentication** (deception-sandbox input); others behind auth or on model output | Bounded / anchored rewrites, each compared with its original on attack and look-alike samples | `audit/redos_scan.mjs`: 13 → 0; `redosFixes.test.ts` 39 cases |
| S1 | `packet.srcIp`, written by the caller, keyed the rate limiter and decided exclusion from analyst review | Medium | Review exclusion only for ADMIN + direct loopback + declared header; limiter keyed on principal + TCP peer on the model path it protects; payloads > 1 MiB refused with 413 | Audit #102, #103 |
| B2 | Write-behind buffer lost on every normal stop: no SIGINT/SIGTERM handlers; the report's exit-hook claim was wrong | Medium | `server/gracefulShutdown.ts` | Real SQLite file in a child process: SIGTERM/SIGINT write 25/25, SIGKILL 0/25 (control). Real server in CI: SIGTERM wrote 20/20, exit 0 |
| C1 | CI detection steps could not fail (`process.exit(0)` regardless of result) | Medium | `--gate` floors in `audit/regression_gate.json`; dev-half gate pinned by SHA-256; audit suite, ReDoS scan and shutdown check in CI | Each gate exits 1 when a floor is raised above the measured value |
| D1 | Docs vs results inconsistencies; four result files edited by hand | Low | Docs corrected; files regenerated; `audit/results/PROVENANCE.md` | Regenerated baselines identical to the edited ones |

Changes to the `/api/v1/agent/ai-analyze` contract, both deliberate: a payload above 1,048,576
characters now gets **413 `PAYLOAD_TOO_LARGE`** instead of being classified; and the self-DoS
limiter (429) now applies only when an external model is configured, keyed on the caller. On the
sovereign path no 429 is returned; per-request cost is bounded by the size limit and linear-time
rules instead. Response fields are unchanged.

Detection after these fixes: HttpParams dev half in-process identical to `candidate-48h-2` at both
thresholds and every class; Set A and Set B unchanged (all three enforced by the CI gate).

API contracts otherwise unchanged: `ClassificationResult` and the `/api/v1/agent/ai-analyze`
response keep their fields; `classifyPayload()` gained an optional second argument used only by
harnesses.

## 5. Before / after

### Detection, per class

| Set | Class | Before | After |
|---|---|---|---|
| HttpParams sealed | SQL injection | 39.25% | 99.85% |
| | XSS | 83.27% | 83.27% |
| | Command injection | 6.82% | 59.09% |
| | Path traversal | 23.42% | 42.41% |
| | **All attacks** | **40.54%** | **97.28%** |
| Fwaf sealed | All attacks (no class labels) | 38.94% | 41.60% |
| HttpParams whole file (half regression) | All attacks | 40.92% | 97.68% |

### False positives

| Set | Before | After | 95% CI after |
|---|---|---|---|
| HttpParams sealed benign | 0 / 9,664 | 0 / 9,664 | 0.00 – 0.04% |
| HttpParams whole-file benign | 0 / 19,304 | 0 / 19,304 | 0.00 – 0.02% |
| Fwaf sealed benign | 9 / 10,000 | 12 / 10,000 | 0.07 – 0.21% |
| Set B benign | 0 / 22 | 0 / 22 | |
| Hand-written look-alike tests (names with apostrophes, prose about SQL, arithmetic, Arabic and Spanish text, JSON bodies, shell-like field names) | — | 0 flags at score 25 | |

The CSIC-derived benign side of HttpParams is mostly short names and addresses and contains
little SQL-like text, so its zero is weak evidence on its own. The look-alike tests and the
second source exist to cover that gap.

### Performance (100 concurrent clients)

Throughput on this laptop moves a lot from day to day: `c435d2e` measured 637.3 req/s on
2026-11-15 and 255.9 req/s (median of 3) on 2026-11-18. Figures from different days are not
compared. The final claim rests on interleaved A/B runs on the same day, fresh server and fresh
database per run:

| Interleaved, 2026-11-18, 3 rounds each | A | B | Change |
|---|---|---|---|
| Baseline `2ab323e` (A) vs final code (B) — `perf_ab_2ab323e_vs_27267a2.json` | 172.6 req/s (156.2–181.4), p95 772.5 ms | **316.9 req/s (306.1–647.8), p95 425.1 ms** | **+83.6 %**, ranges separated |
| `candidate-48h-2` (A) vs final code (B) — `perf_ab_c435d2e_vs_27267a2.json` | 255.9 req/s (235.1–276.8), p95 633.1 ms | 285.4 req/s (267.9–286.0), p95 476.9 ms | +11.5 %, ranges overlap: **no regression from the review fixes** |
| Failed requests | 0 | 0 | |
| RSS after load (medians) | 303.3 / 380.0 MB | 377.0 / 340.2 MB | inconsistent between the two runs; follows GC timing. Not heap-profiled |

A single standard benchmark on the final code the same morning read 365.8 / 364.2 req/s
(`perf_final_99fa259_run*.json`); against the candidates' pass-day figures that looked like a
34 % drop, which the interleaved run shows was the machine, not the code.

Pass-day figures (2026-11-15), kept for the record:

| | Before | After |
|---|---|---|
| Throughput, standard benchmark (2 runs each) | 172.8 / 205.4 req/s | 555.1 / 510.6 req/s |
| p95 | 583.2 / 500.8 ms | 212.1 / 248.3 ms |
| p99 | 1,145.6 / 764.0 ms | 344.8 / 254.0 ms |
| Interleaved A/B (3 rounds each) | median 176.8 req/s | median 454.9 req/s |
| Failed requests | 0 | 0 |
| RSS after load (A/B medians) | 289 MB | 284 MB |
| Single sequential request p50 | 15.3 ms | 14.8 ms |

## 6. Zero-egress verification

`SD_EGRESS_SOAK_SEC=300 node scripts/zero-egress-check.mjs audit/results/egress_237420e.json`
on the frozen candidate, `GEMINI_API_KEY` removed, 50 classifier requests then a 300-second soak:

| | Baseline (45 s soak) | Candidate (300 s soak) |
|---|---|---|
| External connection attempts | 0 | **0** |
| LAN connection attempts | 0 | 0 |
| `/inference-posture` `zeroExternalApiCalls` | true | true |
| Positive control (`fetch https://example.com` under the probe) | logged as EXTERNAL dns + tcp:443 | same probe, unchanged |

Re-run on the final code after the review fixes (`egress_final_99fa259.json`): 120 s soak,
0 external, 0 LAN, posture reports zero external calls.

No dependency was added in this pass, so the candidate adds no new outbound path.

Outbound code paths that exist and are **off by default**, found by grep (each trigger read,
not each exercised): external model (`GEMINI_API_KEY`), alert webhooks to Slack/Telegram (only
when an operator configures a token), intel-feed import and Tor/AbuseIPDB lookups
(`intelFeeds`, `liveThreatIntel`; operator-triggered or `ABUSEIPDB_API_KEY`), the target scanner
(operator-supplied URL), object-storage replication (`STORAGE_*`). None fired during the soak.

Limits: in-process probe only. Child processes (`bpftool`, `arp`), native modules and the
browser loading the dashboard are not observed, timers longer than 300 s were not waited for,
and no host packet capture was taken.

## 7. Regression tests

| Check | Result |
|---|---|
| `npm run lint` | 0 errors |
| `npx vitest run` | 251 / 251 (53 existing + 198 new), Windows and Linux CI; on Linux the shutdown tests use real OS signals |
| `npm run build` | succeeds |
| `npx tsx audit/audit_suite.ts` | 94 / 94 PASS (92 existing + #102, #103), Windows and Linux CI |
| `node audit/redos_scan.mjs` | 0 of 385 super-linear (was 13) |
| Detection gates (`--gate`) | dev half, Set A, Set B at their floors; each shown to fail when a floor is raised |
| Real-server SIGTERM flush (`audit/shutdown_flush_check.mjs`, CI) | 20 / 20 rows written, exit 0 |
| Set A / Set B | 1 miss (was 2) / unchanged |
| Write-behind tests with the buffer off | 5 / 5 |

CI evidence is published as annotations on each run, readable without a GitHub login.

## 8. Environment and reproduction

Laptop, Intel Core i5-1235U (12 logical CPUs), 7.7 GB RAM, Windows 11 Pro 10.0.26200,
Node v24.20.0, npm 11.19.0, dev-mode server (`tsx`), one process.

```bash
# data (not committed)
curl -sSL -o data/external/payload_full.csv https://raw.githubusercontent.com/Morzeux/HttpParamsDataset/master/payload_full.csv
npx tsx audit/split_external.ts data/external/payload_full.csv data/external audit/results/external_split_manifest.json
# second source: goodqueries.txt and badqueries.txt from github.com/faizann24/Fwaf-Machine-Learning-driven-Web-Application-Firewall
node audit/build_external2.mjs data/external2 audit/results/external2_manifest.json

# detection, sealed (once per frozen candidate)
SD_EVAL_SEALED=1 node scripts/with-server.mjs \
  "npx tsx audit/eval_external_httpparams.ts data/external/httpparams_sealed.csv audit/results/sealed_httpparams_<commit>.json" \
  "npx tsx audit/eval_external_httpparams.ts data/external2/fwaf_test_sealed.csv audit/results/sealed_fwaf_<commit>.json"
node scripts/compare-detection.mjs audit/results/baseline_external_sealed_2ab323e.json audit/results/sealed_httpparams_<commit>.json --min-recall-gain=20

# performance
node scripts/with-server.mjs "node audit/perf_benchmark.mjs audit/results/perf_<commit>.json"
node scripts/compare-perf.mjs audit/results/baseline_perf_2ab323e.json audit/results/perf_<commit>.json --min-throughput-gain=20
node scripts/perf-ab.mjs SD_ADJUDICATION_WRITE_BEHIND off on 3 audit/results/perf_ab.json

# regression and egress
npm run lint && npx vitest run && npm run build
node scripts/with-server.mjs "npx tsx audit/audit_suite.ts" "npx tsx audit/eval_harness.ts" "npx tsx audit/eval_holdout_b.ts"
SD_EGRESS_SOAK_SEC=300 node scripts/zero-egress-check.mjs audit/results/egress_<commit>.json
```

Expected SHA-256: `payload_full.csv` `a4e62ba1…f03d`; dev half `45cf0f1c…3192`; sealed half
`be6096a7…d42`; Fwaf files in `audit/results/external2_manifest.json`.

## 9. Remaining limitations

- **The gain is concentrated in one dataset's distribution.** Out-of-distribution recall rose
  2.7 points. A third, untouched dataset with labelled classes is needed before claiming
  general SQLi robustness.
- **XSS unchanged** (83.27% sealed). No XSS work was done.
- **Route threshold.** Every route figure, before and after, uses `vector: 'UNKNOWN'`, which
  blocks at score 25; a request without `vector` is judged at 55. In-process at 55 the dev half
  reads 96.63% against 98.09% at 25.
- **Benign evidence is thin where it matters.** HttpParams benign values are names and
  addresses; Fwaf "good" labels contain real attacks. Neither is real API traffic.
- **Structural coverage above 256 KB.** Beyond 256 KB only the first and last 128 KB are
  analysed structurally (a cost bound; section 4b). An injection with more than 128 KB of filler
  on both sides is judged by the signature rules alone. The usual padding attack — filler first,
  injection last — is covered at any size.
- **No request-count limit on the sovereign path.** After the srcIp fix the self-DoS limiter
  applies only to the external-model path, keyed on the caller. The local path is bounded per
  request (1 MiB, linear rules, roughly 0.1 s per MB of signature work) but an authenticated
  caller can still send many requests. A cost-based per-caller budget is the next step.
- **Write-behind trade-off.** A normal stop (SIGINT, SIGTERM, Ctrl+C, docker stop) now flushes
  the buffer. A hard kill (SIGKILL, `taskkill /F`, Windows TerminateProcess, OOM, crash, power
  loss) still loses up to 50 ms or 256 pending-review rows. Labels and the audit trail are
  written synchronously and are not affected.
- **Windows signal delivery is not tested end to end.** One Windows process cannot send SIGTERM
  to another, so on Windows the shutdown tests raise the signal in-process; real delivery is
  proven on Linux in CI. Ctrl+C in a Windows console delivers SIGINT, which the same handler
  covers, but no automated test drives it.
- **Drift and retention input changed.** Verified evaluation traffic no longer feeds drift
  statistics or the learner's retention store; before this change harness traffic did.
- **Single-request latency** (~15 ms) is unexplained and unchanged.
- **Not measured:** Linux, XDP generic or native, kernel latency, built-bundle throughput, a
  host packet capture. No kernel figure in this report; containment ran in simulation on
  Windows.
- **Pre-edit result files are in public history.** Four result files were edited by hand
  before the review; their originals at `ac9dc78` / `17e0d23` contain a few dozen lines of the
  unlicensed second source. See `audit/results/PROVENANCE.md`.

## 10. Git commits and evidence

```
c435d2e fix(detect): close the 4 KB padding bypass in structural SQL analysis   <- candidate-48h-2
237420e perf(adjudication): write the pending queue behind the request path   <- candidate-48h-1
d7ae2a3 feat(detect): command-injection and traversal shapes; prose guard counts sentence punctuation only
ac9dc78 feat(detect): structural SQL injection analysis alongside the signature rules
7a46165 merge: origin/main, renaming Data to notebooks/cic_ids2018_colab.py
1f54c62 chore(eval): reproducible baseline, dev/sealed split, gates and project skills
```

Review-fix commits after `candidate-48h-2`: `c139113` (7 classifier regexes, scanner),
`53b3db5` (6 more regexes), `0c4f9a0` + `c31c91c` (srcIp trust), `03d9430` (graceful shutdown),
`a53f5e4`, `99fa259`, `27267a2` (CI gates, evidence), and the documentation commit.

Evidence files: `audit/results/`, described file by file in
[`audit/results/PROVENANCE.md`](../audit/results/PROVENANCE.md). The branch is pushed and is
PR #2; nothing is merged.

## 11. Recommended next engineering priorities

0. **A cost-based per-caller budget on the sovereign path** (bytes classified per minute per
   principal), now that identity comes from the server rather than the request body.
1. **Third independent evaluation set** with class labels (for example a SQLi corpus not built
   with sqlmap), scored once, before any further SQLi claim.
2. **Second-source gap, by size:** encoded command injection (commix-style `$(echo …)`,
   `$((a+b))`, `$IFS`), XSS markup without script tags (`<meta http-equiv>`, attribute
   injection), remote file inclusion (URL in a path-like parameter). Develop on Fwaf attack lines
   outside the sealed ranks, which are allowed; keep the sealed ranks closed.
3. **Scanner probes with no payload** (requests for `/javascript/java.exe`) cannot be judged from
   the payload. They need request-rate or path-reputation signals, not rules.
4. Decide whether evaluation should send no `vector` (threshold 55) and republish both figures.
5. Purge the 1,942 pre-fix 10.40.x rows from the local adjudication queue after a backup.
6. Run the egress check, the audit suite and the performance A/B on the Linux/WSL2 host with
   XDP attached, and add a packet capture.
