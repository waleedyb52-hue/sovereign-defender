# Sovereign Defender — 48-hour engineering pass, final report

**Date:** 2026-11-15 · **Branch:** `improvement/48h-detection-performance` · **Before:** `2ab323e`
(code identical to the poster's `989befb`) · **After:** `237420e`, tag `candidate-48h-1`

Detailed tables: [`IMPROVEMENT_EVIDENCE.md`](IMPROVEMENT_EVIDENCE.md) · per-change record:
[`EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md) · baseline: [`BASELINE_METRICS.md`](BASELINE_METRICS.md).

## 1. Executive summary

| Goal | Result | Met? |
|---|---|---|
| External recall +20 pp, held-out | HttpParams sealed half **40.54% → 97.28%** (+56.7 pp), FP 0 / 9,664 | Yes, in-distribution |
| — on a second, independent source | Fwaf sealed test **38.94% → 41.60%** (+2.7 pp), FP 9 → 12 of 10,000 | **No** |
| Throughput +20% (≥ 220 req/s) | 100 clients: **172.8–205.4 → 510.6–555.1 req/s**; interleaved A/B median 176.8 → 454.9 | Yes |
| p95 at 100 clients not worse | 500.8–583.2 → 212.1–248.3 ms | Yes |
| No regressions | lint 0 errors, unit 172 / 172, build ok, audit suite 92 / 92, Set B unchanged | Yes |
| Zero egress | 0 external connection attempts over a 300 s soak (in-process probe) | Yes, within the probe's limits |

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
| `237420e` | Pending-queue write-behind (labels stay synchronous, readers flush first, exit hook); 10.40.x reserved as an evaluation source |

API contracts unchanged: `ClassificationResult` and the `/api/v1/agent/ai-analyze` response
keep their fields; `classifyPayload()` gained an optional second argument used only by harnesses.

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
| `npx vitest run` | 172 / 172 (53 existing + 119 new) |
| `npm run build` | succeeds |
| `npx tsx audit/audit_suite.ts` | 92 / 92 PASS, 0 WARN, 0 FAIL |
| Set A / Set B | 1 miss (was 2) / unchanged |
| Write-behind tests with the buffer off | 5 / 5 |

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
- **Padding bypass of the new component.** `analyseSqlStructure()` reads the first 4,096
  characters only (a cost bound). An injection placed after 4 KB of filler is judged by the
  signature rules alone — baseline behaviour, not worse, but the new component is blind to it.
  Found in review after the freeze; no evaluated payload exceeds 1,058 characters, so no figure
  here is affected. Fix: also analyse the last window, or windows around each quote.
- **Write-behind trade-off.** Up to 50 ms or 256 pending-review suggestions can be lost on a
  hard kill. Labels are not affected.
- **Single-request latency** (~15 ms) is unexplained and unchanged.
- **Not measured:** Linux, XDP generic or native, kernel latency, built-bundle throughput, a
  host packet capture. No kernel figure in this report; containment ran in simulation on
  Windows.
- **CI workflow** has not run on GitHub yet (nothing pushed).

## 10. Git commits and evidence

```
237420e perf(adjudication): write the pending queue behind the request path   <- candidate-48h-1
d7ae2a3 feat(detect): command-injection and traversal shapes; prose guard counts sentence punctuation only
ac9dc78 feat(detect): structural SQL injection analysis alongside the signature rules
7a46165 merge: origin/main, renaming Data to notebooks/cic_ids2018_colab.py
1f54c62 chore(eval): reproducible baseline, dev/sealed split, gates and project skills
```

Evidence files: `audit/results/` (baseline_*, sealed_*, dev_*, full_*, perf_*, perf_ab_*,
fp_stress_*, dev_miss_analysis_*, fwaf_transfer_diagnosis_*, egress_*, audit_suite_*,
manifests). Nothing pushed to the remote.

## 11. Recommended next engineering priorities

0. **Close the 4 KB padding bypass** in `sqlStructure.ts` (limitation above), with a unit test
   that pads a known injection past the window.
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
