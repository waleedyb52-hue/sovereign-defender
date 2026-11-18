# Improvement evidence — before / after

**Before:** `2ab323e` (code identical to the poster's `989befb`). **After:** `237420e`, tag
`candidate-48h-1`, frozen before the sealed runs. Same laptop, same Node (v24.20.0, Windows 11),
dev-mode server, fresh process per measurement, `GEMINI_API_KEY` unset.

Every figure is copied from the JSON named under its table. Nothing here was typed in.
Protocol: [`48H_IMPROVEMENT_ROADMAP.md`](48H_IMPROVEMENT_ROADMAP.md). Cycle-by-cycle record:
[`EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md).

## How to read the detection figures

| Set | Independence from the work | Use |
|---|---|---|
| HttpParams **sealed half** | Never read, never used for a rule. **Same generator** (sqlmap, XSSYA, Vega, FuzzDB) as the dev half the rules were designed from | Held-out, in-distribution: does the fix generalise beyond the samples it was built from? |
| Second source **sealed test** (Fwaf) | Different author, different tools, never read | Out-of-distribution: does it generalise to someone else's attacks? |
| HttpParams dev half / whole file | Dev half was read; whole file = dev + sealed | Regression only |

The two independent figures answer different questions and both are reported.

## 1. HttpParams sealed half — held-out, same generator

`node scripts/compare-detection.mjs audit/results/baseline_external_sealed_2ab323e.json audit/results/sealed_httpparams_237420e.json --min-recall-gain=20`

| | Before | After | Change |
|---|---|---|---|
| TP / FN / FP / TN | 2,397 / 3,515 / 0 / 9,664 | 5,751 / 161 / 0 / 9,664 | |
| **Recall** (95% Wilson CI) | 40.54% (39.30 – 41.80) | **97.28%** (96.83 – 97.66) | **+56.74 pp** |
| Precision (95% CI) | 100.00% | 100.00% (99.93 – 100.00) | 0 |
| FPR (95% CI) | 0.00% (0.00 – 0.04) | 0.00% (0.00 – 0.04) | 0 |
| F1 / MCC | 57.70% / 0.5453 | 98.62% / 0.9782 | |
| SQL injection | 39.25% (2,138 / 5,447) | 99.85% (5,439 / 5,447) | +60.60 pp |
| XSS | 83.27% (219 / 263) | 83.27% (219 / 263) | 0 |
| Command injection | 6.82% (3 / 44) | 59.09% (26 / 44) | +52.27 pp |
| Path traversal | 23.42% (37 / 158) | 42.41% (67 / 158) | +18.99 pp |

Gate: **PASS**. F1 is above the 0.95 range that TESSERACT treats as a warning sign. The
explanation is the shared generator: sqlmap emits a small number of payload templates, the
structural rules recognise those template *shapes*, and the sealed half was drawn from the same
templates. The figure is genuine — no sealed sample was seen — but it measures template coverage,
not robustness to a new tool. Section 2 measures that.

## 2. Second source sealed test — out of distribution

`node scripts/compare-detection.mjs audit/results/baseline_fwaf_test_2ab323e.json audit/results/sealed_fwaf_237420e.json`

| | Before | After | Change |
|---|---|---|---|
| TP / FN / FP / TN | 1,947 / 3,053 / 9 / 9,991 | 2,080 / 2,920 / 12 / 9,988 | |
| **Recall** (95% CI) | 38.94% (37.60 – 40.30) | **41.60%** (40.24 – 42.97) | **+2.66 pp** |
| Precision (95% CI) | 99.54% (99.13 – 99.76) | 99.43% (99.00 – 99.67) | −0.11 pp |
| FPR (95% CI) | 0.09% (0.05 – 0.17) | 0.12% (0.07 – 0.21) | +3 flags |
| F1 / MCC | 55.98% / 0.5439 | 58.66% / 0.5644 | |

**The 20-point goal is not met on this source.** The recall intervals barely separate.

Why, from second-source attack lines disjoint from this test (`audit/diagnose_fwaf_transfer.ts`,
`fwaf_transfer_diagnosis_237420e.json`, 10,000 lines, recall there 40.56%): of 5,944 misses only
**56 contain SQL keywords**. The rest are scanner requests for script paths with no payload
(970), encoded shell commands in commix style (940, plus most of 2,493 "other"), XSS markup such
as `<meta http-equiv=set-cookie>` (679), plain paths (466) and remote file inclusion (220). The
improvement targeted SQL injection, and that class barely occurs here.

The 3 additional flags on this source's benign side were not inspected: the test is sealed. On
100,000 benign-labelled dev lines from the same source, every line the new rules flagged was a
real attack mislabelled as good (EXPERIMENT_LOG cycles 1–2), which is the likely explanation
here too. This is unverified.

## 3. Regression sets

| | Before | After |
|---|---|---|
| HttpParams dev half (read during development) | 41.29%, FP 0 | 98.09%, FP 0 — `dev_httpparams_237420e.json` |
| HttpParams whole file (half dev, half sealed) | 40.92% (4,813 / 11,763), FP 0 / 19,304 | 97.68% (11,490 / 11,763), FP 0 / 19,304 — `full_httpparams_237420e.json` |
| Whole file per class: SQLi / XSS / cmdi / traversal | 39.36 / 84.77 / 6.74 / 29.31% | 99.82 / 84.77 / 68.54 / 50.34% |
| Set A (regression) | 2 misses | 1 miss (base64-wrapped RCE) |
| Set B overall / benign FP | 66.7% / 0 of 22 | 66.7% / 0 of 22 |
| Set B Tier 1 / Tier 2 | 15 / 15, 3 / 12 | 15 / 15, 3 / 12 (Tier 2 untouched, as required) |

The whole-file figure is the one directly comparable with the poster's 40.9%, and it must be
quoted with its label: half of it is data the rules were designed from.

## 4. Performance — same machine, same mode

Standard benchmark (`audit/perf_benchmark.mjs`), two runs per side, at 100 concurrent clients:

| | Baseline run 1 | Baseline run 2 | Candidate run 1 | Candidate run 2 |
|---|---|---|---|---|
| Throughput | 172.8 req/s | 205.4 req/s | **555.1 req/s** | **510.6 req/s** |
| p50 / p95 / p99 ms | 543.7 / 583.2 / 1,145.6 | 467.3 / 500.8 / 764.0 | 166.2 / 212.1 / 344.8 | 184.6 / 248.3 / 254.0 |
| Non-200 responses | 0 | 0 | 0 | 0 |

Files: `baseline_perf_2ab323e.json`, `baseline_perf_run2_2ab323e.json`,
`perf_candidate_237420e_run1.json`, `perf_candidate_237420e_run2.json`. All four pairings pass
`compare-perf.mjs --min-throughput-gain=20` (smallest gain +148.6%).

Interleaved A/B of the single change responsible (`perf_ab_writebehind.json`, 3 rounds each,
alternating, fresh server per run): median 176.8 → 454.9 req/s, ranges 140.4–188.5 vs
432.2–550.4, p95 657 → 315 ms, 0 failed requests.

| Other operations (candidate run 1 vs baseline run 1) | Before | After |
|---|---|---|
| Single sequential request p50 | 15.3 ms | 14.8 ms |
| 10 clients | 133.8 req/s | 451.2 req/s |
| 50 clients | 169.2 req/s | 529.6 req/s |

Single-request latency did not improve: about 15 ms per request at one client is spent outside
the classifier (≈ 30 µs) and outside the write that was removed. Not investigated.

Poster comparison: the poster's 183 req/s / p95 790 ms were taken on a different host and are
not used as a baseline.

### Same-day interleaved comparison on the final code (2026-11-18)

| | A | B | Change |
|---|---|---|---|
| `2ab323e` → final (`perf_ab_2ab323e_vs_27267a2.json`) | median 172.6 req/s (156.2–181.4) | median 316.9 req/s (306.1–647.8) | **+83.6 %, ranges separated**; p95 772.5 → 425.1 ms; 0 failed |
| `c435d2e` → final (`perf_ab_c435d2e_vs_27267a2.json`) | median 255.9 req/s (235.1–276.8) | median 285.4 req/s (267.9–286.0) | +11.5 %, ranges overlap; review fixes cost nothing measurable |

Same code, different days: `c435d2e` read 637.3 req/s on 2026-11-15 and 255.9 on 2026-11-18.
Only same-day interleaved runs are compared.

## 5. Tests

| | Before | After |
|---|---|---|
| `npm run lint` | 0 errors | 0 errors |
| `npx vitest run` | 53 / 53 | 251 / 251 after the review fixes (172 at `237420e`, 208 at `c435d2e`) |
| `npm run build` | — | succeeds |
| Audit suite (`audit/audit_suite.ts`) | 92 / 92 (29 Sep report) | 94 / 94 after the review fixes (#102, #103 added); 92 / 92 at `237420e` — `audit/results/audit_suite_237420e.txt` |
| ReDoS scan (`audit/redos_scan.mjs`, 385 regexes) | 13 super-linear (`redos_scan_before_fixes.json`) | 0 (`redos_scan_after_fixes.json`) |

## 6. Zero egress

| | Before (`baseline_egress_2ab323e.json`) | After (`egress_237420e.json`) |
|---|---|---|
| Soak | 45 s | 300 s |
| External / LAN connection attempts | 0 / 0 | 0 / 0 |

Method and limits: section 6 of [`FINAL_ENGINEERING_REPORT.md`](FINAL_ENGINEERING_REPORT.md).

## 6b. Re-evaluation on `candidate-48h-2` (`c435d2e`)

After the sealed runs, the padding-bypass fix and two adjacency fixes were made (EXPERIMENT_LOG
cycle 5). Both sealed sets were scored once more, labelled as a re-evaluation:

| | `candidate-48h-1` | `candidate-48h-2` |
|---|---|---|
| HttpParams sealed TP / FN / FP / TN | 5,751 / 161 / 0 / 9,664 | 5,751 / 161 / 0 / 9,664 |
| Fwaf sealed TP / FN / FP / TN | 2,080 / 2,920 / 12 / 9,988 | 2,080 / 2,920 / 12 / 9,988 |
| Set A misses / Set B overall | 1 / 66.7% | 1 / 66.7% |
| Audit suite | 92 / 92 | 92 / 92 |
| Throughput @100 clients | 555.1 / 510.6 req/s | 637.3 req/s (one run, within noise) |

Files: `reeval_sealed_httpparams_c435d2e.json`, `reeval_sealed_fwaf_c435d2e.json`,
`dev_httpparams_c435d2e.json`, `perf_candidate2_c435d2e.json`.

## 7. Integrity disclosures

1. Before the split was made, the very first whole-file run printed 12 missed examples from the
   whole file, so up to 12 strings may belong to what became the sealed half. They were removed
   from the stored JSON by editing it — which broke this project's own rule that results are
   generated, never edited. Three more files were edited the same way to drop second-source
   lines. All four are listed in [`audit/results/PROVENANCE.md`](../audit/results/PROVENANCE.md)
   with clean regenerated replacements; the regenerated baselines match the edited files figure
   for figure. No rule contains a literal from any dataset; the rules are structural.
2. Both sealed sets were scored three times: on `2ab323e`, on `237420e` (the independent
   result), and on `c435d2e` after the padding fix (a re-evaluation, identical result). The
   post-freeze changes were driven by hand-written tests, not by sealed results.
3. All route figures use `vector: 'UNKNOWN'`, which makes the route block at score 25 instead of
   55. Unchanged from the poster's method, so before and after are the same measurement.
4. The local adjudication queue (`data/adjudication.db`, not in git) still holds 1,942 rows from
   10.40.x — external-harness payloads from earlier runs, including sealed-half strings. They
   were not deleted. Harnesses now declare evaluation traffic with a header the server verifies
   (ADMIN + direct loopback), so no further harness rows are added.
5. The second source has no stated licence and is used for local measurement only; it is not
   committed. Its labels are noisy in both directions.
