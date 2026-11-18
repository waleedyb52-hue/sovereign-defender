# Sovereign Defender — Final release report

Date: 2026-11-18 · Branch `improvement/followups-defense` (PR #3) · Base `main` at `faad341`.
All figures are taken from generated files under `audit/results/`. `PROVENANCE.md` there names
the script and the commit behind each file.

## Verdict: **READY WITH LIMITATIONS**

The platform builds, every regression gate passes, and no known critical regression remains.
The console no longer shows invented figures in the places this pass found. It is not
"READY" for three reasons:

1. **The requested 2026 dataset was not evaluated.** Mendeley Data returned HTTP 500 for the
   whole service throughout the window, including for an unrelated control dataset. An
   independent **2025 production** set was scored in its place (section D).
2. **The UI changes were not exercised in a browser with a signed-in operator.** They are
   covered by type checks, the production build and code review only.
3. **The analysis API still returns two fixed fields:** `confidence: 0.96` and a constant
   `xaiAttribution` block in the local-classifier response. Since PR #3 the console no longer
   displays them, but an API consumer still receives them. They are listed as a risk, not fixed,
   because removing response fields is an API change that needs its own review.

## What changed in this release

| Change | Where | Evidence |
|---|---|---|
| 13 hardcoded fallbacks (3,410 · 24,820 · 42,890 · 16,420 …) and a fixed 96.8 % fast-path share now show the live value or "N/A" | `KernelIngressPerformanceCenter.tsx` | type check, build |
| Sample count no longer falls back to a fixed 20,000 | `BehavioralAnomalyStudio.tsx` | type check, build |
| eBPF tab: 5,000,000 PPS, 56.8 Gbps, 4,825,000 drops and 1.84 ms had no measurement behind them; it now reads "Not measured" and says native XDP is unverified | `SystemComplianceReport.tsx` | type check, build |
| **Unban bug:** a host was removed from the quarantine list even when the request failed. It is now removed only after a 2xx response. | `App.tsx` | code review |
| A failed isolate, release or unban command now shows a dismissible alert. Before, the error went only to the browser console. | `App.tsx` | code review |
| Independent evaluation: protocol committed before scoring, split with an untouched reserve, harness that counts every failure kind | `audit/build_modsec_independent.mjs`, `audit/eval_independent.ts`, `audit/summarize_independent.mjs` | `docs/INDEPENDENT_2026_EVALUATION.md` |

Kept as they were, because they passed every check: the PR #3 console-honesty modal, the
per-caller budget, the second-source rules, SQLite write-behind, graceful shutdown and the
ReDoS rewrites. **No detection rule and no threshold was changed in this release.**

## Results, kept apart by kind

### A. Historical baseline (poster, commit `2ab323e`)
40.9 % external recall · 183 req/s · p95 790 ms, as printed on the poster.
`BASELINE_METRICS.md` has the regenerated baseline files.

### B. PR #2, measured (merged as `faad341`)
| Measure | Before → after | Kind |
|---|---|---|
| HttpParams sealed half | 40.54 % → 97.28 % (FP 0 / 9,664) | held-out half of the source used for development: in-distribution |
| Fwaf sealed test (second source, independent at the time) | 38.94 % → 41.60 % (FP 9 → 12 of 10,000) | independent when scored: the out-of-distribution gain was **+2.7 pp only** |
| Throughput, interleaved A/B on one machine and day | median 172.6 → 316.9 req/s (**+83.6 %**), ranges separated; p95 772.5 → 425.1 ms | `perf_ab_2ab323e_vs_27267a2.json`. Measured on PR #2's code, not re-measured on this release |

### C. PR #3, measured (open, not merged)
| Measure | Before → after | Kind |
|---|---|---|
| Fwaf validation chunk, never read | 40.72 % → **67.38 %** | held-out within the source used for development |
| Fwaf sealed test | 41.60 % → **67.24 %** | **in-distribution**: rules were developed on the same source |
| HttpParams sealed half | 97.28 % → 97.50 % | re-evaluation, not new evidence |
| False positives, HttpParams sealed benign | 0 / 9,664 | in-distribution |
| Set A held-out / Set B Tier 1 / Set B benign | 14/14 · 15/15 · 0/22 | regression |
| Throughput | no regression; ranges overlap; **no gain claimed** | `perf_ab_faad341_vs_cfda6e8.json` |

Fwaf and HttpParams are **no longer independent tests** of this code.

### D. New independent evaluation (Zenodo 17178461, real production blocks, 2025)
Scored once, through the real API server, on code frozen at `1a62551`, under a protocol
committed beforehand. 12,949 unique requests, every one answered (0 failures of any kind).

| Commit | Recall on CRS payload families (n = 3,015) | 95% CI |
|---|---:|---|
| `2ab323e` baseline | 27.63 % | 26.06 – 29.25 |
| `faad341` main | 47.16 % | 45.39 – 48.95 |
| `1a62551` this release | **50.91 %** | 49.13 – 52.69 |

SQL injection 91.72 % · XSS 58.67 % · command execution 39.15 % · PHP 49.22 % · **file inclusion 8.29 % (a
clear gap)**. All 12,949 rows: 12.84 %, because 9,934 were blocked for header, protocol or
unattributed reasons that a payload classifier does not receive. The set contains no benign traffic, so
**it gives no false-positive figure**. Details: `docs/INDEPENDENT_2026_EVALUATION.md`.

### E. Unverified capabilities
- **Native XDP:** never tested. The 29 September report (`docs/test-report-2026-09-29.txt`)
  shows XDP in **generic** mode under WSL2 (Linux 6.18). It passed 300,000 packets before
  isolation and dropped all 300,000 after. The sender's rate limited that test, so it is no capacity measure.
- XDP throughput (packets/s) and per-packet latency inside the kernel: not measured.
- Inline interception of live traffic: not evaluated; every detection figure is from the analysis endpoint.
- The external-model path (Gemini): not evaluated; every figure is the local classifier.
- Simulator screens (war games, digital twin) show scripted scenarios, not measurements.

## What was tested in this release (2026-11-18)

| Check | Result |
|---|---|
| TypeScript (`npm run lint`) | pass |
| Unit tests (`npx vitest run`) | **306 / 306** |
| ReDoS scan | **0 of 412** regexes super-linear |
| Production build (`npm run build`) | pass |
| HttpParams dev regression gate | PASS |
| Set A gate · Set B gate | PASS · PASS |
| Audit suite (incl. audit-trail chain, size limit, auth on telemetry and sensors) | **94 / 94** |
| Per-caller budget, real server | PASS (200, then 429 with `Retry-After`; verified evaluation exempt) |
| Graceful-shutdown flush, real server | **skipped on Windows** (needs POSIX signals); it runs in CI on Linux |
| Independent set, three versions | section D |

## Not tested

- The UI changes in a live browser session.
- The 2026 Mendeley dataset (provider outage).
- Native XDP; Linux performance for this release; a packet capture for zero egress on Linux.
- An adaptive attacker who sees the rules and mutates payloads against them.

## Threats to validity

| Threat | Status |
|---|---|
| Dataset age | HttpParams 2016; Fwaf older still; the new set is from 2025. No 2026 data was scored. |
| Shared generators | The requested 2026 set includes `llm_claude.csv`. The rules here were written with a Claude model, so that file must be reported separately if it is ever run. |
| Template bias | HttpParams and Fwaf attacks are tool-generated and repetitive. The new set is de-duplicated, but scanners still dominate it. |
| Author influence | Rules were written by people (and a model) who knew the attack families in the dev data. The new set was never seen before scoring. |
| Dataset contamination | Fwaf and HttpParams are now in-distribution, and are labelled so. The new set has 0 exact overlaps with the development files. |
| Repeated evaluation | The sealed halves of HttpParams and Fwaf have been scored more than once. Only the first score of each is independent. The new set was scored once per version; the reserve half stays untouched. |
| Threshold differences | The route blocks at score ≥ 25 for an `UNKNOWN` vector; the classifier's own threshold is 55. Both are reported. |
| Label noise | Fwaf "benign" contains scanner attacks: 1,565 flags on 100,000 dev lines were read and all were attacks. The new set's labels are ModSecurity decisions. |
| No adaptive-attacker evaluation | Not done. |
| Performance variability | The same code varied up to 4× on the same day. Only interleaved A/B ranges are claimed. |
| No native XDP verification | Generic mode under WSL2 only (section E). |
| Limited production evidence | One production set (blocked requests only), no benign production traffic, so no production false-positive rate. |

## Remaining risks

1. Fixed `confidence` and `xaiAttribution` fields in the analysis API response (see the verdict).
2. File-inclusion detection is weak on production traffic (8.29 %).
3. A single Node.js process: throughput is capped by one CPU core.
4. The September report notes that under WSL2, tail latency reaches seconds at 50 or more concurrent requests.

## How to run it

Windows (PowerShell), from the repository root:
```powershell
npm ci
npm run build
$env:ADMIN_API_KEY = "<your admin key>"; npm start
```
Development mode: `npm run dev`. Then open http://localhost:3000.

WSL2 (Linux, for XDP in generic mode; needs root for the kernel path):
```bash
npm ci && npm run build
ADMIN_API_KEY='<your admin key>' sudo -E node dist/server.cjs
```

Reproduce the independent evaluation (the data is not redistributed here; it is CC BY 4.0 at
Zenodo record 17178461, `owasp.zip`, md5 `95b7a8237abc163d8ca31e49f7318efd`):
```bash
node audit/build_modsec_independent.mjs <extracted owasp.zip dir> <out dir>
node scripts/with-server.mjs "npx tsx audit/eval_independent.ts <out dir>/modsec_test.jsonl audit/results/x.json name"
node audit/summarize_independent.mjs audit/results/x.json audit/results/x_summary.json
```
