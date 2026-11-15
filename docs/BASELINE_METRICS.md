# Baseline metrics — before the 48-hour improvement pass

**Measured:** 2026-11-15 · **Branch:** `improvement/48h-detection-performance`
**Code under test:** commit `2ab323e`. The poster cites `989befb`; the two differ only by the
root file `Data` (a Colab notebook script, no server code — `git diff --stat 2ab323e 989befb`
shows that one file). The branch was cut from `2ab323e` because `Data` collides with the
ignored `data/` directory on a case-insensitive Windows filesystem. See "Open issues".

Every figure below was produced by a command in this document, on the machine described here,
on that day. Result files are in `audit/results/`.

## Environment

| | |
|---|---|
| Machine | Laptop, Intel Core i5-1235U (12 logical CPUs), 7.7 GB RAM |
| OS | Windows 11 Pro 10.0.26200 |
| Node | v24.20.0, npm 11.19.0 |
| Server mode | development (`npx tsx server.ts`), single process |
| Configuration | no `.env`, `GEMINI_API_KEY` unset (sovereign path), `SD_CORPUS_CORROBORATION` unset (off) |
| Containment | simulation mode (no XDP on Windows). No kernel figure is claimed from this host. |

This is **not** the poster's performance host (the poster states a 4-core host). Detection
figures are host-independent and reproduce exactly; performance figures do not, and only the
same-machine before/after comparison is valid.

## 1. Build and tests

| Check | Command | Result |
|---|---|---|
| Type check | `npm run lint` | pass, 0 errors |
| Unit tests | `npx vitest run` | 53 / 53 pass |

The 92-case audit suite was **not** re-run in this session (not yet needed for the baseline;
it is part of the final gate).

## 2. Detection — external dataset, whole file

HttpParamsDataset `payload_full.csv`, SHA-256
`a4e62ba13435ad3dd583c5790db2175629020fc41c56e1b26baa02a9ae45f03d` (matches the September report).

```bash
ADMIN_API_KEY=test_admin_key_123 npx tsx server.ts
ADMIN_API_KEY=test_admin_key_123 npx tsx audit/eval_external_httpparams.ts data/external/payload_full.csv audit/results/baseline_external_2ab323e.json
```

| | Measured today | Poster |
|---|---|---|
| TP / FN / FP / TN | 4,813 / 6,950 / 0 / 19,304 | 4,813 / 6,950 / 0 / 19,304 |
| Recall | 40.92% (95% CI 40.03 – 41.81) | 40.9% |
| Precision | 100.00% (95% CI 99.92 – 100.00) | 100% |
| F1 / MCC | 58.07% / 0.5485 | — |
| SQL injection | 4,271 / 10,852 = 39.36% | 39.4% |
| XSS | 451 / 532 = 84.77% | 84.8% |
| Path traversal | 85 / 290 = 29.31% | 29.3% |
| Command injection | 6 / 89 = 6.74% | 6.7% |
| Failed requests | 0 | — |

**The poster's detection figures reproduce exactly.**

## 3. Detection — dev half and sealed half

The file was split once, before any rule change, by `audit/split_external.ts`
(rule: `SHA-256(payload)[0] & 1`; manifest in `audit/results/external_split_manifest.json`).

| | Dev half (may be read) | Sealed half (aggregate only) |
|---|---|---|
| File SHA-256 | `45cf0f1c…94f3192` | `be6096a7…908ed42` |
| Rows | 15,491 | 15,576 |
| TP / FN / FP / TN | 2,416 / 3,435 / 0 / 9,640 | 2,397 / 3,515 / 0 / 9,664 |
| Recall | 41.29% (40.04 – 42.56) | 40.54% (39.30 – 41.80) |
| F1 / MCC | 58.45% / 0.5518 | 57.70% / 0.5453 |
| SQL injection | 2,133 / 5,405 = 39.46% | 2,138 / 5,447 = 39.25% |
| XSS | 232 / 269 = 86.25% | 219 / 263 = 83.27% |
| Path traversal | 48 / 132 = 36.36% | 37 / 158 = 23.42% |
| Command injection | 3 / 45 = 6.67% | 3 / 44 = 6.82% |

The two halves sum to the whole-file confusion matrix. The sealed half was scored with
`SD_EVAL_SEALED=1`; no sample from it was printed, stored or read.

```bash
npx tsx audit/eval_external_httpparams.ts data/external/httpparams_dev.csv audit/results/baseline_external_dev_2ab323e.json
SD_EVAL_SEALED=1 npx tsx audit/eval_external_httpparams.ts data/external/httpparams_sealed.csv audit/results/baseline_external_sealed_2ab323e.json
```

## 4. Detection — in-repo sets

| Set | Command | Result | Report of 29 Sep |
|---|---|---|---|
| Set B overall recall | `npx tsx audit/eval_holdout_b.ts` | 66.7%, 0 / 22 false positives, 9 Tier 2 misses | same |
| Set A | `npx tsx audit/eval_harness.ts` | 2 misses (URL-encoded SQLi, base64 RCE) | same |

## 5. Performance — this machine, dev mode

```bash
ADMIN_API_KEY=test_admin_key_123 node audit/perf_benchmark.mjs audit/results/baseline_perf_2ab323e.json
```

| Concurrent clients | req/s | p50 ms | p95 ms | p99 ms | non-200 |
|---|---|---|---|---|---|
| 1 | 66.4 | 15.2 | 23.2 | 27.2 | 0 |
| 10 | 133.8 | 72.5 | 93.5 | 108.8 | 0 |
| 50 | 169.2 | 291.3 | 312.2 | 506.8 | 0 |
| 100 | **172.8** | 543.7 | 583.2 | 1,145.6 | 0 |

| Operation | p50 |
|---|---|
| Containment / release (API, simulated) | 30.3 ms / 14.4 ms |
| Ransomware tripwire (6/6 detected, includes 150 ms debounce) | 201.7 ms |
| ARP spoof alert (5/5 detected) | 82.2 ms |
| Audit chain verification (53 entries) | 16.9 ms, intact |

Poster values (183 req/s, median 399 ms, p95 790 ms at 100 clients) were taken on a different
host and are **not** the baseline for the 20% throughput goal. The baseline is **172.8 req/s**.
This is a single run; a second baseline run is required before a 20% claim (see roadmap H+1).

## 6. Zero egress

```bash
SD_EGRESS_SOAK_SEC=45 node scripts/zero-egress-check.mjs audit/results/baseline_egress_2ab323e.json
```

| | |
|---|---|
| External connection attempts | **0** |
| LAN connection attempts | 0 |
| Classifier requests during the run | 50 |
| `/inference-posture` reports `zeroExternalApiCalls` | true |
| Positive control (`fetch https://example.com` under the probe) | logged as EXTERNAL dns + tcp:443 |

Limits: 45-second soak, in-process probe only. Child processes and jobs on timers longer than
45 s were not observed. No packet capture was taken.

## 7. Findings from the audit that affect interpretation

1. **The evaluation's "neutral" vector lowers the block threshold.** In `server.ts`
   (`/api/v1/agent/ai-analyze`), `isAttack` is true when
   `packet.vector && packet.vector !== 'CLEAN_TRAFFIC' && classification.score >= 25`. The
   harnesses send `vector: 'UNKNOWN'`, so the route blocks at score 25, while
   `classifyPayload()` alone blocks at 55. Measured on the dev half: the classifier in-process
   misses 3,320 SQLi and 97 XSS; through the route it misses 3,272 and 37. All published
   figures, including today's, are therefore "route with vector=UNKNOWN" figures. This is left
   unchanged so before/after stays comparable, and it is disclosed here. A request carrying no
   `vector` field would be judged at 55.
2. **Each evaluation run writes the dataset into the local adjudication queue**
   (`globalAdjudication.recordPending`, `data/adjudication.db`, git-ignored). After today's
   runs that queue contains sealed-half payloads. Do not browse the adjudication panel on this
   machine, or clear the store, before rule work.
3. **No maintained `libinjection` package exists on npm** (`npm view libinjection` → 404).
   Using it would mean compiling the C library to WASM or a native addon inside the 48 hours.

## Open issues

- `main` on this machine is 3 commits behind `origin/main`. Fast-forwarding fails on Windows
  because the upstream file `Data` and the local directory `data/` differ only by case.
  Renaming `Data` upstream (for example to `notebooks/cic_ids2018_colab.py`) resolves it.

## Not measured

- 92-case audit suite on this commit today.
- Performance of the built bundle (`npm run build && npm start`).
- Anything on Linux, XDP native or generic, kernel latency.
- Egress over a soak longer than 45 s, or by packet capture.
