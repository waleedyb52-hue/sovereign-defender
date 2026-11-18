# Provenance of the result files in this folder

Every file here was written by a script in this repository. The table says which script,
on which code, and whether anything touched the file afterwards. A figure quoted in `docs/`
must come from one of these files.

## Files that were edited after generation, and their clean replacements

Four files were post-processed by hand on 2026-11-15 to remove sample strings. Removing them
was right (sealed-half strings, and lines from a dataset with no stated licence); doing it by
editing a generated file was not, because the project's rule is that results are generated,
never edited. No figure was changed — the regenerated files below prove it. The edited files
are kept unchanged so the history stays readable; the docs now cite the replacements.

| Edited file | What was removed, when | Original (pre-edit) | Clean replacement | Figures identical? |
|---|---|---|---|---|
| `baseline_external_2ab323e.json` | `missedExamples` (12 strings from the whole file, before the dev/sealed split existed); a `note` field added. Edited before its first commit. | Never committed — not recoverable | `regen_baseline_external_2ab323e.json`: same harness in aggregate-only mode (`SD_EVAL_SEALED=1`) against a server built from `2ab323e` in a separate worktree, 2026-11-18 | **Yes**: TP 4,813 / FN 6,950 / FP 0 / TN 19,304, every class equal |
| `baseline_fwaf_devbenign_2ab323e.json` | `fpExamples` (9 lines of the second source), `ba5b48f` | `ac9dc78` | `regen_baseline_fwaf_devbenign_2ab323e.json`, same method as above | **Yes**: FP 9 / TN 9,991 |
| `fp_stress_structure_dev.json` | `flaggedOnlyByStructure` sample lines, `ba5b48f` | `ac9dc78` | `fp_stress_dev_a53f5e4.json` (`--no-samples`, code at `a53f5e4`) | Structure-only flags: 5 → 5. Flags without structure 105 → 126, because the command-injection rules (`d7ae2a3`) were added in between |
| `fwaf_transfer_diagnosis_237420e.json` | `examples`, `ba5b48f` | `17e0d23` | `fwaf_transfer_diagnosis_a53f5e4.json` (`--no-samples`, code at `a53f5e4`) | Detected 4,056 → 4,057, missed by shape within 1 line (ReDoS rewrites in between) |

The pre-edit originals at `ac9dc78` and `17e0d23` are in the public history of the PR
branch and contain a few dozen lines of the second source. They cannot be removed without
rewriting published history, which this project does not do; it is disclosed here instead.

## Everything else — generated, never edited

| File | Script | Code | Notes |
|---|---|---|---|
| `external_split_manifest.json` | `audit/split_external.ts` | — | dev/sealed split of HttpParamsDataset, SHA-256 of each half |
| `external2_manifest.json` | `audit/build_external2.mjs` | — | second source: hash-ranked sealed test and dev-benign subsets |
| `baseline_external_dev_2ab323e.json` | `eval_external_httpparams.ts` | `2ab323e` | dev half; contains dev-half missed examples (allowed) |
| `baseline_external_sealed_2ab323e.json` | same, `SD_EVAL_SEALED=1` | `2ab323e` | aggregate only |
| `baseline_fwaf_test_2ab323e.json` | same, `SD_EVAL_SEALED=1` | `2ab323e` | aggregate only |
| `baseline_perf_2ab323e.json`, `baseline_perf_run2_2ab323e.json` | `audit/perf_benchmark.mjs` | `2ab323e` | the two runs differ by 18.9 %; both are kept |
| `baseline_egress_2ab323e.json` | `scripts/zero-egress-check.mjs` | `2ab323e` | 45 s soak |
| `dev_miss_analysis_2ab323e.json` | `audit/analyze_dev_misses.ts` | `2ab323e` | counts only |
| `dev_structure_cand1.json` | `eval_external_httpparams.ts` | `ac9dc78` | dev half, first structural candidate |
| `perf_ab_writebehind.json` | `scripts/perf-ab.mjs` | `237420e` | interleaved A/B, 3 rounds each |
| `sealed_httpparams_237420e.json`, `sealed_fwaf_237420e.json` | `eval_external_httpparams.ts`, `SD_EVAL_SEALED=1` | `237420e` | **the independent results**, scored once on the frozen candidate |
| `dev_httpparams_237420e.json`, `full_httpparams_237420e.json` | same | `237420e` | regression figures |
| `perf_candidate_237420e_run1.json`, `_run2.json` | `perf_benchmark.mjs` | `237420e` | |
| `egress_237420e.json` | `zero-egress-check.mjs` | `237420e` | 300 s soak |
| `audit_suite_237420e.txt` | `audit/audit_suite.ts` | `237420e` | console output |
| `reeval_sealed_*_c435d2e.json` | `SD_EVAL_SEALED=1` | `c435d2e` | **re-evaluation**, not new evidence |
| `dev_httpparams_c435d2e.json`, `perf_candidate2_c435d2e.json` | as named | `c435d2e` | |
| `redos_scan_before_fixes.json` | `audit/redos_scan.mjs` | `e564577` | 13 super-linear regexes |
| `redos_scan_after_fixes.json` | `audit/redos_scan.mjs` | `53b3db5` | 0 of 385 |
| `regen_baseline_external_2ab323e.json`, `regen_baseline_fwaf_devbenign_2ab323e.json` | `eval_external_httpparams.ts`, `SD_EVAL_SEALED=1` | server at `2ab323e` (separate worktree) | clean replacements, see above |
| `fp_stress_dev_a53f5e4.json`, `fwaf_transfer_diagnosis_a53f5e4.json` | `fp_stress_dev.ts`, `diagnose_fwaf_transfer.ts`, `--no-samples` | `a53f5e4` | counts only |
| `perf_final_99fa259_run1.json`, `_run2.json` | `perf_benchmark.mjs` | `99fa259` | final code, 2026-11-18 |
| `egress_final_99fa259.json` | `zero-egress-check.mjs` | `99fa259` | 120 s soak |
| `reeval_sealed_httpparams_99fa259.json`, `reeval_sealed_fwaf_99fa259.json` | `SD_EVAL_SEALED=1` | `99fa259` | **re-evaluation** of the final code, not new evidence |
| `dev_httpparams_99fa259.json` | `eval_external_httpparams.ts`, `SD_EVAL_SEALED=1` | `99fa259` | regression figure |
| `perf_ab_c435d2e_vs_27267a2.json` | `scripts/perf-ab.mjs --checkout` | `c435d2e` vs `27267a2` | interleaved, fresh worktrees and databases on both sides |
