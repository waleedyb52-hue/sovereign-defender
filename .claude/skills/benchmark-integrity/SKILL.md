---
name: benchmark-integrity
description: Use before running, reporting or comparing any detection figure, when handling the external dataset or its dev/sealed halves, when adding an evaluation set, or when a result looks too good. Enforces the evaluation rules of docs/DEVELOPMENT_PLAN.md - held-out data, label withholding, SHA-256 provenance, confidence intervals and leak checks.
---

# Benchmark integrity

The project's claim is that its numbers are honest. One contaminated figure costs more than a
low one. `docs/DEVELOPMENT_PLAN.md` section 2 is binding; this skill is how to apply it.

## The data, and what each set may be used for

| Set | Where | May design rules from it | What a score on it means |
|---|---|---|---|
| Set A | `audit/eval_harness.ts` | yes (already contaminated) | regression only |
| Set B Tier 1 / benign | `audit/eval_holdout_b.ts` | no | class coverage, FP guard |
| Set B Tier 2 | same | **never** | ceiling of signature detection |
| External, dev half | `data/external/httpparams_dev.csv` | yes | regression only, once used |
| External, sealed half | `data/external/httpparams_sealed.csv` | **never, do not open the file** | the independent figure |
| Adjudicated, newest fold | adjudication store | **never** | test fold |
| Second source, sealed test | `data/external2/fwaf_test_sealed.csv` | **never, do not open the file** | out-of-distribution figure |
| Second source, dev | `fwaf_dev_benign.csv`; `badqueries.txt` / `goodqueries.txt` lines outside the sealed ranks (see `audit/build_external2.mjs`) | yes | regression only |

Hashes and the split rule are in `audit/results/external_split_manifest.json`. The split is
`SHA-256(payload)[0] & 1`, re-derivable by anyone from the published file.

## Hard rules

1. Never read, grep, print or sample the sealed half. Score it only with `SD_EVAL_SEALED=1`,
   which suppresses example output.
2. Score the sealed half **once per release candidate**, after the rules are frozen. If a rule
   changes after a sealed result was seen, say so in the report: the next sealed figure is a
   re-evaluation, not independent evidence.
3. The label never reaches the classifier: evaluation requests use `vector: 'UNKNOWN'` and no
   `threatScore`. Check this in any new harness — `/ai-analyze` lets a caller-supplied vector
   and score tip a borderline verdict.
4. A renamed set is the same set. Data that informed a rule cannot become a test set.
5. Decision rule fixed in advance: any verdict other than `ALLOW` is a detection; a failed
   request counts against the system.
6. Report the confusion matrix, precision, recall, F1, MCC and 95% Wilson intervals, per class
   and overall, with the dataset SHA-256 and the commit. Never a single blended "efficiency" number.
7. Never edit a results JSON or a poster figure by hand. Regenerate it. If a file must not carry
   samples, generate it without them (`SD_EVAL_SEALED=1`, `--no-samples`). This rule was broken
   once in the 48-hour pass; `audit/results/PROVENANCE.md` records what was edited and the clean
   regenerated replacements.
8. If something could not be measured, write that down with the reason.
9. Evaluation traffic is declared with the `x-sd-evaluation-source: 1` header, which the server
   honours only from an ADMIN caller on a direct loopback connection. Never by source address:
   `packet.srcIp` is written by the caller and decides nothing.
10. Detection floors live in `audit/regression_gate.json`; harnesses run with `--gate` exit 1 if a
    figure falls below its floor. Raise a floor after a measured gain; lowering one needs the
    reason in the commit.

## Leak checks before reporting a number

- `git diff` of the classifier since the baseline: does any regex contain a literal that only
  appears in test data (random sqlmap integers, generated aliases)? That is memorisation.
- Was the server restarted since the last code change? The LRU cache holds verdicts 5 minutes.
- Is `GEMINI_API_KEY` unset? With it set the figure measures an external model.
- Is `SD_CORPUS_CORROBORATION` in the state you are reporting?
- Recall near 100% on any held-out set means the harness is broken until proven otherwise.

## Procedure

```bash
# once, before any rule change (already done for commit 2ab323e)
npx tsx audit/split_external.ts data/external/payload_full.csv data/external audit/results/external_split_manifest.json

# during development - dev half only
npx tsx audit/eval_external_httpparams.ts data/external/httpparams_dev.csv audit/results/dev_<commit>.json

# once, on the frozen candidate
SD_EVAL_SEALED=1 npx tsx audit/eval_external_httpparams.ts data/external/httpparams_sealed.csv audit/results/sealed_<commit>.json
node scripts/compare-detection.mjs audit/results/baseline_external_sealed_2ab323e.json audit/results/sealed_<commit>.json --min-recall-gain=20
```

## Success criterion

Every reported figure has: commit, dataset SHA-256, command, confusion matrix, intervals, and a
stated category (independent / regression / re-evaluation). Nothing from a forbidden set
appears in the diff, the conversation, or a results file.

## Examples

- "Recall went up 30 points on the dev half" → report it as a regression figure and withhold
  any generalisation claim until the sealed run.
- "Show me some sealed misses so I can fix them" → refuse; offer dev-half misses of the same class.
