---
name: detection-engineering
description: Use when changing what the payload classifier detects - adding or widening rules for SQL injection, XSS, path traversal or command injection, touching canonicalisation, analysing why an attack was missed, or assessing false positives. Covers server/services/payloadClassifier.service.ts and the regression tests that guard it.
---

# Detection engineering

## Where detection actually happens

- `POST /api/v1/agent/ai-analyze` (`server.ts`) → `sanitizeUntrustedInput` → per-source rate
  limiter → 5-minute LRU cache → `classifyPayload()` → optional corpus corroboration → verdict.
- `classifyPayload()` in `server/services/payloadClassifier.service.ts` is the only detector on
  a sovereign deployment. It is additive weighted regex rules per family, `BLOCK_THRESHOLD = 55`.
- `canonicalisePayload()` already does bounded URL-decoding (3 rounds), SQL comment stripping
  and HTML numeric entities. Rules are tested against raw **and** canonical text.
- False-positive guards: `BENIGN_GUARDS`, `looksLikeProse()`, `isProseInJsonValue()`. Prose
  suppresses SQL/RCE rules of weight ≤ 65.

Read the current file before proposing anything. Do not infer behaviour from rule labels.

## Rules of the work

1. **Fix the class, not the string.** A rule that matches one sample is memorisation. Write the
   structural property (token sequence, syntax shape) and prove it on payloads you did not
   start from.
2. **Evidence comes only from permitted data**: the dev half of the external set
   (`data/external/httpparams_dev.csv`), Set A, and payloads you generate yourself. Never Set B
   Tier 2 misses, never the sealed half, never the newest adjudication fold. See the
   `benchmark-integrity` skill.
3. **Every new rule ships with both directions of test** in a vitest file next to the service:
   attacks it must catch, and benign text that resembles it and must pass (prose about SQL,
   names with apostrophes such as `o'brien`, arithmetic like `price=10-5`, Spanish/Arabic text).
4. **Normalisation must be bounded and meaning-preserving**: cap input length and decode rounds,
   never decode base64 speculatively on every request, keep matching against the raw form too.
5. **No catastrophic regex.** Avoid nested quantifiers over overlapping classes; the classifier
   runs on attacker-controlled input of up to megabytes.
6. Keep `ClassificationResult` and the `/ai-analyze` response shape unchanged. New evidence goes
   in `signatures`.

## Procedure

1. Measure first: `npx tsx audit/eval_external_httpparams.ts data/external/httpparams_dev.csv out.json`.
2. Bucket the dev-half misses by structure (not by sample) and rank buckets by count.
3. Implement the largest bucket. Add unit tests in both directions.
4. Re-run the dev half, Set A (`audit/eval_harness.ts`) and Set B (`audit/eval_holdout_b.ts`).
5. Compare: `node scripts/compare-detection.mjs <baseline.json> out.json`.
6. Record the change and its measured effect in `docs/IMPROVEMENT_EVIDENCE.md`.

## Success criterion

Dev-half recall rises, no attack class loses more than 1 pp, false positives on the 9,640 dev
benign values and the 22 Set B benign requests stay at zero (or every new one is listed and
justified), `npm run lint` and `npx vitest run` pass.

## Verification

```bash
npm run lint && npx vitest run
npx tsx audit/eval_harness.ts && npx tsx audit/eval_holdout_b.ts
node scripts/compare-detection.mjs audit/results/baseline_external_dev_2ab323e.json out.json
```

## Examples

- "Why is `1) or 3400=6002` allowed?" → trace it through `classifyPayload`, name the rule that
  should have fired and the structural reason it did not, then propose the class-level fix.
- "Add numeric tautology detection" → rule + tests for `1 or 1=1`, `1) and 5=5--`, and benign
  `a=1&b=1`, `x or y`, `2=2 is true`.
