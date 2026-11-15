---
name: security-code-review
description: Use before committing or merging a change to the detector, the request path, evaluation harnesses or security services - to check that it introduces no vulnerability, breaks no API contract, disables no protection, and does not contaminate evaluation data.
---

# Security code review

Review the diff against the base branch, not the files in isolation:
`git diff main...HEAD -- server.ts server/ audit/ scripts/`.

## Checklist

**Detector changes** (`payloadClassifier.service.ts`)
- No regex with catastrophic backtracking: nested quantifiers, `(a+)+`, `[\s\S]*` between two
  optional groups. Time each new rule against a 1 MB adversarial string; it must stay in
  milliseconds.
- Input length and decode rounds are bounded.
- A benign guard cannot launder a clear attack (guards halve, never clear).
- No rule contains a literal lifted from a test set. Cross-check with `benchmark-integrity`.
- Every new rule has attack tests and look-alike benign tests.

**Contracts**
- `ClassificationResult` fields, the `/api/v1/agent/ai-analyze` response keys and status codes,
  and the verdict vocabulary (`ALLOW`, `BLOCK`, `DIVERT_HONEYPOT`) are unchanged.
- Local imports keep the `.js` extension (ESM).
- No new dependency without a stated reason; none that phones home (`zero-egress-validation`).

**Protections that must still be on**
- Self-DoS rate limiter, prompt isolation (`sanitizeUntrustedInput`), admin key checks, RBAC.
- Audit trail stays append-only and hash-chained; adjudication stays append-only with
  mandatory provenance; the test fold stays unreachable for tuning.
- MITRE technique mapping still present on alerts; unknown stays `UNMAPPED`.
- Corpus corroboration default remains off unless its benefit was measured.

**Honesty rules** (`.clauderules` section 0 and 11)
- No hardcoded or estimated figure presented as measured, in UI, docs or results files.
- Results JSON files are generated, never edited.

## Verification

```bash
npm run lint
npx vitest run
npm run build
ADMIN_API_KEY=... npx tsx audit/audit_suite.ts     # must stay at zero failures
```

## Success criterion

All four commands pass, every checklist item is either confirmed or listed as a finding with
file and line, and no finding of the "protection disabled" or "contract changed" kind is left
open.

## Examples

- "Review my SQLi rule" → run the ReDoS timing, list benign strings it would flag, confirm tests.
- "Is this branch safe to merge?" → walk the checklist over `git diff main...HEAD` and report
  findings ranked by severity.
