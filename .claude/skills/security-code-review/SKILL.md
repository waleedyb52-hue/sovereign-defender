---
name: security-code-review
description: Use before committing or merging a change to the detector, the request path, evaluation harnesses or security services - to check that it introduces no vulnerability, breaks no API contract, disables no protection, and does not contaminate evaluation data.
---

# Security code review

Review the diff against the base branch, not the files in isolation:
`git diff main...HEAD -- server.ts server/ audit/ scripts/`.

## Checklist

**Detector changes** (`payloadClassifier.service.ts` and any service that matches untrusted text)
- `node audit/redos_scan.mjs` reports 0 super-linear regexes. It parses every regex in the server
  and times it on adversarial input; reading patterns by eye missed 13, two of them reachable
  without authentication through the deception sandbox.
- Input length and decode rounds are bounded.
- A benign guard cannot launder a clear attack (guards halve, never clear).
- No rule contains a literal lifted from a test set. Cross-check with `benchmark-integrity`.
- Every new rule has attack tests and look-alike benign tests.

**Contracts**
- `ClassificationResult` fields, the `/api/v1/agent/ai-analyze` response keys and status codes,
  and the verdict vocabulary (`ALLOW`, `BLOCK`, `DIVERT_HONEYPOT`) are unchanged.
- Local imports keep the `.js` extension (ESM).
- No new dependency without a stated reason; none that phones home (`zero-egress-validation`).

**Trust boundaries**
- No security decision reads a value the caller writes about itself. `packet.srcIp` is the
  analysed packet's claimed source: data for rules and reports, never identity. Rate limiting
  keys on the authenticated principal plus the TCP peer; exclusion of evaluation traffic needs
  ADMIN + direct loopback + the declared header (`isVerifiedEvaluation` in server.ts).
- Size bounds refuse (413), never truncate: a truncated payload is a bypass.

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
node audit/redos_scan.mjs                            # 0 super-linear regexes
```

Harness exit codes are part of the review: a check that always exits 0 is not a check. Every
harness CI runs must be able to fail (`--gate`), and that should be shown once by raising a floor.

## Success criterion

All four commands pass, every checklist item is either confirmed or listed as a finding with
file and line, and no finding of the "protection disabled" or "contract changed" kind is left
open.

## Examples

- "Review my SQLi rule" → run the ReDoS timing, list benign strings it would flag, confirm tests.
- "Is this branch safe to merge?" → walk the checklist over `git diff main...HEAD` and report
  findings ranked by severity.
