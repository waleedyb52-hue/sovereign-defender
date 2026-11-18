# Sovereign Defender — one-page brief for judges

**Problem.** A web application's operators need to know when a request carries an attack —
SQL injection, cross-site scripting, command execution, file inclusion — and to act on it
without sending their traffic to a third-party cloud model.

**Solution.** A self-hosted defence console (Node.js/TypeScript server, React console). A local
payload classifier canonicalises each request: URL decoding, comments, entities and Unicode NFKC.
It then scores the request with a structural SQL tokenizer and weighted rules. Operator actions —
block, isolate, release — go through an audited, authenticated API. On Linux, an XDP program
can drop traffic from an isolated source inside the kernel. No outbound connection is needed;
a soak test measured 0.

**Measured evidence (every figure from a generated file in `audit/results/`):**

| What | Result | What kind of figure |
|---|---|---|
| **Real production attacks it never saw** (Zenodo 17178461, 2025, ModSecurity-blocked; 3,015 payload attacks) | poster baseline **27.63 % → 50.91 %** [49.13–52.69] | independent, scored once on frozen code under a pre-committed protocol |
| — SQL injection in that set (n = 1,159) | 41.59 % → **91.72 %** | independent |
| HttpParams sealed half | 40.54 % → 97.50 %, 0 false positives / 9,664 | in-distribution |
| Fwaf validation chunk, never read | 40.72 % → 67.38 % | held-out, same source as development |
| Throughput (PR #2, interleaved A/B) | 172.6 → 316.9 req/s median (+83.6 %), p95 772 → 425 ms | one machine, one day |
| Quality gates | 306 unit tests · 94/94 audit checks · 0 of 412 regexes vulnerable to ReDoS · CI regression floors | every commit |

**Highlights of the engineering work.** A structural SQL tokenizer that scans payloads up to
256 KB in overlapping windows. Thirteen catastrophic-backtracking regexes rewritten, with a
scanner in CI that keeps them out. Write-behind SQLite with a flush on shutdown. A per-caller
budget for classification. A console that shows a real result or an explicit error, never an
invented verdict. Evaluation traffic that cannot be forged from a packet field.

**Demonstration you can repeat.**
1. `npm ci && npm run build`, then `npm start`.
2. Run `node scripts/with-server.mjs "npx tsx audit/audit_suite.ts"` to get 94 security checks
   against a fresh server.
3. Run `node audit/budget_check.mjs` to watch the budget refuse a flooding caller with 429.
4. Rebuild the independent result from the public Zenodo file with the three commands in
   `docs/FINAL_RELEASE_REPORT.md`.

**Limits, stated plainly.**
- File-inclusion detection is weak on production traffic (8.29 %).
- The production set holds no benign traffic, so it gives no false-positive rate.
- Every detection figure comes from the analysis endpoint, not inline interception.
- XDP was verified in generic mode under WSL2 only, never on a native driver.
- The requested 2026 dataset could not be downloaded; the provider was down.
- No adaptive-attacker test has been run.
- The analysis API still returns two fixed descriptive fields (`confidence`, `xaiAttribution`).

**Research value.** The project treats evaluation as part of the product:
- sealed splits re-derivable by anyone from a SHA-256 rule;
- protocols committed before scoring;
- every failed request counted against the system;
- Wilson intervals on every figure;
- a reserve half kept untouched for the next check;
- a written record of every place where a figure was weaker than hoped, including a
  second-source gain of only +2.7 pp that motivated the later work.
