# Sovereign Defender — Security Audit & Test Suite

Reproducible 50-case audit that exercises the running server + core modules
directly. Produced during the architectural/security remediation pass.

## Contents
- `audit_suite.ts` — the 50 automated test cases (eBPF/XDP, Tarpit, FIM, AI, E2E).
  Runs live HTTP integration against `127.0.0.1:3000`, direct module unit tests,
  and static invariant checks on kernel-only code paths. Writes `audit_results.json`.
- `build_pdf.py` — renders the results in `audit_results.json` into a visual PDF
  (`Sovereign_Defender_Test_Report.pdf`) with matplotlib charts + reportlab.

## Run it
```bash
# 1. Start the server (from the repo root)
ADMIN_API_KEY=test_admin_key_123 npx tsx server.ts

# 2. In another shell, from the repo root, run the suite
ADMIN_API_KEY=test_admin_key_123 npx tsx audit/audit_suite.ts
#    -> prints the 50-test matrix and writes audit_results.json

# 3. (optional) Build the visual PDF report
python -m pip install matplotlib reportlab arabic_reshaper python-bidi
python audit/build_pdf.py
```

## Latest result
50 / 50 PASS · 0 WARN · 0 FAIL (see `audit_results.json` for the measured
per-test response times). Every number in the PDF is read from that JSON — none
is hand-authored.
