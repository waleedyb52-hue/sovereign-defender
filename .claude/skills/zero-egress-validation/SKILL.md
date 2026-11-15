---
name: zero-egress-validation
description: Use when verifying or defending the zero-egress claim - checking that the running server makes no unauthorised outbound connections, after adding a dependency, service or scheduled job, or when preparing evidence for a reviewer.
---

# Zero-egress validation

The claim is about the **running application in its default configuration**, not about
`npm install` or `git`. Keep those separate in every statement.

## Tools in this repository

- `scripts/egress-probe.mjs` - a preload that records every TCP/TLS client socket, DNS lookup
  and UDP send made by the Node process, classified LOOPBACK / LAN / EXTERNAL. Observes only.
- `scripts/zero-egress-check.mjs` - starts the server under the probe with `GEMINI_API_KEY`
  removed, sends classifier traffic, soaks, and exits 1 on any EXTERNAL attempt.

```bash
SD_EGRESS_SOAK_SEC=300 node scripts/zero-egress-check.mjs audit/results/egress_<commit>.json
```

## What the probe does and does not prove

- Proves: no outbound connection from Node-level networking during the observed window.
- Does not see: child processes (`bpftool`, `arp`, `curl`, `ip`), native modules, the browser
  loading the dashboard.
- A short soak misses jobs on long timers. Grep for `setInterval`, `setTimeout`, `fetch(`,
  `https.request`, `new WebSocket(` in `server.ts` and `server/services/` and list every site
  with its trigger. Intel feeds, threat-intel lookups, object-storage replication and the
  Gemini client are the known opt-in egress paths.

## Procedure

1. Positive control first: run a one-line `fetch('https://example.com')` under the probe and
   confirm it is logged. A probe that reports zero without a control proves nothing.
2. Run the check with a soak long enough to cover the longest default-on timer.
3. Repeat with each opt-in feature enabled, to show the probe sees it and the posture endpoint
   (`/api/v1/soc/inference-posture`) reports it truthfully.
4. Independent confirmation on a host you control: packet capture limited to the server's
   traffic (Linux: run the server in a network namespace with no route and confirm it still
   starts and classifies; or `tcpdump -i any 'not host 127.0.0.1 and not net <lan>'`).
5. Frontend: build, then confirm `dist/` references no external origin
   (`grep -rEo "https?://[^\"' )]+" dist/assets | sort -u`), per `.clauderules` section 2.

## Success criterion

Zero EXTERNAL events in the default configuration over the stated soak, the positive control
logged, every opt-in egress path enumerated with its switch, and the limits of the method
written next to the result.

## Examples

- "Prove zero egress for the poster" → control, 5-minute soak, static site list, result JSON,
  and one sentence on what a packet capture would add.
- "I added a dependency" → re-run the check and grep the new package for network calls.
