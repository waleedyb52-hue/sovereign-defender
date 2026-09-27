# Sovereign Defender — Development Plan

**Status:** living document · **Owner:** Waleed · **Last revised:** 2026-09-25

This plan governs the remaining work. Every phase states what is built, which
published research motivates it, and the acceptance criterion that decides
whether the phase is actually done. A phase is not "complete" because code was
written — it is complete when its criterion is met and measured.

---

## 0. The problem this plan exists to solve

A detection benchmark run on 2026-09-25 returned **100% accuracy**. That result
was rejected, not celebrated. Two reasons, one practical and one from the
literature:

1. The rules and the test payloads were authored by the same process, in the
   same session. The classifier was being asked to recognise patterns it had
   been given. That is memorisation, not detection.
2. TESSERACT (USENIX Security 2019) states the position plainly: F1 scores
   above 0.99 in security classification are, in practice, a signature of
   experimental bias rather than of a superior detector.

So the first deliverable of this plan is not a better detector. It is an
evaluation method honest enough to tell us how bad the current one really is.

---

## 1. Research foundations

The plan is built on four bodies of work. Each one dictates a concrete design
decision, not just a citation.

| Source | Venue / institution | What it obliges us to do |
|---|---|---|
| **TESSERACT: Eliminating Experimental Bias in Malware Classification** — Pendlebury et al. | USENIX Security 2019 · Royal Holloway, King's College London | Split data by **time**, never at random. Test on **realistic class ratios**. Report performance **as a curve over time** (AUT), not a single number. |
| **Dos and Don'ts of Machine Learning in Computer Security** — Arp et al. | USENIX Security 2022 · TU Braunschweig, KCL, UCL, Royal Holloway | Avoid the ten pitfalls. The four most prevalent in the literature are lab-only evaluation (92% of surveyed papers), base-rate neglect (77%), inappropriate performance measures (69%) and sampling bias (69%). |
| **Continual learning under concept drift for NIDS** — SSF, INSOMNIA and related | Peer-reviewed NIDS literature | A detector trained once decays. Updating it naively causes catastrophic forgetting. Any live-training loop needs **strategic retention**, not blind appending. |
| **CyberRAG** — agentic RAG for attack classification | Future Generation Computer Systems, 2025 | Iterative retrieve-and-reason beats single-shot retrieval. Reported 94.92% on SQLi/XSS/SSTI — a realistic target band, and a reminder that **94.92% is what a strong published system looks like**. |

**Research gap this project addresses.** The surveyed literature evaluates
detectors offline, on static corpora, and reports a single accuracy figure.
TESSERACT and Arp et al. both identify lab-only evaluation as the dominant
methodological failure. This project's contribution is a **defence platform
that carries its own bias-controlled evaluation harness in production**, so the
reported numbers are continuously re-earned against live traffic rather than
asserted once in a paper. That is the gap: not a new algorithm, but evaluation
honesty as a shipped, running feature.

---

## 2. Non-negotiable principles

These override convenience at every point in the plan.

1. **A number the platform cannot defend is not reported.** Where data is
   insufficient, the system says so. MTTD/MTTR already behave this way.
2. **The label never reaches the classifier.** Any evaluation that passes the
   attack family, the expected verdict, or a pre-computed score as input is
   measuring nothing. This was a real defect, found and fixed.
3. **Test data is never used to develop rules.** A held-out set that informs a
   rule stops being held out permanently.
4. **Sovereignty is the default, not a mode.** Every capability added must work
   with zero egress. Anything that leaves the machine is opt-in, encrypted
   before it leaves, and visible in the UI.
5. **Live and reviewable.** The platform must be startable and inspectable by a
   third party at any point in the plan — not a demo assembled at the end.

---

## 3. Phases

### Phase 1 — Evaluation honesty *(in progress)*

**Build:** a bias-controlled evaluation harness implementing TESSERACT's
constraints and avoiding the Arp et al. pitfalls.

- Temporal split: every training/tuning sample strictly precedes every test
  sample.
- Realistic base rate: attacks are a small minority of the test stream, as in
  real traffic, instead of the ~60% used previously.
- Held-out adversarial set: mutation families never consulted while writing
  rules.
- Base-rate-aware reporting: precision, recall, F1, plus false positives per
  10,000 requests at the deployed prevalence.
- Performance reported over time windows, not as one snapshot.

**Acceptance criterion:** the harness reports a *lower* score than the naive
benchmark, and the gap is explainable. If it still reports ~100%, the harness
is wrong and Phase 1 is not done.

**Result — criterion met.** The naive benchmark reported 100%. Set A reported
F1 54.5% on first run, with 891 false alarms per 10,000 requests projected at
a 2% deployed prevalence. After OWASP/CWE rule families and a structural
prose guard, Set A reads F1 92.3% with zero false positives — but Set A is now
contaminated, because its failures were visible before those rules were
written. It is retained as a regression baseline only.

**Set B** (`audit/eval_holdout_b.ts`) was authored afterwards and separates two
claims that are usually blended:

| | Recall | What it measures |
|---|---|---|
| Tier 1 — covered classes, unseen payloads | **100%** (15/15) | Rules capture their class, not the string they were written against |
| Tier 2 — classes with no rule | **25%** (3/12) | The measured ceiling of signature detection |
| Benign — fresh legitimate traffic | **0 / 22 false positives** | Guards hold on traffic never seen before |
| Overall attack recall | **66.7%** | The honest headline number |

Tier 1 began at 86.7%: two rules were written narrowly enough to miss their
own class (an SSTI probe containing a call, and prototype pollution expressed
as nested JSON keys rather than property access). Both were genuine defects
and were widened; the benign set confirmed the widening introduced no false
positives. **Tier 2 was deliberately left untouched.** Writing rules for SSI,
XSLT, request smuggling, formula injection, entity expansion, ReDoS, cache
poisoning, CORS abuse or unicode traversal would raise the number and destroy
the measurement. 25% is the finding, and it is the evidence for Phase 3.

### Phase 2 — Live data, honestly labelled *(pipeline built; corpus accruing)*

**Build:** a labelling pipeline that turns live traffic into evaluation data
without fabricating ground truth.

- Operator adjudication surface: analyst confirms or overturns a verdict; that
  decision becomes the label.
- Provenance on every label: who or what produced it, and when.
- Strict separation of adjudicated data into temporally ordered folds.

**Acceptance criterion:** a labelled set exists that no rule was written
against, with recorded provenance and timestamps, large enough for the harness
to produce a stable figure.

**Status: built and verified; criterion not yet met.** The pipeline exists and
its guarantees are tested. The corpus does not — it needs operators ruling on
real traffic, and no amount of engineering substitutes for that. The platform
says so rather than filling the gap: `audit/eval_from_adjudicated.ts` prints the
shortfall and exits 0, because an honest "not yet" is the correct output.

| Component | Where |
|---|---|
| Label store, folds, exports | [`server/services/adjudication.service.ts`](../server/services/adjudication.service.ts) |
| Operator API | [`server/routes/adjudication.routes.ts`](../server/routes/adjudication.routes.ts) |
| Analyst surface | [`src/components/soc/AdjudicationPanel.tsx`](../src/components/soc/AdjudicationPanel.tsx) |
| Scoring harness | [`audit/eval_from_adjudicated.ts`](../audit/eval_from_adjudicated.ts) |
| Machinery drill | [`audit/seed_adjudication_drill.ts`](../audit/seed_adjudication_drill.ts) |

**Five guarantees, each enforced by structure rather than by a comment.** Tests
51–60 in the audit suite assert the refusals, not the happy paths.

1. **Append-only.** No `UPDATE`, no `DELETE`, and no HTTP delete route. A
   revision inserts a row that supersedes its predecessor and the predecessor
   stays readable, so it can be proved that a label was not quietly rewritten.
2. **Provenance is mandatory.** An adjudication without an identity is refused
   with `ADJUDICATOR_IDENTITY_REQUIRED`. A label without provenance is an
   assertion, and this plan does not report assertions as measurements.
3. **Agreement is derived, never supplied.** `agreed` is computed from the two
   verdicts inside the service. A client able to assert it could manufacture the
   platform's own accuracy figure, which is precisely the failure Phase 1 exists
   to prevent.
4. **The test fold is unreachable for tuning.** `exportForTuning()` excludes the
   newest fold before the slice is taken. There is no parameter that returns it
   — principle 3 expressed as an API rather than as a promise.
5. **The label cannot reach the classifier.** `exportForTest()` withholds labels
   by default. A caller classifies first, then fetches the answers, so at the
   moment of classification the answers are not in its process.

**Drill validation.** Because the fold and export machinery must not ship
untested, `seed_adjudication_drill.ts` fills the store with 81 labels marked
`AUTOMATED_IMPORT` / `DRILL`. Folds computed correctly (20/20/20/22, newest
reserved for test) and the two-step scoring protocol ran end to end, returning
F1 81.8% on the test fold. **That figure measures the pipeline, not the
detector**, and it cannot be mistaken for one that does: `stats()` reports label
counts by origin, `operatorGrounded` goes false, and the harness prints a
NOT OPERATOR-GROUNDED banner *above* the numbers. The drill data was purged
afterwards; the store ships empty.

**What the drill found anyway.** Scoring against labels assigned from payload
construction rather than from classifier output surfaced three real defects,
all in the test fold and therefore **deliberately left unfixed**:

| Payload | Operator label | Machine |
|---|---|---|
| `POST /api/v1/tickets {"desc":"User sees an alert(1) popup on checkout"}` | BENIGN | blocked — false positive on prose |
| `'; EXEC xp_cmdshell 'dir'--` | MALICIOUS | allowed |
| `X-Forwarded-Host: evil.tld` | MALICIOUS | allowed |
| `query{__schema{types{name fields{name}}}}` | MALICIOUS | allowed |

Fixing these from the test fold would convert it into tuning data and destroy
the only clean measurement surface the platform has. They are recorded here as
known defects; repairs must come from tuning-fold evidence or a fresh set.

A separate gap, found through the same surface and also unfixed: the classifier
still misses quoteless numeric SQL tautologies — `id=1 OR 1=1--` classifies as
`CLEAN_TRAFFIC`. This is the Set A miss from Phase 1 reappearing in live
traffic, which is some evidence the adjudication surface does what it is for.

**Blocked on:** operator rulings. Needs live traffic and an analyst.

### Phase 3 — Continual learning under drift

**Build:** a learned component that updates from adjudicated live data.

- Drift detection on the incoming distribution.
- Strategic retention (keep representative history, drop stale samples) rather
  than appending everything — directly from the SSF/continual-learning results.
- Every promotion of a new model gated on beating the incumbent on the held-out
  temporal fold. A model that does not win is not promoted.

**Acceptance criterion:** a model update measurably improves AUT over the
frozen baseline on data postdating both, with no catastrophic forgetting on
earlier folds.

### Phase 4 — Retrieval quality *(half the criterion met and measured)*

**Build:** iterative retrieve-and-reason loop, replacing single-shot retrieval
(CyberRAG pattern).

**Acceptance criterion:** measurable reduction in false positives on the
held-out set versus single-shot retrieval, with the retrieval cost bounded.

**Built.** [`iterativeRetrieval.service.ts`](../server/services/iterativeRetrieval.service.ts)
loops at most three rounds and reports its own cost. Round 2 refines the query
using techniques discovered in round 1 — the refinement single-shot cannot make,
because those techniques were unknown when the first query was built. Measured
against a 44,000-incident corpus: single-shot 7 evidence items, iterative 9, with
round 2 surfacing `T1048.003` from a retrieved incident.

`SUFFICIENCY_THRESHOLD` was raised from 6 to 14 after measurement: at 6 the loop
terminated on round 1 every time, because a rich corpus satisfies it immediately.
Iteration earns its cost when the corpus is sparse or the packet uninformative,
not universally.

**The obstacle, and what was done about it.** The criterion could not be assessed
at all, for a structural reason rather than a missing feature: retrieved context
reached only the external model's prompt, while the sovereign detection path is
`classifyPayload()` and never consulted the corpus. With no external model
configured — the shipping default — retrieval could not move any rate, because it
took no part in the decision.

[`corpusCorroboration.service.ts`](../server/services/corpusCorroboration.service.ts)
makes it take part, under four constraints: band-limited to scores in
`[40, BLOCK_THRESHOLD)`, never applied to a zero score, requires two independent
corroborating signals, and capped at 18 points with every signal returned for
inspection.

**Measured by [`corroboration_impact.ts`](../audit/corroboration_impact.ts), with
the decision rule fixed before the run:**

| | Result |
|---|---|
| False positives on benign traffic from known-bad actors | **0 of 12** |
| Fired where the actor had no history | **0** |
| Movement on Set A and Set B (58 payloads) | **none** |
| Verdict changes on ambiguous borderline payloads | 4 |

The false-positive half of the criterion **holds and is measured**. The recall half
does not: the four verdict changes are on genuinely ambiguous payloads — a
localhost URL in a `url` parameter is either SSRF probing or a health-check
config — and no label says which. Counting them as catches would assert ground
truth the harness does not have.

A second finding from the same run: only 2 of 12 probe payloads scored inside the
band at all. **This rule set is bimodal** — payloads are either clearly hostile or
clearly clean — so there is very little borderline for history to tip. That limits
how much this mechanism can ever contribute.

**Shipping default: off.** `SD_CORPUS_CORROBORATION=on` enables it. The
false-positive cost is proven zero, but the benefit is unproven, and this project
does not enable a feature whose benefit has not been measured. It becomes a
one-line change once the borderline band has adjudicated labels.

### Phase 5 — Operator surfaces *(criterion met)*

**Build:** investigation/query interface over telemetry; dynamic attack-path
graph derived from data rather than drawn statically.

**Acceptance criterion:** an analyst can answer "what else did this actor
touch" without leaving the platform or writing SQL.

**Met.** `GET /api/v1/soc/investigate/actor?indicator=…` walks the corpus outward
from an indicator: direct incidents, the techniques in those incidents, then other
actors sharing those techniques. Every related finding carries its hop distance, so
a second-hop link is not presented with the confidence of a direct hit, and
confidence is derived from corroborating count rather than assigned.

Measured on `194.26.29.112`: 5 direct incidents, 5 techniques, 1 related actor at
hop 2, HIGH confidence with a stated basis, 411 ms. An empty corpus returns
`corpusEmpty: true` and `confidence: NONE` with the words "absence of evidence, not
evidence of safety" — rather than an empty graph that reads as a clean bill.

### Phase 6 — Durability and review *(criterion met, 10/10)*

**Build:** encrypted replication to self-hosted object storage; reproducible
deployment.

**Acceptance criterion:** a reviewer can stand the platform up from the repo on
a clean machine and reproduce the reported numbers.

**Met.** [`reproducibility_check.ts`](../audit/reproducibility_check.ts) verifies
the things that actually break reproducibility rather than restating a README:
lockfile tracked, container definition present, no credential required to start,
harnesses present and runnable, figures quoted in this plan matching what the
harnesses print, provenance on every reported figure, the test fold structurally
unreachable for tuning, no external frontend requests, and replication encrypted
before egress and opt-in. **10 PASS, 0 WARN, 0 FAIL.**

It found one real gap on its first run: no `engines.node` while the project depends
on `node:sqlite`, so a reviewer on Node 20 got an unexplained module-not-found.
Pinned to `>=22.5.0`.

### Kernel verification on a host that has a kernel

The platform's central claim is kernel-level defence, and on Windows it cannot be
checked: XDP is Linux-only, so kernel integrity returns `UNAVAILABLE` and
`meanKernelLatencyUs` is null. Honest, but not measurements.

[`scripts/kernel-audit.mjs`](../scripts/kernel-audit.mjs) takes them where a kernel
exists. Zero dependencies — nothing outside node's standard library — so it runs
under a bare `node` with no `npm ci`, no build and no native modules. Verified
under WSL2 (kernel 6.18.33.2):

| | Result |
|---|---|
| Syscall table integrity | **VERIFIED** — 941 `__x64_sys_*` symbols hashed |
| `ebpf/xdp_drop.c` compiles | **Yes** — 11,456-byte object, `xdp` section 600 bytes, `.maps` and `license` present, `loadable: true` |
| bpftool / bpffs | v7.7.0, `/sys/fs/bpf` mounted |
| Live packet & latency counters | **Unavailable** — needs privilege, and no figure is produced without it |

**The XDP program had never been compiled before this script existed.** The product
claimed kernel-level packet dropping on the strength of a `.c` file nobody had put
through a compiler. It does compile, to valid BPF bytecode that reads from the
`xdp_md` context.

**What running it on Linux actually exposed.** Moving the whole server into WSL2
was meant to turn the kernel claims from simulated into verified. It did that for
syscall integrity — and it produced two false claims within seconds, both of which
were invisible on Windows because the code path never ran there:

| Reported | Actually true on that host |
|---|---|
| `mode: KERNEL_NATIVE`, "counters read from the kernel" | `/sys/fs/bpf` empty, `bpftool prog show` → Operation not permitted |
| `meanKernelLatencyUs` tagged `MEASURED` | value was `null` |

The second is the general lesson: the tag was computed from a **capability flag**
rather than from the figure. A flag says what the host could do; it does not say
whether a number was obtained. A true flag over an absent value produced
`MEASURED: null`.

Fixed by proving readability with an actual `bpftool prog show` and deriving the
tag from the value — `latencyValue != null ? 'MEASURED' : 'UNAVAILABLE'` — plus a
third state for the case that was being mislabelled. Re-verified on the same WSL2
host after the fix:

```
mode                : KERNEL_TOOLING_PRESENT_UNREADABLE
toolingPresent      : true      countersReadable : false
meanKernelLatencyUs : null      tag              : UNAVAILABLE
kernel integrity    : VERIFIED  941 symbols, 218 ms
```

Both facts now coexist without contradiction: the syscall table genuinely is
readable, and the packet counters genuinely are not. Guard 85 fails if the tag is
computed from the capability flag again.

**This is why the audit was run rather than reasoned about.** Source inspection
from Windows would have confirmed the fix and missed the defect, because the defect
only existed on the platform the code claimed to support.

The intake endpoint accepts only verified facts. A latency or packet figure in the
body is **discarded** — tested by posting `meanKernelLatencyUs: 0.01` with
`liveKernelCountersAvailable: true`, after which the platform's value remained
`null`. Readings expire after an hour and are tagged
`MEASURED_VIA_KERNEL_AUDIT`, deliberately distinct from a live in-process reading,
with the host and kernel recorded.

---

## 4. Current state

| Capability | State | Evidence |
|---|---|---|
| Corpus + retrieval (RAG) | Done | 48,258 indicators · 697 ATT&CK techniques · 1,716 KEV CVEs |
| Prompt-injection defence | Done | Regression test #35.5; four attack variants neutralised |
| Payload classifier reads payloads | Done | Replaced a decision that read a caller-supplied label |
| MTTD / MTTR measured | Done | MTTD 2 ms p95 (n=30); MTTR 5 ms p95 (n=25); reports "insufficient data" when unmeasured |
| Encrypted object storage | Built, **unverified end to end** | Crypto and refusal paths tested; no live S3 round-trip yet — Docker is not installed on the development machine |
| Honest evaluation harness | Done | Set A (regression) + Set B (clean); Tier 2 recall 25% is the measured signature ceiling |
| Operator adjudication pipeline | Built, corpus empty | Append-only, provenance-bearing, temporally folded; reports its shortfall instead of a figure |
| Continual learning (Phase 3) | 66.5% measured | Drift and retention done; learner and gate built but UNVALIDATED — half credit, not full |
| Iterative retrieval (Phase 4) | Half the criterion | FP cost proven zero and measured; recall gain unverified; corroboration ships off by default |
| Investigation surface (Phase 5) | Done | Actor pivot with hop distance and derived confidence |
| Reproducibility (Phase 6) | Done, 10/10 | Automated check; found and fixed a missing Node version constraint |
| Kernel verification | Done under WSL2 | Syscall integrity VERIFIED; the shipped XDP program compiles to valid BPF for the first time |
| International benchmark | 86.1% assessable | 13 MEETS, 5 PARTIAL, 0 FAILS, 3 declined as not applicable |
| Live training | Phase 3, not started | — |

---

## 5. Open risks

- **The classifier is rule-based.** It cannot generalise to attack classes
  nobody wrote a rule for. Set B Tier 2 measures this precisely: 3 of 12
  unseen classes detected, and the three hits were incidental (a traversal
  path inside a zip-slip payload, a Host-header pattern) rather than the class
  being understood. Rules plateau here by construction, which is the entire
  argument for Phase 3.
- **Set B will degrade with use.** Every rule written against a Tier 2 miss
  converts Set B into Set A. When Tier 2 is exhausted, a Set C must be authored
  before any further generalisation claim is made.
- **Live traffic volume.** Phases 2 and 3 need real adjudicated data. Synthetic
  substitutes would reintroduce the bias this plan exists to remove.
- **Storage is unproven.** The S3 client is written and its cryptography is
  tested, but it has never completed a round trip against a real endpoint.
