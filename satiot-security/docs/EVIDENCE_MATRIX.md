# P1 Implemented application-security profile, Evidence matrix:

RQ1: what bounded application-security composition is implemented under the assumed trust topology?
RQ2: which protocol/freshness/lifecycle behaviours hold under the configured adversarial and failure cases?
RQ3: how do representation and communication scenarios affect modelled cost and completion?

Architecture is specified in PROTOCOL.md, assumptions in ASSUMPTIONS.md, configurations in ../config/experiments.json, implementation in ../src/core.py and exact source identity in ../results/reference/run_manifest.json. Only principal run evidence is mapped below. 

## Operational security-requirement catalogue:

| ID | Meaning | Threat | Mechanism | Evidence | Status | Residual boundary |
|---|---|---|---|---|---|---|
|SR1|Authenticate provisioned establishment requests|T1|KMS registration/epoch/HMAC|Join tamper/epoch tests, lifecycle|Implemented; tests support checked paths|Captured authenticated requests remain processable|
|SR2|Authenticate responses against current pending request|T1/T4|DID/ND matching and HMAC|Join response manipulation/delay tests|Implemented; empirical checked paths|No backend receipt confirmation|
|SR3|Protect uplink confidentiality under unique key/nonce use|T2/T4|AES-256-GCM|Serialized plaintext roundtrip; rollback negative control|Conditional primitive/engineering claim|No formal proof, no protection after root compromise or nonce reuse|
|SR4|Reject modified payload and authenticated context|T2|GCM tag/AAD|Adversarial + existing-context substitution|Implemented; mutation coverage bounded|No arbitrary attacker success probability|
|SR5|Separate device/session contexts|T2/T5|DID/SID in AAD and key derivation|Cross-installed-context test|Implemented; checked substitution|Separation is not distributed retirement|
|SR6|Maintain nonce uniqueness while sender state is continuous|T4|Prefix+uint64 sequence; exhaustion check|Counter test, unsafe and safe rollback|Conditional; continuity is a caller obligation|No durable anti-rollback detector|
|SR7|Reject duplicate protected messages|T3|Replay window|Duplicate attack and replay driver|Implemented in active in-memory context|State lost on AS process reset|
|SR8|Admit bounded unseen reordering|T3/T6|Window lower boundary rule|Replay driver and boundary tests|Implemented; deterministic scenarios|Window is not channel calibration|
|SR9|Preserve freshness state after failed authentication/install retry|T2/T3|Authenticate before commit; idempotent install|High-sequence tamper and reinstall tests; lifecycle|Implemented in same process|No persistent crash-atomic restore|
|SR10|Reject malformed representation and exhausted counters|T2/T4|Range/length validation and strict decoder|Malformed/parser/counter tests|Implemented; selected boundaries|No fuzzer or arbitrary parser assurance|
|SR11|Cancel pending establishment on local invalidation|T4|Clear pending ND|Delayed/overwritten accept tests; lifecycle|Implemented locally|No KMS cancellation message|
|SR12|Require explicit fresh establishment after uncertain state|T4|Caller invalidate then establish|Recovery driver/key-change checks|Procedure demonstrated; requirement caller-enforced|No automatic rollback detection/recovery|
|SR13|Permit explicit local session retirement|T5|AS retirement operation|Lifecycle same-AS undelivered-old check|Implemented locally|Other AS instances remain unaffected|
|SR14|Scope join authorisation and active-session revocation|T1/T5|KMS revoke plus separate AS revoke|Lifecycle + scoped-revocation tests|Implemented as separate operations|No immediate distributed revocation|
|SR15|Characterise security representation/communication cost under stated scenarios|T6|Size, airtime, loss and contact models|Airtime/network/contact/integrated|Modelled/analysed, not availability guarantee|Jamming, radio scheduling and physical links unvalidated|

## Experiment-to-conclusion chain:

| ID | Evidence/units | SR / RQ | Principal supported conclusion | Boundary |
|---|---|---|---|---|
|P1-A|adversarial.py: 1400 (Measured prototype behaviour)|SR4 SR7 / RQ1 RQ2|Supports specified mutations and duplicate rejection|Fixed procedures; no global attack probability|
|P1-B|automated security suite: 60 tests (Executed unit/regression tests)|SR1 SR2 SR3 SR5 SR6 SR9 SR10 SR11 / RQ1 RQ2|Selected joining, plaintext/wire, parser, key derivation and freshness invariants|Not formal proof, parser fuzzing or physical interoperability|
|S1|replay.py: 24 (Deterministic prototype deliveries)|SR7 SR8 / RQ2|Bounded reordering trades freshness policy for useful acceptance|One configured delivery order plus boundary tests|
|S2|rollback.py: 200 (Measured prototype negative/control trials)|SR3 SR6 SR12 / RQ2|Fresh sender material is required before transmission after uncertain state|Receiver rejection cannot repair confidentiality loss; recovery caller-enforced|
|S3|lifecycle.py: 200 (Measured prototype trials)|SR1 SR9 SR11 SR12 SR13 SR14 / RQ1 RQ2|Functional joining, idempotency/cancellation and explicit local administration demonstrated|No requester liveness, distributed retirement, durable state or forward secrecy|
|C1|airtime.py: 90 (Deterministic modelling)|SR15 / RQ3|Security representation cost produces discrete packet/airtime increases|P0 unprotected size baseline; arbitrary capacity/SF scenarios; no fragmentation implementation|
|C2|network.py: 1500 (Seeded stochastic simulation)|SR15 / RQ3|Independent object-loss model quantifies configured completion and conditional traversal delay|Loss and jitter confounded; not frame-level or physical satellite reliability|
|C3|contact.py: 32 (Deterministic virtual-time prototype scenarios)|SR15 / RQ3|Residual continuous contact, not start availability alone, controls abstract completion|10ms abstract traversals exclude airtime/receive windows; one observation/case, no CI|
|C4|integrated.py: 405 (Analytical inference/model sensitivity)|SR15 / RQ3|Connects representation/chunk count to independent frame loss and serial airtime budget|Not sampled radio evidence; assumed metadata, no retries, symmetric SF and no scheduling|

Every mapped conclusion is bounded by the residual column. Implementation, empirical testing, deterministic modelling and assumed properties are separate statuses. SR3 and SR6 are especially conditional and accepting authenticated plaintext is not a proof of confidentiality, and no receiver action repairs an already reused GCM nonce. SR12 is an explicit caller procedure and SR15 characterises impairment, it does not promise availability under jamming.
