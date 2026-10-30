# LoRaWAN and Satellite Communication Security for Satellite IoT Networks 

## SatIoT Security Research:

This research artefact accompanies the dissertation and provides the P1 implementation, experimental evidence and reproduction workflow. P1 is an application-security profile designed to protect application traffic across an untrusted forwarding path. This study examines protocol correctness, session-state continuity, lifecycle enforcement and satellite-aware communication trade-offs.

The prototype operates in memory within a single-threaded Python environment. Satellite connectivity and LoRa communication costs are represented through explicitly configured simulations and analytical models. The resulting evidence supports conclusions within these assumptions; it does not establish physical satellite integration or LoRaWAN interoperability.

## Evidence and reproduction:

`src/core.py` is the authoritative implementation of P1. The `results/reference/` directory contains the recorded experimental observations, derived tables and figures, verification logs and a reproduction manifest. The manifest identifies the source, dependencies, execution environment and configuration associated with the reference results, supporting traceability from implementation to reported findings.

The verified execution environment is Python 3.12 on Linux. To reproduce this study, create and activate a virtual environment, kindly install the complete dependency set specified in requirements-lock.txt:


```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python run.py --out runs/my-study
.venv/bin/python -m analysis.analyze --raw results/reference/raw --out runs/reference-analysis
```

Kindly select a new directory for every `run.py` invocation and existing directories are rejected. The runner configures imports and output paths, executes the tests, runs eight drivers, performs schema-checked analysis, and records its source identity and raw-file hashes. Dependencies are installed from the package index; wheels are not bundled. See `docs/REPRODUCTION.md`.

## Research Areas:

| Area | Evidence |
|---|---|
| Protocol correctness and security assurance | Functional establishment, seven adversarial procedures with legitimate controls, strict wire validation, context-substitution and join-response tests |
| Session state and lifecycle | Replay/reordering, lower boundaries, authentication-before-commit, duplicate installation, pending cancellation, negative-control rollback, explicit fresh recovery, local retirement and scoped revocation |
| Communication trade-offs | Representation, arithmetic packetisation, deterministic LoRa airtime, seeded independent object-loss simulation, completion-gated contact cases and a separate frame-loss/airtime sensitivity analysis |

For six-byte ASCII device identifiers the representations are JOIN_INIT **44 B**, JOIN_ACCEPT **64 B**, establishment **108 B**, and application overhead **44 B**. Sizes are application-security representations; lower-layer framing and fragmentation costs are separate. Longer identifiers increase each representation by the identifier-length difference.

## Scope and Security Contracts:

- HMAC-SHA256/128 authenticates the exchange under a provisioned 32-byte root; HKDF-SHA256 derives AES-256-GCM traffic keys and a four-byte nonce prefix.
- Sequence continuity is required under each key. Uncertain state requires explicit invalidation and fresh establishment before sending. Receiver rejection cannot repair GCM nonce reuse.
- Reinstalling identical material preserves the existing replay window; conflicting installation is rejected. New sessions coexist unless `retire_previous=True` explicitly retires the same device's prior contexts at the same AS.
- KMS revocation blocks new establishment. Installed AS sessions survive until an explicit AS revocation/retirement operation. No distributed immediate revocation is claimed.
- Invalidating the device cancels its pending establishment and active local context. The backend does not receive a cancellation message.
- The KMS does not cache request nonces: authenticated captured join requests can be processed again. No requester-liveness, forward-secrecy, durable state or denial-of-service guarantee follows.
- Wire encode/decode is tested, but experiment drivers exchange objects. No over-the-air fragmentation/reassembly, Class A receive-window scheduler or backend secure channel is implemented.

The protocol and assumptions are specified in `docs/PROTOCOL.md` and `docs/ASSUMPTIONS.md`; methodology and exact configurations are in `docs/METHODOLOGY.md` and `config/experiments.json`; the bounded claim chain is in `docs/EVIDENCE_MATRIX.md`.

## Structure:

- `src/`: P1 protocol and communication-model utilities.
- `tests/`: automated positive, negative and invariant checks.
- `experiments/`: eight retained drivers; all settings are read from `config/experiments.json`.
- `analysis/`: strict schemas, count summaries, Wilson simulation intervals, descriptive quantiles, deterministic effects and figures.
- `results/reference/`: final-source evidence, including observation-level CSVs and run manifest.
- `docs/`: protocol, threat/evidence mapping, methodology, limitations and reproduction.
