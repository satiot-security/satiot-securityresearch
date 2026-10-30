# Focused P1 evidence results

Every raw file in this run is a new execution of the identified source. Supplied observations are excluded from this analysis. Eight drivers span protocol assurance, lifecycle state and communication trade-offs. No host join timing or encryption/decryption timing claim is made.

Attack counts describe seven fixed mutation procedures, not arbitrary attacker probabilities. No confidence intervals are inferred from these repetitions. Replay and contact cases are deterministic, with no inferential intervals. Unsafe rollback is a negative control: rejection does not prevent prior GCM nonce reuse.

Network intervals are Wilson intervals across per-profile seeded Bernoulli object simulations. Profiles jointly change loss and jitter. Seeds overlap across profiles but branch-dependent consumption precludes simple matched delay comparisons. Quantiles use linear interpolation (type 7), conditional on successful joins. Processing, failed-workflow timeouts, airtime, retries and scheduling are excluded. Rate differences from ideal are descriptive effects, not isolated causal estimates.

P0 is an unprotected size baseline. Airtime effects are deterministic, not measured physical or energy costs. Integrated completion probability is analytical independent frame loss without retries. Serialization budget adds summed airtime to three assumed 21-ms traversals; it assumes serial transmission, symmetric radio parameters, no extra waits and no processing. This is no orbital or LoRaWAN feasibility threshold.

Explicit AS retirement is local. Active contexts survive KMS revocation until explicitly removed at the AS. Captured authenticated join requests remain processable. Forward secrecy, durable anti-rollback state and concurrency safety are not claimed.

See CSV tables, summary.json, run_manifest.json and verification/tests.xml for exact observations and provenance.
