# Threat model, assumptions and residual risks:

The primary abstract topology is ED → untrusted forwarding/relay path → trusted application service, with a trusted KMS and root provisioning/key-distribution path. Satellite transport is represented by loss, traversal delay and intermittent availability. The abstraction does not select an operational direct-to-satellite LoRaWAN radio design; mapping to Class A downlinks and regional settings remains a deployment task.

Threat labels used in this artefact are T1 request/response impersonation or manipulation, T2 protected-message modification/context substitution, T3 replay/reordering, T4 stale/rolled-back endpoint state, T5 retained or revoked session context, and T6 disruption/intermittency. These labels are local evidence-navigation labels, not asserted copies of an unseen dissertation threat catalogue.

The adversary can observe, inject, mutate, reorder and replay forwarded objects. Trusted-endpoint compromise, root disclosure and malicious administrative code are outside the protection claim. Environmental loss/jitter/contact closure are simulated impairments, not all attacker actions. Counter rollback is injected as a failure case rather than assumed detectable by P1.

The endpoints, process memory, cryptographic library and OS random source are trusted. Backend key transfer, root provisioning and caller-controlled recovery are assumed secure. Python provides no verified key zeroisation. Cryptographic strength is inherited conditionally from library primitives; empirical rejection counts are not proofs, and the study does not estimate arbitrary adversarial success probability.

| Residual issue | Consequence and scope |
|---|---|
| No durable state or rollback detection | The sender must invalidate and freshly establish before transmitting when continuity is uncertain. Unsafe resume can leak plaintext XOR despite replay rejection. |
| Captured JOIN_INIT accepted again | Request authentication does not establish fresh requester liveness; processing/resource exhaustion remains possible. |
| No forward secrecy | Root compromise can expose past traffic from recorded establishment transcripts. |
| Revocation/retirement are local | KMS authorisation and AS active contexts require explicit separate administration; other servers are unaffected. |
| In-memory SID history and replay windows | Collision protection/replay continuity do not survive a process reset; resource growth is not production bounded. |
| Local orchestration, no transactions | Partial installation and backend transport protection are outside implemented assurance. |
| Single-threaded processing | Concurrent sequence allocation or check/commit could race; concurrency is unsupported. |
| Uplink-only protected messages | No protected application downlink, key-confirmation acknowledgement or operational LoRaWAN scheduler. |
| No radio/embedded/formal validation | Timing, energy, physical feasibility and formal authentication/secrecy claims are not established. |
