# Experimental Methodology:

All principal evidence is from `results/reference/raw/`, executed against the source identity in that run's manifest.

| Driver | Unit, configuration and control | Evidence type and interpretation |
|---|---|---|
| adversarial | 200 runs/class; seven fixed classes; legitimate-object control after mutation, or before duplicate replay | 1,400 observation-level implementation trials; no arbitrary attack probability CI |
| replay | Four windows; delivery 0,1,3,2,4,2 | 24 deterministic deliveries; last delivery is a duplicate; explicit delivery index drives analysis |
| rollback | 100/mode; sequences 0–4 then injected restore to 2, or explicit invalidation/fresh establishment at same AS | 200 trials; key/nonce reuse recorded explicitly; unsafe mode is a negative control |
| lifecycle | 200 fresh independent local setups; functional joins, duplicate installation, pending cancellation, local retirement, scoped revocation | 200 rows with separately recorded properties; no host timing claim |
| airtime | 5 payloads × 3 capacities × 3 SFs × P0/P1 | 90 deterministic model rows; P0 is only an unprotected overhead baseline |
| network | 500/profile; ideal 21/0/0, moderate 21/±5/.05, degraded 21/±15/.15 (ms/ms/loss); seed=run+7 | 1,500 seeded independent object-traversal simulations; observed crypto path acceptance, virtual delay |
| contact | 3 periodic patterns, base offsets plus closure boundaries; 10-ms traversal; no loss/jitter | 32 unique deterministic cases, one per configuration; completion must stay in one continuous available interval |
| integrated | 3 capacities × 3 SFs × 3 metadata lengths × 5 payloads × 3 frame-loss rates | 405 analytical sensitivity rows; frame-loss theory and serial airtime budget, no sampled channel observations |

Automated tests supply targeted join-response tamper/cancellation, existing-context substitution, replay boundary, authentication-before-commit, malformed-input, counter-exhaustion, SID collision, parser and HKDF checks. They complement rather than replace observation-level driver results. The test runner's XML/log supplies actual counts.

## Radio representation assumptions:

For airtime use bandwidth 125 kHz, coding rate index 1 (=4/5), preamble 8 symbols, explicit header, PHY CRC on, and LDRO on for SF≥11 at this bandwidth. Symbol duration=2^SF/BW. Preamble duration=(8+4.25) symbols. Payload symbols=8+max(ceil((8PL−4SF+28+16CRC−20IH)/(4(SF−2DE)))×(CR+4),0). Airtime is their sum times symbol duration. The implementation follows the conventional Semtech modem equation; computational consistency is not physical validation.

Each arithmetic chunk adds 13 B minimum LoRaWAN PHYPayload overhead, assuming no FOpts and a present FPort. Capacity/SF combinations are sensitivity scenarios, not an approved regional configuration matrix. The base model excludes fragment metadata, retries, reassembly, scheduling, receive activity and regulatory waiting. The integrated model varies assumed fragment metadata 0/2/4 B inside capacity, separately from 13 B framing; it does not implement any particular fragmentation protocol.

For integrated analysis the three representations are 44 B, 64 B and p+44 B. All are serially chunked under the same symmetric radio assumptions. Independent frame-loss completion without retries is (1−loss)^N. Budget=summed frame airtime+3×21 ms. This constructed duration excludes receive-window timing, processing and other waits. Object-loss simulation uses (1−loss)^2 for establishment and (1−loss)^3 for establishment plus one application traversal; the two probability models have different units and must not be conflated.

Contact starts require phase<available duration. A traversal ending exactly at closure is permitted; a traversal starting at closure is rejected. Two 10-ms traversals require sufficient residual availability, not merely an available starting instant. This contact test is distinct from the airtime sensitivity model; it is not a radio contact-feasibility result.

## Analysis and statistics:

Strict schemas reject unknown Booleans, duplicate/missing trial keys, invalid counts, nonfinite/negative numeric fields, inconsistent network outcomes, and inconsistent configured identities. Data are sorted by explicit keys; replay selection uses delivery indices and is independent of CSV row order. No generic statistics over configuration, identifiers, medians or heterogeneous aggregate rows are emitted.

Wilson 90/95/99% intervals apply only to per-profile simulated Bernoulli outcomes. Across profiles, seeds overlap and branch-dependent PRNG consumption differs; no unpaired causal loss/jitter inference is made. Simulated establishment quantiles (median, Q1, Q3, p95, type-7 interpolation) condition on successful joins and exclude cryptographic processing and failed-attempt timeouts. Empty subsets produce unavailable values, not NaN. Descriptive rate differences from ideal and deterministic airtime differences/ratios are reported. Fixed mutation counts, deterministic contact repeats and lifecycle checks are not assigned general security probabilities or artificial inferential significance.
