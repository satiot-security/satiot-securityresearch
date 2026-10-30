# P1 Implemented application-security protocol and lifecycle contract:

## Provisioning and derivation:

The device and KMS share a 32-byte secret root and a uint32 provisioning epoch. IDs are nonempty ASCII, 1–255 bytes. All integers are unsigned big-endian. Version is 1, uplink direction is 0, join nonces are 16 bytes, SID and sequence are uint64, and tags are 16 bytes.

The join key is HKDF-SHA256(root, info=`SATIOT|JOIN|` || DID), with default zero salt. Session master material uses info=`SATIOT|SESSION|` || DID || SID and salt=ND || NS. Uplink key and four-byte prefix use the master as input with info=`SATIOT|UP|` || DID || SID and `SATIOT|NONCE|` || DID || SID respectively. The root is not replaced by fresh establishment. Disclosure of the root allows retrospective derivation from captured transcripts; forward secrecy is absent.

## Representation:

| Object | Ordered fields | Total for DID length d |
|---|---|---|
| JOIN_INIT | version 1, DID length 1, DID d, epoch 4, ND 16, HMAC tag 16 | 38+d |
| JOIN_ACCEPT | version 1, DID length 1, DID d, SID 8, ND 16, NS 16, HMAC tag 16 | 58+d |
| Protected application object | AAD header: version 1, DID length 1, DID d, SID 8, sequence 8, direction 1, type 1; ciphertext length 2; ciphertext p; GCM tag 16 | p+38+d |

At d=6: JOIN_INIT=44 B, JOIN_ACCEPT=64 B, establishment=108 B, AAD=26 B, and application overhead=44 B. HMAC authenticates the unsigned join representation. AES-256-GCM encrypts the payload and authenticates the 26-byte header. Nonce=prefix(4)||sequence(8). Ciphertext length is a parser field outside AAD; the decoder enforces exact total length and rejects trailing bytes, bad version/direction, invalid ID and truncated representations. Authenticated decryption covers the ciphertext/tag. Caller-supplied `kind` selects the decoder; the transport must supply message discrimination. There is no radio parser or protocol-negotiation mechanism.

## State and ordering:

`join_init()` creates one outstanding ND, replacing any older pending request; it does not itself invalidate a prior active session. `accept()` validates structure, matching DID and outstanding ND, then HMAC; only success installs device material and resets sequence. Replayed or delayed responses without a matching outstanding request are rejected. The KMS authenticates format, registration, authorisation, epoch and HMAC before issuing a SID. Its in-memory issued-SID set detects same-device collisions, retrying up to 16 draws. It is not durable and grows without a production retention policy. There is no request-nonce replay cache or backend confirmation of response receipt.

`protect()` rejects invalid payload/type, missing session and counter exhaustion. It increments sequence after successful encryption. Uncertain continuity must be handled by the caller before encryption; no rollback detector or persistent secure store exists. Direct counter assignments in the rollback experiment deliberately violate this contract and are fault injection, not recovery.

AS receive: validate fields → look up context → check replay eligibility → authenticate/decrypt → commit replay state. Failed authentication and malformed objects do not advance freshness state. Strict mode accepts only sequences above the highest authenticated one. Window W accepts an unseen sequence s iff s>highest−W; boundary equality is rejected. Installation is idempotent for identical keys and rejects conflicting keys under an existing DID/SID. Replay state remains in memory and is lost on process restart.

`invalidate()` clears active device material, sequence and pending ND. `establish(..., retire_previous=True)` explicitly retires prior contexts only at the AS object passed to it, after installation/acceptance. Default establishment permits coexistence. `revoke_session()` and `retire_device_sessions()` are explicit local administrative operations. KMS revocation blocks new joins only. Existing contexts at another AS are unaffected.

## Orchestration and failure boundaries:

`establish()` is a trusted local helper, not a third protocol message or distributed transaction. It installs backend keys after response delivery and coordinates device acceptance through local calls. A dropped response leaves prior active contexts intact; an already-issued SID remains recorded at the KMS. Failure between AS installation and device acceptance can leave an orphan backend context. There is no distributed acknowledgement, crash-atomic commit, authenticated backend transport or persistent restoration. Endpoints, callers, root provisioning and backend key distribution are trusted assumptions. Execution is single-threaded and no locking or concurrent-use guarantee is supplied.
