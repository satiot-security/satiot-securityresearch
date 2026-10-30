# Reproduction instructions

For Reproduction, kindly preserve `results/reference/` as supplied and regenerate into a new directory and do not overwrite observations. Linux/Python 3.12 and the full locked dependency closure are the tested baseline. Other environments are unverified. This project has no data/service credentials and needs no external accounts at runtime. Package installation requires access to a package index and offline wheels are not included.

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements-lock.txt
.venv/bin/python -m pytest -q -p no:cacheprovider
.venv/bin/python run.py --out runs/reproduction
.venv/bin/python -m analysis.analyze --raw results/reference/raw --out runs/analysis-only
.venv/bin/python -m analysis.analyze --raw results/reference/raw --out runs/analysis-90 --confidence .90
.venv/bin/python -m analysis.analyze --raw results/reference/raw --out runs/analysis-99 --confidence .99
```

Here, the runner refuses an existing output directory and configures project imports and a raw output directory, executes the complete security/statistics tests, runs all eight configured drivers, and writes run provenance even when a step fails. Individual drivers can be invoked as modules from the project root with `SATIOT_RAW_DIR` pointing to an existing directory. Full runner invocation is the preferred interface.

Expected reference evidence: 1,400 adversarial rows, 24 replay rows, 200 rollback rows, 200 lifecycle rows, 90 airtime rows, 1,500 network rows, 32 contact cases and 405 analytical rows. There are eight derived CSV tables, summary JSON, results Markdown, and three PNG/PDF figure pairs.

Expected behaviours: Here, all legitimate adversarial controls accepted and fixed attack/duplicate attempts rejected; strict replay accepts 4/5 first deliveries and windows 8/32/64 accept 5/5, each rejecting the repeated delivery; unsafe rollback repeats a key/nonce pair and is rejected after encryption; explicit recovery changes key and admits the new message; local retirement rejects old context at the same AS; KMS revocation blocks new joins while active AS context survives, and contact simulation matches its specified completion-gating theory.

Random cryptographic secrets are intentionally OS-generated and not retained as key dumps. Seeds control impairment only. Fresh SIDs and keys may vary across runs; the recorded behavioural outcomes and seeded/model outputs are the expected comparison, not secret-material equality. No host-performance timings are claimed. Record deviations in a separate run manifest/report and retaining the failed observations.

`run_manifest.json` contains a canonical SHA-256 source/config/test/dependency identity, exact configuration, command sequence, environment and raw hashes. Top-level `SHA256SUMS.txt` covers stable packaged files and excludes itself. Verify with `sha256sum -c SHA256SUMS.txt` from the root. Hash agreement checks identity and not scientific correctness.
