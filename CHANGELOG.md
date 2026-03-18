# Changelog

## 0.1.1 - 2026-03-17

- Hardened access control with subject validation and UI role locking.
- Added API-key gating for red-team and federated dashboard endpoints.
- Replaced unsafe pickle usage with safe JSON+base64 serialization.
- Refreshed GUI and dashboard visuals for a more robust, grounded feel.
- Added `capstone` and `click` to requirements to support tests and Flask CLI.
- Rebuilt Azure integration with DefaultAzureCredential-first clients and config schema.
- Removed HQC from QuantaWeave and docs, switching to ML-KEM/ML-DSA + Falcon.
- Renamed ML-KEM/ML-DSA bridge to `mlkem_mldsa_bridge.py` with a deprecation stub.
- Updated hybrid examples/tests and benchmark baselines for Falcon sign/verify.
- Added dashboard import compatibility package and dev dependency install helpers.

## 0.1.0 - 2026-02-13

- Added HQC KEM implementation (HQC-1/3/5) with PKE/KEM flow.
- Added HQC KEM tests and example usage.
- Added benchmark tests with baseline tracking and nightly CI job.
- Added production hardening guidance and API notes.
