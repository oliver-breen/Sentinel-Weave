# Change Summary (2026-03-17)

## Security and access control
- Access Control now validates subjects against an authoritative directory and denies role spoofing.
- GUI Access Control tab locks role selection to the subject profile and displays the department.
- Dashboard red-team and federated endpoints are gated by an optional API key via `SENTINELWEAVE_API_KEY` or `SENTINELWEAVE_DASHBOARD_API_KEY`.

## Safe serialization (pickle removal)
- Added safe JSON + base64 serializer in `quantaweave/safe_serialize.py`.
- Replaced all project `pickle` usage with safe serialization in:
  - `quantaweave/pq_schemes.py`
  - `quantaweave/woven_algorithm.py`
  - `quantaweave/lattice_sig_core.py`
  - `examples/azure_pqc_integration.py`
  - `tests/test_azure_integration.py`
- `SklearnSecurityClassifier` JSON export now stores configuration only (no model weights). Re-train after load.

## GUI and dashboard visuals
- Updated GUI palette and button styling for a more robust, grounded look without bright hover effects.
- Set default GUI font to Bahnschrift for a sturdier visual tone.
- Added a full dashboard HTML/JS front-end with a grounded visual theme.

## Dependency updates
- Added `capstone>=4.0` to dev requirements.
- Added `click>=8.1` to both runtime and dev requirements for Flask CLI compatibility.

## Tests
## Azure integration rebuild
- Rebuilt Azure integration around DefaultAzureCredential with explicit config schema.
- Added Key Vault, Service Bus, and Event Hubs wrappers with offline fallback.
- Added Azure config validation and documented new environment variables.
- Updated sklearn serialization tests to reflect safe, non-pickled behavior.
- Shellcode and BinaryFuzzer tests are skipped when optional dependencies (capstone/pwntools) are not installed.

## Files changed
- `sentinel_weave/event_analyzer.py`
- `sentinel_weave/gui/sentinel_weave_gui.py`
- `sentinel_weave/access_controller.py`
- `sentinel_weave/dashboard/app.py`
- `sentinel_weave/dashboard/templates/index.html`
- `sentinel_weave/dashboard/static/js/dashboard.js`
- `quantaweave/safe_serialize.py`
- `quantaweave/pq_schemes.py`
- `quantaweave/woven_algorithm.py`
- `quantaweave/lattice_sig_core.py`
- `examples/azure_pqc_integration.py`
- `sentinel_weave/ml_pipeline.py`
- `tests/test_azure_integration.py`
- `sentinel_weave/Tests/test_enhanced_core.py`
- `requirements.txt`
- `requirements-dev.txt`

## Notes
- Red-team endpoints remain available locally; set an API key to require auth.
- Sklearn classifier JSON exports no longer contain model weights by design.
