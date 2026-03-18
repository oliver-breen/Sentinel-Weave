# SentinelWeave

SentinelWeave is an AI-powered cybersecurity threat detection platform with post-quantum secure reporting. It combines log parsing, anomaly detection, ML classification, and optional Azure integrations, then wraps sensitive reports using QuantaWeave (LWE + ML-KEM/ML-DSA + Falcon) with AES-GCM.

## Highlights

- Threat detection engine (z-score + signatures) with explainable scoring.
- ML pipeline (logistic regression + k-fold CV) with Azure ML export schema.
- CIA triad modules: RBAC, HMAC integrity chain, token-bucket availability.
- SIEM exporters: CEF (ArcSight) and LEEF (QRadar).
- Web dashboard (Flask + Chart.js) with live SSE updates.
- PyQt6 GUI with 8 tabs including Email Scanner and ML Pipeline.
- Azure integrations with offline-safe fallbacks.
- QuantaWeave PQC primitives with formal proof sketches.

## Quick Start

### Python CLI

```bash
python -m venv .venv
.
\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# Run the interactive demo
python -m sentinel_weave demo

# Analyze a log file
python -m sentinel_weave analyze /var/log/auth.log --verbose
```

### Web Dashboard

```bash
python -m dashboard
# Then open http://127.0.0.1:5000
```

### Desktop GUI

```bash
pip install PyQt6
python gui/sentinel_weave_gui.py
```

## Architecture (High-Level)

```
Raw Logs -> EventAnalyzer -> ThreatDetector -> ThreatReport
									-> SecureReporter -> QuantaWeave PQ + AES encrypted report
									-> SIEM Export (CEF / LEEF)
									-> Azure Integrations (optional)
```

## Key Modules

- `sentinel_weave.event_analyzer` — parse logs, extract 13-feature vectors, detect signatures.
- `sentinel_weave.threat_detector` — anomaly scoring, threat levels, explainability.
- `sentinel_weave.ml_pipeline` — train/evaluate classifier + Azure ML schema export.
- `sentinel_weave.secure_reporter` — hybrid PQ + AES-GCM encrypted reports.
- `sentinel_weave.siem_exporter` — CEF/LEEF exports and file output.
- `sentinel_weave.dashboard` — live web dashboard with SSE.
- `sentinel_weave.gui` — PyQt6 desktop GUI.

## Azure Integration (Optional)

Set the following environment variables to enable Azure services. When possible,
DefaultAzureCredential is used; connection strings/keys are optional fallbacks.

- `AZURE_STORAGE_CONNECTION_STRING`
- `AZURE_STORAGE_ACCOUNT_URL`
- `AZURE_STORAGE_CONTAINER`
- `AZURE_TEXT_ANALYTICS_ENDPOINT`
- `AZURE_TEXT_ANALYTICS_KEY`
- `AZURE_APPINSIGHTS_CONNECTION_STRING`
- `AZURE_COSMOS_CONNECTION_STRING`
- `AZURE_COSMOS_ENDPOINT`
- `AZURE_COSMOS_DATABASE`
- `AZURE_COSMOS_CONTAINER`
- `AZURE_COSMOS_PARTITION_KEY`
- `AZURE_KEYVAULT_URL`
- `AZURE_SERVICEBUS_CONNECTION_STRING`
- `AZURE_SERVICEBUS_NAMESPACE`
- `AZURE_SERVICEBUS_QUEUE`
- `AZURE_EVENTHUBS_CONNECTION_STRING`
- `AZURE_EVENTHUBS_NAMESPACE`
- `AZURE_EVENTHUB_NAME`
- `SENTINELWEAVE_AZURE_ENDPOINT`
- `SENTINELWEAVE_AZURE_API_KEY`
- `SENTINELWEAVE_AZURE_ML_USE_AAD`
- `SENTINELWEAVE_AZURE_ML_SCOPE`

## Roadmap

### Completed

- Core threat detection engine (z-score + signature matching)
- ML pipeline (logistic regression, k-fold cross-validation)
- Log analyzer (RFC-syslog + freetext parsing)
- CIA triad modules: RBAC, HMAC integrity chain, availability
- PyQt6 GUI (Dashboard, Log Analyzer, Threat Detection, ML Pipeline,
  Access Control, Integrity, Availability, Email Scanner)
- Email Scanner (single, batch, IMAP inbox)
- Azure integrations (Blob Storage, Text Analytics, Monitor telemetry)
- Web dashboard (Flask + Chart.js) with SSE live updates
- SIEM integration (CEF + LEEF) with file export

### Planned

1. Threat hunting query language
	- DSL like `level:HIGH src:192.168.* sig:SSH_BRUTE_FORCE`
	- CLI and GUI integration

2. Kubernetes deployment
	- Containerized dashboard and worker
	- Helm chart and CI pipeline to ACR
	- Local k8s devcontainer

3. Federated threat intelligence
	- PQ-encrypted summary exchange between peers
	- REST gossip protocol and dedup logic
	- CLI: `python -m sentinel_weave federate --peer https://node2.example.com`

For the full roadmap and legacy HQC build notes, see [sentinel_weave/TODO.md](sentinel_weave/TODO.md).

## Documentation

- Project overview: [sentinel_weave/SENTINEL_WEAVE.md](sentinel_weave/SENTINEL_WEAVE.md)
- GUI guide: [docs/GUI.md](docs/GUI.md)
- Algorithm notes: [docs/ALGORITHM.md](docs/ALGORITHM.md)
- Proof sketches: [docs/PROOFS.md](docs/PROOFS.md)
- Security: [SECURITY.md](SECURITY.md)

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## License

See [LICENSE](LICENSE).