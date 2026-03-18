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
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# Linux/macOS
# source .venv/bin/activate
pip install -r requirements.txt

# Run the interactive demo
python -m sentinel_weave demo

# Run demo with all bundled dummy logs
python -m sentinel_weave demo --fixtures

# Analyze a log file
python -m sentinel_weave analyze /var/log/auth.log --verbose

# Threat-hunting DSL query
python -m sentinel_weave hunt sentinel_weave/Examples/dummy_logs/11_weekly_soc_mixed_840.log level:HIGH src:203.0.113.* sig:SSH_BRUTE_FORCE
```

### Demo Dataset (Weekly SOC Simulation)

The repository includes synthetic SOC logs for realistic testing:

- `sentinel_weave/Examples/dummy_logs/11_weekly_soc_mixed_840.log`

Use it directly with the analyzer:

```bash
python -m sentinel_weave analyze sentinel_weave/Examples/dummy_logs/11_weekly_soc_mixed_840.log --verbose
```

In the GUI, run **Log Analyzer → Analyze**, then open **Threat Detection** and use
the threat hunt DSL box (e.g. `level:HIGH src:192.168.* sig:SSH_BRUTE_FORCE`).

### Web Dashboard

```bash
python -m dashboard
# Then open http://127.0.0.1:5000
```

For the rebuilt React dashboard:

```bash
cd sentinel_weave/dashboard_web
npm install
npm run dev
# Then open http://127.0.0.1:5173
```

### Desktop GUI

```bash
pip install PyQt6
python gui/sentinel_weave_gui.py
```

## Architecture (High-Level)

```
Raw Logs
  -> EventAnalyzer
  -> ThreatDetector
  -> ThreatReport
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

SentinelWeave runs fully offline by default. Azure features activate only when
the related settings are present.

Authentication preference:
- Primary: `DefaultAzureCredential` (recommended)
- Fallback: connection strings / API keys

### Storage (Encrypted report persistence)
- `AZURE_STORAGE_ACCOUNT_URL`
- `AZURE_STORAGE_CONTAINER`
- `AZURE_STORAGE_CONNECTION_STRING` (fallback)

### Text Analytics (NLP enrichment)
- `AZURE_TEXT_ANALYTICS_ENDPOINT`
- `AZURE_TEXT_ANALYTICS_KEY`

### Application Insights (Telemetry)
- `AZURE_APPINSIGHTS_CONNECTION_STRING`

### Cosmos DB (Report storage/indexing)
- `AZURE_COSMOS_ENDPOINT`
- `AZURE_COSMOS_DATABASE`
- `AZURE_COSMOS_CONTAINER`
- `AZURE_COSMOS_PARTITION_KEY`
- `AZURE_COSMOS_CONNECTION_STRING` (fallback)

### Service Bus
- `AZURE_SERVICEBUS_NAMESPACE`
- `AZURE_SERVICEBUS_QUEUE`
- `AZURE_SERVICEBUS_CONNECTION_STRING` (fallback)

### Event Hubs
- `AZURE_EVENTHUBS_NAMESPACE`
- `AZURE_EVENTHUB_NAME`
- `AZURE_EVENTHUBS_CONNECTION_STRING` (fallback)

### Key Vault
- `AZURE_KEYVAULT_URL`

### Azure ML Endpoint Scoring (optional)
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
- Kubernetes deployment assets (dashboard + worker, Helm chart, ACR CI workflow, devcontainer)

### Planned

1. Threat hunting query language
	- DSL like `level:HIGH src:192.168.* sig:SSH_BRUTE_FORCE`
	- CLI and GUI integration

2. Federated threat intelligence
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

## Kubernetes Deployment

### Containerized dashboard + worker

- Dashboard container: default `Dockerfile` command serves `python -m dashboard`
- Worker container command: `python -m sentinel_weave.worker`

### Helm chart

Chart path: `helm/sentinel-weave`

```bash
# Local render
helm template sentinel-weave ./helm/sentinel-weave

# Install
helm upgrade --install sentinel-weave ./helm/sentinel-weave \
  --set image.repository=<acr>.azurecr.io/sentinel-weave-dashboard \
  --set image.tag=<tag> \
  --set worker.image.repository=<acr>.azurecr.io/sentinel-weave-worker \
  --set worker.image.tag=<tag>
```

### CI pipeline to Azure Container Registry (ACR)

Workflow: `.github/workflows/k8s-acr.yml`

Required repository secrets:
- `ACR_LOGIN_SERVER` (example: `myregistry.azurecr.io`)
- `ACR_USERNAME`
- `ACR_PASSWORD`

The workflow builds/pushes dashboard and worker images, packages Helm, and pushes
the chart to ACR as an OCI artifact.

### Local k8s devcontainer

Use `.devcontainer/devcontainer.json` to get a Python + Docker-in-Docker +
kubectl + Helm + Azure CLI workspace.

```bash
# Inside devcontainer terminal
kind create cluster --name sentinel-weave
helm upgrade --install sentinel-weave ./helm/sentinel-weave
```

## Tests

```bash
pip install -r requirements-dev.txt
pytest
```

## License

See [LICENSE](LICENSE).
