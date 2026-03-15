# SentinelWeave — AI-Powered Cybersecurity Threat Detection with Post-Quantum Secure Reporting

> **Project concept for a cybersecurity major** with minors in AI automation (Microsoft Azure) and Python development.

---

## 🎯 Why This Project?

SentinelWeave bridges your three areas of study into a single, production-inspired platform:

| Study Area | How It's Used |
|---|---|
| **Cybersecurity** | Attack-signature detection, anomaly scoring, threat classification, IOC extraction |
| **AI Automation (Azure)** | Azure ML inference endpoint, Azure Cognitive Services Text Analytics, Azure Monitor telemetry |
| **Python Development** | Modular package design, CLI tooling, statistical ML, async-ready architecture |

It also directly extends the **QuantaWeave** post-quantum cryptography library already in this repository, giving you hands-on experience with PQ primitives in a real-world context.

---

## 🔬 Architecture Overview

```
Raw Security Logs / Events
         │
         ▼
┌──────────────────────┐
│   EventAnalyzer      │  Regex-based parsing, IP extraction, timestamp parsing,
│   (event_analyzer.py)│  13-feature vector extraction, attack-signature matching
└──────────┬───────────┘
           │ SecurityEvent
           ▼
┌──────────────────────┐
│   ThreatDetector     │  Welford online baseline, z-score anomaly detection,
│   (threat_detector.py)│  composite threat scoring, optional Azure ML endpoint
└──────────┬───────────┘
           │ ThreatReport
           ▼
┌──────────────────────┐
│   SecureReporter     │  Hybrid encryption: QuantaWeave (PQ, LWE) wraps an
│   (secure_reporter.py)│  AES-256 session key → AES-GCM encrypts the report
└──────────┬───────────┘
           │ Encrypted blob
           ▼
┌──────────────────────┐
│   Azure Integration  │  Blob Storage (report persistence), Cognitive Services
│   (azure_integration.py)│  (NLP on log messages), Monitor (telemetry)
└──────────────────────┘
```

### Hybrid Post-Quantum Encryption (Why & How)

```
Session Key (32 bytes, random)
        │
        ├──► QuantaWeave LWE encrypt ──► PQ Ciphertext  ─┐
        │     (post-quantum KEM)                          │
        │                                               stored together
        └──► AES-256-GCM encrypt ──► AES Ciphertext    ─┘
              (symmetric, fast)
```

**Why hybrid?** The QuantaWeave LWE KEM is limited to 32-byte payloads (by design — it encodes bits as polynomial coefficients). Wrapping a symmetric key is the canonical use of any KEM, mirroring TLS 1.3 and standard lattice KEM designs. This protects against "harvest now, decrypt later" attacks on long-lived threat intelligence.

---

## 📦 Module Reference

### `sentinel_weave.event_analyzer`

| Class / Function | Purpose |
|---|---|
| `EventAnalyzer` | Parse log lines into `SecurityEvent` objects |
| `EventAnalyzer.parse(line)` | Single-line parser |
| `EventAnalyzer.parse_bulk(lines)` | Batch parse |
| `analyze_log_file(path)` | Convenience wrapper for log files |
| `SecurityEvent` | Dataclass: raw text, IP, timestamp, type, severity, features, signatures |

**Attack signatures detected:**

| Signature | Pattern |
|---|---|
| `SSH_BRUTE_FORCE` | "Failed password for … from …" |
| `SQL_INJECTION` | UNION SELECT, DROP TABLE, `'1=1`, etc. |
| `XSS_ATTEMPT` | `<script>`, `javascript:`, `onerror=` |
| `PATH_TRAVERSAL` | `../`, `..\`, `%2e%2e` |
| `COMMAND_INJECTION` | Shell metacharacters before system commands |
| `PRIVILEGE_ESCALATION` | sudo, chmod 777, setuid |
| `DDoS_INDICATOR` | flood, amplification keywords |
| `MALWARE_INDICATOR` | ransomware, rootkit, C2, keylogger |
| `CREDENTIAL_DUMP` | mimikatz, lsass, pass-the-hash |
| `PORT_SCAN` | nmap, masscan, SYN flood |

---

### `sentinel_weave.threat_detector`

| Class / Function | Purpose |
|---|---|
| `ThreatDetector` | Core detection engine |
| `ThreatDetector.update_baseline(event)` | Feed benign events to build the traffic baseline |
| `ThreatDetector.analyze(event)` | Score a single event → `ThreatReport` |
| `ThreatDetector.analyze_bulk(events)` | Batch analysis |
| `ThreatDetector.top_threats(reports, n)` | Return the *n* highest-scored reports |
| `FeatureBaseline` | Welford online mean/std tracker (O(1) memory) |
| `summarize_reports(reports)` | Aggregate statistics over a batch |
| `ThreatLevel` | Enum: BENIGN / LOW / MEDIUM / HIGH / CRITICAL |
| `ThreatReport` | Dataclass: level, anomaly score, z-scores, explanation |

**Composite score formula** (no Azure ML):

```
score = 0.45 × signature_score  +  0.30 × keyword_severity  +  0.25 × z_score_anomaly
```

**Azure ML** (when configured via env vars):

```
score = 0.40 × sig  +  0.25 × kw  +  0.25 × z  +  0.10 × azure_model_score
```

---

### `sentinel_weave.azure_integration`

| Class | Azure Service | Offline Fallback |
|---|---|---|
| `BlobStorageClient` | Azure Blob Storage | `~/.sentinelweave/blobs/` |
| `TextAnalyticsClient` | Cognitive Services Text Analytics | Keyword-based NLP |
| `SecurityTelemetry` | Azure Monitor / App Insights | `~/.sentinelweave/telemetry.jsonl` |

**Environment variables:**

| Variable | Service |
|---|---|
| `AZURE_STORAGE_CONNECTION_STRING` | Blob Storage connection string |
| `AZURE_TEXT_ANALYTICS_ENDPOINT` | Text Analytics resource endpoint |
| `AZURE_TEXT_ANALYTICS_KEY` | Text Analytics API key |
| `AZURE_APPINSIGHTS_CONNECTION_STRING` | Application Insights connection string |
| `SENTINELWEAVE_AZURE_ENDPOINT` | Azure ML real-time inference endpoint |
| `SENTINELWEAVE_AZURE_API_KEY` | Azure ML endpoint API key |

---

### `sentinel_weave.secure_reporter`

| Class / Function | Purpose |
|---|---|
| `SecureReporter` | Hybrid PQ + AES-GCM report encryption |
| `SecureReporter.generate_keys()` | Generate QuantaWeave PQ key pair |
| `SecureReporter.create_and_store(title, events, pub_key)` | Encrypt and store report |
| `SecureReporter.retrieve_and_decrypt(report_id, priv_key)` | Retrieve and decrypt |
| `SecureReporter.list_reports()` | List stored report IDs |

---

## 🚀 Quick Start

### Run the interactive demo (no credentials needed)

```bash
python -m sentinel_weave demo
```

### Analyse a log file

```bash
python -m sentinel_weave analyze /var/log/auth.log --verbose
```

### Generate an encrypted threat report

```bash
python -m sentinel_weave report /var/log/auth.log --title "Weekly Auth Audit"
# Output:
# ✔ Encrypted report stored: report-20240115-123456-weekly-auth-audit-abc12345.bin
#   Private key saved to:    report-20240115-123456-weekly-auth-audit-abc12345.key.json
```

### Decrypt a stored report

```bash
python -m sentinel_weave decrypt report-20240115-123456-weekly-auth-audit-abc12345.bin
```

### Use the Python API

```python
from sentinel_weave import EventAnalyzer, ThreatDetector, summarize_reports

analyzer = EventAnalyzer()
detector = ThreatDetector()

# Warm the baseline with benign events
for line in open("/var/log/syslog"):
    detector.update_baseline(analyzer.parse(line))

# Detect threats in auth.log
events  = analyzer.parse_bulk(open("/var/log/auth.log").readlines())
reports = detector.analyze_bulk(events)
summary = summarize_reports(reports)

print(f"HIGH threats: {summary['by_level']['HIGH']}")
print(f"Top IPs:      {summary['unique_ips']}")
```

---

## 🔌 Azure Integration (Optional)

### Connect to Azure Blob Storage

```bash
export AZURE_STORAGE_CONNECTION_STRING="DefaultEndpointsProtocol=https;AccountName=...;..."
```

```bash
pip install azure-storage-blob
```

### Connect to Azure Cognitive Services Text Analytics

```bash
export AZURE_TEXT_ANALYTICS_ENDPOINT="https://myresource.cognitiveservices.azure.com/"
export AZURE_TEXT_ANALYTICS_KEY="<your-key>"
```

```bash
pip install azure-ai-textanalytics
```

### Connect to Azure ML for Model-Backed Scoring

```bash
export SENTINELWEAVE_AZURE_ENDPOINT="https://my-ml-endpoint.azureml.net/score"
export SENTINELWEAVE_AZURE_API_KEY="<your-key>"
```

Your Azure ML endpoint should accept:
```json
{"input": [[f1, f2, ..., f13]]}
```
and return:
```json
{"score": 0.87}
```

---

## 🎓 Learning Outcomes

Working on this project will help you develop skills in:

### Cybersecurity
- Log analysis and forensic event parsing
- Attack-signature development and regex crafting
- Statistical anomaly detection (z-score, Welford's algorithm)
- Threat scoring and classification systems
- IOC (Indicator of Compromise) extraction
- Post-quantum cryptography in real-world key-encapsulation scenarios
- Hybrid encryption (PQ-KEM + AES-GCM) — mirrors TLS 1.3 design

### AI & Azure Automation
- Designing feature vectors for security ML models
- Integrating Azure ML real-time inference endpoints
- Azure Cognitive Services (NLP, entity recognition, PII detection)
- Azure Monitor structured telemetry
- Azure Blob Storage as a data lake for encrypted intelligence
- Offline-safe SDK wrappers and graceful degradation patterns

### Python Development
- Modular package design with clean public APIs
- Dataclasses, Enums, and type annotations
- Online statistical algorithms (Welford's) without NumPy
- Lazy imports and optional dependency management
- argparse CLI with sub-commands
- Comprehensive unit testing (69 tests)

---

## 🗺️ Extension Ideas

Once comfortable with the core, here are directions to take this further:

1. **Real-time stream processing** — Integrate with `asyncio` and tail `/var/log/auth.log` live
2. **Azure Event Hubs ingest** — Replace file-based input with streaming telemetry
3. **ML model training pipeline** — Export labelled events to Azure ML and train a proper classifier
4. **Dashboard** — Build a web dashboard (Flask + Chart.js) showing live threat metrics
5. **SIEM integration** — Export findings in CEF/LEEF format for SIEM tools
6. **Threat hunting queries** — Add a query language for searching stored reports
7. **Kubernetes deployment** — Containerise and deploy to AKS with Helm charts
8. **Federated threat intel** — Peer-to-peer sharing of encrypted threat summaries between nodes

---

## 📁 File Structure

```
sentinel_weave/
├── __init__.py          # Public package API
├── __main__.py          # python -m sentinel_weave entry point
├── event_analyzer.py    # Log parsing, feature extraction, signature detection
├── threat_detector.py   # Anomaly detection, threat scoring, report generation
├── azure_integration.py # Azure Blob, Text Analytics, Monitor wrappers
├── secure_reporter.py   # Hybrid PQ + AES-GCM report encryption
└── cli.py               # Command-line interface (analyze / report / decrypt / demo)

tests/
└── test_sentinel_weave.py  # 69 unit tests
```

---

*Built on top of [QuantaWeave](https://github.com/oliver-breen/New-Algorithm-for-Post-Quantum-Cryptography) — a lattice-based post-quantum cryptography suite.*
