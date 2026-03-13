# SentinelWeave — Roadmap & TODO

## ✅ Completed Features
- Core threat detection engine (z-score + signature matching)
- ML pipeline (logistic-regression classifier, k-fold cross-validation)
- Log analyzer (RFC-syslog + freetext parsing, attack-signature detection)
- CIA-triad modules: RBAC, HMAC integrity chain, token-bucket availability
- PyQt6 GUI (8 tabs: Dashboard, Log Analyzer, Threat Detection, ML Pipeline,
  Access Control, Integrity Monitor, Availability, **Email Scanner**)
- Email Scanner — single, batch, and IMAP inbox modes with 9 threat detectors
- Azure integrations (Blob Storage, Text Analytics, Monitor telemetry)

## 🔄 Planned Features

### 4. Web Dashboard ✅ (implemented in `dashboard/`)
Build a Flask + Chart.js web dashboard showing **live threat metrics**:
- Real-time threat timeline (threats/minute)
- Threat-level distribution pie chart
- Top attacking IP table
- Email risk score histogram
- Server-Sent Events (SSE) for live push updates
- REST API endpoints (`/api/events`, `/api/summary`, `/api/stream`)

### 5. SIEM Integration ✅ (implemented in `sentinel_weave/siem_exporter.py`)
Export findings in **CEF** (ArcSight) and **LEEF** (IBM QRadar) format:
- `CefExporter` — full ArcSight Common Event Format strings
- `LeefExporter` — IBM QRadar Log Event Extended Format strings
- `SiemExporter` facade — unified `export_cef()` / `export_leef()` /
  `to_syslog()` / `to_file()` API
- Supports `ThreatReport`, `EmailScanResult`, and `AttackCampaign`

### 6. Threat Hunting Queries
Add a **query language** for searching stored threat reports:
- Simple DSL: `level:HIGH src:192.168.* sig:SSH_BRUTE_FORCE`
- Filter across `ThreatReport`, `EmailScanResult`, and `AttackCampaign` stores
- CLI integration: `python -m sentinel_weave query 'level:CRITICAL'`
- GUI integration: add query bar to the Dashboard tab

### 7. Kubernetes Deployment
**Containerise** and deploy to AKS with Helm charts:
- `Dockerfile` for the Flask dashboard and CLI worker
- `helm/sentinelweave/` chart with Deployment, Service, Ingress, HPA
- GitHub Actions CI pipeline that builds, tests, and pushes to ACR
- `.devcontainer/` for local Kubernetes-in-Docker development

### 8. Federated Threat Intelligence
**Peer-to-peer sharing** of encrypted threat summaries between nodes:
- QuantaWeave LWE-encrypted summary capsules
- Simple REST gossip protocol for node discovery and broadcast
- Merge/dedup logic for incoming intel from untrusted peers
- CLI: `python -m sentinel_weave federate --peer https://node2.example.com`

---

# Legacy Build Issues (vendor/hqc C code)


1. **Missing Header Files**
   - Files like `symmetric.h`, `parameters.h`, `reed_solomon.h`, `<cstdio.h>`, and `<stdint.h>` were not found.
   - **Resolution:**
     - Ensure these files are available in the correct include paths.
     - For `<cstdio.h>` and `<stdint.h>`, verify that the standard library dependencies are correctly installed in your build environment.
     - Other headers (e.g., `symmetric.h`, `parameters.h`) need to be available in your project or vendor directories. Update the include paths in your build configuration.

2. **Resource Leak**
   - Example from `vendor/hqc/packaging/utils/helpers/main_kat.c` line 49: "Resource leak: fp_req."
   - **Resolution:**
     - Ensure all opened resources (like file pointers) are properly closed before returning from the function (even in error conditions).

3. **Undefined or Implementation-Defined Behavior**
   - Shifting values by more bits than their size (e.g., Shifting 64-bit value by 65534 bits) is undefined behavior.
   - **Files affected:**
     - `vendor/hqc/src/ref/gf.c`
     - `vendor/hqc/src/x86_64/avx256/gf.c`
   - **Resolution:**
     - Verify the logic for calculating shift distances and ensure the shift values are within valid ranges (0 to the bit size minus 1).
   - Shifting signed 32-bit values by 31 bits was flagged as implementation-defined.
   - **Files affected:**
     - `vendor/hqc/src/ref/reed_solomon.c`
     - Equivalent headers in the avx256 directory.
   - **Resolution:**
     - Ensure inputs to shifts are unsigned or otherwise processed safely.

4. **Uninitialized Variable**
   - Example from `vendor/hqc/src/x86_64/avx256/hqc-1/reed_solomon.c` line 534: "syndromes[i] is uninitialized."
   - **Resolution:**
     - Initialize all variables before use to avoid undefined behavior or runtime crashes.

5. **Syntax Errors**
   - Examples:
     - `munit_assert_int(result, ==, 0);` in `vendor/hqc/tests/api/test_pke.c`.
     - `SetCoeff(out, static_cast<long>(bit));` in `vendor/hqc/tests/unit/test_vect_mul.cpp`.
   - **Resolution:**
     - Evaluate for typos or incompatible standards during compilation (e.g., potentially mismatched C vs. C++).
     - Ensure appropriate flags are passed to the compiler (`--std`, `--language`) for this file.

6. **Improve Code Style and Portability**
   - Warnings about variable scope, const qualifiers, etc.
   - These may not cause the build to fail, but fixing them can prevent future issues.