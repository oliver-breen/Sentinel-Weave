"""
SentinelWeave — AI-Powered Cybersecurity Threat Detection with
Post-Quantum Secure Reporting.

Combines:
* Security log analysis and attack-signature detection
* Statistical (z-score) anomaly detection
* Attack-campaign correlation across time-windowed IP streams
* Supervised ML threat classification (pure-Python logistic regression)
* sklearn-backed ensemble classifier (RandomForest / GradientBoosting)
* pandas DataFrame integration for datasets, reports, and SIEM exports
* Optional Azure ML model scoring and Azure ML endpoint export
* Azure Cognitive Services NLP for log enrichment
* Post-quantum encryption (QuantaWeave LWE) for threat reports
* Azure Blob Storage for encrypted report persistence
* Azure Monitor telemetry
* CIA-triad security modules:
    - Confidentiality: Role-Based Access Control (RBAC)
    - Integrity:       HMAC event signing + tamper-evident audit chain
    - Availability:    Token-bucket rate limiting + heartbeat monitoring
* Red-team / offensive security toolkit (authorized use only):
    - TCP port scanning
    - Service fingerprinting (banner grabbing)
    - Vulnerability assessment against known CVE patterns
    - Password / credential strength auditing
    - Passive DNS reconnaissance
    - pwntools-backed fuzzing payload generation (BinaryFuzzer)
    - pandas aggregate scan reporting (aggregate_scan_results)
* Advanced offensive security strategies (authorized use only):
    - Shellcode disassembly & classification (Capstone)
    - YARA malware rule scanning (yara-python)
    - ML-based anomaly detection on scan data (scikit-learn + pandas)
    - Binary security-mitigation auditing & ROP gadget discovery (pwntools)
    - Memory forensics: process/network/injection analysis (Volatility 3)
* Dependency-integrated improvements to core modules:
    - YaraEventAnalyzer: YARA-augmented log-line signature detection
    - detect_shellcode(): Capstone-based shellcode analysis in event_analyzer
    - IsolationForestDetector: sklearn IsolationForest anomaly detector
    - summarize_reports_df(): pandas DataFrame summary of ThreatReports
    - SklearnSecurityClassifier: sklearn ensemble threat classifier
    - DatasetBuilder.to_dataframe / from_dataframe: pandas integration
    - SiemExporter.to_dataframe / summary_stats: pandas SIEM analytics
    - BinaryFuzzer: pwntools cyclic/de-Bruijn fuzzing payloads
    - aggregate_scan_results(): pandas scan aggregation
"""

__version__ = "0.4.0"
__author__  = "Oliver Breen"

from .event_analyzer      import EventAnalyzer, SecurityEvent, analyze_log_file
from .threat_detector     import ThreatDetector, ThreatReport, ThreatLevel, summarize_reports
from .azure_integration   import BlobStorageClient, TextAnalyticsClient, SecurityTelemetry
from .threat_correlator   import ThreatCorrelator, AttackCampaign
from .ml_pipeline         import (
    SecurityClassifier, DatasetBuilder, LabeledEvent,
    evaluate_classifier, k_fold_cross_validate,
    SklearnSecurityClassifier,
)
from .access_controller   import AccessController, Role, Action, AccessRequest
from .integrity_monitor   import IntegrityMonitor, AuditEntry, ChainVerificationResult
from .availability_monitor import (
    TokenBucketRateLimiter, AvailabilityMonitor,
    AvailabilityAlert, AlertSeverity, RateLimitResult,
)
from .email_scanner import (
    EmailScanner, EmailMessage, EmailScanResult, EmailIndicator,
)
from .siem_exporter import (
    SiemExporter, CefRecord, LeefRecord,
)
from .red_team_toolkit import (
    PortScanner, PortScanResult,
    ServiceFingerprinter, ServiceFingerprintResult,
    VulnerabilityAssessor, VulnerabilityFinding,
    CredentialAuditor, PasswordAuditResult,
    ReconScanner, ReconResult,
    summarize_scan, aggregate_scan_results,
    BinaryFuzzer,
    COMMON_PORTS, WEB_PORTS, DB_PORTS, ADMIN_PORTS,
)
from .event_analyzer import (
    YaraEventAnalyzer, detect_shellcode,
)
from .threat_detector import (
    IsolationForestDetector, summarize_reports_df,
)
from .advanced_offensive import (
    # Shellcode analysis (Capstone)
    ShellcodeAnalyzer, ShellcodeAnalysisResult, DisassembledInstruction,
    # YARA scanning
    YaraScanner, YaraMatch, YaraScanResult, BUILTIN_RULE_NAMES,
    # ML anomaly detection (scikit-learn + pandas)
    AnomalyDetector, AnomalyRecord, AnomalyReport,
    # Binary auditing (pwntools)
    BinaryAuditor, MitigationReport, RopGadget, BinaryAuditResult,
    # Memory forensics (Volatility 3)
    MemoryForensicsScanner, ProcessEntry, NetworkEntry, ForensicsReport,
)

__all__ = [
    # Event parsing
    "EventAnalyzer",
    "SecurityEvent",
    "analyze_log_file",
    # Capstone-backed shellcode detection
    "detect_shellcode",
    # YARA-backed log-line analyzer
    "YaraEventAnalyzer",
    # Threat detection
    "ThreatDetector",
    "ThreatReport",
    "ThreatLevel",
    "summarize_reports",
    # sklearn IsolationForest anomaly detector
    "IsolationForestDetector",
    # pandas threat-report summary
    "summarize_reports_df",
    # Campaign correlation
    "ThreatCorrelator",
    "AttackCampaign",
    # ML pipeline — pure-Python
    "SecurityClassifier",
    "DatasetBuilder",
    "LabeledEvent",
    "evaluate_classifier",
    "k_fold_cross_validate",
    # ML pipeline — sklearn backed
    "SklearnSecurityClassifier",
    # Azure integration
    "BlobStorageClient",
    "TextAnalyticsClient",
    "SecurityTelemetry",
    # CIA triad — Confidentiality (RBAC)
    "AccessController",
    "Role",
    "Action",
    "AccessRequest",
    # CIA triad — Integrity (HMAC + audit chain)
    "IntegrityMonitor",
    "AuditEntry",
    "ChainVerificationResult",
    # CIA triad — Availability (rate limiting + heartbeats)
    "TokenBucketRateLimiter",
    "AvailabilityMonitor",
    "AvailabilityAlert",
    "AlertSeverity",
    "RateLimitResult",
    # Email scanning
    "EmailScanner",
    "EmailMessage",
    "EmailScanResult",
    "EmailIndicator",
    # SIEM export
    "SiemExporter",
    "CefRecord",
    "LeefRecord",
    # Red-team / offensive security toolkit (authorized use only)
    "PortScanner",
    "PortScanResult",
    "ServiceFingerprinter",
    "ServiceFingerprintResult",
    "VulnerabilityAssessor",
    "VulnerabilityFinding",
    "CredentialAuditor",
    "PasswordAuditResult",
    "ReconScanner",
    "ReconResult",
    "summarize_scan",
    # pandas scan aggregation
    "aggregate_scan_results",
    # pwntools fuzzing payloads
    "BinaryFuzzer",
    "COMMON_PORTS",
    "WEB_PORTS",
    "DB_PORTS",
    "ADMIN_PORTS",
    # Advanced offensive security strategies (authorized use only)
    # Shellcode analysis
    "ShellcodeAnalyzer",
    "ShellcodeAnalysisResult",
    "DisassembledInstruction",
    # YARA scanning
    "YaraScanner",
    "YaraMatch",
    "YaraScanResult",
    "BUILTIN_RULE_NAMES",
    # ML anomaly detection
    "AnomalyDetector",
    "AnomalyRecord",
    "AnomalyReport",
    # Binary auditing
    "BinaryAuditor",
    "MitigationReport",
    "RopGadget",
    "BinaryAuditResult",
    # Memory forensics
    "MemoryForensicsScanner",
    "ProcessEntry",
    "NetworkEntry",
    "ForensicsReport",
]
