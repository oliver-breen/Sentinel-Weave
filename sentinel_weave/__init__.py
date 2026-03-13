"""
SentinelWeave — AI-Powered Cybersecurity Threat Detection with
Post-Quantum Secure Reporting.

Combines:
* Security log analysis and attack-signature detection
* Statistical (z-score) anomaly detection
* Attack-campaign correlation across time-windowed IP streams
* Supervised ML threat classification (pure-Python logistic regression)
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
"""

__version__ = "0.3.0"
__author__  = "Oliver Breen"

from .event_analyzer      import EventAnalyzer, SecurityEvent, analyze_log_file
from .threat_detector     import ThreatDetector, ThreatReport, ThreatLevel, summarize_reports
from .azure_integration   import BlobStorageClient, TextAnalyticsClient, SecurityTelemetry
from .threat_correlator   import ThreatCorrelator, AttackCampaign
from .ml_pipeline         import (
    SecurityClassifier, DatasetBuilder, LabeledEvent,
    evaluate_classifier, k_fold_cross_validate,
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
    summarize_scan,
    COMMON_PORTS, WEB_PORTS, DB_PORTS, ADMIN_PORTS,
)

__all__ = [
    # Event parsing
    "EventAnalyzer",
    "SecurityEvent",
    "analyze_log_file",
    # Threat detection
    "ThreatDetector",
    "ThreatReport",
    "ThreatLevel",
    "summarize_reports",
    # Campaign correlation
    "ThreatCorrelator",
    "AttackCampaign",
    # ML pipeline
    "SecurityClassifier",
    "DatasetBuilder",
    "LabeledEvent",
    "evaluate_classifier",
    "k_fold_cross_validate",
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
    "COMMON_PORTS",
    "WEB_PORTS",
    "DB_PORTS",
    "ADMIN_PORTS",
]
