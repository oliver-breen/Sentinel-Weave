"""
SentinelWeave — AI-Powered Cybersecurity Threat Detection with
Post-Quantum Secure Reporting.

Combines:
* Security log analysis and attack-signature detection
* Statistical (z-score) anomaly detection
* Optional Azure ML model scoring
* Azure Cognitive Services NLP for log enrichment
* Post-quantum encryption (QuantaWeave LWE) for threat reports
* Azure Blob Storage for encrypted report persistence
* Azure Monitor telemetry
"""

__version__ = "0.1.0"
__author__  = "Oliver Breen"

from .event_analyzer  import EventAnalyzer, SecurityEvent, analyze_log_file
from .threat_detector import ThreatDetector, ThreatReport, ThreatLevel, summarize_reports
from .azure_integration import BlobStorageClient, TextAnalyticsClient, SecurityTelemetry

__all__ = [
    "EventAnalyzer",
    "SecurityEvent",
    "analyze_log_file",
    "ThreatDetector",
    "ThreatReport",
    "ThreatLevel",
    "summarize_reports",
    "BlobStorageClient",
    "TextAnalyticsClient",
    "SecurityTelemetry",
]
