"""
Event Analyzer — SentinelWeave

Parses raw security log lines and security events, extracts numeric feature
vectors, and detects well-known attack signatures (SSH brute-force, port
scans, failed login floods, web-injection attempts, etc.).

This module is intentionally dependency-free so it works in any Python 3.10+
environment without additional packages.
"""

from __future__ import annotations

import re
import math
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Attack signature patterns
# ---------------------------------------------------------------------------

_SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("SSH_BRUTE_FORCE",    re.compile(r"Failed password for .* from [\d.]+", re.IGNORECASE)),
    ("PORT_SCAN",          re.compile(r"(nmap|masscan|port.scan|SYN.flood)", re.IGNORECASE)),
    ("SQL_INJECTION",      re.compile(r"(union.*select|drop\s+table|'.*or.*'.*=|1=1|--\s*$)", re.IGNORECASE)),
    ("XSS_ATTEMPT",        re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=)", re.IGNORECASE)),
    ("PATH_TRAVERSAL",     re.compile(r"(\.\./|\.\.\\|%2e%2e)", re.IGNORECASE)),
    ("COMMAND_INJECTION",  re.compile(r"(;|\||\$\(|`)\s*(ls|cat|wget|curl|bash|sh|cmd)", re.IGNORECASE)),
    ("PRIVILEGE_ESCALATION", re.compile(r"(sudo|su -|chmod 777|setuid|passwd)", re.IGNORECASE)),
    ("DDoS_INDICATOR",     re.compile(r"(flood|dos|ddos|amplification|reflection)", re.IGNORECASE)),
    ("MALWARE_INDICATOR",  re.compile(r"(trojan|ransomware|rootkit|keylogger|C2|command.and.control)", re.IGNORECASE)),
    ("CREDENTIAL_DUMP",    re.compile(r"(mimikatz|lsass|hashdump|pass-the-hash|ntlm)", re.IGNORECASE)),
]


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """
    Represents a parsed security event with extracted metadata and features.

    Attributes:
        raw:            Original log line or event string.
        timestamp:      Parsed timestamp (None if not found).
        source_ip:      Source IP address string (None if absent).
        event_type:     High-level category (e.g. 'AUTH', 'NETWORK', 'SYSTEM').
        severity:       0.0–1.0 normalised severity score.
        matched_sigs:   List of attack-signature names that matched.
        features:       Numeric feature vector for ML-based analysis.
        metadata:       Arbitrary key/value pairs extracted from the log line.
    """

    raw: str
    timestamp: Optional[datetime] = None
    source_ip: Optional[str] = None
    event_type: str = "UNKNOWN"
    severity: float = 0.0
    matched_sigs: list[str] = field(default_factory=list)
    features: list[float] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Analyzer
# ---------------------------------------------------------------------------

class EventAnalyzer:
    """
    Parses and analyses security log lines or event strings.

    Usage::

        analyzer = EventAnalyzer()
        event = analyzer.parse("Failed password for root from 192.168.1.5")
        print(event.severity, event.matched_sigs)
    """

    # Timestamp patterns (most common log formats)
    _TS_PATTERNS: list[tuple[str, str]] = [
        (r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}", "%Y-%m-%dT%H:%M:%S"),
        (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", "%Y-%m-%d %H:%M:%S"),
        (r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}",            "%b %d %H:%M:%S"),
        (r"\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}",                    "%d/%m/%Y %H:%M:%S"),
    ]

    _IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

    _TYPE_KEYWORDS: list[tuple[str, re.Pattern[str]]] = [
        ("AUTH",    re.compile(r"(login|logon|password|auth|ssh|pam|sudo|su\b)", re.IGNORECASE)),
        ("NETWORK", re.compile(r"(port|tcp|udp|icmp|connection|firewall|iptables|nft)", re.IGNORECASE)),
        ("WEB",     re.compile(r"(http|https|GET|POST|PUT|DELETE|request|response|url|uri)", re.IGNORECASE)),
        ("SYSTEM",  re.compile(r"(kernel|syslog|process|daemon|service|cron|disk|memory)", re.IGNORECASE)),
        ("FILE",    re.compile(r"(file|directory|chmod|chown|read|write|delete|mkdir)", re.IGNORECASE)),
    ]

    # Severity keyword weights (additive)
    _SEV_WEIGHTS: list[tuple[re.Pattern[str], float]] = [
        (re.compile(r"\b(critical|emergency|alert)\b", re.IGNORECASE), 0.9),
        (re.compile(r"\b(error|fail|denied|refused|blocked)\b", re.IGNORECASE), 0.6),
        (re.compile(r"\b(warning|warn)\b", re.IGNORECASE), 0.4),
        (re.compile(r"\b(notice|info)\b", re.IGNORECASE), 0.2),
        (re.compile(r"\b(debug|verbose)\b", re.IGNORECASE), 0.05),
    ]

    def parse(self, raw_line: str) -> SecurityEvent:
        """
        Parse a single log line or event string into a :class:`SecurityEvent`.

        Args:
            raw_line: Raw log line, syslog entry, or event description string.

        Returns:
            A populated :class:`SecurityEvent` instance.
        """
        event = SecurityEvent(raw=raw_line)

        event.timestamp = self._extract_timestamp(raw_line)
        event.source_ip = self._extract_ip(raw_line)
        event.event_type = self._classify_type(raw_line)
        event.matched_sigs = self._match_signatures(raw_line)
        event.severity = self._score_severity(raw_line, event.matched_sigs)
        event.features = self._build_features(raw_line, event)
        event.metadata = self._extract_metadata(raw_line, event)

        return event

    def parse_bulk(self, lines: list[str]) -> list[SecurityEvent]:
        """Parse multiple log lines and return a list of events."""
        return [self.parse(line) for line in lines if line.strip()]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _extract_timestamp(self, text: str) -> Optional[datetime]:
        for pattern, fmt in self._TS_PATTERNS:
            m = re.search(pattern, text)
            if m:
                try:
                    # Syslog format has no year — default to current year
                    dt_str = m.group()
                    if "%Y" not in fmt:
                        dt_str = f"{datetime.now().year} {dt_str}"
                        fmt = f"%Y {fmt}"
                    return datetime.strptime(dt_str, fmt)
                except ValueError:
                    continue
        return None

    def _extract_ip(self, text: str) -> Optional[str]:
        m = self._IP_RE.search(text)
        return m.group(1) if m else None

    def _classify_type(self, text: str) -> str:
        for type_name, pattern in self._TYPE_KEYWORDS:
            if pattern.search(text):
                return type_name
        return "UNKNOWN"

    def _match_signatures(self, text: str) -> list[str]:
        return [name for name, pattern in _SIGNATURES if pattern.search(text)]

    def _score_severity(self, text: str, matched_sigs: list[str]) -> float:
        score = 0.0
        for pattern, weight in self._SEV_WEIGHTS:
            if pattern.search(text):
                score = max(score, weight)
        # Each matched signature bumps severity
        score = min(1.0, score + len(matched_sigs) * 0.15)
        return round(score, 4)

    def _build_features(self, text: str, event: SecurityEvent) -> list[float]:
        """
        Build a numeric feature vector for downstream ML analysis.

        Features (13 values):
            0  – normalised text length (log scale, capped at 1)
            1  – number of digits / total chars
            2  – number of special chars (non-alphanum) / total chars
            3  – uppercase ratio
            4  – has source IP (0/1)
            5  – has timestamp (0/1)
            6  – event_type encoded (AUTH=1, NETWORK=2, WEB=3, SYSTEM=4, FILE=5, UNKNOWN=0)
            7  – number of matched signatures (normalised by 10)
            8  – raw severity score
            9  – contains URL / path chars (/  \\ ?)
            10 – line entropy (Shannon, normalised to [0,1] by dividing by log2(256))
            11 – number of IP addresses in line (normalised by 5)
            12 – keyword threat density (threat words / total words)
        """
        n = len(text) or 1
        digits = sum(c.isdigit() for c in text)
        specials = sum(not c.isalnum() and c != " " for c in text)
        uppers = sum(c.isupper() for c in text)
        words = text.split()
        n_words = len(words) or 1

        type_map = {"UNKNOWN": 0, "AUTH": 1, "NETWORK": 2, "WEB": 3, "SYSTEM": 4, "FILE": 5}

        threat_words = {"attack", "malware", "exploit", "vulnerability", "breach",
                        "intrusion", "compromise", "payload", "backdoor", "ransomware"}
        threat_density = sum(1 for w in words if w.lower() in threat_words) / n_words

        # Shannon entropy
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        entropy = -sum((c / n) * math.log2(c / n) for c in freq.values()) / math.log2(256) if n > 1 else 0.0

        ip_count = len(self._IP_RE.findall(text))

        return [
            min(1.0, math.log1p(n) / math.log1p(500)),
            digits / n,
            specials / n,
            uppers / n,
            1.0 if event.source_ip else 0.0,
            1.0 if event.timestamp else 0.0,
            type_map.get(event.event_type, 0) / 5.0,
            min(1.0, len(event.matched_sigs) / 10.0),
            event.severity,
            1.0 if re.search(r"[/\\?]", text) else 0.0,
            entropy,
            min(1.0, ip_count / 5.0),
            threat_density,
        ]

    def _extract_metadata(self, text: str, event: SecurityEvent) -> dict:
        meta: dict = {}
        if event.source_ip:
            meta["source_ip"] = event.source_ip
        # Extract usernames from common patterns
        m = re.search(r"for\s+(invalid user\s+)?(\w+)\s+from", text, re.IGNORECASE)
        if m:
            meta["target_user"] = m.group(2)
        # Extract HTTP status codes
        m = re.search(r"\b([1-5]\d{2})\b", text)
        if m:
            meta["http_status"] = int(m.group(1))
        # Extract port numbers
        m = re.search(r"port\s+(\d+)", text, re.IGNORECASE)
        if m:
            meta["port"] = int(m.group(1))
        return meta


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def analyze_log_file(path: str) -> list[SecurityEvent]:
    """
    Read a log file line-by-line and return a list of parsed security events.

    Args:
        path: Filesystem path to the log file.

    Returns:
        List of :class:`SecurityEvent` instances.
    """
    with open(path, encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()
    analyzer = EventAnalyzer()
    return analyzer.parse_bulk(lines)
