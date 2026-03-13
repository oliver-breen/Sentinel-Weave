"""
SIEM Exporter — SentinelWeave
==============================

Exports SentinelWeave findings to industry-standard SIEM ingestion formats:

* **CEF** (ArcSight Common Event Format, RFC-style header + key-value extension)
* **LEEF** (IBM QRadar Log Event Extended Format)

Both formats are understood by all major SIEM products (Splunk, QRadar,
ArcSight, Microsoft Sentinel, Sumo Logic, etc.).

Supported source types
----------------------
* :class:`~sentinel_weave.threat_detector.ThreatReport`
* :class:`~sentinel_weave.email_scanner.EmailScanResult`
* :class:`~sentinel_weave.threat_correlator.AttackCampaign`

Usage
-----
::

    from sentinel_weave import ThreatDetector, EventAnalyzer
    from sentinel_weave.siem_exporter import SiemExporter

    analyzer = EventAnalyzer()
    detector = ThreatDetector()
    event  = analyzer.parse("Failed password for root from 10.0.0.1")
    report = detector.analyze(event)

    exporter = SiemExporter(vendor="Acme Corp", product="SentinelWeave")

    # Single-event export
    print(exporter.export_cef(report))
    print(exporter.export_leef(report))

    # Batch export to file
    exporter.to_file([report], "/var/log/sentinel.cef", fmt="cef")

    # UDP syslog forward
    exporter.to_syslog([report], host="10.0.0.5", port=514, fmt="cef")
"""

from __future__ import annotations

import datetime
import re
import socket
import os
from dataclasses import dataclass, field
from typing import Union

from .threat_detector import ThreatReport, ThreatLevel
from .email_scanner   import EmailScanResult
from .threat_correlator import AttackCampaign


# ---------------------------------------------------------------------------
# Type alias for anything the exporter can consume
# ---------------------------------------------------------------------------

Exportable = Union[ThreatReport, EmailScanResult, AttackCampaign]


# ---------------------------------------------------------------------------
# Severity mappings
# ---------------------------------------------------------------------------

# CEF severity is 0–10 (integer)
_CEF_SEVERITY: dict[ThreatLevel, int] = {
    ThreatLevel.BENIGN:   0,
    ThreatLevel.LOW:      3,
    ThreatLevel.MEDIUM:   5,
    ThreatLevel.HIGH:     8,
    ThreatLevel.CRITICAL: 10,
}

# LEEF severity is a free string; IBM recommends 1–10 as well
_LEEF_SEVERITY: dict[ThreatLevel, str] = {
    ThreatLevel.BENIGN:   "1",
    ThreatLevel.LOW:      "3",
    ThreatLevel.MEDIUM:   "5",
    ThreatLevel.HIGH:     "8",
    ThreatLevel.CRITICAL: "10",
}


# ---------------------------------------------------------------------------
# CEF field-value escaping (ArcSight spec §3.3)
# ---------------------------------------------------------------------------

def _cef_escape_header(value: str) -> str:
    """Escape pipe and backslash in CEF header fields."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_ext(value: str) -> str:
    """Escape equals, newline, and backslash in CEF extension values."""
    return (
        value.replace("\\", "\\\\")
             .replace("=", "\\=")
             .replace("\n", "\\n")
             .replace("\r", "\\r")
    )


# ---------------------------------------------------------------------------
# LEEF field-value escaping (IBM QRadar LEEF 2.0 spec)
# ---------------------------------------------------------------------------

_LEEF_INVALID_CHARS = re.compile(r"[\x00-\x1f\x7f]")

def _leef_escape(value: str) -> str:
    """Strip control characters and escape tab (field delimiter)."""
    value = value.replace("\t", " ")
    return _LEEF_INVALID_CHARS.sub("", value)


# ---------------------------------------------------------------------------
# Timestamp helpers
# ---------------------------------------------------------------------------

def _now_utc_str() -> str:
    """Return ISO-8601 UTC timestamp string."""
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _epoch_ms(dt: datetime.datetime | None) -> str:
    """Convert a datetime to epoch-milliseconds string, or 'unknown'."""
    if dt is None:
        return "unknown"
    return str(int(dt.timestamp() * 1000))


# ---------------------------------------------------------------------------
# CEFRecord — intermediate representation
# ---------------------------------------------------------------------------

@dataclass
class CefRecord:
    """
    Structured CEF record before serialisation.

    Attributes:
        device_vendor:   Vendor name (header field 1).
        device_product:  Product name (header field 2).
        device_version:  Product version (header field 3).
        signature_id:    Short event identifier / class (header field 4).
        name:            Human-readable event name (header field 5).
        severity:        0–10 integer (header field 6).
        extensions:      Ordered list of ``(key, value)`` extension pairs.
    """
    device_vendor:  str
    device_product: str
    device_version: str
    signature_id:   str
    name:           str
    severity:       int
    extensions:     list[tuple[str, str]] = field(default_factory=list)

    def to_string(self) -> str:
        """Serialise to the canonical CEF string."""
        header = "|".join([
            "CEF:0",
            _cef_escape_header(self.device_vendor),
            _cef_escape_header(self.device_product),
            _cef_escape_header(self.device_version),
            _cef_escape_header(self.signature_id),
            _cef_escape_header(self.name),
            str(self.severity),
        ])
        ext = " ".join(
            f"{k}={_cef_escape_ext(str(v))}"
            for k, v in self.extensions
        )
        return f"{header}|{ext}" if ext else f"{header}|"


# ---------------------------------------------------------------------------
# LeefRecord — intermediate representation
# ---------------------------------------------------------------------------

@dataclass
class LeefRecord:
    """
    Structured LEEF 2.0 record before serialisation.

    Attributes:
        vendor:     Vendor name.
        product:    Product name.
        version:    Product version.
        event_id:   Short event class identifier.
        delimiter:  Field delimiter (LEEF 2.0 default: ``\\t``).
        attributes: Ordered list of ``(key, value)`` attribute pairs.
    """
    vendor:     str
    product:    str
    version:    str
    event_id:   str
    delimiter:  str = "\t"
    attributes: list[tuple[str, str]] = field(default_factory=list)

    def to_string(self) -> str:
        """Serialise to the canonical LEEF 2.0 string."""
        # LEEF 2.0 header includes explicit delimiter spec
        header = (
            f"LEEF:2.0|{self.vendor}|{self.product}|{self.version}"
            f"|{self.event_id}|{self.delimiter}"
        )
        attrs = self.delimiter.join(
            f"{k}={_leef_escape(str(v))}"
            for k, v in self.attributes
        )
        return f"{header}|{attrs}" if attrs else f"{header}|"


# ---------------------------------------------------------------------------
# SiemExporter
# ---------------------------------------------------------------------------

class SiemExporter:
    """
    Unified SIEM export facade for SentinelWeave findings.

    Supports :class:`ThreatReport`, :class:`EmailScanResult`, and
    :class:`AttackCampaign` objects.

    Args:
        vendor:  Vendor name embedded in CEF/LEEF headers (default: ``"SentinelWeave"``).
        product: Product name embedded in headers (default: ``"SentinelWeave"``).
        version: Product version string (default: ``"1.0"``).
    """

    def __init__(
        self,
        vendor:  str = "SentinelWeave",
        product: str = "SentinelWeave",
        version: str = "1.0",
    ) -> None:
        self.vendor  = vendor
        self.product = product
        self.version = version

    # ------------------------------------------------------------------
    # Public CEF API
    # ------------------------------------------------------------------

    def export_cef(self, item: Exportable) -> str:
        """Return a single CEF string for *item*."""
        record = self._to_cef_record(item)
        return record.to_string()

    def export_cef_bulk(self, items: list[Exportable]) -> list[str]:
        """Return a list of CEF strings, one per item."""
        return [self.export_cef(i) for i in items]

    # ------------------------------------------------------------------
    # Public LEEF API
    # ------------------------------------------------------------------

    def export_leef(self, item: Exportable) -> str:
        """Return a single LEEF 2.0 string for *item*."""
        record = self._to_leef_record(item)
        return record.to_string()

    def export_leef_bulk(self, items: list[Exportable]) -> list[str]:
        """Return a list of LEEF strings, one per item."""
        return [self.export_leef(i) for i in items]

    # ------------------------------------------------------------------
    # Output helpers
    # ------------------------------------------------------------------

    def to_file(
        self,
        items: list[Exportable],
        path: str,
        fmt: str = "cef",
        append: bool = True,
    ) -> int:
        """
        Write *items* to *path* as CEF or LEEF lines.

        Args:
            items:  List of exportable findings.
            path:   Destination file path.
            fmt:    ``"cef"`` or ``"leef"`` (case-insensitive).
            append: If ``True`` (default) append to an existing file;
                    if ``False`` overwrite it.

        Returns:
            Number of lines written.
        """
        lines = (
            self.export_cef_bulk(items)
            if fmt.lower() == "cef"
            else self.export_leef_bulk(items)
        )
        mode = "a" if append else "w"
        with open(path, mode, encoding="utf-8") as fh:
            for line in lines:
                fh.write(line + "\n")
        return len(lines)

    def to_syslog(
        self,
        items: list[Exportable],
        host: str = "127.0.0.1",
        port: int = 514,
        fmt: str = "cef",
    ) -> int:
        """
        Forward *items* as syslog UDP datagrams to *host*:*port*.

        Each CEF/LEEF line is wrapped with a minimal syslog priority prefix
        (``<14>`` = facility 1 (user-level), severity 6 (info)).

        Args:
            items: List of exportable findings.
            host:  Syslog server host.
            port:  Syslog server UDP port.
            fmt:   ``"cef"`` or ``"leef"``.

        Returns:
            Number of messages sent.
        """
        lines = (
            self.export_cef_bulk(items)
            if fmt.lower() == "cef"
            else self.export_leef_bulk(items)
        )
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sent = 0
        try:
            for line in lines:
                msg = f"<14>{line}".encode("utf-8")
                sock.sendto(msg, (host, port))
                sent += 1
        finally:
            sock.close()
        return sent

    # ------------------------------------------------------------------
    # Internal builders — ThreatReport
    # ------------------------------------------------------------------

    def _to_cef_record(self, item: Exportable) -> CefRecord:
        if isinstance(item, ThreatReport):
            return self._cef_threat_report(item)
        if isinstance(item, EmailScanResult):
            return self._cef_email_result(item)
        if isinstance(item, AttackCampaign):
            return self._cef_campaign(item)
        raise TypeError(f"Unsupported type for CEF export: {type(item)}")

    def _to_leef_record(self, item: Exportable) -> LeefRecord:
        if isinstance(item, ThreatReport):
            return self._leef_threat_report(item)
        if isinstance(item, EmailScanResult):
            return self._leef_email_result(item)
        if isinstance(item, AttackCampaign):
            return self._leef_campaign(item)
        raise TypeError(f"Unsupported type for LEEF export: {type(item)}")

    # -- CEF: ThreatReport ------------------------------------------------

    def _cef_threat_report(self, report: ThreatReport) -> CefRecord:
        ev   = report.event
        sigs = ",".join(ev.matched_sigs) if ev.matched_sigs else "none"
        expl = "; ".join(report.explanation) if report.explanation else "n/a"
        ext: list[tuple[str, str]] = [
            ("rt",          _now_utc_str()),
            ("src",         ev.source_ip or "unknown"),
            ("cat",         ev.event_type),
            ("cs1",         sigs),
            ("cs1Label",    "AttackSignatures"),
            ("cn1",         f"{report.anomaly_score:.4f}"),
            ("cn1Label",    "AnomalyScore"),
            ("msg",         expl[:500]),
        ]
        if ev.timestamp:
            ext.insert(0, ("start", ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")))
        return CefRecord(
            device_vendor  = self.vendor,
            device_product = self.product,
            device_version = self.version,
            signature_id   = f"SW-{ev.event_type}",
            name           = f"Threat detected: {report.threat_level.value}",
            severity       = _CEF_SEVERITY[report.threat_level],
            extensions     = ext,
        )

    # -- CEF: EmailScanResult ---------------------------------------------

    def _cef_email_result(self, result: EmailScanResult) -> CefRecord:
        em   = result.email
        inds = ",".join(i.name for i in result.indicators) or "none"
        ext: list[tuple[str, str]] = [
            ("rt",         _now_utc_str()),
            ("suser",      em.sender or "unknown"),
            ("duser",      ",".join(em.recipients[:3]) or "unknown"),
            ("cs1",        inds),
            ("cs1Label",   "ThreatIndicators"),
            ("cn1",        f"{result.risk_score:.4f}"),
            ("cn1Label",   "RiskScore"),
            ("msg",        (em.subject or "")[:200]),
        ]
        return CefRecord(
            device_vendor  = self.vendor,
            device_product = self.product,
            device_version = self.version,
            signature_id   = "SW-EMAIL",
            name           = f"Email threat: {result.threat_level.value}",
            severity       = _CEF_SEVERITY[result.threat_level],
            extensions     = ext,
        )

    # -- CEF: AttackCampaign ----------------------------------------------

    def _cef_campaign(self, campaign: AttackCampaign) -> CefRecord:
        ext: list[tuple[str, str]] = [
            ("rt",           _now_utc_str()),
            ("src",          campaign.attacker_ip or "unknown"),
            ("cn1",          str(campaign.event_count)),
            ("cn1Label",     "EventCount"),
            ("start",        _epoch_ms(campaign.first_seen)),
            ("end",          _epoch_ms(campaign.last_seen)),
            ("cs1",          ",".join(campaign.signatures) if campaign.signatures else "none"),
            ("cs1Label",     "Signatures"),
            ("msg",          campaign.summary()),
        ]
        return CefRecord(
            device_vendor  = self.vendor,
            device_product = self.product,
            device_version = self.version,
            signature_id   = "SW-CAMPAIGN",
            name           = f"Attack campaign: {campaign.severity.value}",
            severity       = _CEF_SEVERITY[campaign.severity],
            extensions     = ext,
        )

    # -- LEEF: ThreatReport -----------------------------------------------

    def _leef_threat_report(self, report: ThreatReport) -> LeefRecord:
        ev   = report.event
        sigs = ",".join(ev.matched_sigs) if ev.matched_sigs else "none"
        expl = "; ".join(report.explanation) if report.explanation else "n/a"
        attrs: list[tuple[str, str]] = [
            ("devTime",       _now_utc_str()),
            ("src",           ev.source_ip or "unknown"),
            ("cat",           ev.event_type),
            ("sev",           _LEEF_SEVERITY[report.threat_level]),
            ("attackSigs",    sigs),
            ("anomalyScore",  f"{report.anomaly_score:.4f}"),
            ("threatLevel",   report.threat_level.value),
            ("msg",           expl[:500]),
        ]
        if ev.timestamp:
            attrs.insert(0, ("eventTime", ev.timestamp.strftime("%Y-%m-%dT%H:%M:%SZ")))
        return LeefRecord(
            vendor    = self.vendor,
            product   = self.product,
            version   = self.version,
            event_id  = f"ThreatDetected_{report.threat_level.value}",
            attributes = attrs,
        )

    # -- LEEF: EmailScanResult --------------------------------------------

    def _leef_email_result(self, result: EmailScanResult) -> LeefRecord:
        em   = result.email
        inds = ",".join(i.name for i in result.indicators) or "none"
        attrs: list[tuple[str, str]] = [
            ("devTime",       _now_utc_str()),
            ("sender",        em.sender or "unknown"),
            ("recipients",    ",".join(em.recipients[:3]) or "unknown"),
            ("subject",       (em.subject or "")[:200]),
            ("sev",           _LEEF_SEVERITY[result.threat_level]),
            ("indicators",    inds),
            ("riskScore",     f"{result.risk_score:.4f}"),
            ("threatLevel",   result.threat_level.value),
        ]
        return LeefRecord(
            vendor    = self.vendor,
            product   = self.product,
            version   = self.version,
            event_id  = f"EmailThreat_{result.threat_level.value}",
            attributes = attrs,
        )

    # -- LEEF: AttackCampaign ---------------------------------------------

    def _leef_campaign(self, campaign: AttackCampaign) -> LeefRecord:
        attrs: list[tuple[str, str]] = [
            ("devTime",     _now_utc_str()),
            ("src",         campaign.attacker_ip or "unknown"),
            ("sev",         _LEEF_SEVERITY[campaign.severity]),
            ("eventCount",  str(campaign.event_count)),
            ("firstSeen",   _epoch_ms(campaign.first_seen)),
            ("lastSeen",    _epoch_ms(campaign.last_seen)),
            ("signatures",  ",".join(campaign.signatures) if campaign.signatures else "none"),
            ("threatLevel", campaign.severity.value),
            ("msg",         campaign.summary()),
        ]
        return LeefRecord(
            vendor    = self.vendor,
            product   = self.product,
            version   = self.version,
            event_id  = f"AttackCampaign_{campaign.severity.value}",
            attributes = attrs,
        )
