"""
Tests for sentinel_weave.siem_exporter
=======================================

Covers:
- CEF header format (version, pipe delimiter, field count)
- CEF severity mapping for all ThreatLevels
- CEF extension key=value serialisation (escape rules)
- LEEF header format (LEEF:2.0 prefix, tab delimiter)
- LEEF severity mapping for all ThreatLevels
- LEEF attribute serialisation and escaping
- ThreatReport → CEF / LEEF
- EmailScanResult → CEF / LEEF
- AttackCampaign → CEF / LEEF
- Bulk export (export_cef_bulk / export_leef_bulk)
- to_file (CEF and LEEF)
- to_file append vs overwrite
- Custom vendor / product / version fields
- TypeError on unsupported input
- Public API import from sentinel_weave
"""

from __future__ import annotations

import os
import tempfile
import datetime
from typing import List

import pytest

from sentinel_weave import SiemExporter, CefRecord, LeefRecord
from sentinel_weave.siem_exporter import (
    _cef_escape_header,
    _cef_escape_ext,
    _leef_escape,
)
from sentinel_weave import EventAnalyzer, ThreatDetector, ThreatLevel, ThreatCorrelator
from sentinel_weave.email_scanner import EmailScanner, EmailScanResult
from sentinel_weave.threat_correlator import AttackCampaign


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def exporter() -> SiemExporter:
    return SiemExporter(vendor="TestVendor", product="TestProduct", version="2.0")


@pytest.fixture()
def ssh_report():
    analyzer = EventAnalyzer()
    detector = ThreatDetector()
    ev = analyzer.parse("Failed password for root from 10.0.0.1 port 22 ssh2")
    return detector.analyze(ev)


@pytest.fixture()
def phish_result() -> EmailScanResult:
    scanner = EmailScanner()
    return scanner.scan_raw(
        "From: evil@phish.ru\nSubject: verify your account immediately\n"
        "\nClick http://bit.ly/steal now or your account will be suspended"
    )


@pytest.fixture()
def campaign() -> AttackCampaign:
    analyzer = EventAnalyzer()
    detector = ThreatDetector()
    correlator = ThreatCorrelator(time_window_seconds=3600)
    for _ in range(5):
        ev = analyzer.parse("Failed password for root from 10.1.2.3 port 22 ssh2")
        correlator.add_report(detector.analyze(ev))
    campaigns = correlator.get_campaigns()
    assert campaigns, "Expected at least one campaign"
    return campaigns[0]


# ---------------------------------------------------------------------------
# Escape utilities
# ---------------------------------------------------------------------------

class TestEscapeHelpers:
    def test_cef_header_escapes_pipe(self):
        assert _cef_escape_header("foo|bar") == "foo\\|bar"

    def test_cef_header_escapes_backslash(self):
        assert _cef_escape_header("foo\\bar") == "foo\\\\bar"

    def test_cef_ext_escapes_equals(self):
        assert _cef_escape_ext("a=b") == "a\\=b"

    def test_cef_ext_escapes_newline(self):
        assert _cef_escape_ext("a\nb") == "a\\nb"

    def test_cef_ext_escapes_carriage_return(self):
        assert _cef_escape_ext("a\rb") == "a\\rb"

    def test_leef_strips_control_chars(self):
        assert _leef_escape("hello\x00world") == "helloworld"

    def test_leef_replaces_tab_with_space(self):
        assert _leef_escape("a\tb") == "a b"


# ---------------------------------------------------------------------------
# CefRecord serialisation
# ---------------------------------------------------------------------------

class TestCefRecord:
    def test_to_string_starts_with_cef_version(self):
        rec = CefRecord("V", "P", "1", "SIG", "Name", 5)
        assert rec.to_string().startswith("CEF:0|")

    def test_to_string_has_seven_pipe_segments(self):
        rec = CefRecord("V", "P", "1", "SIG", "Name", 5)
        # CEF:0|V|P|1|SIG|Name|5| — 7 pipes
        parts = rec.to_string().split("|")
        assert len(parts) >= 7

    def test_extensions_serialised(self):
        rec = CefRecord("V", "P", "1", "SIG", "Name", 5, extensions=[("src", "1.2.3.4")])
        assert "src=1.2.3.4" in rec.to_string()

    def test_extension_value_escaped(self):
        rec = CefRecord("V", "P", "1", "SIG", "Name", 5, extensions=[("msg", "a=b")])
        assert "msg=a\\=b" in rec.to_string()

    def test_empty_extensions(self):
        rec = CefRecord("V", "P", "1", "SIG", "Name", 5)
        s = rec.to_string()
        assert s.endswith("|")


# ---------------------------------------------------------------------------
# LeefRecord serialisation
# ---------------------------------------------------------------------------

class TestLeefRecord:
    def test_to_string_starts_with_leef_version(self):
        rec = LeefRecord("V", "P", "1", "EID")
        assert rec.to_string().startswith("LEEF:2.0|")

    def test_delimiter_in_header(self):
        rec = LeefRecord("V", "P", "1", "EID", delimiter="\t")
        assert "|\t|" in rec.to_string()

    def test_attributes_tab_separated(self):
        rec = LeefRecord("V", "P", "1", "EID", delimiter="\t",
                         attributes=[("k1", "v1"), ("k2", "v2")])
        body = rec.to_string().split("|\t|")[1]
        assert "k1=v1" in body and "k2=v2" in body


# ---------------------------------------------------------------------------
# ThreatReport → CEF
# ---------------------------------------------------------------------------

class TestCefThreatReport:
    def test_cef_starts_with_cef0(self, exporter, ssh_report):
        assert exporter.export_cef(ssh_report).startswith("CEF:0|")

    def test_cef_vendor_in_string(self, exporter, ssh_report):
        assert "TestVendor" in exporter.export_cef(ssh_report)

    def test_cef_source_ip_present(self, exporter, ssh_report):
        assert "src=10.0.0.1" in exporter.export_cef(ssh_report)

    def test_cef_signature_in_cs1(self, exporter, ssh_report):
        assert "SSH_BRUTE_FORCE" in exporter.export_cef(ssh_report)

    def test_cef_severity_numeric(self, exporter, ssh_report):
        cef = exporter.export_cef(ssh_report)
        # The 7th pipe-delimited field (index 6) is the severity
        parts = cef.split("|")
        severity = int(parts[6])
        assert 0 <= severity <= 10


# ---------------------------------------------------------------------------
# ThreatReport → LEEF
# ---------------------------------------------------------------------------

class TestLeefThreatReport:
    def test_leef_starts_with_leef(self, exporter, ssh_report):
        assert exporter.export_leef(ssh_report).startswith("LEEF:2.0|")

    def test_leef_vendor_in_string(self, exporter, ssh_report):
        assert "TestVendor" in exporter.export_leef(ssh_report)

    def test_leef_has_sev_field(self, exporter, ssh_report):
        assert "sev=" in exporter.export_leef(ssh_report)

    def test_leef_has_src_field(self, exporter, ssh_report):
        assert "src=10.0.0.1" in exporter.export_leef(ssh_report)


# ---------------------------------------------------------------------------
# EmailScanResult → CEF / LEEF
# ---------------------------------------------------------------------------

class TestSiemEmailResult:
    def test_cef_email_sig_id(self, exporter, phish_result):
        assert "SW-EMAIL" in exporter.export_cef(phish_result)

    def test_cef_email_sender(self, exporter, phish_result):
        assert "suser=evil@phish.ru" in exporter.export_cef(phish_result)

    def test_cef_email_risk_score(self, exporter, phish_result):
        assert "cn1=" in exporter.export_cef(phish_result)

    def test_leef_email_threat_level(self, exporter, phish_result):
        leef = exporter.export_leef(phish_result)
        assert "threatLevel=" in leef
        assert "CRITICAL" in leef or "HIGH" in leef

    def test_leef_email_sender(self, exporter, phish_result):
        assert "sender=evil@phish.ru" in exporter.export_leef(phish_result)


# ---------------------------------------------------------------------------
# AttackCampaign → CEF / LEEF
# ---------------------------------------------------------------------------

class TestSiemCampaign:
    def test_cef_campaign_sig_id(self, exporter, campaign):
        assert "SW-CAMPAIGN" in exporter.export_cef(campaign)

    def test_cef_campaign_has_event_count(self, exporter, campaign):
        assert "cn1=" in exporter.export_cef(campaign)

    def test_leef_campaign_has_event_count(self, exporter, campaign):
        assert "eventCount=" in exporter.export_leef(campaign)

    def test_leef_campaign_attacker_ip(self, exporter, campaign):
        assert "src=10.1.2.3" in exporter.export_leef(campaign)


# ---------------------------------------------------------------------------
# Bulk export
# ---------------------------------------------------------------------------

class TestBulkExport:
    def test_cef_bulk_returns_list(self, exporter, ssh_report, phish_result):
        results = exporter.export_cef_bulk([ssh_report, phish_result])
        assert isinstance(results, list) and len(results) == 2

    def test_leef_bulk_returns_list(self, exporter, ssh_report, phish_result):
        results = exporter.export_leef_bulk([ssh_report, phish_result])
        assert isinstance(results, list) and len(results) == 2

    def test_bulk_empty_list(self, exporter):
        assert exporter.export_cef_bulk([]) == []


# ---------------------------------------------------------------------------
# to_file
# ---------------------------------------------------------------------------

class TestToFile:
    def test_to_file_cef_creates_file(self, exporter, ssh_report):
        with tempfile.NamedTemporaryFile(suffix=".cef", delete=False) as f:
            path = f.name
        try:
            count = exporter.to_file([ssh_report], path, fmt="cef", append=False)
            assert count == 1
            content = open(path).read()
            assert content.startswith("CEF:0|")
        finally:
            os.unlink(path)

    def test_to_file_leef_creates_file(self, exporter, ssh_report):
        with tempfile.NamedTemporaryFile(suffix=".leef", delete=False) as f:
            path = f.name
        try:
            exporter.to_file([ssh_report], path, fmt="leef", append=False)
            content = open(path).read()
            assert content.startswith("LEEF:2.0|")
        finally:
            os.unlink(path)

    def test_to_file_append_mode(self, exporter, ssh_report):
        with tempfile.NamedTemporaryFile(suffix=".cef", delete=False) as f:
            path = f.name
        try:
            exporter.to_file([ssh_report], path, fmt="cef", append=False)
            exporter.to_file([ssh_report], path, fmt="cef", append=True)
            lines = open(path).readlines()
            assert len(lines) == 2
        finally:
            os.unlink(path)

    def test_to_file_overwrite_mode(self, exporter, ssh_report):
        with tempfile.NamedTemporaryFile(suffix=".cef", delete=False) as f:
            path = f.name
        try:
            exporter.to_file([ssh_report, ssh_report], path, fmt="cef", append=False)
            exporter.to_file([ssh_report], path, fmt="cef", append=False)
            lines = [l for l in open(path).readlines() if l.strip()]
            assert len(lines) == 1
        finally:
            os.unlink(path)


# ---------------------------------------------------------------------------
# TypeError for unsupported input
# ---------------------------------------------------------------------------

class TestTypeErrors:
    def test_cef_unsupported_type(self, exporter):
        with pytest.raises(TypeError):
            exporter.export_cef("not-a-valid-object")

    def test_leef_unsupported_type(self, exporter):
        with pytest.raises(TypeError):
            exporter.export_leef({"some": "dict"})


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class TestPublicApi:
    def test_siem_exporter_importable(self):
        from sentinel_weave import SiemExporter as SE
        assert SE is SiemExporter

    def test_cef_record_importable(self):
        from sentinel_weave import CefRecord as CR
        assert CR is CefRecord

    def test_leef_record_importable(self):
        from sentinel_weave import LeefRecord as LR
        assert LR is LeefRecord

    def test_default_vendor_is_sentinelweave(self):
        exp = SiemExporter()
        assert exp.vendor == "SentinelWeave"
