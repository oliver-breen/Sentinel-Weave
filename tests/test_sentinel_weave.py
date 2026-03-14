"""
Tests for the SentinelWeave module.

Covers:
- EventAnalyzer: parsing, feature extraction, signature detection
- ThreatDetector: scoring, baseline, report generation
- AzureIntegration: offline fallback mode for all three clients
- SecureReporter: encrypt/store/decrypt round-trip
- CLI: demo command
"""

from __future__ import annotations

import sys
import os
import json
import random
import tempfile
import unittest

# ---------------------------------------------------------------------------
# Make sure the repo root is on sys.path regardless of how the tests are run
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.event_analyzer import EventAnalyzer, SecurityEvent
from sentinel_weave.threat_detector import (
    ThreatDetector, ThreatLevel, ThreatReport,
    FeatureBaseline, summarize_reports,
)
from sentinel_weave.azure_integration import (
    BlobStorageClient, TextAnalyticsClient, SecurityTelemetry,
)


# ===========================================================================
# EventAnalyzer tests
# ===========================================================================

class TestEventAnalyzerParsing(unittest.TestCase):
    """Verify that raw log lines are parsed into SecurityEvent objects."""

    def setUp(self) -> None:
        self.analyzer = EventAnalyzer()

    def test_returns_security_event(self) -> None:
        event = self.analyzer.parse("Some log line")
        self.assertIsInstance(event, SecurityEvent)

    def test_raw_preserved(self) -> None:
        raw = "Jan 15 10:23:01 server sshd: Failed password for root"
        event = self.analyzer.parse(raw)
        self.assertEqual(event.raw, raw)

    def test_ip_extraction(self) -> None:
        event = self.analyzer.parse("Connection from 192.168.1.100 refused")
        self.assertEqual(event.source_ip, "192.168.1.100")

    def test_no_ip_when_absent(self) -> None:
        event = self.analyzer.parse("Normal system log message")
        self.assertIsNone(event.source_ip)

    def test_timestamp_iso_format(self) -> None:
        event = self.analyzer.parse("2024-01-15T10:23:01 server kernel: message")
        self.assertIsNotNone(event.timestamp)

    def test_timestamp_syslog_format(self) -> None:
        event = self.analyzer.parse("Jan 15 10:23:01 server sshd: message")
        self.assertIsNotNone(event.timestamp)

    def test_event_type_auth(self) -> None:
        event = self.analyzer.parse("Failed password for root from 10.0.0.1")
        self.assertEqual(event.event_type, "AUTH")

    def test_event_type_network(self) -> None:
        event = self.analyzer.parse("iptables DROP IN=eth0 port 22 TCP")
        self.assertEqual(event.event_type, "NETWORK")

    def test_event_type_web(self) -> None:
        event = self.analyzer.parse("GET /admin HTTP/1.1 404")
        self.assertEqual(event.event_type, "WEB")

    def test_event_type_unknown(self) -> None:
        event = self.analyzer.parse("random stuff with no keywords")
        self.assertEqual(event.event_type, "UNKNOWN")

    def test_feature_vector_length(self) -> None:
        event = self.analyzer.parse("Failed password for root from 10.0.0.1")
        self.assertEqual(len(event.features), 13)

    def test_feature_vector_range(self) -> None:
        event = self.analyzer.parse("Failed password for root from 10.0.0.1")
        for f in event.features:
            self.assertGreaterEqual(f, 0.0)
            self.assertLessEqual(f, 1.0)

    def test_severity_is_float_in_range(self) -> None:
        event = self.analyzer.parse("CRITICAL error: system failure")
        self.assertGreaterEqual(event.severity, 0.0)
        self.assertLessEqual(event.severity, 1.0)

    def test_parse_bulk_returns_list(self) -> None:
        lines = ["line one", "line two", "line three"]
        events = self.analyzer.parse_bulk(lines)
        self.assertEqual(len(events), 3)

    def test_parse_bulk_ignores_blank_lines(self) -> None:
        lines = ["line one", "", "  ", "line two"]
        events = self.analyzer.parse_bulk(lines)
        self.assertEqual(len(events), 2)


class TestSignatureDetection(unittest.TestCase):
    """Verify that attack-signature patterns fire correctly."""

    def setUp(self) -> None:
        self.analyzer = EventAnalyzer()

    def _sigs(self, line: str) -> list[str]:
        return self.analyzer.parse(line).matched_sigs

    def test_ssh_brute_force(self) -> None:
        self.assertIn("SSH_BRUTE_FORCE", self._sigs(
            "Failed password for root from 192.168.1.1 port 22 ssh2"
        ))

    def test_sql_injection(self) -> None:
        self.assertIn("SQL_INJECTION", self._sigs(
            "GET /?id=1' UNION SELECT * FROM users-- HTTP/1.1 200"
        ))

    def test_xss_attempt(self) -> None:
        self.assertIn("XSS_ATTEMPT", self._sigs(
            "<script>alert('xss')</script> in request body"
        ))

    def test_path_traversal(self) -> None:
        self.assertIn("PATH_TRAVERSAL", self._sigs(
            "GET /../../etc/passwd HTTP/1.1 403"
        ))

    def test_command_injection(self) -> None:
        self.assertIn("COMMAND_INJECTION", self._sigs(
            "POST /exec?cmd=;cat /etc/shadow HTTP/1.1"
        ))

    def test_privilege_escalation(self) -> None:
        self.assertIn("PRIVILEGE_ESCALATION", self._sigs(
            "sudo chmod 777 /etc/passwd executed by www-data"
        ))

    def test_malware_indicator(self) -> None:
        self.assertIn("MALWARE_INDICATOR", self._sigs(
            "Ransomware activity detected on host ws-42"
        ))

    def test_credential_dump(self) -> None:
        self.assertIn("CREDENTIAL_DUMP", self._sigs(
            "mimikatz sekurlsa::logonpasswords executed on DC01"
        ))

    def test_benign_line_no_sigs(self) -> None:
        self.assertEqual([], self._sigs(
            "User alice logged in successfully from 10.1.0.20"
        ))

    def test_multiple_sigs_on_one_line(self) -> None:
        sigs = self._sigs(
            "Failed password for root; sudo chmod 777 from 1.2.3.4"
        )
        self.assertGreaterEqual(len(sigs), 2)


# ===========================================================================
# FeatureBaseline tests
# ===========================================================================

class TestFeatureBaseline(unittest.TestCase):

    def test_initial_count(self) -> None:
        bl = FeatureBaseline(n_features=3)
        self.assertEqual(bl.count, 0)

    def test_update_increments_count(self) -> None:
        bl = FeatureBaseline(n_features=3)
        bl.update([0.1, 0.2, 0.3])
        self.assertEqual(bl.count, 1)

    def test_means_after_updates(self) -> None:
        bl = FeatureBaseline(n_features=2)
        bl.update([2.0, 4.0])
        bl.update([4.0, 8.0])
        means = bl.means()
        self.assertAlmostEqual(means[0], 3.0, places=5)
        self.assertAlmostEqual(means[1], 6.0, places=5)

    def test_stds_with_single_sample(self) -> None:
        bl = FeatureBaseline(n_features=2)
        bl.update([1.0, 2.0])
        # std is undefined with 1 sample — should return 1.0 as sentinel
        stds = bl.stds()
        self.assertEqual(stds, [1.0, 1.0])

    def test_ignores_wrong_length(self) -> None:
        bl = FeatureBaseline(n_features=3)
        bl.update([1.0, 2.0])  # wrong length — should be silently ignored
        self.assertEqual(bl.count, 0)


# ===========================================================================
# ThreatDetector tests
# ===========================================================================

class TestThreatDetector(unittest.TestCase):

    def setUp(self) -> None:
        self.analyzer = EventAnalyzer()
        self.detector = ThreatDetector(min_baseline_samples=3)

    def _report(self, line: str) -> ThreatReport:
        return self.detector.analyze(self.analyzer.parse(line))

    def test_returns_threat_report(self) -> None:
        report = self._report("Normal log message")
        self.assertIsInstance(report, ThreatReport)
        self.assertIsInstance(report.threat_level, ThreatLevel)

    def test_benign_has_low_score(self) -> None:
        report = self._report("User alice logged in successfully from 10.1.0.5")
        self.assertLess(report.anomaly_score, 0.35)

    def test_ssh_brute_force_elevates_score(self) -> None:
        report = self._report(
            "Failed password for root from 192.168.1.100 port 22 ssh2"
        )
        self.assertGreater(report.anomaly_score, 0.0)
        # SSH_BRUTE_FORCE signature should push it above BENIGN
        self.assertNotEqual(report.threat_level, ThreatLevel.BENIGN)

    def test_critical_threat_level_for_high_score(self) -> None:
        # Multiple signatures on one line should yield HIGH or CRITICAL
        report = self._report(
            "Failed password for root; sudo chmod 777; UNION SELECT FROM users; "
            "mimikatz sekurlsa::logonpasswords from 1.2.3.4"
        )
        self.assertIn(report.threat_level, (ThreatLevel.HIGH, ThreatLevel.CRITICAL))

    def test_anomaly_score_range(self) -> None:
        for line in [
            "Normal backup completed",
            "Failed password for root from 10.0.0.1",
            "SQL injection UNION SELECT",
            "Ransomware detected on host",
        ]:
            r = self._report(line)
            self.assertGreaterEqual(r.anomaly_score, 0.0)
            self.assertLessEqual(r.anomaly_score, 1.0)

    def test_explanation_list(self) -> None:
        report = self._report("Failed password for root from 10.0.0.1 port 22 ssh2")
        self.assertIsInstance(report.explanation, list)

    def test_z_scores_populated_after_baseline_warm(self) -> None:
        benign_lines = [
            "Normal login success for bob",
            "Service started successfully",
            "Backup completed OK",
        ]
        for line in benign_lines:
            self.detector.update_baseline(self.analyzer.parse(line))

        report = self._report("Failed password for root from 10.0.0.1 ssh2")
        self.assertGreater(len(report.z_scores), 0)

    def test_z_scores_empty_before_baseline_warm(self) -> None:
        fresh = ThreatDetector(min_baseline_samples=100)
        report = fresh.analyze(self.analyzer.parse("anything"))
        self.assertEqual(report.z_scores, [])

    def test_update_baseline_increments_count(self) -> None:
        event = self.analyzer.parse("Normal message")
        self.detector.update_baseline(event)
        self.assertGreaterEqual(self.detector.baseline.count, 1)

    def test_analyze_bulk_returns_list(self) -> None:
        events = self.analyzer.parse_bulk(["line 1", "line 2", "line 3"])
        reports = self.detector.analyze_bulk(events)
        self.assertEqual(len(reports), 3)

    def test_top_threats_sorted(self) -> None:
        events = self.analyzer.parse_bulk([
            "Normal message",
            "Failed password for root from 1.2.3.4 ssh2",
            "User logged in OK",
            "UNION SELECT * FROM users -- SQL injection attempt",
        ])
        reports = self.detector.analyze_bulk(events)
        top = self.detector.top_threats(reports, n=2)
        self.assertEqual(len(top), 2)
        self.assertGreaterEqual(top[0].anomaly_score, top[1].anomaly_score)

    def test_summary_report_returns_dict(self) -> None:
        events = self.analyzer.parse_bulk(["line 1", "line 2"])
        reports = self.detector.analyze_bulk(events)
        summary = summarize_reports(reports)
        self.assertIn("total", summary)
        self.assertIn("by_level", summary)
        self.assertIn("unique_ips", summary)

    def test_summary_of_empty_list(self) -> None:
        self.assertEqual(summarize_reports([]), {})

    def test_threat_report_summary_string(self) -> None:
        report = self._report("Failed password for root from 10.0.0.1 ssh2")
        s = report.summary()
        self.assertIsInstance(s, str)
        self.assertIn("score=", s)


# ===========================================================================
# Azure integration — offline fallback mode
# ===========================================================================

class TestBlobStorageClientLocal(unittest.TestCase):
    """BlobStorageClient without Azure credentials → local filesystem mode."""

    def setUp(self) -> None:
        self.client = BlobStorageClient()
        # Override local root to a temp dir to keep tests clean
        import sentinel_weave.azure_integration as mod
        self._orig = mod._LOCAL_ROOT
        self._tmp  = tempfile.mkdtemp()
        from pathlib import Path
        mod._LOCAL_ROOT = Path(self._tmp)

    def tearDown(self) -> None:
        import sentinel_weave.azure_integration as mod
        mod._LOCAL_ROOT = self._orig

    def test_not_azure_connected(self) -> None:
        self.assertFalse(self.client.is_azure_connected)

    def test_upload_returns_local_uri(self) -> None:
        uri = self.client.upload(b"hello", "test.bin")
        self.assertTrue(uri.startswith("local://"))

    def test_download_returns_uploaded_data(self) -> None:
        self.client.upload(b"sentinel_data", "payload.bin")
        data = self.client.download("payload.bin")
        self.assertEqual(data, b"sentinel_data")

    def test_download_missing_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.client.download("does_not_exist.bin")

    def test_list_blobs_returns_uploaded(self) -> None:
        self.client.upload(b"a", "file_a.bin")
        self.client.upload(b"b", "file_b.bin")
        blobs = self.client.list_blobs()
        self.assertIn("file_a.bin", blobs)
        self.assertIn("file_b.bin", blobs)


class TestTextAnalyticsClientLocal(unittest.TestCase):
    """TextAnalyticsClient without Azure credentials → local keyword analysis."""

    def setUp(self) -> None:
        self.client = TextAnalyticsClient()

    def test_not_azure_connected(self) -> None:
        self.assertFalse(self.client.is_azure_connected)

    def test_analyze_returns_dict(self) -> None:
        result = self.client.analyze("Failed login attempt detected")
        self.assertIsInstance(result, dict)

    def test_required_keys_present(self) -> None:
        result = self.client.analyze("Normal system message")
        for key in ("sentiment", "key_phrases", "entities", "pii_redacted", "source"):
            self.assertIn(key, result)

    def test_negative_sentiment_for_attack_message(self) -> None:
        result = self.client.analyze("Critical error: attack detected, system compromised")
        self.assertEqual(result["sentiment"], "negative")

    def test_positive_sentiment_for_success_message(self) -> None:
        result = self.client.analyze("User authenticated successfully, connection granted")
        self.assertEqual(result["sentiment"], "positive")

    def test_source_is_local(self) -> None:
        result = self.client.analyze("anything")
        self.assertEqual(result["source"], "local")

    def test_ip_redaction(self) -> None:
        result = self.client.analyze("Connection from 192.168.1.1 blocked")
        self.assertNotIn("192.168.1.1", result["pii_redacted"])
        self.assertIn("[REDACTED]", result["pii_redacted"])

    def test_ip_entity_extracted(self) -> None:
        result = self.client.analyze("Attack from 10.0.0.5 detected")
        ips = [e["text"] for e in result["entities"] if e["category"] == "IPAddress"]
        self.assertIn("10.0.0.5", ips)


class TestSecurityTelemetryLocal(unittest.TestCase):
    """SecurityTelemetry without Azure credentials → local JSON-lines log."""

    def setUp(self) -> None:
        import sentinel_weave.azure_integration as mod
        self._tmp = tempfile.mkdtemp()
        from pathlib import Path
        self._orig = mod._LOCAL_ROOT
        mod._LOCAL_ROOT = Path(self._tmp)
        self.telemetry = SecurityTelemetry()
        self.telemetry._local_log = Path(self._tmp) / "telemetry.jsonl"

    def tearDown(self) -> None:
        import sentinel_weave.azure_integration as mod
        mod._LOCAL_ROOT = self._orig

    def test_not_azure_connected(self) -> None:
        self.assertFalse(self.telemetry.is_azure_connected)

    def test_track_threat_writes_local(self) -> None:
        self.telemetry.track_threat(
            threat_level="HIGH",
            source_ip="10.0.0.5",
            signatures=["SSH_BRUTE_FORCE"],
            anomaly_score=0.75,
        )
        events = self.telemetry.get_local_events()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["threat_level"], "HIGH")
        self.assertEqual(events[0]["source_ip"], "10.0.0.5")

    def test_multiple_events_accumulate(self) -> None:
        for _ in range(5):
            self.telemetry.track_threat(threat_level="MEDIUM")
        events = self.telemetry.get_local_events()
        self.assertEqual(len(events), 5)

    def test_get_local_events_empty_when_no_log(self) -> None:
        events = SecurityTelemetry().get_local_events()
        self.assertIsInstance(events, list)


# ===========================================================================
# SecureReporter tests — encrypt / decrypt round-trip
# ===========================================================================

class TestSecureReporter(unittest.TestCase):
    """End-to-end encrypt/store/decrypt test using local blob storage."""

    def setUp(self) -> None:
        import sentinel_weave.azure_integration as mod
        from pathlib import Path
        self._tmp  = tempfile.mkdtemp()
        self._orig = mod._LOCAL_ROOT
        mod._LOCAL_ROOT = Path(self._tmp)

        from sentinel_weave.secure_reporter import SecureReporter
        self.reporter = SecureReporter(security_level="LEVEL1")

        self.analyzer = EventAnalyzer()
        self.detector = ThreatDetector()

    def tearDown(self) -> None:
        import sentinel_weave.azure_integration as mod
        mod._LOCAL_ROOT = self._orig

    def _make_reports(self, lines: list[str]) -> list:
        events = self.analyzer.parse_bulk(lines)
        return self.detector.analyze_bulk(events)

    def test_generate_keys_returns_pair(self) -> None:
        pub, priv = self.reporter.generate_keys()
        self.assertIn("A", pub)
        self.assertIn("s", priv)

    def test_create_and_store_returns_string(self) -> None:
        pub, _ = self.reporter.generate_keys()
        reports = self._make_reports(["Failed password for root from 1.2.3.4"])
        report_id = self.reporter.create_and_store("Test Report", reports, pub)
        self.assertIsInstance(report_id, str)
        self.assertTrue(report_id.startswith("report-"))

    def test_round_trip_decrypt(self) -> None:
        pub, priv = self.reporter.generate_keys()
        reports = self._make_reports([
            "Failed password for root from 192.168.1.1",
            "Normal backup completed",
        ])
        report_id = self.reporter.create_and_store("Round-trip Test", reports, pub)
        decrypted = self.reporter.retrieve_and_decrypt(report_id, priv)

        self.assertEqual(decrypted["title"], "Round-trip Test")
        self.assertEqual(decrypted["summary"]["total_events"], 2)

    def test_report_events_preserved(self) -> None:
        pub, priv = self.reporter.generate_keys()
        reports = self._make_reports(["SSH_BRUTE_FORCE attempt from 10.0.0.1"])
        report_id = self.reporter.create_and_store("Sig Test", reports, pub)
        decrypted = self.reporter.retrieve_and_decrypt(report_id, priv)
        self.assertGreaterEqual(len(decrypted["events"]), 1)

    def test_list_reports_includes_new_report(self) -> None:
        pub, _ = self.reporter.generate_keys()
        reports = self._make_reports(["test line"])
        report_id = self.reporter.create_and_store("List Test", reports, pub)
        stored = self.reporter.list_reports()
        self.assertIn(report_id, stored)

    def test_wrong_key_raises(self) -> None:
        pub, _   = self.reporter.generate_keys()
        _, priv2 = self.reporter.generate_keys()
        reports  = self._make_reports(["test"])
        report_id = self.reporter.create_and_store("Key Test", reports, pub)
        # Decrypting with the wrong private key should raise an error
        with self.assertRaises(Exception):
            self.reporter.retrieve_and_decrypt(report_id, priv2)


# ===========================================================================
# CLI demo smoke-test
# ===========================================================================

class TestCLIDemo(unittest.TestCase):
    """Ensure the demo command runs without errors."""

    def test_demo_exits_zero(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_demo
        args = argparse.Namespace()
        rc = cmd_demo(args)
        self.assertEqual(rc, 0)


class TestCLIAnalyze(unittest.TestCase):
    """Ensure the analyze command processes a real temp file."""

    def test_analyze_temp_log(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_analyze

        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write("Jan 15 10:00:00 server sshd: Failed password for root from 192.168.1.1\n")
            fh.write("Jan 15 10:00:01 server syslog: Normal backup completed\n")
            path = fh.name

        try:
            args = argparse.Namespace(
                file=path,
                verbose=False,
                top=5,
                z_threshold=3.0,
                min_baseline=10,
                telemetry=False,
            )
            rc = cmd_analyze(args)
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)




# ===========================================================================
# ThreatCorrelator tests
# ===========================================================================

from sentinel_weave.threat_correlator import ThreatCorrelator, AttackCampaign
from sentinel_weave.event_analyzer    import SecurityEvent


def _make_report(
    ip: str | None = None,
    score: float = 0.5,
    sigs: list[str] | None = None,
    threat_level: ThreatLevel = ThreatLevel.HIGH,
    timestamp_sec: float | None = None,
) -> ThreatReport:
    """Build a minimal ThreatReport for correlator testing."""
    from datetime import datetime, timezone
    ts = (
        datetime.fromtimestamp(timestamp_sec, tz=timezone.utc)
        if timestamp_sec is not None else None
    )
    event = SecurityEvent(
        raw="test event",
        source_ip=ip,
        timestamp=ts,
        matched_sigs=sigs or [],
        features=[0.1] * 13,
        severity=0.5,
    )
    return ThreatReport(
        event=event,
        threat_level=threat_level,
        anomaly_score=score,
    )


class TestThreatCorrelatorBasic(unittest.TestCase):
    """Verify basic add/count behaviour."""

    def setUp(self) -> None:
        self.corr = ThreatCorrelator(time_window_seconds=300, min_events=2)

    def test_empty_correlator_no_campaigns(self) -> None:
        self.assertEqual(self.corr.get_campaigns(), [])

    def test_empty_top_attackers(self) -> None:
        self.assertEqual(self.corr.get_top_attackers(), [])

    def test_report_without_ip_not_tracked_for_campaigns(self) -> None:
        self.corr.add_report(_make_report(ip=None, score=0.8))
        self.corr.add_report(_make_report(ip=None, score=0.8))
        self.assertEqual(self.corr.get_campaigns(), [])

    def test_total_counts_tracks_all_ips(self) -> None:
        self.corr.add_report(_make_report(ip="1.2.3.4", score=0.8))
        self.corr.add_report(_make_report(ip="1.2.3.4", score=0.8))
        self.corr.add_report(_make_report(ip="5.6.7.8", score=0.8))
        top = self.corr.get_top_attackers()
        ips = [ip for ip, _ in top]
        self.assertIn("1.2.3.4", ips)
        self.assertIn("5.6.7.8", ips)

    def test_top_attackers_sorted_descending(self) -> None:
        for _ in range(3):
            self.corr.add_report(_make_report(ip="10.0.0.1", score=0.8))
        self.corr.add_report(_make_report(ip="10.0.0.2", score=0.8))
        top = self.corr.get_top_attackers()
        self.assertEqual(top[0][0], "10.0.0.1")
        self.assertGreater(top[0][1], top[1][1])

    def test_add_reports_bulk(self) -> None:
        reports = [_make_report(ip="9.9.9.9", score=0.6, timestamp_sec=float(i))
                   for i in range(5)]
        self.corr.add_reports(reports)
        campaigns = self.corr.get_campaigns()
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0].attacker_ip, "9.9.9.9")

    def test_report_below_min_score_not_in_campaign(self) -> None:
        low_corr = ThreatCorrelator(min_score=0.5)
        for _ in range(5):
            low_corr.add_report(_make_report(ip="1.1.1.1", score=0.1))
        self.assertEqual(low_corr.get_campaigns(), [])


class TestThreatCorrelatorCampaigns(unittest.TestCase):
    """Verify campaign detection, grouping, and attributes."""

    def setUp(self) -> None:
        self.corr = ThreatCorrelator(time_window_seconds=300, min_events=2)

    def test_same_ip_forms_one_campaign(self) -> None:
        for i in range(3):
            self.corr.add_report(_make_report(ip="192.168.1.1", score=0.6,
                                              timestamp_sec=float(i * 10)))
        campaigns = self.corr.get_campaigns()
        self.assertEqual(len(campaigns), 1)

    def test_different_ips_separate_campaigns(self) -> None:
        for i in range(2):
            self.corr.add_report(_make_report(ip="1.1.1.1", score=0.6,
                                              timestamp_sec=float(i * 10)))
        for i in range(2):
            self.corr.add_report(_make_report(ip="2.2.2.2", score=0.6,
                                              timestamp_sec=float(i * 10)))
        campaigns = self.corr.get_campaigns()
        ips = {c.attacker_ip for c in campaigns}
        self.assertIn("1.1.1.1", ips)
        self.assertIn("2.2.2.2", ips)

    def test_campaign_event_count(self) -> None:
        for i in range(4):
            self.corr.add_report(_make_report(ip="3.3.3.3", score=0.6,
                                              timestamp_sec=float(i * 5)))
        c = self.corr.get_campaigns()[0]
        self.assertEqual(c.event_count, 4)

    def test_campaign_peak_score(self) -> None:
        for score in [0.3, 0.7, 0.5]:
            self.corr.add_report(_make_report(ip="4.4.4.4", score=score,
                                              timestamp_sec=float(score * 100)))
        c = self.corr.get_campaigns()[0]
        self.assertAlmostEqual(c.peak_score, 0.7, places=4)

    def test_campaign_collects_signatures(self) -> None:
        self.corr.add_report(_make_report(ip="5.5.5.5", score=0.6,
                                          sigs=["SSH_BRUTE_FORCE"],
                                          timestamp_sec=0.0))
        self.corr.add_report(_make_report(ip="5.5.5.5", score=0.6,
                                          sigs=["PORT_SCAN"],
                                          timestamp_sec=10.0))
        c = self.corr.get_campaigns()[0]
        self.assertIn("SSH_BRUTE_FORCE", c.signatures)
        self.assertIn("PORT_SCAN", c.signatures)

    def test_campaign_type_brute_force(self) -> None:
        for i in range(3):
            self.corr.add_report(_make_report(ip="6.6.6.6", score=0.6,
                                              sigs=["SSH_BRUTE_FORCE"],
                                              timestamp_sec=float(i * 10)))
        c = self.corr.get_campaigns()[0]
        self.assertEqual(c.campaign_type, "BRUTE_FORCE")

    def test_campaign_kill_chain_reconnaissance(self) -> None:
        for i in range(2):
            self.corr.add_report(_make_report(ip="7.7.7.7", score=0.6,
                                              sigs=["PORT_SCAN"],
                                              timestamp_sec=float(i * 10)))
        c = self.corr.get_campaigns()[0]
        self.assertEqual(c.kill_chain_phase, "RECONNAISSANCE")

    def test_campaign_kill_chain_furthest_phase(self) -> None:
        """PRIVILEGE_ESCALATION should beat RECONNAISSANCE."""
        self.corr.add_report(_make_report(ip="8.8.8.8", score=0.6,
                                          sigs=["PORT_SCAN"],
                                          timestamp_sec=0.0))
        self.corr.add_report(_make_report(ip="8.8.8.8", score=0.6,
                                          sigs=["PRIVILEGE_ESCALATION"],
                                          timestamp_sec=10.0))
        c = self.corr.get_campaigns()[0]
        self.assertEqual(c.kill_chain_phase, "PRIVILEGE_ESCALATION")

    def test_severity_escalated_for_many_events(self) -> None:
        """4+ events → severity escalated above single-event max."""
        base_level = ThreatLevel.MEDIUM
        for i in range(4):
            self.corr.add_report(_make_report(ip="9.9.9.0", score=0.4,
                                              threat_level=base_level,
                                              timestamp_sec=float(i * 5)))
        c = self.corr.get_campaigns()[0]
        order = list(ThreatLevel)
        self.assertGreater(order.index(c.severity), order.index(base_level))

    def test_campaigns_sorted_by_severity(self) -> None:
        # critical IP
        for i in range(2):
            self.corr.add_report(_make_report(ip="10.0.0.1", score=0.9,
                                              threat_level=ThreatLevel.CRITICAL,
                                              timestamp_sec=float(i)))
        # low IP
        for i in range(2):
            self.corr.add_report(_make_report(ip="10.0.0.2", score=0.1,
                                              threat_level=ThreatLevel.LOW,
                                              timestamp_sec=float(i)))
        camps = self.corr.get_campaigns()
        self.assertEqual(camps[0].attacker_ip, "10.0.0.1")

    def test_min_events_threshold_filters(self) -> None:
        """Single event should not form a campaign with min_events=2."""
        corr = ThreatCorrelator(min_events=2)
        corr.add_report(_make_report(ip="1.2.3.4", score=0.9, timestamp_sec=0.0))
        self.assertEqual(corr.get_campaigns(), [])

    def test_campaign_summary_string(self) -> None:
        for i in range(2):
            self.corr.add_report(_make_report(ip="11.0.0.1", score=0.5,
                                              timestamp_sec=float(i * 10)))
        c = self.corr.get_campaigns()[0]
        s = c.summary()
        self.assertIn("11.0.0.1", s)
        self.assertIsInstance(s, str)

    def test_summary_stats_keys(self) -> None:
        self.corr.add_report(_make_report(ip="12.0.0.1", score=0.5, timestamp_sec=0.0))
        self.corr.add_report(_make_report(ip="12.0.0.1", score=0.5, timestamp_sec=10.0))
        stats = self.corr.summary_stats()
        for key in ("unique_ips", "total_reports", "campaign_count",
                    "top_campaign_severity", "most_common_phase"):
            self.assertIn(key, stats)

    def test_out_of_window_events_separate_campaigns(self) -> None:
        """Events 1 hour apart should be in separate campaign buckets."""
        corr = ThreatCorrelator(time_window_seconds=300, min_events=2)
        for i in range(2):
            corr.add_report(_make_report(ip="13.0.0.1", score=0.5,
                                         timestamp_sec=float(i * 10)))
        for i in range(2):
            corr.add_report(_make_report(ip="13.0.0.1", score=0.5,
                                         timestamp_sec=float(3600 + i * 10)))
        camps = corr.get_campaigns()
        self.assertEqual(len(camps), 2)

    def test_no_timestamp_reports_still_correlate(self) -> None:
        """Reports without timestamps should still form a campaign together."""
        corr = ThreatCorrelator(min_events=2)
        for _ in range(3):
            corr.add_report(_make_report(ip="14.0.0.1", score=0.6,
                                         timestamp_sec=None))
        camps = corr.get_campaigns()
        self.assertEqual(len(camps), 1)
        self.assertIsNone(camps[0].first_seen)
        self.assertIsNone(camps[0].duration_seconds)


# ===========================================================================
# ML Pipeline tests
# ===========================================================================

from sentinel_weave.ml_pipeline import (
    SecurityClassifier, DatasetBuilder, LabeledEvent, evaluate_classifier,
)


def _make_labeled(label: int, scale: float = 1.0) -> LabeledEvent:
    """Create a synthetic labeled event with simple separable features."""
    features = [scale * (0.9 if label == 1 else 0.1)] * 13
    return LabeledEvent(features=features, label=label)


def _separable_dataset(n: int = 60) -> list[LabeledEvent]:
    """Create a linearly separable dataset (equal classes)."""
    half = n // 2
    return [_make_labeled(1) for _ in range(half)] + \
           [_make_labeled(0) for _ in range(half)]


class TestLabeledEvent(unittest.TestCase):

    def test_default_weight(self) -> None:
        ev = LabeledEvent(features=[0.0] * 13, label=0)
        self.assertEqual(ev.weight, 1.0)

    def test_custom_weight(self) -> None:
        ev = LabeledEvent(features=[0.0] * 13, label=1, weight=2.5)
        self.assertEqual(ev.weight, 2.5)


class TestDatasetBuilder(unittest.TestCase):

    def _make_reports(self) -> list:
        analyzer = EventAnalyzer()
        detector = ThreatDetector()
        lines = [
            "Failed password for root from 1.2.3.4",
            "Normal backup completed successfully",
            "SQL UNION SELECT attack from 5.6.7.8",
            "Cron job finished",
            "Port scan detected from 9.9.9.9",
            "Service nginx started",
        ]
        events = analyzer.parse_bulk(lines)
        return detector.analyze_bulk(events)

    def test_from_reports_returns_list(self) -> None:
        reports = self._make_reports()
        dataset = DatasetBuilder.from_reports(reports)
        self.assertIsInstance(dataset, list)

    def test_from_reports_length_matches(self) -> None:
        reports = self._make_reports()
        dataset = DatasetBuilder.from_reports(reports)
        self.assertLessEqual(len(dataset), len(reports))

    def test_labels_are_binary(self) -> None:
        dataset = DatasetBuilder.from_reports(self._make_reports())
        for ev in dataset:
            self.assertIn(ev.label, (0, 1))

    def test_features_length_13(self) -> None:
        dataset = DatasetBuilder.from_reports(self._make_reports())
        for ev in dataset:
            self.assertEqual(len(ev.features), 13)

    def test_balance_oversample_equal_classes(self) -> None:
        positives = [_make_labeled(1) for _ in range(5)]
        negatives = [_make_labeled(0) for _ in range(20)]
        balanced  = DatasetBuilder.balance(positives + negatives, strategy="oversample")
        pos = sum(1 for e in balanced if e.label == 1)
        neg = sum(1 for e in balanced if e.label == 0)
        self.assertEqual(pos, neg)

    def test_balance_undersample_equal_classes(self) -> None:
        positives = [_make_labeled(1) for _ in range(5)]
        negatives = [_make_labeled(0) for _ in range(20)]
        balanced  = DatasetBuilder.balance(positives + negatives, strategy="undersample")
        pos = sum(1 for e in balanced if e.label == 1)
        neg = sum(1 for e in balanced if e.label == 0)
        self.assertEqual(pos, neg)

    def test_balance_invalid_strategy_raises(self) -> None:
        with self.assertRaises(ValueError):
            DatasetBuilder.balance([_make_labeled(0), _make_labeled(1)],
                                   strategy="magic")

    def test_split_sizes(self) -> None:
        dataset     = _separable_dataset(20)
        train, test = DatasetBuilder.split(dataset, test_ratio=0.2)
        self.assertEqual(len(train) + len(test), 20)

    def test_split_sum_equals_total(self) -> None:
        dataset     = _separable_dataset(50)
        train, test = DatasetBuilder.split(dataset, test_ratio=0.3)
        self.assertEqual(len(train) + len(test), 50)

    def test_split_test_ratio_respected(self) -> None:
        dataset     = _separable_dataset(100)
        _, test     = DatasetBuilder.split(dataset, test_ratio=0.20)
        self.assertAlmostEqual(len(test) / 100, 0.20, delta=0.05)


class TestSecurityClassifier(unittest.TestCase):

    def setUp(self) -> None:
        self.clf     = SecurityClassifier(learning_rate=0.1, epochs=100)
        self.dataset = _separable_dataset(80)
        self.train, self.test = DatasetBuilder.split(self.dataset)

    def test_predict_proba_in_range_before_training(self) -> None:
        p = self.clf.predict_proba([0.5] * 13)
        self.assertGreaterEqual(p, 0.0)
        self.assertLessEqual(p, 1.0)

    def test_predict_returns_binary_before_training(self) -> None:
        pred = self.clf.predict([0.5] * 13)
        self.assertIn(pred, (0, 1))

    def test_train_returns_history_dict(self) -> None:
        history = self.clf.train(self.train)
        self.assertIsInstance(history, dict)

    def test_history_required_keys(self) -> None:
        history = self.clf.train(self.train)
        for key in ("epochs", "initial_loss", "final_loss", "loss_history"):
            self.assertIn(key, history)

    def test_loss_history_length(self) -> None:
        history = self.clf.train(self.train)
        self.assertEqual(len(history["loss_history"]), 100)

    def test_final_loss_not_negative(self) -> None:
        history = self.clf.train(self.train)
        self.assertGreaterEqual(history["final_loss"], 0.0)

    def test_predict_proba_in_range_after_training(self) -> None:
        self.clf.train(self.train)
        for ev in self.test:
            p = self.clf.predict_proba(ev.features)
            self.assertGreaterEqual(p, 0.0)
            self.assertLessEqual(p, 1.0)

    def test_predict_returns_binary_after_training(self) -> None:
        self.clf.train(self.train)
        for ev in self.test:
            self.assertIn(self.clf.predict(ev.features), (0, 1))

    def test_accuracy_on_separable_data(self) -> None:
        """Well-trained classifier should achieve > 0.7 accuracy on easy data."""
        clf = SecurityClassifier(learning_rate=0.1, epochs=300)
        clf.train(self.train)
        metrics = clf.evaluate(self.test)
        self.assertGreater(metrics["accuracy"], 0.70)

    def test_robustness_on_noisy_data(self) -> None:
        """Classifier should still learn above chance on overlapping distributions."""
        rng = random.Random(99)
        noisy: list[LabeledEvent] = []
        for _ in range(60):
            # Threat features: mean 0.7 with noise
            feats = [max(0.0, min(1.0, 0.7 + rng.gauss(0, 0.2))) for _ in range(13)]
            noisy.append(LabeledEvent(features=feats, label=1))
        for _ in range(60):
            # Benign features: mean 0.3 with noise
            feats = [max(0.0, min(1.0, 0.3 + rng.gauss(0, 0.2))) for _ in range(13)]
            noisy.append(LabeledEvent(features=feats, label=0))
        train_n, test_n = DatasetBuilder.split(noisy, test_ratio=0.2)
        clf = SecurityClassifier(learning_rate=0.1, epochs=300)
        clf.train(train_n)
        metrics = clf.evaluate(test_n)
        # On noisy but separable distributions, accuracy should beat random (0.5)
        self.assertGreater(metrics["accuracy"], 0.5)

    def test_evaluate_returns_all_keys(self) -> None:
        self.clf.train(self.train)
        metrics = self.clf.evaluate(self.test)
        for key in ("accuracy", "precision", "recall", "f1",
                    "true_positives", "false_positives",
                    "true_negatives", "false_negatives"):
            self.assertIn(key, metrics)

    def test_evaluate_accuracy_in_range(self) -> None:
        self.clf.train(self.train)
        metrics = self.clf.evaluate(self.test)
        self.assertGreaterEqual(metrics["accuracy"], 0.0)
        self.assertLessEqual(metrics["accuracy"], 1.0)

    def test_train_empty_dataset_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.clf.train([])

    def test_partial_fit_updates_weights_and_marks_trained(self) -> None:
        """partial_fit() must change weights and set _trained=True."""
        self.clf.train(self.train)
        before = list(self.clf.weights)
        result = self.clf.partial_fit(self.train[:20], epochs=5)
        self.assertIn("loss", result)
        self.assertIsInstance(result["loss"], float)
        self.assertNotEqual(self.clf.weights, before)
        self.assertTrue(self.clf._trained)

    def test_partial_fit_empty_raises(self) -> None:
        """partial_fit() on an empty dataset must raise ValueError."""
        with self.assertRaises(ValueError):
            self.clf.partial_fit([])

    def test_save_and_load_round_trip(self) -> None:
        self.clf.train(self.train)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            self.clf.save(path)
            loaded = SecurityClassifier.load(path)
            self.assertEqual(self.clf.weights, loaded.weights)
        finally:
            os.unlink(path)

    def test_loaded_model_predicts_same(self) -> None:
        self.clf.train(self.train)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as fh:
            path = fh.name
        try:
            self.clf.save(path)
            loaded = SecurityClassifier.load(path)
            sample = self.test[0].features
            self.assertEqual(self.clf.predict(sample), loaded.predict(sample))
        finally:
            os.unlink(path)

    def test_load_invalid_file_raises(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as fh:
            json.dump({"model_type": "wrong"}, fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                SecurityClassifier.load(path)
        finally:
            os.unlink(path)

    def test_to_azure_ml_schema_keys(self) -> None:
        schema = self.clf.to_azure_ml_schema()
        for key in ("model_spec", "input_schema", "score_function_stub"):
            self.assertIn(key, schema)

    def test_azure_ml_schema_n_features(self) -> None:
        schema = self.clf.to_azure_ml_schema()
        self.assertEqual(schema["model_spec"]["n_features"], 13)

    def test_azure_ml_schema_input_names_length(self) -> None:
        schema = self.clf.to_azure_ml_schema()
        self.assertEqual(len(schema["input_schema"]["names"]), 13)

    def test_azure_ml_score_stub_is_string(self) -> None:
        schema = self.clf.to_azure_ml_schema()
        self.assertIsInstance(schema["score_function_stub"], str)
        self.assertIn("def score", schema["score_function_stub"])


class TestEvaluateClassifierHelper(unittest.TestCase):

    def _make_reports_for_ml(self) -> list:
        analyzer = EventAnalyzer()
        detector = ThreatDetector()
        lines = (
            ["Failed password for root from 1.2.3.4"] * 10
            + ["SQL UNION SELECT attack"] * 10
            + ["Port scan from 9.9.9.9"] * 10
            + ["Normal backup completed"] * 10
            + ["Service nginx started OK"] * 10
            + ["Cron job finished successfully"] * 10
        )
        return detector.analyze_bulk(analyzer.parse_bulk(lines))

    def test_returns_classifier_and_metrics(self) -> None:
        reports = self._make_reports_for_ml()
        clf, metrics = evaluate_classifier(reports, epochs=50)
        self.assertIsInstance(clf, SecurityClassifier)
        self.assertIn("accuracy", metrics)

    def test_too_few_reports_raises(self) -> None:
        analyzer = EventAnalyzer()
        detector = ThreatDetector()
        reports  = detector.analyze_bulk(analyzer.parse_bulk(["line1", "line2"]))
        with self.assertRaises(ValueError):
            evaluate_classifier(reports)


# ===========================================================================
# CLI correlate and train smoke-tests
# ===========================================================================

class TestCLICorrelate(unittest.TestCase):

    def _write_log(self, lines: list[str]) -> str:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write("\n".join(lines))
            return fh.name

    def test_correlate_exits_zero(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_correlate
        path = self._write_log([
            "Jan 15 10:00:00 server sshd: Failed password for root from 192.168.1.1",
            "Jan 15 10:00:05 server sshd: Failed password for admin from 192.168.1.1",
            "Jan 15 10:00:10 server sshd: Failed password for alice from 192.168.1.1",
        ])
        try:
            args = argparse.Namespace(
                file=path, window=300, min_events=2, top=10, top_attackers=5,
            )
            rc = cmd_correlate(args)
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_correlate_empty_file_returns_nonzero(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_correlate
        path = self._write_log([])
        try:
            args = argparse.Namespace(
                file=path, window=300, min_events=2, top=10, top_attackers=0,
            )
            rc = cmd_correlate(args)
            self.assertNotEqual(rc, 0)
        finally:
            os.unlink(path)


class TestCLITrain(unittest.TestCase):

    def _write_log(self, lines: list[str]) -> str:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as fh:
            fh.write("\n".join(lines))
            return fh.name

    def test_train_exits_zero(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_train
        lines = (
            ["Failed password for root from 1.2.3.4"] * 10
            + ["SQL UNION SELECT attack from 5.6.7.8"] * 10
            + ["Normal backup completed OK"] * 10
            + ["Service nginx started OK"] * 10
        )
        path = self._write_log(lines)
        try:
            args = argparse.Namespace(
                file=path, epochs=50, test_ratio=0.25,
                output=None, azure_export=None,
            )
            rc = cmd_train(args)
            self.assertEqual(rc, 0)
        finally:
            os.unlink(path)

    def test_train_saves_model_file(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_train
        lines = (
            ["Failed password for root from 1.2.3.4"] * 10
            + ["SQL UNION SELECT attack from 5.6.7.8"] * 10
            + ["Normal backup OK"] * 10
            + ["Service nginx started OK"] * 10
        )
        log_path   = self._write_log(lines)
        model_path = log_path.replace(".log", ".model.json")
        try:
            args = argparse.Namespace(
                file=log_path, epochs=50, test_ratio=0.25,
                output=model_path, azure_export=None,
            )
            cmd_train(args)
            self.assertTrue(os.path.exists(model_path))
        finally:
            os.unlink(log_path)
            if os.path.exists(model_path):
                os.unlink(model_path)

    def test_train_saves_azure_export(self) -> None:
        import argparse
        from sentinel_weave.cli import cmd_train
        lines = (
            ["Failed password for root from 1.2.3.4"] * 10
            + ["SQL UNION SELECT attack from 5.6.7.8"] * 10
            + ["Normal backup completed OK"] * 10
            + ["Service nginx started OK"] * 10
        )
        log_path    = self._write_log(lines)
        azure_path  = log_path.replace(".log", ".azure.json")
        try:
            args = argparse.Namespace(
                file=log_path, epochs=50, test_ratio=0.25,
                output=None, azure_export=azure_path,
            )
            cmd_train(args)
            self.assertTrue(os.path.exists(azure_path))
            with open(azure_path) as fh:
                schema = json.load(fh)
            self.assertIn("model_spec", schema)
        finally:
            os.unlink(log_path)
            if os.path.exists(azure_path):
                os.unlink(azure_path)


# ===========================================================================
# CIA Triad — Confidentiality: AccessController
# ===========================================================================

from sentinel_weave.access_controller import AccessController, Role, Action, AccessRequest


class TestAccessControllerPermissions(unittest.TestCase):
    """Role-permission matrix correctness."""

    def setUp(self) -> None:
        self.ac = AccessController()

    def test_viewer_can_list(self) -> None:
        self.assertTrue(self.ac.check(Role.VIEWER, Action.LIST))

    def test_viewer_cannot_read(self) -> None:
        self.assertFalse(self.ac.check(Role.VIEWER, Action.READ))

    def test_viewer_cannot_delete(self) -> None:
        self.assertFalse(self.ac.check(Role.VIEWER, Action.DELETE))

    def test_analyst_can_list_read_export(self) -> None:
        for action in (Action.LIST, Action.READ, Action.EXPORT):
            self.assertTrue(self.ac.check(Role.ANALYST, action))

    def test_analyst_cannot_acknowledge(self) -> None:
        self.assertFalse(self.ac.check(Role.ANALYST, Action.ACKNOWLEDGE))

    def test_analyst_cannot_manage_keys(self) -> None:
        self.assertFalse(self.ac.check(Role.ANALYST, Action.MANAGE_KEYS))

    def test_responder_can_acknowledge(self) -> None:
        self.assertTrue(self.ac.check(Role.RESPONDER, Action.ACKNOWLEDGE))

    def test_responder_cannot_configure(self) -> None:
        self.assertFalse(self.ac.check(Role.RESPONDER, Action.CONFIGURE))

    def test_admin_has_all_actions(self) -> None:
        for action in Action:
            self.assertTrue(self.ac.check(Role.ADMIN, action))

    def test_permitted_actions_viewer(self) -> None:
        actions = self.ac.permitted_actions(Role.VIEWER)
        self.assertIn(Action.LIST, actions)
        self.assertNotIn(Action.READ, actions)

    def test_permitted_actions_admin(self) -> None:
        actions = self.ac.permitted_actions(Role.ADMIN)
        self.assertEqual(actions, frozenset(Action))


class TestAccessControllerAssertPermitted(unittest.TestCase):
    """assert_permitted raises PermissionError on denied actions."""

    def setUp(self) -> None:
        self.ac = AccessController()

    def test_raises_permission_error_for_denied_action(self) -> None:
        with self.assertRaises(PermissionError):
            self.ac.assert_permitted(Role.VIEWER, Action.MANAGE_KEYS)

    def test_does_not_raise_for_allowed_action(self) -> None:
        # Should not raise
        self.ac.assert_permitted(Role.ADMIN, Action.DELETE, "report-001.bin", "admin")

    def test_error_message_contains_role_and_action(self) -> None:
        with self.assertRaises(PermissionError) as ctx:
            self.ac.assert_permitted(Role.ANALYST, Action.DELETE)
        msg = str(ctx.exception)
        self.assertIn("ANALYST", msg)
        self.assertIn("DELETE", msg)


class TestAccessControllerAuditLog(unittest.TestCase):
    """Audit log records every decision."""

    def setUp(self) -> None:
        self.ac = AccessController()

    def test_log_grows_on_each_check(self) -> None:
        self.ac.check(Role.ANALYST, Action.READ, "r1", "alice")
        self.ac.check(Role.VIEWER, Action.DELETE, "r2", "bob")
        self.assertEqual(len(self.ac.get_audit_log()), 2)

    def test_log_records_granted_true_for_allowed(self) -> None:
        self.ac.check(Role.ANALYST, Action.READ, "r1", "alice")
        entry = self.ac.get_audit_log()[0]
        self.assertTrue(entry.granted)

    def test_log_records_granted_false_for_denied(self) -> None:
        self.ac.check(Role.VIEWER, Action.DELETE, "r2", "bob")
        entry = self.ac.get_audit_log()[0]
        self.assertFalse(entry.granted)

    def test_clear_audit_log(self) -> None:
        self.ac.check(Role.ANALYST, Action.READ)
        self.ac.clear_audit_log()
        self.assertEqual(len(self.ac.get_audit_log()), 0)

    def test_audit_disabled_generates_no_log(self) -> None:
        ac = AccessController(audit_enabled=False)
        ac.check(Role.ADMIN, Action.DELETE)
        self.assertEqual(len(ac.get_audit_log()), 0)

    def test_audit_summary_counts_granted_denied(self) -> None:
        self.ac.check(Role.ANALYST, Action.READ)       # granted
        self.ac.check(Role.ANALYST, Action.READ)       # granted
        self.ac.check(Role.VIEWER,  Action.DELETE)     # denied
        summary = self.ac.audit_summary()
        self.assertEqual(summary["granted"], 2)
        self.assertEqual(summary["denied"], 1)
        self.assertEqual(summary["total"], 3)

    def test_audit_summary_most_denied_action(self) -> None:
        self.ac.check(Role.VIEWER, Action.DELETE)
        self.ac.check(Role.VIEWER, Action.DELETE)
        self.ac.check(Role.VIEWER, Action.MANAGE_KEYS)
        summary = self.ac.audit_summary()
        self.assertEqual(summary["most_denied_action"], "DELETE")

    def test_audit_summary_empty_log(self) -> None:
        summary = self.ac.audit_summary()
        self.assertEqual(summary["total"], 0)
        self.assertIsNone(summary["most_denied_action"])

    def test_get_audit_log_returns_copy(self) -> None:
        self.ac.check(Role.ANALYST, Action.READ)
        log1 = self.ac.get_audit_log()
        log1.clear()
        self.assertEqual(len(self.ac.get_audit_log()), 1)

    def test_access_request_str_contains_verdict(self) -> None:
        self.ac.check(Role.ANALYST, Action.READ, "report-x", "alice")
        entry = self.ac.get_audit_log()[0]
        text = str(entry)
        self.assertIn("GRANTED", text)
        self.assertIn("alice", text)


# ===========================================================================
# CIA Triad — Integrity: IntegrityMonitor
# ===========================================================================

from sentinel_weave.integrity_monitor import (
    IntegrityMonitor, AuditEntry, ChainVerificationResult,
)


class TestIntegrityMonitorEventSigning(unittest.TestCase):
    """HMAC event signing and verification."""

    def setUp(self) -> None:
        self.ea  = EventAnalyzer()
        self.mon = IntegrityMonitor(secret_key=b"test-key-32-bytes-exactly!!!!!!!!")

    def _event(self, text: str):
        return self.ea.parse(text)

    def test_sign_returns_64_char_hex(self) -> None:
        sig = self.mon.sign_event(self._event("Failed password for root"))
        self.assertEqual(len(sig), 64)
        int(sig, 16)  # must be valid hex

    def test_verify_valid_signature(self) -> None:
        ev  = self._event("Failed password for root from 10.0.0.1")
        sig = self.mon.sign_event(ev)
        self.assertTrue(self.mon.verify_event(ev, sig))

    def test_verify_detects_raw_tamper(self) -> None:
        ev  = self._event("Accepted publickey for alice")
        sig = self.mon.sign_event(ev)
        ev.raw = "Malicious replacement"
        self.assertFalse(self.mon.verify_event(ev, sig))

    def test_verify_detects_source_ip_tamper(self) -> None:
        ev  = self._event("Failed password for root from 10.0.0.1")
        sig = self.mon.sign_event(ev)
        ev.source_ip = "9.9.9.9"
        self.assertFalse(self.mon.verify_event(ev, sig))

    def test_verify_detects_severity_tamper(self) -> None:
        ev  = self._event("Failed password for root from 10.0.0.1")
        sig = self.mon.sign_event(ev)
        ev.severity = 0.0
        self.assertFalse(self.mon.verify_event(ev, sig))

    def test_verify_wrong_signature_string(self) -> None:
        ev = self._event("info: cron job started")
        self.assertFalse(self.mon.verify_event(ev, "a" * 64))

    def test_two_identical_events_have_same_signature(self) -> None:
        ev1 = self._event("Port scan detected from 192.168.1.1")
        ev2 = self._event("Port scan detected from 192.168.1.1")
        self.assertEqual(self.mon.sign_event(ev1), self.mon.sign_event(ev2))

    def test_different_secret_key_produces_different_signature(self) -> None:
        ev   = self._event("Failed password for root")
        mon2 = IntegrityMonitor(secret_key=b"different-key-32-bytes-exactly!!!")
        self.assertNotEqual(self.mon.sign_event(ev), mon2.sign_event(ev))


class TestIntegrityMonitorAuditChain(unittest.TestCase):
    """Audit chain construction and verification."""

    _CLOCK_VAL = ["2026-01-01T00:00:00+00:00"]

    def _clock(self) -> str:
        return self._CLOCK_VAL[0]

    def setUp(self) -> None:
        self.mon = IntegrityMonitor(
            secret_key=b"chain-key-32-bytes-exactly!!!!!!",
            clock=self._clock,
        )

    def test_empty_chain_verifies_valid(self) -> None:
        result = self.mon.verify_chain()
        self.assertTrue(result.valid)
        self.assertEqual(result.length, 0)

    def test_append_increases_chain_length(self) -> None:
        self.mon.append_to_chain({"action": "opened"}, subject="alice")
        self.assertEqual(self.mon.chain_length, 1)

    def test_first_entry_index_is_zero(self) -> None:
        entry = self.mon.append_to_chain({"x": 1})
        self.assertEqual(entry.index, 0)

    def test_second_entry_prev_hash_matches_first_entry_hash(self) -> None:
        e1 = self.mon.append_to_chain({"step": 1})
        e2 = self.mon.append_to_chain({"step": 2})
        self.assertEqual(e2.prev_hash, e1.entry_hash)

    def test_valid_chain_verifies(self) -> None:
        for i in range(5):
            self.mon.append_to_chain({"i": i}, subject="sys")
        result = self.mon.verify_chain()
        self.assertTrue(result.valid)
        self.assertEqual(result.length, 5)

    def test_tampered_data_breaks_chain(self) -> None:
        self.mon.append_to_chain({"action": "login"})
        self.mon.append_to_chain({"action": "read_report"})
        # Silently mutate first entry's data
        self.mon._chain[0].data["action"] = "wiped_logs"
        result = self.mon.verify_chain()
        self.assertFalse(result.valid)
        self.assertEqual(result.broken_at, 0)

    def test_tampered_prev_hash_breaks_chain(self) -> None:
        self.mon.append_to_chain({"step": 1})
        self.mon.append_to_chain({"step": 2})
        self.mon._chain[1].prev_hash = "a" * 64
        result = self.mon.verify_chain()
        self.assertFalse(result.valid)
        self.assertIsNotNone(result.broken_at)

    def test_export_chain_is_json_serialisable(self) -> None:
        self.mon.append_to_chain({"msg": "hello"}, subject="bot")
        exported = self.mon.export_chain()
        import json
        text = json.dumps(exported)  # must not raise
        self.assertIsInstance(text, str)

    def test_export_chain_has_correct_length(self) -> None:
        for i in range(3):
            self.mon.append_to_chain({"i": i})
        self.assertEqual(len(self.mon.export_chain()), 3)

    def test_get_chain_returns_copy(self) -> None:
        self.mon.append_to_chain({"x": 1})
        chain_copy = self.mon.get_chain()
        chain_copy.clear()
        self.assertEqual(self.mon.chain_length, 1)

    def test_verification_reason_contains_count(self) -> None:
        self.mon.append_to_chain({"a": 1})
        self.mon.append_to_chain({"b": 2})
        result = self.mon.verify_chain()
        self.assertIn("2", result.reason)


# ===========================================================================
# CIA Triad — Availability: TokenBucketRateLimiter & AvailabilityMonitor
# ===========================================================================

from sentinel_weave.availability_monitor import (
    TokenBucketRateLimiter, AvailabilityMonitor,
    AvailabilityAlert, AlertSeverity, RateLimitResult,
)


class TestTokenBucketRateLimiter(unittest.TestCase):
    """Token-bucket rate limiter behaviour."""

    def _make_clock(self, initial: float = 0.0):
        """Return a mutable clock list and a clock callable."""
        t = [initial]
        return t, lambda: t[0]

    def test_burst_allows_initial_requests(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=3.0, clock=clock)
        results = [limiter.check("ip") for _ in range(3)]
        self.assertTrue(all(r.allowed for r in results))

    def test_exceeding_burst_is_denied(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=3.0, clock=clock)
        for _ in range(3):
            limiter.check("ip")
        result = limiter.check("ip")
        self.assertFalse(result.allowed)

    def test_retry_after_seconds_positive_when_denied(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=1.0, clock=clock)
        limiter.check("ip")  # consume the single token
        result = limiter.check("ip")
        self.assertFalse(result.allowed)
        self.assertGreater(result.retry_after_seconds, 0.0)

    def test_tokens_replenish_over_time(self) -> None:
        t, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=2.0, burst=2.0, clock=clock)
        limiter.check("ip")
        limiter.check("ip")  # bucket empty
        t[0] = 1.0           # advance 1 second → 2 new tokens
        result = limiter.check("ip")
        self.assertTrue(result.allowed)

    def test_reset_restores_full_bucket(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=2.0, clock=clock)
        limiter.check("ip")
        limiter.check("ip")  # exhaust
        limiter.reset("ip")
        result = limiter.check("ip")
        self.assertTrue(result.allowed)

    def test_different_subjects_are_independent(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=1.0, clock=clock)
        limiter.check("ip-a")  # exhaust ip-a
        result_b = limiter.check("ip-b")
        self.assertTrue(result_b.allowed)

    def test_invalid_rate_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            TokenBucketRateLimiter(rate=0.0, burst=10.0)

    def test_invalid_burst_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            TokenBucketRateLimiter(rate=1.0, burst=-5.0)

    def test_bucket_state_returns_empty_for_unknown_subject(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=5.0, clock=clock)
        self.assertEqual(limiter.bucket_state("never-seen"), {})

    def test_bucket_state_after_check(self) -> None:
        _, clock = self._make_clock(0.0)
        limiter = TokenBucketRateLimiter(rate=1.0, burst=5.0, clock=clock)
        limiter.check("ip")
        state = limiter.bucket_state("ip")
        self.assertIn("tokens", state)
        self.assertLess(state["tokens"], 5.0)


class TestAvailabilityMonitorRates(unittest.TestCase):
    """Sliding-window event-rate monitoring."""

    def _make_clock(self, initial: float = 0.0):
        t = [initial]
        return t, lambda: t[0]

    def test_rate_below_threshold_returns_no_alert(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=10.0, rate_threshold=100.0, clock=clock)
        alert = monitor.record_event("ip", count=5)
        self.assertIsNone(alert)

    def test_rate_above_threshold_returns_alert(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=10.0, rate_threshold=5.0, clock=clock)
        alert = monitor.record_event("ip", count=100)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.alert_type, "RATE_EXCEEDED")

    def test_alert_contains_correct_subject(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=10.0, rate_threshold=1.0, clock=clock)
        alert = monitor.record_event("attacker-ip", count=50)
        self.assertEqual(alert.subject, "attacker-ip")

    def test_get_current_rate_zero_before_any_events(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=60.0, rate_threshold=100.0, clock=clock)
        self.assertEqual(monitor.get_current_rate("ip"), 0.0)

    def test_get_current_rate_reflects_recorded_events(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=10.0, rate_threshold=1000.0, clock=clock)
        monitor.record_event("ip", count=50)
        rate = monitor.get_current_rate("ip")
        self.assertAlmostEqual(rate, 5.0)  # 50 events / 10s window

    def test_old_events_evicted_from_window(self) -> None:
        t, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=10.0, rate_threshold=1000.0, clock=clock)
        monitor.record_event("ip", count=100)   # at t=0
        t[0] = 20.0                              # advance past window
        rate = monitor.get_current_rate("ip")
        self.assertEqual(rate, 0.0)

    def test_flush_alerts_clears_list(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(window_seconds=10.0, rate_threshold=1.0, clock=clock)
        monitor.record_event("ip", count=100)
        alerts = monitor.flush_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(len(monitor.get_alerts()), 0)

    def test_invalid_window_raises(self) -> None:
        with self.assertRaises(ValueError):
            AvailabilityMonitor(window_seconds=-1.0)

    def test_invalid_threshold_raises(self) -> None:
        with self.assertRaises(ValueError):
            AvailabilityMonitor(rate_threshold=0.0)


class TestAvailabilityMonitorHeartbeats(unittest.TestCase):
    """Service heartbeat tracking."""

    def _make_clock(self, initial: float = 0.0):
        t = [initial]
        return t, lambda: t[0]

    def test_fresh_heartbeat_not_flagged(self) -> None:
        t, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        monitor.heartbeat("detector")
        t[0] = 10.0  # 10s later
        alerts = monitor.check_services(max_age_seconds=30.0)
        self.assertEqual(len(alerts), 0)

    def test_stale_heartbeat_raises_alert(self) -> None:
        t, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        monitor.heartbeat("detector")
        t[0] = 120.0  # 2 minutes later — way past max_age
        alerts = monitor.check_services(max_age_seconds=30.0)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].alert_type, "SERVICE_DOWN")
        self.assertEqual(alerts[0].subject, "detector")

    def test_multiple_services_independent(self) -> None:
        t, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        monitor.heartbeat("svc-a")
        monitor.heartbeat("svc-b")
        t[0] = 100.0
        monitor.heartbeat("svc-b")  # renew svc-b
        t[0] = 110.0
        alerts = monitor.check_services(max_age_seconds=30.0)
        subjects = [a.subject for a in alerts]
        self.assertIn("svc-a", subjects)
        self.assertNotIn("svc-b", subjects)

    def test_registered_services_returns_sorted_list(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        monitor.heartbeat("zebra-svc")
        monitor.heartbeat("alpha-svc")
        svcs = monitor.registered_services()
        self.assertEqual(svcs, sorted(svcs))

    def test_invalid_max_age_raises(self) -> None:
        _, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        with self.assertRaises(ValueError):
            monitor.check_services(max_age_seconds=0.0)

    def test_critical_severity_for_very_stale_service(self) -> None:
        t, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        monitor.heartbeat("detector")
        t[0] = 1000.0  # far beyond 3× max_age
        alerts = monitor.check_services(max_age_seconds=30.0)
        self.assertEqual(alerts[0].severity, AlertSeverity.CRITICAL)

    def test_availability_alert_summary_is_string(self) -> None:
        t, clock = self._make_clock(0.0)
        monitor = AvailabilityMonitor(clock=clock)
        monitor.heartbeat("svc")
        t[0] = 200.0
        alerts = monitor.check_services(max_age_seconds=10.0)
        self.assertIsInstance(alerts[0].summary(), str)


if __name__ == "__main__":
    unittest.main()
