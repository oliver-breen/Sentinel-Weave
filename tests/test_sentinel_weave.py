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


if __name__ == "__main__":
    unittest.main()
