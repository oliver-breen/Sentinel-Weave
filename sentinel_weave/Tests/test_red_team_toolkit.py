"""
Tests for sentinel_weave.red_team_toolkit
==========================================

Covers all five components of the red-team toolkit:

- PortScanner:           scan(), open_ports(), scan_range(), _probe(), summarize_scan()
- ServiceFingerprinter:  fingerprint(), fingerprint_multiple(), _apply_rules()
- VulnerabilityAssessor: assess(), assess_multiple(), highest_severity()
- CredentialAuditor:     audit(), audit_bulk(), weak_passwords()
- ReconScanner:          recon(), recon_multiple(), _resolve(), _reverse_lookup()

Network-dependent tests (actual TCP connections) are avoided; socket calls are
mocked where necessary so the suite runs offline in CI.
"""

from __future__ import annotations

import socket
import sys
import os
import unittest
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.red_team_toolkit import (
    ADMIN_PORTS,
    COMMON_PORTS,
    DB_PORTS,
    WEB_PORTS,
    CredentialAuditor,
    PasswordAuditResult,
    PortScanResult,
    PortScanner,
    ReconResult,
    ReconScanner,
    ServiceFingerprintResult,
    ServiceFingerprinter,
    VulnerabilityAssessor,
    VulnerabilityFinding,
    summarize_scan,
)


# ===========================================================================
# Helpers shared across test cases
# ===========================================================================

def _mock_connected_socket(banner: bytes = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n"):
    """Return a context-manager mock simulating a successful TCP connection."""
    mock_sock = MagicMock()
    mock_sock.__enter__ = MagicMock(return_value=mock_sock)
    mock_sock.__exit__ = MagicMock(return_value=False)
    mock_sock.recv.return_value = banner
    mock_sock.settimeout = MagicMock()
    return mock_sock


def _mock_refused_socket():
    """Return a socket.create_connection that raises ConnectionRefusedError."""
    def _raise(*args, **kwargs):
        raise ConnectionRefusedError("Connection refused")
    return _raise


# ===========================================================================
# PortScanner
# ===========================================================================

class TestPortScannerDefaults(unittest.TestCase):
    """PortScanner default port list and construction."""

    def test_default_timeout(self) -> None:
        scanner = PortScanner()
        self.assertEqual(scanner.timeout, 1.0)

    def test_custom_timeout(self) -> None:
        scanner = PortScanner(timeout=0.5)
        self.assertEqual(scanner.timeout, 0.5)

    def test_default_banner_bytes(self) -> None:
        scanner = PortScanner()
        self.assertEqual(scanner.banner_bytes, 256)

    def test_common_ports_nonempty(self) -> None:
        self.assertGreater(len(COMMON_PORTS), 0)

    def test_web_ports_subset_of_common(self) -> None:
        for p in WEB_PORTS:
            self.assertIn(p, COMMON_PORTS)

    def test_admin_ports_subset_of_common(self) -> None:
        for p in ADMIN_PORTS:
            self.assertIn(p, COMMON_PORTS)

    def test_db_ports_subset_of_common(self) -> None:
        for p in DB_PORTS:
            self.assertIn(p, COMMON_PORTS)


class TestPortScannerProbeOpen(unittest.TestCase):
    """PortScanner._probe — open port."""

    def test_probe_returns_port_scan_result(self) -> None:
        scanner = PortScanner()
        mock_sock = _mock_connected_socket(b"SSH-2.0-OpenSSH_8.9\r\n")
        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner._probe("127.0.0.1", 22)
        self.assertIsInstance(result, PortScanResult)

    def test_probe_open_when_connected(self) -> None:
        scanner = PortScanner()
        mock_sock = _mock_connected_socket()
        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner._probe("127.0.0.1", 22)
        self.assertTrue(result.is_open)

    def test_probe_banner_captured(self) -> None:
        scanner = PortScanner()
        mock_sock = _mock_connected_socket(b"SSH-2.0-OpenSSH_8.9p1\r\n")
        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner._probe("127.0.0.1", 22)
        self.assertIn("OpenSSH", result.banner)

    def test_probe_service_hint_ssh(self) -> None:
        scanner = PortScanner()
        mock_sock = _mock_connected_socket()
        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner._probe("127.0.0.1", 22)
        self.assertEqual(result.service_hint, "SSH")

    def test_probe_service_hint_unknown_port(self) -> None:
        scanner = PortScanner()
        mock_sock = _mock_connected_socket(b"")
        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner._probe("127.0.0.1", 9999)
        self.assertEqual(result.service_hint, "UNKNOWN")

    def test_probe_host_and_port_preserved(self) -> None:
        scanner = PortScanner()
        mock_sock = _mock_connected_socket()
        with patch("socket.create_connection", return_value=mock_sock):
            result = scanner._probe("10.0.0.1", 80)
        self.assertEqual(result.host, "10.0.0.1")
        self.assertEqual(result.port, 80)


class TestPortScannerProbeClosed(unittest.TestCase):
    """PortScanner._probe — closed / refused port."""

    def test_probe_closed_not_open(self) -> None:
        scanner = PortScanner()
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = scanner._probe("127.0.0.1", 9999)
        self.assertFalse(result.is_open)

    def test_probe_closed_empty_banner(self) -> None:
        scanner = PortScanner()
        with patch("socket.create_connection", side_effect=ConnectionRefusedError()):
            result = scanner._probe("127.0.0.1", 9999)
        self.assertEqual(result.banner, "")

    def test_probe_oserror_recorded(self) -> None:
        scanner = PortScanner()
        with patch("socket.create_connection", side_effect=OSError("timeout")):
            result = scanner._probe("10.0.0.1", 22)
        self.assertFalse(result.is_open)
        self.assertIn("timeout", result.error)


class TestPortScannerScan(unittest.TestCase):
    """PortScanner.scan() and open_ports() high-level API."""

    def _make_scanner_mock_open(self, ports: list[int]):
        """Return a PortScanner whose _probe always returns open for given ports."""
        scanner = PortScanner()

        def mock_probe(host, port):
            return PortScanResult(
                host=host,
                port=port,
                is_open=port in ports,
                service_hint="SSH" if port == 22 else "HTTP",
            )

        scanner._probe = mock_probe
        return scanner

    def test_scan_returns_list(self) -> None:
        scanner = self._make_scanner_mock_open([22])
        results = scanner.scan("127.0.0.1", ports=[22, 80])
        self.assertIsInstance(results, list)

    def test_scan_result_count_matches_ports(self) -> None:
        scanner = self._make_scanner_mock_open([22, 80])
        results = scanner.scan("127.0.0.1", ports=[22, 80, 443])
        self.assertEqual(len(results), 3)

    def test_scan_open_ports_correct(self) -> None:
        scanner = self._make_scanner_mock_open([22, 80])
        open_list = scanner.open_ports("127.0.0.1", ports=[22, 80, 443])
        self.assertIn(22, open_list)
        self.assertIn(80, open_list)
        self.assertNotIn(443, open_list)

    def test_scan_range_correct_count(self) -> None:
        scanner = self._make_scanner_mock_open([])
        results = scanner.scan_range("127.0.0.1", 20, 25)
        # ports 20,21,22,23,24,25 = 6
        self.assertEqual(len(results), 6)

    def test_scan_default_ports_used_when_none_given(self) -> None:
        scanner = self._make_scanner_mock_open([])
        results = scanner.scan("127.0.0.1")
        self.assertEqual(len(results), len(COMMON_PORTS))

    def test_scan_port_range_overrides_ports(self) -> None:
        scanner = self._make_scanner_mock_open([])
        results = scanner.scan("127.0.0.1", port_range=(100, 105))
        self.assertEqual(len(results), 6)


class TestSummarizeScan(unittest.TestCase):
    """summarize_scan() helper."""

    def test_empty_returns_empty_dict(self) -> None:
        self.assertEqual(summarize_scan([]), {})

    def test_open_count(self) -> None:
        results = [
            PortScanResult("h", 22, is_open=True,  service_hint="SSH"),
            PortScanResult("h", 80, is_open=False, service_hint="HTTP"),
            PortScanResult("h", 443, is_open=True, service_hint="HTTPS"),
        ]
        summary = summarize_scan(results)
        self.assertEqual(summary["open_count"], 2)

    def test_total_probed(self) -> None:
        results = [
            PortScanResult("h", 22, is_open=True),
            PortScanResult("h", 80, is_open=False),
        ]
        self.assertEqual(summarize_scan(results)["total_probed"], 2)

    def test_open_ports_list(self) -> None:
        results = [
            PortScanResult("h", 22, is_open=True),
            PortScanResult("h", 80, is_open=False),
        ]
        summary = summarize_scan(results)
        self.assertIn(22, summary["open_ports"])
        self.assertNotIn(80, summary["open_ports"])

    def test_services_dict_populated(self) -> None:
        results = [PortScanResult("h", 22, is_open=True, service_hint="SSH")]
        summary = summarize_scan(results)
        self.assertEqual(summary["services"][22], "SSH")

    def test_host_captured(self) -> None:
        results = [PortScanResult("10.0.0.1", 22, is_open=True)]
        self.assertEqual(summarize_scan(results)["host"], "10.0.0.1")


# ===========================================================================
# ServiceFingerprinter
# ===========================================================================

class TestServiceFingerprinter(unittest.TestCase):
    """ServiceFingerprinter._apply_rules() and fingerprint()."""

    def setUp(self) -> None:
        self.fp = ServiceFingerprinter()

    def _fingerprint_with_banner(self, port: int, banner: str) -> ServiceFingerprintResult:
        """Run fingerprinting with a pre-set banner without touching the network."""
        result = ServiceFingerprintResult(host="127.0.0.1", port=port, raw_banner=banner)
        self.fp._apply_rules(result)
        return result

    def test_openssh_detected(self) -> None:
        r = self._fingerprint_with_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertEqual(r.service_name, "OpenSSH")

    def test_openssh_version_extracted(self) -> None:
        r = self._fingerprint_with_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertEqual(r.service_version, "8.9p1")

    def test_openssh_os_ubuntu(self) -> None:
        r = self._fingerprint_with_banner(22, "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")
        self.assertIn("Ubuntu", r.os_hint)

    def test_apache_detected(self) -> None:
        r = self._fingerprint_with_banner(80, "Server: Apache/2.4.54 (Debian)")
        self.assertEqual(r.service_name, "Apache httpd")

    def test_apache_version_extracted(self) -> None:
        r = self._fingerprint_with_banner(80, "Server: Apache/2.4.54 (Debian)")
        self.assertEqual(r.service_version, "2.4.54")

    def test_nginx_detected(self) -> None:
        r = self._fingerprint_with_banner(80, "Server: nginx/1.22.1")
        self.assertEqual(r.service_name, "nginx")

    def test_nginx_version(self) -> None:
        r = self._fingerprint_with_banner(80, "Server: nginx/1.22.1")
        self.assertEqual(r.service_version, "1.22.1")

    def test_iis_detected(self) -> None:
        r = self._fingerprint_with_banner(80, "Server: Microsoft-IIS/10.0")
        self.assertEqual(r.service_name, "Microsoft IIS")

    def test_iis_version(self) -> None:
        r = self._fingerprint_with_banner(80, "Server: Microsoft-IIS/10.0")
        self.assertEqual(r.service_version, "10.0")

    def test_vsftpd_detected(self) -> None:
        r = self._fingerprint_with_banner(21, "220 (vsftpd 3.0.3)")
        self.assertEqual(r.service_name, "vsftpd")

    def test_redis_detected(self) -> None:
        r = self._fingerprint_with_banner(6379, "redis_version:7.0.5\r\nredis_mode:standalone")
        self.assertEqual(r.service_name, "Redis")

    def test_unknown_service_fallback(self) -> None:
        r = self._fingerprint_with_banner(9999, "SomeUnknownDaemon/1.0 ready")
        # Should use first banner line as name (not "UNKNOWN" since banner present)
        self.assertNotEqual(r.service_name, "")

    def test_empty_banner_gives_unknown(self) -> None:
        result = ServiceFingerprintResult(host="h", port=9999, raw_banner="")
        self.fp._apply_rules(result)
        self.assertEqual(result.service_name, "UNKNOWN")

    def test_fingerprint_multiple_returns_list(self) -> None:
        with patch.object(self.fp, "_grab_banner", return_value="Server: nginx/1.22.1"):
            results = self.fp.fingerprint_multiple("127.0.0.1", [80, 443])
        self.assertEqual(len(results), 2)

    def test_fingerprint_result_type(self) -> None:
        with patch.object(self.fp, "_grab_banner", return_value="Server: nginx/1.22.1"):
            result = self.fp.fingerprint("127.0.0.1", 80)
        self.assertIsInstance(result, ServiceFingerprintResult)


# ===========================================================================
# VulnerabilityAssessor
# ===========================================================================

class TestVulnerabilityAssessor(unittest.TestCase):
    """VulnerabilityAssessor.assess() pattern matching."""

    def setUp(self) -> None:
        self.assessor = VulnerabilityAssessor()

    def test_returns_list(self) -> None:
        findings = self.assessor.assess("Server: nginx/1.22.0")
        self.assertIsInstance(findings, list)

    def test_openssh_rce_cve_matched(self) -> None:
        # OpenSSH < 9.3p2 → CVE-2023-38408
        findings = self.assessor.assess("SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2023-38408", cve_ids)

    def test_finding_has_required_fields(self) -> None:
        findings = self.assessor.assess("SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        self.assertTrue(len(findings) > 0)
        f = findings[0]
        self.assertIsInstance(f, VulnerabilityFinding)
        self.assertIsInstance(f.cve_id, str)
        self.assertIsInstance(f.severity, str)
        self.assertIsInstance(f.cvss_score, float)
        self.assertIsInstance(f.description, str)

    def test_apache_49_critical_matched(self) -> None:
        findings = self.assessor.assess("Server: Apache/2.4.49 (Unix)")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2021-41773", cve_ids)

    def test_apache_50_critical_matched(self) -> None:
        findings = self.assessor.assess("Server: Apache/2.4.50 (Unix)")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2021-42013", cve_ids)

    def test_vsftpd_backdoor_matched(self) -> None:
        findings = self.assessor.assess("220 (vsftpd 2.3.4)")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2011-2523", cve_ids)

    def test_vsftpd_backdoor_is_critical(self) -> None:
        findings = self.assessor.assess("220 (vsftpd 2.3.4)")
        by_cve = {f.cve_id: f for f in findings}
        self.assertEqual(by_cve["CVE-2011-2523"].severity, "CRITICAL")

    def test_redis_cve_matched(self) -> None:
        findings = self.assessor.assess("redis_version:6.2.5\r\nredis_mode:standalone")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2022-0543", cve_ids)

    def test_iis_10_critical(self) -> None:
        findings = self.assessor.assess("Server: Microsoft-IIS/10.0")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("CVE-2022-21907", cve_ids)

    def test_telnet_flagged(self) -> None:
        findings = self.assessor.assess("Welcome to telnet server")
        cve_ids = [f.cve_id for f in findings]
        self.assertIn("ISSUE-TELNET-PLAINTEXT", cve_ids)

    def test_no_findings_for_clean_banner(self) -> None:
        # A banner with no recognisable vulnerable version
        findings = self.assessor.assess("Custom daemon v42 ready")
        self.assertEqual(findings, [])

    def test_assess_multiple_returns_nested_list(self) -> None:
        results = self.assessor.assess_multiple([
            "SSH-2.0-OpenSSH_8.9p1",
            "Custom daemon v42 ready",
        ])
        self.assertEqual(len(results), 2)
        self.assertGreater(len(results[0]), 0)   # first has findings
        self.assertEqual(results[1], [])          # second is clean

    def test_highest_severity_critical(self) -> None:
        findings = self.assessor.assess("220 (vsftpd 2.3.4)")
        hs = VulnerabilityAssessor.highest_severity(findings)
        self.assertEqual(hs, "CRITICAL")

    def test_highest_severity_none_on_empty(self) -> None:
        hs = VulnerabilityAssessor.highest_severity([])
        self.assertEqual(hs, "NONE")

    def test_match_token_populated(self) -> None:
        findings = self.assessor.assess("220 (vsftpd 2.3.4)")
        found = [f for f in findings if f.cve_id == "CVE-2011-2523"]
        self.assertTrue(len(found) > 0)
        self.assertNotEqual(found[0].match_token, "")

    def test_cvss_score_in_range(self) -> None:
        findings = self.assessor.assess("SSH-2.0-OpenSSH_8.9p1 Ubuntu")
        for f in findings:
            self.assertGreaterEqual(f.cvss_score, 0.0)
            self.assertLessEqual(f.cvss_score, 10.0)


# ===========================================================================
# CredentialAuditor
# ===========================================================================

class TestCredentialAuditorStrength(unittest.TestCase):
    """CredentialAuditor.audit() strength ratings and entropy."""

    def setUp(self) -> None:
        self.auditor = CredentialAuditor()

    def test_returns_audit_result(self) -> None:
        result = self.auditor.audit("SomeP@ssw0rd!")
        self.assertIsInstance(result, PasswordAuditResult)

    def test_strong_password_rated_correctly(self) -> None:
        result = self.auditor.audit("X7#mP9!qLzR3@wN6")
        self.assertIn(result.strength, ("STRONG", "VERY_STRONG"))

    def test_very_weak_all_digits(self) -> None:
        result = self.auditor.audit("12345678")
        self.assertIn(result.strength, ("VERY_WEAK", "WEAK"))

    def test_very_weak_short(self) -> None:
        result = self.auditor.audit("abc")
        self.assertEqual(result.strength, "VERY_WEAK")

    def test_common_password_flagged(self) -> None:
        result = self.auditor.audit("password123")
        self.assertTrue(result.is_common)

    def test_keyboard_walk_flagged(self) -> None:
        result = self.auditor.audit("qwerty123")
        self.assertTrue(result.is_common)

    def test_strong_password_not_common(self) -> None:
        result = self.auditor.audit("X7#mP9!qLzR3@wN6")
        self.assertFalse(result.is_common)

    def test_length_correct(self) -> None:
        pw = "AbCdEf12!@"
        result = self.auditor.audit(pw)
        self.assertEqual(result.length, len(pw))

    def test_entropy_positive(self) -> None:
        result = self.auditor.audit("SomeP@ssw0rd!")
        self.assertGreater(result.entropy_bits, 0)

    def test_empty_password_entropy_zero(self) -> None:
        result = self.auditor.audit("")
        self.assertEqual(result.entropy_bits, 0.0)

    def test_password_not_stored_plaintext(self) -> None:
        pw = "SuperSecret99!"
        result = self.auditor.audit(pw)
        # The result should store a hash, not the plaintext
        self.assertNotEqual(result.password_hash, pw)
        self.assertEqual(len(result.password_hash), 64)   # SHA-256 hex = 64 chars

    def test_issues_list_for_weak_password(self) -> None:
        result = self.auditor.audit("abc")
        self.assertGreater(len(result.issues), 0)

    def test_suggestions_nonempty_for_weak(self) -> None:
        result = self.auditor.audit("abc")
        self.assertGreater(len(result.suggestions), 0)

    def test_no_uppercase_flagged(self) -> None:
        result = self.auditor.audit("alllowercase1!")
        issues_text = " ".join(result.issues)
        self.assertIn("uppercase", issues_text.lower())

    def test_no_digits_flagged(self) -> None:
        result = self.auditor.audit("AllLettersNoNumbers!")
        issues_text = " ".join(result.issues)
        self.assertIn("digit", issues_text.lower())

    def test_no_special_chars_flagged(self) -> None:
        result = self.auditor.audit("NoSpecial1234")
        issues_text = " ".join(result.issues)
        self.assertIn("special", issues_text.lower())

    def test_audit_bulk_returns_list(self) -> None:
        results = self.auditor.audit_bulk(["abc", "X7#mP9!qLzR3@wN6"])
        self.assertEqual(len(results), 2)

    def test_audit_bulk_each_is_result(self) -> None:
        results = self.auditor.audit_bulk(["abc", "X7#mP9!qLzR3@wN6"])
        for r in results:
            self.assertIsInstance(r, PasswordAuditResult)

    def test_weak_passwords_returns_weak_only(self) -> None:
        passwords = ["abc", "X7#mP9!qLzR3@wN6", "123"]
        weak = self.auditor.weak_passwords(passwords)
        for idx, result in weak:
            self.assertIn(result.strength, ("VERY_WEAK", "WEAK"))

    def test_weak_passwords_index_correct(self) -> None:
        passwords = ["abc", "X7#mP9!qLzR3@wN6", "123"]
        weak = self.auditor.weak_passwords(passwords)
        weak_indices = [idx for idx, _ in weak]
        self.assertIn(0, weak_indices)   # "abc" is weak
        self.assertIn(2, weak_indices)   # "123" is weak
        self.assertNotIn(1, weak_indices)  # strong password should not be in weak

    def test_year_suffix_flagged(self) -> None:
        result = self.auditor.audit("password2023")
        # Should either flag common pattern OR low entropy
        self.assertGreater(len(result.issues), 0)

    def test_entropy_higher_for_longer_complex(self) -> None:
        short = self.auditor.audit("abc")
        long_complex = self.auditor.audit("X7#mP9!qLzR3@wN6$hJ2")
        self.assertGreater(long_complex.entropy_bits, short.entropy_bits)


# ===========================================================================
# ReconScanner
# ===========================================================================

class TestReconScanner(unittest.TestCase):
    """ReconScanner with mocked DNS lookups."""

    def setUp(self) -> None:
        self.recon = ReconScanner(timeout=1.0)

    def test_returns_recon_result(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["93.184.216.34"]):
            with patch.object(self.recon, "_reverse_lookup", return_value="example.com"):
                result = self.recon.recon("example.com")
        self.assertIsInstance(result, ReconResult)

    def test_target_preserved(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["93.184.216.34"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("example.com")
        self.assertEqual(result.target, "example.com")

    def test_resolved_ips_populated(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["1.2.3.4"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("example.com")
        self.assertIn("1.2.3.4", result.resolved_ips)

    def test_reverse_hostname_populated(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["1.2.3.4"]):
            with patch.object(self.recon, "_reverse_lookup", return_value="host.example.com"):
                result = self.recon.recon("example.com")
        self.assertIn("host.example.com", result.reverse_hostnames)

    def test_ip_version_ipv4(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["93.184.216.34"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("example.com")
        self.assertEqual(result.ip_version, "IPv4")

    def test_private_ip_flagged(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["192.168.1.1"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("internal.host")
        self.assertTrue(result.is_private)

    def test_public_ip_not_private(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["93.184.216.34"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("example.com")
        self.assertFalse(result.is_private)

    def test_empty_resolved_returns_early(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=[]):
            result = self.recon.recon("nonexistent.invalid")
        self.assertEqual(result.resolved_ips, [])
        self.assertEqual(result.ip_version, "")

    def test_metadata_primary_ip(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["10.0.0.5"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("internal")
        self.assertEqual(result.metadata["primary_ip"], "10.0.0.5")

    def test_metadata_total_ips(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["1.2.3.4", "5.6.7.8"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                result = self.recon.recon("dual-stack.example.com")
        self.assertEqual(result.metadata["total_ips"], 2)

    def test_recon_multiple_returns_list(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["1.2.3.4"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                results = self.recon.recon_multiple(["host1", "host2"])
        self.assertEqual(len(results), 2)

    def test_recon_multiple_each_is_recon_result(self) -> None:
        with patch.object(self.recon, "_resolve", return_value=["1.2.3.4"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                results = self.recon.recon_multiple(["host1", "host2"])
        for r in results:
            self.assertIsInstance(r, ReconResult)

    def test_quick_probe_ports_finds_open(self) -> None:
        mock_result = PortScanResult(host="1.2.3.4", port=22, is_open=True)
        with patch.object(self.recon, "_resolve", return_value=["1.2.3.4"]):
            with patch.object(self.recon, "_reverse_lookup", return_value=""):
                with patch(
                    "sentinel_weave.red_team_toolkit.PortScanner._probe",
                    return_value=mock_result,
                ):
                    result = self.recon.recon("example.com", quick_probe_ports=[22])
        self.assertIn(22, result.open_ports_hint)

    def test_resolve_returns_empty_on_error(self) -> None:
        with patch("socket.getaddrinfo", side_effect=socket.gaierror("no such host")):
            ips = self.recon._resolve("nonexistent.invalid")
        self.assertEqual(ips, [])

    def test_reverse_lookup_returns_empty_on_error(self) -> None:
        with patch("socket.gethostbyaddr", side_effect=socket.herror()):
            hostname = self.recon._reverse_lookup("1.2.3.4")
        self.assertEqual(hostname, "")


# ===========================================================================
# Public API import test
# ===========================================================================

class TestPublicApiImport(unittest.TestCase):
    """Verify that all new symbols are importable from sentinel_weave directly."""

    def test_port_scanner_importable(self) -> None:
        from sentinel_weave import PortScanner as PS  # noqa: F401
        self.assertIsNotNone(PS)

    def test_vulnerability_assessor_importable(self) -> None:
        from sentinel_weave import VulnerabilityAssessor as VA  # noqa: F401
        self.assertIsNotNone(VA)

    def test_credential_auditor_importable(self) -> None:
        from sentinel_weave import CredentialAuditor as CA  # noqa: F401
        self.assertIsNotNone(CA)

    def test_recon_scanner_importable(self) -> None:
        from sentinel_weave import ReconScanner as RS  # noqa: F401
        self.assertIsNotNone(RS)

    def test_service_fingerprinter_importable(self) -> None:
        from sentinel_weave import ServiceFingerprinter as SF  # noqa: F401
        self.assertIsNotNone(SF)

    def test_summarize_scan_importable(self) -> None:
        from sentinel_weave import summarize_scan as ss  # noqa: F401
        self.assertIsNotNone(ss)

    def test_constant_lists_importable(self) -> None:
        from sentinel_weave import COMMON_PORTS, WEB_PORTS, DB_PORTS, ADMIN_PORTS  # noqa: F401
        self.assertIsInstance(COMMON_PORTS, list)
        self.assertIsInstance(WEB_PORTS, list)


if __name__ == "__main__":
    unittest.main()
