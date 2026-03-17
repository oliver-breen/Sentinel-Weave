"""
Tests for sentinel_weave.email_scanner
"""

from __future__ import annotations

import textwrap
import pytest

from sentinel_weave.email_scanner import (
    EmailScanner, EmailMessage, EmailScanResult, EmailIndicator,
)
from sentinel_weave.threat_detector import ThreatLevel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def scanner() -> EmailScanner:
    return EmailScanner()


# ---------------------------------------------------------------------------
# Raw RFC 5322 sample emails
# ---------------------------------------------------------------------------

_PHISHING_RAW = textwrap.dedent("""\
    From: PayPal Support <phisher@evil-domain.ru>
    To: victim@example.com
    Subject: Your account has been suspended - verify your account immediately
    Date: Fri, 13 Mar 2026 12:00:00 +0000
    Message-ID: <abc123@evil-domain.ru>

    Dear customer,

    We detected unusual sign-in activity on your account.
    You must respond within 24 hours or we will terminate your account.
    Please click here immediately to verify your account and avoid suspension:
    http://paypal-security-update.com/verify

    Do NOT ignore this email.
""")

_LEGITIMATE_RAW = textwrap.dedent("""\
    From: Alice <alice@company.com>
    To: Bob <bob@company.com>
    Subject: Meeting tomorrow at 10am
    Date: Fri, 13 Mar 2026 09:00:00 +0000
    Message-ID: <meeting123@company.com>

    Hi Bob,

    Just a reminder about our team meeting tomorrow at 10am in room 2B.

    Best,
    Alice
""")

_MALWARE_DELIVERY_RAW = textwrap.dedent("""\
    From: IT Helpdesk <admin@corp-it-support.tk>
    To: employee@company.com
    Subject: Action required: install security patch
    Date: Fri, 13 Mar 2026 08:00:00 +0000

    Dear valued member,

    Please download and run the attached security patch immediately.
    The file is named patch_update.exe.

    This is your final warning. Failure to install will lock your account.
""")

_SPOOFED_SENDER_RAW = textwrap.dedent("""\
    From: Microsoft Security <hacker@totally-not-microsoft.xyz>
    To: user@example.com
    Reply-To: harvest@data-collector.cn
    Subject: Confirm your password

    Please re-enter your password to continue using Office 365.
    Click the link: http://bit.ly/3xY9pQz
""")

_BATCH_EMAILS = [_PHISHING_RAW, _LEGITIMATE_RAW, _MALWARE_DELIVERY_RAW]


# ---------------------------------------------------------------------------
# EmailScanner.parse_raw
# ---------------------------------------------------------------------------

class TestParseRaw:
    def test_parses_subject(self, scanner):
        msg = scanner.parse_raw(_PHISHING_RAW)
        assert "suspended" in msg.subject.lower()

    def test_parses_sender(self, scanner):
        msg = scanner.parse_raw(_PHISHING_RAW)
        assert "paypal" in msg.sender.lower() or "phisher" in msg.sender.lower()

    def test_parses_body_text(self, scanner):
        msg = scanner.parse_raw(_PHISHING_RAW)
        assert "verify" in msg.body_text.lower() or "unusual" in msg.body_text.lower()

    def test_parses_reply_to(self, scanner):
        msg = scanner.parse_raw(_SPOOFED_SENDER_RAW)
        assert msg.reply_to != ""

    def test_fallback_on_plain_text(self, scanner):
        """Non-RFC5322 plain text should still produce a usable EmailMessage."""
        plain = "Hey, click http://bit.ly/win-prize to claim your free iPhone!"
        msg = scanner.parse_raw(plain)
        assert msg.body_text != "" or msg.raw_text != ""

    def test_empty_string_does_not_raise(self, scanner):
        msg = scanner.parse_raw("")
        assert isinstance(msg, EmailMessage)


# ---------------------------------------------------------------------------
# EmailScanner.scan — threat level classification
# ---------------------------------------------------------------------------

class TestScanThreatLevel:
    def test_phishing_email_is_high_or_critical(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        assert result.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL)

    def test_legitimate_email_is_benign_or_low(self, scanner):
        result = scanner.scan_raw(_LEGITIMATE_RAW)
        assert result.threat_level in (ThreatLevel.BENIGN, ThreatLevel.LOW)

    def test_malware_delivery_is_medium_or_above(self, scanner):
        result = scanner.scan_raw(_MALWARE_DELIVERY_RAW)
        assert result.threat_level in (
            ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL
        )

    def test_spoofed_sender_is_flagged(self, scanner):
        result = scanner.scan_raw(_SPOOFED_SENDER_RAW)
        assert result.threat_level in (
            ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL
        )

    def test_risk_score_in_range(self, scanner):
        for raw in [_PHISHING_RAW, _LEGITIMATE_RAW, _MALWARE_DELIVERY_RAW]:
            result = scanner.scan_raw(raw)
            assert 0.0 <= result.risk_score <= 1.0


# ---------------------------------------------------------------------------
# EmailScanResult helpers
# ---------------------------------------------------------------------------

class TestEmailScanResult:
    def test_safe_property_true_for_benign(self, scanner):
        result = scanner.scan_raw(_LEGITIMATE_RAW)
        # safe == True for BENIGN or LOW
        assert result.safe == (result.threat_level in (ThreatLevel.BENIGN, ThreatLevel.LOW))

    def test_safe_property_false_for_threat(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        if result.threat_level not in (ThreatLevel.BENIGN, ThreatLevel.LOW):
            assert not result.safe

    def test_str_representation(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        s = str(result)
        assert "THREAT" in s or "SAFE" in s

    def test_indicators_sorted_by_weight_descending(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        weights = [i.weight for i in result.indicators]
        assert weights == sorted(weights, reverse=True)

    def test_explanation_is_non_empty_string(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        assert isinstance(result.explanation, str) and len(result.explanation) > 10


# ---------------------------------------------------------------------------
# Individual detectors via scan_raw
# ---------------------------------------------------------------------------

class TestDetectors:
    def test_phishing_keywords_detected(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        names = {i.name for i in result.indicators}
        assert "PHISHING_KEYWORDS" in names

    def test_social_engineering_detected(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        names = {i.name for i in result.indicators}
        assert "SOCIAL_ENGINEERING" in names

    def test_suspicious_url_shortener(self, scanner):
        raw = "From: x@x.com\nSubject: win\n\nClick http://bit.ly/abc123 now"
        result = scanner.scan_raw(raw)
        names = {i.name for i in result.indicators}
        assert "SUSPICIOUS_URLS" in names

    def test_suspicious_ip_url(self, scanner):
        raw = "From: x@x.com\nSubject: update\n\nGo to http://192.168.1.100/login"
        result = scanner.scan_raw(raw)
        names = {i.name for i in result.indicators}
        assert "SUSPICIOUS_URLS" in names

    def test_sender_spoofing_brand_mismatch(self, scanner):
        result = scanner.scan_raw(_SPOOFED_SENDER_RAW)
        names = {i.name for i in result.indicators}
        assert "SENDER_SPOOFING" in names

    def test_lookalike_domain_detected(self, scanner):
        result = scanner.scan_raw(_PHISHING_RAW)
        names = {i.name for i in result.indicators}
        assert "LOOKALIKE_DOMAIN" in names

    def test_suspicious_exe_attachment(self, scanner):
        result = scanner.scan_raw(_MALWARE_DELIVERY_RAW)
        names = {i.name for i in result.indicators}
        assert "SUSPICIOUS_ATTACHMENTS" in names

    def test_header_anomaly_suspicious_tld(self, scanner):
        result = scanner.scan_raw(_MALWARE_DELIVERY_RAW)
        names = {i.name for i in result.indicators}
        assert "HEADER_ANOMALIES" in names

    def test_header_anomaly_missing_message_id(self, scanner):
        raw = "From: x@x.com\nSubject: test\n\nHello"
        result = scanner.scan_raw(raw)
        names = {i.name for i in result.indicators}
        assert "HEADER_ANOMALIES" in names

    def test_reply_to_domain_mismatch(self, scanner):
        result = scanner.scan_raw(_SPOOFED_SENDER_RAW)
        names = {i.name for i in result.indicators}
        assert "SENDER_SPOOFING" in names


# ---------------------------------------------------------------------------
# Batch scanning
# ---------------------------------------------------------------------------

class TestBatchScanning:
    def test_scan_bulk_returns_correct_count(self, scanner):
        msgs = [scanner.parse_raw(r) for r in _BATCH_EMAILS]
        results = scanner.scan_bulk(msgs)
        assert len(results) == 3

    def test_scan_bulk_raw_returns_correct_count(self, scanner):
        results = scanner.scan_bulk_raw(_BATCH_EMAILS)
        assert len(results) == 3

    def test_scan_bulk_each_is_email_scan_result(self, scanner):
        results = scanner.scan_bulk_raw(_BATCH_EMAILS)
        for r in results:
            assert isinstance(r, EmailScanResult)

    def test_empty_batch_returns_empty_list(self, scanner):
        assert scanner.scan_bulk_raw([]) == []


# ---------------------------------------------------------------------------
# Summarize
# ---------------------------------------------------------------------------

class TestSummarize:
    def test_summarize_empty(self):
        s = EmailScanner.summarize([])
        assert s["total"] == 0

    def test_summarize_total(self, scanner):
        results = scanner.scan_bulk_raw(_BATCH_EMAILS)
        s = EmailScanner.summarize(results)
        assert s["total"] == 3

    def test_summarize_safe_plus_threats_equals_total(self, scanner):
        results = scanner.scan_bulk_raw(_BATCH_EMAILS)
        s = EmailScanner.summarize(results)
        assert s["safe"] + s["threats"] == s["total"]

    def test_summarize_avg_risk_score_in_range(self, scanner):
        results = scanner.scan_bulk_raw(_BATCH_EMAILS)
        s = EmailScanner.summarize(results)
        assert 0.0 <= s["avg_risk_score"] <= 1.0

    def test_summarize_top_indicators_list(self, scanner):
        results = scanner.scan_bulk_raw(_BATCH_EMAILS)
        s = EmailScanner.summarize(results)
        assert isinstance(s["top_indicators"], list)


# ---------------------------------------------------------------------------
# Score aggregation formula
# ---------------------------------------------------------------------------

class TestScoreAggregation:
    def test_no_indicators_gives_zero(self, scanner):
        assert scanner._aggregate_score([]) == 0.0

    def test_single_indicator_gives_its_weight(self, scanner):
        ind = EmailIndicator("TEST", "desc", 0.5)
        score = scanner._aggregate_score([ind])
        assert abs(score - 0.5) < 1e-6

    def test_two_indicators_combine_super_additively(self, scanner):
        a = EmailIndicator("A", "d", 0.5)
        b = EmailIndicator("B", "d", 0.5)
        score = scanner._aggregate_score([a, b])
        # 1 - (1-0.5)*(1-0.5) = 0.75
        assert abs(score - 0.75) < 1e-6

    def test_score_never_exceeds_one(self, scanner):
        indicators = [EmailIndicator(f"X{i}", "d", 0.99) for i in range(10)]
        assert scanner._aggregate_score(indicators) <= 1.0


# ---------------------------------------------------------------------------
# __init__.py exports
# ---------------------------------------------------------------------------

def test_public_api_exports():
    import sentinel_weave as sw
    assert hasattr(sw, "EmailScanner")
    assert hasattr(sw, "EmailMessage")
    assert hasattr(sw, "EmailScanResult")
    assert hasattr(sw, "EmailIndicator")
