"""
Tests for ThreatQueryEngine — the threat hunting query language.

Validates:
- Field equality and comparison operators
- Wildcards (*) in string fields
- Substring (~) operator
- AND / OR boolean logic
- Parenthesised sub-expressions
- List-valued fields (signature, explanation)
- Empty query returns all reports
- Invalid field / operator raises ValueError
- ThreatQueryEngine.count() and ThreatQueryEngine.query_one()
"""

from __future__ import annotations

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.event_analyzer import EventAnalyzer
from sentinel_weave.threat_detector import ThreatDetector, ThreatLevel, ThreatReport
from sentinel_weave.threat_query import ThreatQueryEngine


# ---------------------------------------------------------------------------
# Helper: build a ThreatReport cheaply
# ---------------------------------------------------------------------------

_analyzer = EventAnalyzer()
_detector = ThreatDetector()


def _make_report(raw: str) -> ThreatReport:
    event = _analyzer.parse(raw)
    return _detector.analyze(event)


def _make_report_with_ip(raw: str, source_ip: str) -> ThreatReport:
    report = _make_report(raw)
    report.event.source_ip = source_ip
    return report


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

class TestThreatQueryEngineBasics(unittest.TestCase):
    """Basic field comparison and empty-query behaviour."""

    def setUp(self) -> None:
        self.low = _make_report("Login OK from 10.0.0.1")
        self.low.threat_level = ThreatLevel.LOW
        self.low.event.source_ip = "10.0.0.1"
        self.low.anomaly_score = 0.1

        self.high = _make_report("SSH brute-force from 192.168.1.5")
        self.high.threat_level = ThreatLevel.HIGH
        self.high.event.source_ip = "192.168.1.5"
        self.high.anomaly_score = 0.85
        self.high.event.matched_sigs = ["SSH_BRUTE_FORCE"]

        self.critical = _make_report("SQL injection attempt from 172.16.0.9")
        self.critical.threat_level = ThreatLevel.CRITICAL
        self.critical.event.source_ip = "172.16.0.9"
        self.critical.anomaly_score = 0.98
        self.critical.event.matched_sigs = ["SQL_INJECTION", "COMMAND_INJECTION"]

        self.engine = ThreatQueryEngine([self.low, self.high, self.critical])

    # ------ empty query returns all ------

    def test_empty_query_returns_all(self) -> None:
        self.assertEqual(len(self.engine.query("")), 3)

    def test_whitespace_only_query_returns_all(self) -> None:
        self.assertEqual(len(self.engine.query("   ")), 3)

    # ------ threat_level equality ------

    def test_threat_level_eq(self) -> None:
        results = self.engine.query("threat_level = HIGH")
        self.assertEqual(len(results), 1)
        self.assertIs(results[0], self.high)

    def test_threat_level_neq(self) -> None:
        results = self.engine.query("threat_level != LOW")
        self.assertEqual(len(results), 2)

    def test_threat_level_case_insensitive_value(self) -> None:
        results = self.engine.query("threat_level = high")
        self.assertEqual(len(results), 1)

    # ------ source_ip equality and wildcard ------

    def test_source_ip_exact(self) -> None:
        results = self.engine.query("source_ip = 192.168.1.5")
        self.assertEqual(len(results), 1)
        self.assertIs(results[0], self.high)

    def test_source_ip_wildcard(self) -> None:
        results = self.engine.query("source_ip = 10.0.*")
        self.assertEqual(len(results), 1)
        self.assertIs(results[0], self.low)

    def test_source_ip_wildcard_no_match(self) -> None:
        results = self.engine.query("source_ip = 1.2.3.*")
        self.assertEqual(len(results), 0)

    # ------ anomaly_score numeric comparison ------

    def test_anomaly_score_gt(self) -> None:
        results = self.engine.query("anomaly_score > 0.7")
        self.assertIn(self.high, results)
        self.assertIn(self.critical, results)
        self.assertNotIn(self.low, results)

    def test_anomaly_score_gte(self) -> None:
        results = self.engine.query("anomaly_score >= 0.85")
        self.assertIn(self.high, results)
        self.assertIn(self.critical, results)

    def test_anomaly_score_lt(self) -> None:
        results = self.engine.query("anomaly_score < 0.5")
        self.assertEqual(results, [self.low])

    def test_anomaly_score_eq(self) -> None:
        results = self.engine.query("anomaly_score = 0.1")
        self.assertEqual(results, [self.low])

    # ------ signature list field ------

    def test_signature_eq(self) -> None:
        results = self.engine.query("signature = SSH_BRUTE_FORCE")
        self.assertEqual(len(results), 1)
        self.assertIs(results[0], self.high)

    def test_signature_contains(self) -> None:
        results = self.engine.query("signature ~ INJECTION")
        # SQL_INJECTION and COMMAND_INJECTION both match
        self.assertEqual(len(results), 1)
        self.assertIs(results[0], self.critical)

    def test_signature_no_match(self) -> None:
        results = self.engine.query("signature = UNKNOWN_SIG")
        self.assertEqual(len(results), 0)


class TestThreatQueryEngineBooleans(unittest.TestCase):
    """AND / OR / parenthesised expressions."""

    def setUp(self) -> None:
        self.r1 = _make_report("port scan from 10.1.1.1")
        self.r1.threat_level = ThreatLevel.HIGH
        self.r1.event.source_ip = "10.1.1.1"
        self.r1.anomaly_score = 0.8

        self.r2 = _make_report("low noise from 10.1.1.2")
        self.r2.threat_level = ThreatLevel.LOW
        self.r2.event.source_ip = "10.1.1.2"
        self.r2.anomaly_score = 0.2

        self.r3 = _make_report("critical from external")
        self.r3.threat_level = ThreatLevel.CRITICAL
        self.r3.event.source_ip = "8.8.8.8"
        self.r3.anomaly_score = 0.99

        self.engine = ThreatQueryEngine([self.r1, self.r2, self.r3])

    def test_and_filters_both_conditions(self) -> None:
        results = self.engine.query("source_ip = 10.1.1.* AND threat_level = HIGH")
        self.assertEqual(results, [self.r1])

    def test_or_returns_union(self) -> None:
        results = self.engine.query("threat_level = HIGH OR threat_level = CRITICAL")
        self.assertIn(self.r1, results)
        self.assertIn(self.r3, results)
        self.assertNotIn(self.r2, results)

    def test_and_takes_precedence_over_or(self) -> None:
        # (HIGH AND 10.1.*) OR CRITICAL → r1 and r3
        results = self.engine.query(
            "threat_level = HIGH AND source_ip = 10.1.1.* OR threat_level = CRITICAL"
        )
        self.assertIn(self.r1, results)
        self.assertIn(self.r3, results)
        self.assertNotIn(self.r2, results)

    def test_parentheses_override_precedence(self) -> None:
        # HIGH OR (LOW AND 10.1.1.1) → r1 (HIGH), r2 (LOW∧10.1.1.2 → no)
        results = self.engine.query(
            "(threat_level = HIGH OR threat_level = LOW) AND source_ip = 10.1.1.1"
        )
        self.assertEqual(results, [self.r1])

    def test_nested_parens(self) -> None:
        results = self.engine.query(
            "(threat_level = HIGH OR threat_level = CRITICAL)"
            " AND (anomaly_score > 0.7)"
        )
        self.assertIn(self.r1, results)
        self.assertIn(self.r3, results)


class TestThreatQueryEngineSubstring(unittest.TestCase):
    """Substring (~) operator on raw log and explanation fields."""

    def setUp(self) -> None:
        self.r1 = _make_report("Failed password for root from 1.2.3.4")
        self.r1.explanation = ["Possible brute force detected"]

        self.r2 = _make_report("Accepted publickey for admin from 5.6.7.8")
        self.r2.explanation = ["Key-based authentication"]

        self.engine = ThreatQueryEngine([self.r1, self.r2])

    def test_raw_contains(self) -> None:
        results = self.engine.query("raw ~ password")
        self.assertEqual(results, [self.r1])

    def test_raw_contains_case_insensitive(self) -> None:
        results = self.engine.query("raw ~ PASSWORD")
        self.assertEqual(results, [self.r1])

    def test_explanation_contains(self) -> None:
        results = self.engine.query("explanation ~ brute")
        self.assertEqual(results, [self.r1])

    def test_no_match_returns_empty(self) -> None:
        results = self.engine.query("raw ~ NONEXISTENT_STRING_XYZ")
        self.assertEqual(results, [])


class TestThreatQueryEngineHelpers(unittest.TestCase):
    """count(), query_one(), add(), fields(), __len__()."""

    def setUp(self) -> None:
        self.r1 = _make_report("event one from 10.0.0.1")
        self.r1.threat_level = ThreatLevel.HIGH
        self.r2 = _make_report("event two from 10.0.0.2")
        self.r2.threat_level = ThreatLevel.LOW
        self.engine = ThreatQueryEngine([self.r1, self.r2])

    def test_len(self) -> None:
        self.assertEqual(len(self.engine), 2)

    def test_count_empty_query(self) -> None:
        self.assertEqual(self.engine.count(), 2)

    def test_count_filtered(self) -> None:
        self.assertEqual(self.engine.count("threat_level = HIGH"), 1)

    def test_query_one_returns_first(self) -> None:
        result = self.engine.query_one("threat_level = HIGH")
        self.assertIs(result, self.r1)

    def test_query_one_none(self) -> None:
        result = self.engine.query_one("threat_level = CRITICAL")
        self.assertIsNone(result)

    def test_add_expands_collection(self) -> None:
        r3 = _make_report("event three")
        r3.threat_level = ThreatLevel.CRITICAL
        self.engine.add(r3)
        self.assertEqual(len(self.engine), 3)
        self.assertEqual(self.engine.count("threat_level = CRITICAL"), 1)

    def test_fields_returns_list(self) -> None:
        fields = self.engine.fields()
        self.assertIn("threat_level", fields)
        self.assertIn("source_ip", fields)
        self.assertIn("anomaly_score", fields)
        self.assertIn("signature", fields)


class TestThreatQueryEngineErrors(unittest.TestCase):
    """Invalid queries raise ValueError."""

    def setUp(self) -> None:
        report = _make_report("test event")
        self.engine = ThreatQueryEngine([report])

    def test_unknown_field_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.query("nonexistent_field = foo")

    def test_missing_operator_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.engine.query("threat_level HIGH")

    def test_truncated_predicate_raises(self) -> None:
        with self.assertRaises((ValueError, IndexError)):
            self.engine.query("threat_level =")


if __name__ == "__main__":
    unittest.main()
