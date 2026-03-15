"""
Tests for FederatedIntelHub — peer-to-peer encrypted threat-intel sharing.

Validates:
- Node identity and key generation
- Peer registration and removal
- create_summary: encrypts a bundle we can round-trip
- receive_bundle: decrypts and stores ThreatIntelSummary correctly
- HMAC authentication: tampered ciphertext raises ValueError
- Unknown sender raises KeyError
- summary_stats() aggregation
- list_summaries() / get_summary() helpers
- Wrong key raises ValueError (decryption failure)
"""

from __future__ import annotations

import json
import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.event_analyzer import EventAnalyzer
from sentinel_weave.threat_detector import ThreatDetector, ThreatLevel, ThreatReport
from sentinel_weave.federated_intel import (
    FederatedIntelHub,
    ThreatIntelSummary,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_analyzer = EventAnalyzer()
_detector = ThreatDetector()


def _make_reports(n: int = 3) -> list[ThreatReport]:
    templates = [
        "SSH brute force from 10.0.0.1",
        "SQL injection from 192.168.1.5",
        "Port scan from 172.16.0.9",
        "HTTP flood from 8.8.8.8",
        "Privilege escalation from 10.10.10.1",
    ]
    reports = []
    for i in range(n):
        event = _analyzer.parse(templates[i % len(templates)])
        report = _detector.analyze(event)
        # force some variety in threat levels
        level_list = [
            ThreatLevel.LOW,
            ThreatLevel.HIGH,
            ThreatLevel.CRITICAL,
            ThreatLevel.MEDIUM,
        ]
        report.threat_level = level_list[i % len(level_list)]
        report.anomaly_score = 0.1 + 0.2 * (i % 5)
        reports.append(report)
    return reports


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestFederatedIntelHubIdentity(unittest.TestCase):
    """Node ID and key generation."""

    def test_default_node_id_is_uuid_string(self) -> None:
        hub = FederatedIntelHub()
        self.assertIsInstance(hub.node_id, str)
        self.assertEqual(len(hub.node_id), 36)  # UUID format

    def test_custom_node_id(self) -> None:
        hub = FederatedIntelHub(node_id="my-node")
        self.assertEqual(hub.node_id, "my-node")

    def test_generate_shared_key_is_32_bytes(self) -> None:
        key = FederatedIntelHub.generate_shared_key()
        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_generate_shared_key_is_random(self) -> None:
        k1 = FederatedIntelHub.generate_shared_key()
        k2 = FederatedIntelHub.generate_shared_key()
        self.assertNotEqual(k1, k2)


class TestFederatedIntelHubPeers(unittest.TestCase):
    """Peer registration and removal."""

    def setUp(self) -> None:
        self.hub = FederatedIntelHub(node_id="hub-a")
        self.key = FederatedIntelHub.generate_shared_key()

    def test_register_peer(self) -> None:
        self.hub.register_peer("peer-1", self.key)
        self.assertIn("peer-1", self.hub.list_peers())

    def test_register_peer_invalid_key_raises(self) -> None:
        with self.assertRaises(ValueError):
            self.hub.register_peer("bad-peer", b"short")

    def test_remove_peer(self) -> None:
        self.hub.register_peer("peer-1", self.key)
        self.hub.remove_peer("peer-1")
        self.assertNotIn("peer-1", self.hub.list_peers())

    def test_remove_nonexistent_peer_is_silent(self) -> None:
        self.hub.remove_peer("ghost")  # should not raise

    def test_get_peer_returns_node(self) -> None:
        self.hub.register_peer("peer-1", self.key)
        peer = self.hub.get_peer("peer-1")
        self.assertIsNotNone(peer)
        self.assertEqual(peer.node_id, "peer-1")

    def test_get_peer_unknown_returns_none(self) -> None:
        self.assertIsNone(self.hub.get_peer("unknown"))


class TestFederatedIntelHubRoundTrip(unittest.TestCase):
    """create_summary / receive_bundle round-trip."""

    def setUp(self) -> None:
        self.hub_a = FederatedIntelHub(node_id="node-a")
        self.hub_b = FederatedIntelHub(node_id="node-b")
        self.key = FederatedIntelHub.generate_shared_key()
        self.hub_a.register_peer("node-b", self.key)
        self.hub_b.register_peer("node-a", self.key)
        self.reports = _make_reports(5)

    def test_create_summary_returns_bytes(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        self.assertIsInstance(bundle, bytes)

    def test_bundle_is_valid_json(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        parsed = json.loads(bundle)
        self.assertIn("sender_id", parsed)
        self.assertIn("ciphertext", parsed)
        self.assertIn("hmac", parsed)

    def test_bundle_sender_id_correct(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        parsed = json.loads(bundle)
        self.assertEqual(parsed["sender_id"], "node-a")

    def test_receive_bundle_returns_summary(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        summary = self.hub_b.receive_bundle(bundle)
        self.assertIsInstance(summary, ThreatIntelSummary)

    def test_receive_preserves_event_count(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        summary = self.hub_b.receive_bundle(bundle)
        self.assertEqual(summary.total_events, len(self.reports))

    def test_receive_preserves_sender_id(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        summary = self.hub_b.receive_bundle(bundle)
        self.assertEqual(summary.sender_id, "node-a")

    def test_receive_stores_summary(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        self.hub_b.receive_bundle(bundle)
        summaries = self.hub_b.list_summaries()
        self.assertEqual(len(summaries), 1)

    def test_threat_counts_populated(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        summary = self.hub_b.receive_bundle(bundle)
        self.assertIsInstance(summary.threat_counts, dict)
        total = sum(summary.threat_counts.values())
        self.assertEqual(total, len(self.reports))

    def test_max_anomaly_correct(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        summary = self.hub_b.receive_bundle(bundle)
        expected = max(r.anomaly_score for r in self.reports)
        self.assertAlmostEqual(summary.max_anomaly, expected, places=6)

    def test_metadata_round_trips(self) -> None:
        meta = {"region": "eu-west", "version": "0.4.0"}
        bundle = self.hub_a.create_summary(
            self.reports, peer_id="node-b", metadata=meta
        )
        summary = self.hub_b.receive_bundle(bundle)
        self.assertEqual(summary.metadata["region"], "eu-west")


class TestFederatedIntelHubSecurity(unittest.TestCase):
    """HMAC authentication and wrong-key scenarios."""

    def setUp(self) -> None:
        self.hub_a = FederatedIntelHub(node_id="node-a")
        self.hub_b = FederatedIntelHub(node_id="node-b")
        self.key = FederatedIntelHub.generate_shared_key()
        self.hub_a.register_peer("node-b", self.key)
        self.hub_b.register_peer("node-a", self.key)
        self.reports = _make_reports(2)

    def test_tampered_ciphertext_raises(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        parsed = json.loads(bundle)
        # Flip a nibble in the ciphertext
        ct = parsed["ciphertext"]
        flipped = ("f" if ct[0] != "f" else "0") + ct[1:]
        parsed["ciphertext"] = flipped
        tampered = json.dumps(parsed).encode()
        with self.assertRaises(ValueError):
            self.hub_b.receive_bundle(tampered)

    def test_wrong_hmac_raises(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        parsed = json.loads(bundle)
        parsed["hmac"] = "0" * 64  # wrong HMAC
        tampered = json.dumps(parsed).encode()
        with self.assertRaises(ValueError):
            self.hub_b.receive_bundle(tampered)

    def test_unknown_sender_raises_key_error(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        hub_c = FederatedIntelHub(node_id="node-c")
        # node-c does not know node-a
        with self.assertRaises(KeyError):
            hub_c.receive_bundle(bundle)

    def test_wrong_key_raises_value_error(self) -> None:
        bundle = self.hub_a.create_summary(self.reports, peer_id="node-b")
        hub_c = FederatedIntelHub(node_id="node-c")
        wrong_key = FederatedIntelHub.generate_shared_key()
        hub_c.register_peer("node-a", wrong_key)
        with self.assertRaises(ValueError):
            hub_c.receive_bundle(bundle)

    def test_create_summary_unknown_peer_raises(self) -> None:
        with self.assertRaises(KeyError):
            self.hub_a.create_summary(self.reports, peer_id="node-unknown")

    def test_share_to_peer_no_host_raises(self) -> None:
        # Peer registered without host
        with self.assertRaises(ValueError):
            self.hub_a.share_to_peer(self.reports, peer_id="node-b")


class TestFederatedIntelHubStats(unittest.TestCase):
    """list_summaries, get_summary, summary_stats, clear_summaries."""

    def setUp(self) -> None:
        self.hub_a = FederatedIntelHub(node_id="node-a")
        self.hub_b = FederatedIntelHub(node_id="node-b")
        self.hub_c = FederatedIntelHub(node_id="node-c")
        key_ab = FederatedIntelHub.generate_shared_key()
        key_cb = FederatedIntelHub.generate_shared_key()
        self.hub_a.register_peer("node-b", key_ab)
        self.hub_b.register_peer("node-a", key_ab)
        self.hub_c.register_peer("node-b", key_cb)
        self.hub_b.register_peer("node-c", key_cb)
        self.reports = _make_reports(4)
        # Ingest from both a and c into b
        bundle_a = self.hub_a.create_summary(self.reports, peer_id="node-b")
        self.hub_b.receive_bundle(bundle_a)
        bundle_c = self.hub_c.create_summary(self.reports, peer_id="node-b")
        self.hub_b.receive_bundle(bundle_c)

    def test_list_summaries_length(self) -> None:
        self.assertEqual(len(self.hub_b.list_summaries()), 2)

    def test_get_summary_by_sender(self) -> None:
        s = self.hub_b.get_summary("node-a")
        self.assertIsNotNone(s)
        self.assertEqual(s.sender_id, "node-a")

    def test_get_summary_unknown_returns_none(self) -> None:
        self.assertIsNone(self.hub_b.get_summary("unknown-node"))

    def test_summary_stats_total_summaries(self) -> None:
        stats = self.hub_b.summary_stats()
        self.assertEqual(stats["total_summaries"], 2)

    def test_summary_stats_total_events(self) -> None:
        stats = self.hub_b.summary_stats()
        self.assertEqual(stats["total_events"], len(self.reports) * 2)

    def test_summary_stats_peers_seen(self) -> None:
        stats = self.hub_b.summary_stats()
        self.assertIn("node-a", stats["peers_seen"])
        self.assertIn("node-c", stats["peers_seen"])

    def test_clear_summaries(self) -> None:
        self.hub_b.clear_summaries()
        self.assertEqual(len(self.hub_b.list_summaries()), 0)
        stats = self.hub_b.summary_stats()
        self.assertEqual(stats["total_summaries"], 0)


if __name__ == "__main__":
    unittest.main()
