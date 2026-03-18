"""
Tests for Azure Key Vault integration and ML anomaly detection.

These tests are fully self-contained and do NOT require Azure credentials –
they rely on MockKeyVaultClient and in-process data only.
"""

import sys
import os
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from quantaweave.azure_keyvault import (
    MockKeyVaultClient,
    store_pqc_keypair,
    load_pqc_keypair,
)
from quantaweave.anomaly_detector import (
    AnomalyAlert,
    AnomalyDetector,
    CryptoOperationMonitor,
    OperationRecord,
    _iqr_bounds,
    _zscore,
)


# ---------------------------------------------------------------------------
# Azure Key Vault (mock) tests
# ---------------------------------------------------------------------------

class TestMockKeyVaultClient(unittest.TestCase):
    """Tests for MockKeyVaultClient."""

    def setUp(self):
        self.vault = MockKeyVaultClient()

    def test_store_and_retrieve(self):
        """Round-trip: store then retrieve raw bytes."""
        payload = b"\xde\xad\xbe\xef" * 100
        self.vault.store_key("test-key", payload)
        retrieved = self.vault.retrieve_key("test-key")
        self.assertEqual(payload, retrieved)

    def test_retrieve_missing_raises_key_error(self):
        """Retrieving a non-existent secret raises KeyError."""
        with self.assertRaises(KeyError):
            self.vault.retrieve_key("does-not-exist")

    def test_delete_key(self):
        """Deleted keys are no longer retrievable."""
        self.vault.store_key("to-delete", b"secret")
        self.vault.delete_key("to-delete")
        with self.assertRaises(KeyError):
            self.vault.retrieve_key("to-delete")

    def test_delete_missing_raises_key_error(self):
        """Deleting a non-existent secret raises KeyError."""
        with self.assertRaises(KeyError):
            self.vault.delete_key("ghost")

    def test_list_key_names(self):
        """list_key_names returns all stored secret names."""
        self.vault.store_key("alpha", b"a")
        self.vault.store_key("beta", b"b")
        names = self.vault.list_key_names()
        self.assertIn("alpha", names)
        self.assertIn("beta", names)
        self.assertEqual(len(names), 2)

    def test_overwrite_existing_key(self):
        """Storing under an existing name overwrites the previous value."""
        self.vault.store_key("key", b"original")
        self.vault.store_key("key", b"updated")
        self.assertEqual(self.vault.retrieve_key("key"), b"updated")

    def test_tags_stored_in_metadata(self):
        """Tags passed to store_key are persisted in metadata."""
        self.vault.store_key("tagged", b"data", tags={"env": "test"})
        meta = self.vault.get_metadata("tagged")
        self.assertEqual(meta["tags"]["env"], "test")

    def test_store_empty_bytes(self):
        """Storing empty bytes is allowed."""
        self.vault.store_key("empty", b"")
        self.assertEqual(self.vault.retrieve_key("empty"), b"")


class TestPQCKeypairBundle(unittest.TestCase):
    """Tests for store_pqc_keypair / load_pqc_keypair helpers."""

    def setUp(self):
        self.vault = MockKeyVaultClient()

    def test_round_trip(self):
        """store_pqc_keypair + load_pqc_keypair round-trips both keys correctly."""
        pk = b"public_key_material_xyz" * 4
        sk = b"secret_key_material_abc" * 4
        store_pqc_keypair(self.vault, "demo", pk, sk, algorithm="LWE-KEM")
        loaded_pk, loaded_sk = load_pqc_keypair(self.vault, "demo")
        self.assertEqual(pk, loaded_pk)
        self.assertEqual(sk, loaded_sk)

    def test_bundle_stored_as_single_secret(self):
        """Both keys are stored under a single vault secret name."""
        store_pqc_keypair(self.vault, "bundle", b"pk", b"sk")
        self.assertEqual(self.vault.list_key_names(), ["bundle"])

    def test_algorithm_metadata_present(self):
        """The algorithm field is embedded in the stored JSON bundle."""
        import json
        import base64
        store_pqc_keypair(self.vault, "alg-test", b"pk", b"sk", algorithm="FALCON-1024")
        raw = self.vault.retrieve_key("alg-test")
        bundle = json.loads(raw.decode("utf-8"))
        self.assertEqual(bundle["algorithm"], "FALCON-1024")


# ---------------------------------------------------------------------------
# Statistical helper tests
# ---------------------------------------------------------------------------

class TestStatisticalHelpers(unittest.TestCase):
    """Unit tests for the low-level statistical helpers."""

    def test_zscore_zero_stdev(self):
        """Z-score returns 0.0 when standard deviation is zero."""
        self.assertEqual(_zscore(5.0, 5.0, 0.0), 0.0)

    def test_zscore_positive(self):
        """Z-score is positive for a value above the mean."""
        z = _zscore(10.0, 5.0, 2.5)
        self.assertAlmostEqual(z, 2.0)

    def test_iqr_bounds_symmetric(self):
        """IQR bounds on a symmetric distribution are symmetric about the median."""
        data = list(range(1, 101))  # 1 … 100
        lower, upper = _iqr_bounds(data, k=1.5)
        self.assertLess(lower, 25.0)
        self.assertGreater(upper, 75.0)

    def test_iqr_bounds_outlier_outside(self):
        """A known outlier falls outside the IQR fence."""
        normal = [10.0] * 50
        _, upper = _iqr_bounds(normal + [10.0], k=1.5)
        # All values are identical so IQR = 0, fence = 10.0
        self.assertGreater(10_000.0, upper)


# ---------------------------------------------------------------------------
# CryptoOperationMonitor tests
# ---------------------------------------------------------------------------

class TestCryptoOperationMonitor(unittest.TestCase):
    """Tests for CryptoOperationMonitor."""

    def setUp(self):
        self.monitor = CryptoOperationMonitor()

    def test_record_context_manager_success(self):
        """record() captures a successful operation."""
        with self.monitor.record("keygen"):
            pass
        self.assertEqual(self.monitor.total_count("keygen"), 1)
        self.assertEqual(self.monitor.failure_rate("keygen"), 0.0)

    def test_record_context_manager_failure(self):
        """record() marks an operation as failed when an exception is raised."""
        with self.assertRaises(RuntimeError):
            with self.monitor.record("decrypt"):
                raise RuntimeError("simulated failure")
        self.assertEqual(self.monitor.failure_rate("decrypt"), 1.0)

    def test_manual_add(self):
        """Manually added OperationRecord objects are stored correctly."""
        rec = OperationRecord("encapsulate", duration_ms=2.5, success=True)
        self.monitor.add(rec)
        records = self.monitor.get_records("encapsulate")
        self.assertEqual(len(records), 1)
        self.assertAlmostEqual(records[0].duration_ms, 2.5)

    def test_durations_ms(self):
        """durations_ms returns recorded durations in insertion order."""
        for ms in [1.0, 2.0, 3.0]:
            self.monitor.add(OperationRecord("op", ms, True))
        self.assertEqual(self.monitor.durations_ms("op"), [1.0, 2.0, 3.0])

    def test_window_size_respected(self):
        """Records beyond window_size are dropped (oldest first)."""
        mon = CryptoOperationMonitor(window_size=5)
        for i in range(10):
            mon.add(OperationRecord("op", float(i), True))
        self.assertEqual(mon.total_count("op"), 5)
        # Only the last 5 records should remain
        self.assertEqual(mon.durations_ms("op"), [5.0, 6.0, 7.0, 8.0, 9.0])

    def test_failure_rate_mixed(self):
        """failure_rate calculates correctly for mixed success/failure records."""
        for success in [True, True, False, False, True]:
            self.monitor.add(OperationRecord("op", 1.0, success))
        self.assertAlmostEqual(self.monitor.failure_rate("op"), 2 / 5)

    def test_reset_clears_all(self):
        """reset() removes all records."""
        self.monitor.add(OperationRecord("keygen", 1.0, True))
        self.monitor.reset()
        self.assertEqual(self.monitor.all_operations(), [])

    def test_all_operations(self):
        """all_operations returns every distinct operation name seen."""
        self.monitor.add(OperationRecord("keygen", 1.0, True))
        self.monitor.add(OperationRecord("decrypt", 2.0, True))
        ops = set(self.monitor.all_operations())
        self.assertIn("keygen", ops)
        self.assertIn("decrypt", ops)


# ---------------------------------------------------------------------------
# AnomalyDetector tests
# ---------------------------------------------------------------------------

class TestAnomalyDetector(unittest.TestCase):
    """Tests for AnomalyDetector."""

    def _make_monitor_with_normal_ops(self, operation: str = "decrypt", n: int = 20) -> CryptoOperationMonitor:
        """Return a monitor populated with *n* normal-looking records."""
        monitor = CryptoOperationMonitor()
        for i in range(n):
            monitor.add(OperationRecord(operation, 5.0 + (i % 3) * 0.1, True))
        return monitor

    def test_no_alerts_on_normal_operations(self):
        """No alerts are raised for perfectly normal operations."""
        monitor = self._make_monitor_with_normal_ops()
        detector = AnomalyDetector(monitor, min_samples=5)
        alerts = detector.evaluate()
        self.assertEqual(len(alerts), 0)

    def test_high_failure_rate_triggers_high_alert(self):
        """A failure rate above the threshold triggers a HIGH-severity alert."""
        monitor = CryptoOperationMonitor()
        # 8 failures out of 10 = 80% failure rate
        for success in ([True] * 2 + [False] * 8):
            monitor.add(OperationRecord("decrypt", 5.0, success))
        detector = AnomalyDetector(monitor, max_failure_rate=0.2, min_samples=5)
        alerts = detector.evaluate()
        high = [a for a in alerts if a.severity == "HIGH"]
        self.assertTrue(len(high) >= 1)
        self.assertEqual(high[0].operation, "decrypt")

    def test_timing_spike_triggers_alert(self):
        """A single very slow operation triggers a timing anomaly alert."""
        monitor = CryptoOperationMonitor()
        # 19 fast operations followed by one 10 000x slower
        for _ in range(19):
            monitor.add(OperationRecord("keygen", 5.0, True))
        monitor.add(OperationRecord("keygen", 50_000.0, True))  # massive spike
        detector = AnomalyDetector(monitor, zscore_threshold=3.0, min_samples=5)
        alerts = detector.evaluate_operation("keygen")
        self.assertTrue(len(alerts) >= 1)
        severities = {a.severity for a in alerts}
        self.assertTrue(severities & {"MEDIUM", "LOW"})

    def test_below_min_samples_no_timing_alert(self):
        """Timing checks are skipped when fewer than min_samples records exist."""
        monitor = CryptoOperationMonitor()
        monitor.add(OperationRecord("keygen", 99_999.0, True))
        detector = AnomalyDetector(monitor, min_samples=10)
        alerts = detector.evaluate_operation("keygen")
        # Only 1 sample – statistical checks must be suppressed
        timing_alerts = [a for a in alerts if "Timing" in a.reason]
        self.assertEqual(len(timing_alerts), 0)

    def test_alert_repr_and_str(self):
        """AnomalyAlert __repr__ and __str__ include key fields."""
        alert = AnomalyAlert("HIGH", "decrypt", "Test reason", {"k": "v"})
        self.assertIn("HIGH", repr(alert))
        self.assertIn("decrypt", str(alert))
        self.assertIn("Test reason", str(alert))

    def test_summary_keys(self):
        """summary() contains expected statistical keys for each operation."""
        monitor = self._make_monitor_with_normal_ops()
        detector = AnomalyDetector(monitor)
        s = detector.summary()
        self.assertIn("decrypt", s)
        for key in ("total_count", "failure_rate", "mean_ms", "stdev_ms", "min_ms", "max_ms"):
            self.assertIn(key, s["decrypt"])

    def test_zero_failure_rate_no_alert(self):
        """Zero failures never trigger a HIGH alert regardless of thresholds."""
        monitor = CryptoOperationMonitor()
        for _ in range(20):
            monitor.add(OperationRecord("sign", 3.0, True))
        detector = AnomalyDetector(monitor, max_failure_rate=0.01)
        alerts = [a for a in detector.evaluate() if a.severity == "HIGH"]
        self.assertEqual(len(alerts), 0)


# ---------------------------------------------------------------------------
# Integration test: QuantaWeave + monitor + vault
# ---------------------------------------------------------------------------

class TestAzureIntegration(unittest.TestCase):
    """Integration tests that combine QuantaWeave with vault and anomaly detection."""

    def test_keygen_monitored_and_stored(self):
        """Key generation is successfully monitored and stored in the mock vault."""
        from quantaweave import QuantaWeave
        from quantaweave.safe_serialize import dumps as safe_dumps

        pqc = QuantaWeave("LEVEL1")
        monitor = CryptoOperationMonitor()
        vault = MockKeyVaultClient()

        with monitor.record("keygen"):
            pk, sk = pqc.generate_keypair()

        pk_bytes = safe_dumps(pk)
        sk_bytes = safe_dumps(sk)
        store_pqc_keypair(vault, "integration-key", pk_bytes, sk_bytes)

        loaded_pk_bytes, loaded_sk_bytes = load_pqc_keypair(vault, "integration-key")
        self.assertEqual(pk_bytes, loaded_pk_bytes)
        self.assertEqual(sk_bytes, loaded_sk_bytes)

        self.assertEqual(monitor.total_count("keygen"), 1)
        self.assertEqual(monitor.failure_rate("keygen"), 0.0)

    def test_encrypt_decrypt_round_trip_with_monitoring(self):
        """Encrypt + decrypt round-trip works while monitoring is active."""
        from quantaweave import QuantaWeave

        pqc = QuantaWeave("LEVEL1")
        pk, sk = pqc.generate_keypair()
        monitor = CryptoOperationMonitor()
        message = b"Post-quantum secure message"

        with monitor.record("encrypt"):
            ciphertext = pqc.encrypt(message, pk)

        with monitor.record("decrypt"):
            decrypted = pqc.decrypt(ciphertext, sk)

        self.assertEqual(message, decrypted)
        self.assertEqual(monitor.failure_rate("encrypt"), 0.0)
        self.assertEqual(monitor.failure_rate("decrypt"), 0.0)


if __name__ == "__main__":
    unittest.main()
