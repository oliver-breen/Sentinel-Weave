"""
Optional benchmark tests for LWE and Falcon flows.

Enable with RUN_BENCHMARKS=1. Use BENCHMARK_USE_BASELINE=1 to
enforce per-test thresholds from tests/benchmarks_baseline.json.
"""

import json
import os
import time
import unittest

from quantaweave import QuantaWeave
from quantaweave.falcon import FalconSig

RUN_BENCHMARKS = os.getenv("RUN_BENCHMARKS") == "1"
MAX_MS = float(os.getenv("BENCHMARK_MAX_MS", "0"))
USE_BASELINE = os.getenv("BENCHMARK_USE_BASELINE") == "1"
BASELINE_PATH = os.getenv(
    "BENCHMARK_BASELINE",
    os.path.join(os.path.dirname(__file__), "benchmarks_baseline.json"),
)
TOLERANCE = float(os.getenv("BENCHMARK_TOLERANCE", "0.5"))


def _load_baseline() -> dict:
    if not os.path.exists(BASELINE_PATH):
        return {}
    with open(BASELINE_PATH, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _assert_with_baseline(testcase: unittest.TestCase, name: str, elapsed_ms: float) -> None:
    if MAX_MS > 0:
        testcase.assertLess(elapsed_ms, MAX_MS)
        return
    if not USE_BASELINE:
        return
    baseline = _load_baseline()
    entry = baseline.get(name)
    if not entry:
        testcase.skipTest(f"Missing baseline entry for {name}")
    max_ms = float(entry.get("max_ms", 0))
    if max_ms <= 0:
        testcase.skipTest(f"Invalid baseline max_ms for {name}")
    limit = max_ms * (1 + TOLERANCE)
    testcase.assertLess(elapsed_ms, limit)


class TestBenchmarks(unittest.TestCase):
    """Benchmark-style tests that are skipped by default."""

    @unittest.skipUnless(RUN_BENCHMARKS, "Set RUN_BENCHMARKS=1 to enable benchmarks")
    def test_lwe_round_trip_timing_level1(self):
        pqc = QuantaWeave("LEVEL1")
        public_key, private_key = pqc.generate_keypair()
        message = b"benchmark"

        start = time.perf_counter()
        ciphertext = pqc.encrypt(message, public_key)
        plaintext = pqc.decrypt(ciphertext, private_key)
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertEqual(message, plaintext)
        _assert_with_baseline(self, "lwe_round_trip_level1", elapsed_ms)

    @unittest.skipUnless(RUN_BENCHMARKS, "Set RUN_BENCHMARKS=1 to enable benchmarks")
    def test_falcon_sign_verify_timing(self):
        falcon = FalconSig("Falcon-1024")
        public_key, private_key = falcon.keygen()
        message = b"benchmark"

        start = time.perf_counter()
        signature = falcon.sign(private_key, message)
        valid = falcon.verify(public_key, message, signature)
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertTrue(valid)
        _assert_with_baseline(self, "falcon_sign_verify", elapsed_ms)


if __name__ == "__main__":
    unittest.main()
