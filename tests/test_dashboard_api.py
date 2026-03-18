"""
Smoke tests for the dashboard API endpoints.
"""

import os
import unittest

from sentinel_weave.dashboard.app import create_app


class TestDashboardApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.pop("SENTINELWEAVE_API_KEY", None)
        os.environ.pop("SENTINELWEAVE_DASHBOARD_API_KEY", None)
        cls.app = create_app(demo_mode=False)
        cls.client = cls.app.test_client()

    def test_health(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertEqual(payload.get("status"), "ok")

    def test_summary(self):
        response = self.client.get("/api/summary")
        self.assertEqual(response.status_code, 200)
        payload = response.get_json()
        self.assertIn("total_events", payload)
        self.assertIn("levels", payload)

    def test_ingest(self):
        response = self.client.post("/api/ingest", json={"raw": "Failed password for root from 10.0.0.5"})
        self.assertEqual(response.status_code, 201)
        payload = response.get_json()
        self.assertIn("threat_level", payload)

    def test_quantaweave_roundtrip(self):
        keygen = self.client.post("/api/quantaweave/keygen", json={"level": "LEVEL1"})
        self.assertEqual(keygen.status_code, 200)
        keys = keygen.get_json()
        encrypt = self.client.post(
            "/api/quantaweave/encrypt",
            json={"message": "hello", "public_key": keys["public_key"]},
        )
        self.assertEqual(encrypt.status_code, 200)
        ciphertext = encrypt.get_json()["ciphertext"]
        decrypt = self.client.post(
            "/api/quantaweave/decrypt",
            json={"ciphertext": ciphertext, "private_key": keys["private_key"]},
        )
        self.assertEqual(decrypt.status_code, 200)
        self.assertEqual(decrypt.get_json()["plaintext"], "hello")

    def test_mlkem_keygen_smoke(self):
        response = self.client.post("/api/mlkem/keygen", json={"alg": "ML-KEM-512"})
        self.assertIn(response.status_code, (200, 400))
        payload = response.get_json()
        self.assertTrue("error" in payload or "public_key_b64" in payload)


if __name__ == "__main__":
    unittest.main()
