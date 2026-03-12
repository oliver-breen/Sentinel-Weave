"""
Azure PQC Integration – end-to-end demo.

Demonstrates how to combine QuantaWeave's post-quantum cryptography with:
  1.  Azure Key Vault (via MockKeyVaultClient for local / CI runs).
  2.  ML-powered anomaly detection via CryptoOperationMonitor + AnomalyDetector.

Run this example directly::

    python examples/azure_pqc_integration.py

To use a real Azure Key Vault, set the environment variable ``AZURE_VAULT_URL``
and ensure the ``azure-keyvault-secrets`` and ``azure-identity`` packages are
installed:

    pip install azure-keyvault-secrets azure-identity
    export AZURE_VAULT_URL="https://<your-vault>.vault.azure.net/"
    python examples/azure_pqc_integration.py
"""

import os
import sys
import time

# Make sure the repository root is on the path when running directly.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from quantaweave import QuantaWeave
from quantaweave.azure_keyvault import (
    MockKeyVaultClient,
    PQCKeyVaultClient,
    store_pqc_keypair,
    load_pqc_keypair,
)
from quantaweave.anomaly_detector import (
    AnomalyDetector,
    CryptoOperationMonitor,
    OperationRecord,
)


# ---------------------------------------------------------------------------
# Helper: pick Key Vault client (real Azure or local mock)
# ---------------------------------------------------------------------------

def _build_vault_client():
    vault_url = os.environ.get("AZURE_VAULT_URL")
    if vault_url:
        print(f"[INFO] Using real Azure Key Vault: {vault_url}")
        return PQCKeyVaultClient(vault_url=vault_url)
    print("[INFO] AZURE_VAULT_URL not set – using in-memory MockKeyVaultClient.")
    return MockKeyVaultClient()


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def run_demo():
    print("=" * 60)
    print("  QuantaWeave × Azure Key Vault × Anomaly Detection Demo")
    print("=" * 60)

    # 1. Initialise QuantaWeave and Key Vault client
    pqc = QuantaWeave(security_level="LEVEL1")
    vault = _build_vault_client()
    monitor = CryptoOperationMonitor()
    detector = AnomalyDetector(monitor, max_failure_rate=0.15, min_samples=5)

    # 2. Key generation and storage
    print("\n--- Step 1: Generate PQC keypair ---")
    with monitor.record("keygen"):
        public_key, private_key = pqc.generate_keypair()

    print(f"    Public key size  : {len(str(public_key))} chars (repr)")
    print(f"    Private key size : {len(str(private_key))} chars (repr)")

    print("\n--- Step 2: Store keypair in Key Vault ---")
    import pickle
    pk_bytes = pickle.dumps(public_key)
    sk_bytes = pickle.dumps(private_key)
    store_pqc_keypair(
        vault,
        name="demo-quantaweave-key",
        public_key=pk_bytes,
        private_key=sk_bytes,
        algorithm="QuantaWeave-LEVEL1",
        tags={"environment": "demo", "owner": "quantaweave"},
    )
    print(f"    Stored secrets: {vault.list_key_names()}")

    # 3. Retrieve and verify round-trip
    print("\n--- Step 3: Retrieve keypair from Key Vault ---")
    loaded_pk_bytes, loaded_sk_bytes = load_pqc_keypair(vault, "demo-quantaweave-key")
    loaded_pk = pickle.loads(loaded_pk_bytes)
    loaded_sk = pickle.loads(loaded_sk_bytes)
    assert loaded_pk == public_key, "Public key round-trip mismatch!"
    assert loaded_sk == private_key, "Private key round-trip mismatch!"
    print("    Keypair round-trip: OK")

    # 4. Simulate normal cryptographic operations
    print("\n--- Step 4: Simulate normal operations (10 rounds) ---")
    message = b"Quantum-safe hello from Azure!"

    for i in range(10):
        with monitor.record("encrypt"):
            ciphertext = pqc.encrypt(message, public_key)
        with monitor.record("decrypt"):
            decrypted = pqc.decrypt(ciphertext, private_key)
        assert decrypted == message, f"Decrypt mismatch on round {i}"

    alerts = detector.evaluate()
    print(f"    Anomaly alerts after normal ops : {len(alerts)} (expected 0)")

    # 5. Inject a slow operation to trigger a timing anomaly
    print("\n--- Step 5: Inject slow operation (simulated attack) ---")
    # Add 10 more fast ops so min_samples is met for the 'decrypt' series,
    # then inject one very slow record manually.
    slow_record = OperationRecord(
        operation="decrypt",
        duration_ms=9999.0,   # 9.9 seconds – clearly anomalous
        success=True,
    )
    monitor.add(slow_record)

    alerts = detector.evaluate_operation("decrypt")
    print(f"    Timing anomaly alerts detected  : {len(alerts)}")
    for alert in alerts:
        print(f"      {alert}")

    # 6. Inject failures to trigger failure-rate alert
    print("\n--- Step 6: Inject decapsulation failures ---")
    for _ in range(5):
        fail_record = OperationRecord(
            operation="decrypt",
            duration_ms=8.0,
            success=False,
        )
        monitor.add(fail_record)

    alerts = detector.evaluate_operation("decrypt")
    high_alerts = [a for a in alerts if a.severity == "HIGH"]
    print(f"    High-severity failure-rate alerts: {len(high_alerts)}")
    for alert in high_alerts:
        print(f"      {alert}")

    # 7. Print summary
    print("\n--- Step 7: Operation summary ---")
    summary = detector.summary()
    for op, stats in summary.items():
        print(f"    {op}: {stats}")

    print("\n[DONE] Demo completed successfully.")


if __name__ == "__main__":
    run_demo()
