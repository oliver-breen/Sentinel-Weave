"""
Generate benchmark baseline JSON by timing LWE and Falcon operations.
"""

import json
import os
import time
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from quantaweave import QuantaWeave
from quantaweave.falcon import FalconSig


def _time_lwe_level1() -> float:
    pqc = QuantaWeave("LEVEL1")
    public_key, private_key = pqc.generate_keypair()
    message = b"benchmark"
    start = time.perf_counter()
    ciphertext = pqc.encrypt(message, public_key)
    plaintext = pqc.decrypt(ciphertext, private_key)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if plaintext != message:
        raise RuntimeError("LWE round-trip failed")
    return elapsed_ms


def _time_falcon_sign_verify() -> float:
    falcon = FalconSig("Falcon-1024")
    public_key, private_key = falcon.keygen()
    message = b"benchmark"
    start = time.perf_counter()
    signature = falcon.sign(private_key, message)
    valid = falcon.verify(public_key, message, signature)
    elapsed_ms = (time.perf_counter() - start) * 1000
    if not valid:
        raise RuntimeError("Falcon sign/verify failed")
    return elapsed_ms


def main() -> None:
    baseline = {
        "lwe_round_trip_level1": {
            "max_ms": _time_lwe_level1(),
            "notes": "Level1 LWE encrypt+decrypt",
        },
        "falcon_sign_verify": {
            "max_ms": _time_falcon_sign_verify(),
            "notes": "Falcon-1024 sign+verify",
        },
    }

    out_path = os.path.join(os.path.dirname(__file__), "..", "tests", "benchmarks_baseline.json")
    with open(out_path, "w", encoding="utf-8") as handle:
        json.dump(baseline, handle, indent=2)
        handle.write("\n")

    print(f"Wrote baseline to {out_path}")


if __name__ == "__main__":
    main()
