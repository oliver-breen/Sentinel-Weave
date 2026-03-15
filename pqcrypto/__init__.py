"""
Post-Quantum Cryptography package for SentinelWeave.

Provides a unified bytes-based interface for KEM (LWE-based) and
digital signature (Falcon) schemes, backed by the pure-Python
quantaweave implementations.

Subpackages:
    kem  — Key Encapsulation Mechanisms (lwe_kem)
    dsa  — Digital Signature Algorithms (falcon_dsa)
"""

from .pqcrypto_suite import PQCryptoSuite

__all__ = ["PQCryptoSuite"]
