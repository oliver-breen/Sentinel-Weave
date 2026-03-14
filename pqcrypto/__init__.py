"""
Post-Quantum Cryptography package for SentinelWeave.

Provides a unified bytes-based interface for KEM (Kyber/ML-KEM) and
digital signature (Dilithium) schemes, backed by the pure-Python
quantaweave implementations.

Subpackages:
    kem  — Key Encapsulation Mechanisms (kyber_768, ml_kem_768)
    dsa  — Digital Signature Algorithms (dilithium3)
"""

from .pqcrypto_suite import PQCryptoSuite

__all__ = ["PQCryptoSuite"]
