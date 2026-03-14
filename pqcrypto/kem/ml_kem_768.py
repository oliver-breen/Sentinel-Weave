"""
ML-KEM-768 (NIST-standardised Kyber-768) interface.

This module is an alias of :mod:`pqcrypto.kem.kyber_768`, exposing the
same bytes-based API under the NIST ML-KEM naming convention:

    generate_keypair() -> (pk_bytes, sk_bytes)
    encrypt(pk_bytes)  -> (ciphertext_bytes, shared_secret_bytes)
    decrypt(ciphertext_bytes, sk_bytes) -> shared_secret_bytes
"""

from .kyber_768 import generate_keypair, encrypt, decrypt

__all__ = ["generate_keypair", "encrypt", "decrypt"]
