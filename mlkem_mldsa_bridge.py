"""
Bridge module for ML-KEM and ML-DSA using liboqs-python.

This provides a stable API for QuantaWeave's hybrid wrappers.
"""

from __future__ import annotations

from typing import Tuple
import os
import sys


def _load_oqs():
    try:
        import oqs  # type: ignore
    except Exception as exc:
        repo_root = os.path.dirname(__file__)
        local_path = os.path.join(repo_root, "liboqs-python")
        if os.path.isdir(local_path) and local_path not in sys.path:
            sys.path.insert(0, local_path)
        try:
            import oqs  # type: ignore
        except Exception:
            raise ImportError(
                "liboqs-python is required for ML-KEM/ML-DSA. "
                "Install it or add ./liboqs-python to PYTHONPATH."
            ) from exc
    return oqs


def kem_keygen(alg: str = "ML-KEM-512") -> Tuple[bytes, bytes]:
    """Generate a ML-KEM keypair."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(alg) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return public_key, secret_key


def kem_encaps(public_key: bytes, alg: str = "ML-KEM-512") -> Tuple[bytes, bytes]:
    """Encapsulate a shared secret for ML-KEM."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(alg) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kem_decaps(ciphertext: bytes, secret_key: bytes, alg: str = "ML-KEM-512") -> bytes:
    """Decapsulate a shared secret for ML-KEM."""
    oqs = _load_oqs()
    with oqs.KeyEncapsulation(alg, secret_key) as kem:
        shared_secret = kem.decap_secret(ciphertext)
    return shared_secret


def sig_keygen(alg: str = "ML-DSA-44") -> Tuple[bytes, bytes]:
    """Generate a ML-DSA keypair."""
    oqs = _load_oqs()
    with oqs.Signature(alg) as signer:
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
    return public_key, secret_key


def sig_sign(secret_key: bytes, message: bytes, alg: str = "ML-DSA-44") -> bytes:
    """Sign a message with ML-DSA."""
    oqs = _load_oqs()
    if isinstance(message, str):
        message = message.encode()
    with oqs.Signature(alg, secret_key) as signer:
        return signer.sign(message)


def sig_verify(public_key: bytes, message: bytes, signature: bytes, alg: str = "ML-DSA-44") -> bool:
    """Verify a ML-DSA signature."""
    oqs = _load_oqs()
    if isinstance(message, str):
        message = message.encode()
    with oqs.Signature(alg) as verifier:
        return verifier.verify(message, signature, public_key)
