"""
Kyber-768 KEM interface backed by the QuantaWeave LWE implementation.

Provides a standard bytes-based API compatible with the broader
SentinelWeave post-quantum cryptography suite:

    generate_keypair() -> (pk_bytes, sk_bytes)
    encrypt(pk_bytes)  -> (ciphertext_bytes, shared_secret_bytes)
    decrypt(ciphertext_bytes, sk_bytes) -> shared_secret_bytes
"""

import json
import os

from quantaweave.core import QuantaWeave

_LEVEL = "LEVEL1"


def generate_keypair():
    """Generate a Kyber-768 compatible keypair.

    Returns:
        Tuple[bytes, bytes]: (public_key_bytes, secret_key_bytes).
            Both are JSON-encoded representations of the LWE key material.
    """
    qw = QuantaWeave(_LEVEL)
    pk, sk = qw.generate_keypair()
    return json.dumps(pk).encode(), json.dumps(sk).encode()


def encrypt(pk_bytes):
    """Encapsulate a fresh shared secret under a public key.

    Args:
        pk_bytes (bytes): Public key returned by :func:`generate_keypair`.

    Returns:
        Tuple[bytes, bytes]: (ciphertext_bytes, shared_secret_bytes).
            ``shared_secret_bytes`` is a freshly sampled 32-byte secret.
    """
    pk = json.loads(pk_bytes)
    ss = os.urandom(32)
    qw = QuantaWeave(_LEVEL)
    ct = qw.encrypt(ss, pk)
    return json.dumps(ct).encode(), ss


def decrypt(ciphertext_bytes, sk_bytes):
    """Decapsulate the shared secret from a ciphertext.

    Args:
        ciphertext_bytes (bytes): Ciphertext returned by :func:`encrypt`.
        sk_bytes (bytes): Secret key returned by :func:`generate_keypair`.

    Returns:
        bytes: The recovered 32-byte shared secret.
    """
    ct = json.loads(ciphertext_bytes)
    sk = json.loads(sk_bytes)
    qw = QuantaWeave(_LEVEL)
    return qw.decrypt(ct, sk)
