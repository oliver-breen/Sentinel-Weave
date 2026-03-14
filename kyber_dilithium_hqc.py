# Kyber / ML-KEM and Dilithium Python API
# This module provides a unified interface for Kyber KEM and Dilithium
# (Falcon-backed) signature schemes, using the pure-Python quantaweave
# implementations through the pqcrypto package.

from pqcrypto.kem import ml_kem_768
from pqcrypto.dsa import dilithium3


# ── Kyber KEM ─────────────────────────────────────────────────────────────────

def kyber_keygen():
    """Generate a Kyber keypair.

    Returns:
        dict: ``{'public_key': bytes, 'secret_key': bytes}``
    """
    pk, sk = ml_kem_768.generate_keypair()
    return {'public_key': pk, 'secret_key': sk}


def kyber_encaps(public_key: bytes):
    """Encapsulate a shared secret using a Kyber public key.

    Args:
        public_key (bytes): Public key from :func:`kyber_keygen`.

    Returns:
        dict: ``{'ciphertext': bytes, 'shared_secret': bytes}``
    """
    ct, ss = ml_kem_768.encrypt(public_key)
    return {'ciphertext': ct, 'shared_secret': ss}


def kyber_decaps(ciphertext: bytes, private_key: bytes):
    """Decapsulate the shared secret from a Kyber ciphertext.

    Args:
        ciphertext (bytes): Ciphertext from :func:`kyber_encaps`.
        private_key (bytes): Secret key from :func:`kyber_keygen`.

    Returns:
        bytes: Recovered shared secret.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError(f"'ciphertext' must be bytes, got {type(ciphertext)}")
    if not isinstance(private_key, bytes):
        raise TypeError(f"'private_key' must be bytes, got {type(private_key)}")
    return ml_kem_768.decrypt(ciphertext, private_key)


# ── Dilithium signatures ───────────────────────────────────────────────────────

def dilithium_keygen():
    """Generate a Dilithium signing keypair.

    Returns:
        dict: ``{'public_key': bytes, 'secret_key': bytes}``
    """
    pk, sk = dilithium3.generate_keypair()
    return {'public_key': pk, 'secret_key': sk}


def dilithium_sign(secret_key: bytes, message: bytes):
    """Sign *message* with *secret_key*.

    Args:
        secret_key (bytes): Secret key from :func:`dilithium_keygen`.
        message (bytes): Message to sign.

    Returns:
        bytes: Detached signature.
    """
    return dilithium3.sign(secret_key, message)


def dilithium_verify(public_key: bytes, message: bytes, signature: bytes):
    """Verify a Dilithium signature.

    Args:
        public_key (bytes): Public key from :func:`dilithium_keygen`.
        message (bytes): Original message.
        signature (bytes): Signature from :func:`dilithium_sign`.

    Returns:
        bool: ``True`` if valid, ``False`` otherwise.
    """
    return dilithium3.verify(public_key, message, signature)


# ── Integration stubs ──────────────────────────────────────────────────────────

def integrate_kyber():
    """Placeholder for Kyber algorithm integration."""
    pass


def integrate_dilithium():
    """Placeholder for Dilithium algorithm integration."""
    pass


def integrate_hqc():
    """Placeholder for HQC algorithm integration."""
    pass
