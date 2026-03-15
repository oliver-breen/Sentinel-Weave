# LWE KEM and Falcon Signature Python API
# This module provides a unified interface for LWE-based KEM and Falcon
# signature schemes, using the pure-Python quantaweave implementations
# through the pqcrypto package.

from pqcrypto.kem import lwe_kem
from pqcrypto.dsa import falcon_dsa


# ── LWE KEM ───────────────────────────────────────────────────────────────────

def kem_keygen():
    """Generate an LWE KEM keypair.

    Returns:
        dict: ``{'public_key': bytes, 'secret_key': bytes}``
    """
    pk, sk = lwe_kem.generate_keypair()
    return {'public_key': pk, 'secret_key': sk}


def kem_encaps(public_key: bytes):
    """Encapsulate a shared secret using an LWE public key.

    Args:
        public_key (bytes): Public key from :func:`kem_keygen`.

    Returns:
        dict: ``{'ciphertext': bytes, 'shared_secret': bytes}``
    """
    ct, ss = lwe_kem.encrypt(public_key)
    return {'ciphertext': ct, 'shared_secret': ss}


def kem_decaps(ciphertext: bytes, private_key: bytes):
    """Decapsulate the shared secret from an LWE ciphertext.

    Args:
        ciphertext (bytes): Ciphertext from :func:`kem_encaps`.
        private_key (bytes): Secret key from :func:`kem_keygen`.

    Returns:
        bytes: Recovered shared secret.
    """
    if not isinstance(ciphertext, bytes):
        raise TypeError(f"'ciphertext' must be bytes, got {type(ciphertext)}")
    if not isinstance(private_key, bytes):
        raise TypeError(f"'private_key' must be bytes, got {type(private_key)}")
    return lwe_kem.decrypt(ciphertext, private_key)


# ── Falcon signatures ──────────────────────────────────────────────────────────

def sig_keygen():
    """Generate a Falcon signing keypair.

    Returns:
        dict: ``{'public_key': bytes, 'secret_key': bytes}``
    """
    pk, sk = falcon_dsa.generate_keypair()
    return {'public_key': pk, 'secret_key': sk}


def sig_sign(secret_key: bytes, message: bytes):
    """Sign *message* with *secret_key*.

    Args:
        secret_key (bytes): Secret key from :func:`sig_keygen`.
        message (bytes): Message to sign.

    Returns:
        bytes: Detached signature.
    """
    return falcon_dsa.sign(secret_key, message)


def sig_verify(public_key: bytes, message: bytes, signature: bytes):
    """Verify a Falcon signature.

    Args:
        public_key (bytes): Public key from :func:`sig_keygen`.
        message (bytes): Original message.
        signature (bytes): Signature from :func:`sig_sign`.

    Returns:
        bool: ``True`` if valid, ``False`` otherwise.
    """
    return falcon_dsa.verify(public_key, message, signature)


# ── Integration stubs ──────────────────────────────────────────────────────────

def integrate_lwe():
    """Placeholder for LWE KEM integration."""
    pass


def integrate_falcon():
    """Placeholder for Falcon signature integration."""
    pass


def integrate_hqc():
    """Placeholder for HQC algorithm integration."""
    pass
