"""
Falcon-1024 digital signature interface backed by the QuantaWeave Falcon
implementation.

Provides a standard bytes-based API for signing and verification:

    generate_keypair()              -> (pk_bytes, sk_bytes)
    sign(sk_bytes, message)         -> signature_bytes
    verify(pk_bytes, message, sig)  -> bool
"""

from quantaweave.falcon import FalconSig

_falcon = FalconSig("Falcon-1024")


def generate_keypair():
    """Generate a Falcon-1024 signing keypair.

    Returns:
        Tuple[bytes, bytes]: (public_key_bytes, secret_key_bytes).
    """
    return _falcon.keygen()


def sign(sk_bytes, message):
    """Sign *message* with *sk_bytes*.

    Args:
        sk_bytes (bytes): Secret key from :func:`generate_keypair`.
        message (bytes | str): Message to sign.

    Returns:
        bytes: Detached signature.
    """
    if isinstance(message, str):
        message = message.encode()
    return _falcon.sign(sk_bytes, message)


def verify(pk_bytes, message, signature):
    """Verify *signature* over *message* with *pk_bytes*.

    Args:
        pk_bytes (bytes): Public key from :func:`generate_keypair`.
        message (bytes | str): Original message.
        signature (bytes): Signature from :func:`sign`.

    Returns:
        bool: ``True`` if the signature is valid, ``False`` otherwise.
    """
    if isinstance(message, str):
        message = message.encode()
    if not isinstance(signature, bytes):
        return False
    try:
        return _falcon.verify(pk_bytes, message, signature)
    except Exception:
        return False
