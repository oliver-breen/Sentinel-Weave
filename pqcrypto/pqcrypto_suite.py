"""
Unified Cryptography Suite: LWE KEM, HQC, and Falcon.

Provides a single, high-level interface for KEM (LWE-based, HQC) and
digital signature (Falcon) operations, backed by the pure-Python
quantaweave implementations.

Example::

    from pqcrypto.pqcrypto_suite import PQCryptoSuite

    suite = PQCryptoSuite(kem='lwe', sig='falcon', level='LEVEL1')

    # KEM round-trip
    pk, sk = suite.kem_keypair()
    ct, ss = suite.kem_encapsulate(pk)
    recovered = suite.kem_decapsulate(ct, sk)
    assert ss == recovered

    # Signature round-trip
    sig_pk, sig_sk = suite.sig_keypair()
    signature = suite.sign(sig_sk, b"hello")
    assert suite.verify(sig_pk, b"hello", signature)
"""

from .kem import lwe_kem
from .dsa import falcon_dsa
from quantaweave.falcon import FalconSig


class PQCryptoSuite:
    """Unified interface for KEM and signature operations."""

    def __init__(self, kem: str = "lwe", sig: str = "falcon", level: str = "LEVEL1"):
        """
        Args:
            kem (str): KEM algorithm to use — ``'lwe'`` or ``'hqc'``
                       (HQC falls back to LWE for now).
            sig (str): Signature algorithm — ``'falcon'``.
            level (str): Security level — ``'LEVEL1'``, ``'LEVEL3'``, or ``'LEVEL5'``.
        """
        self.kem_name = kem.lower()
        self.sig_name = sig.lower()
        self.level = level
        self._falcon = FalconSig("Falcon-1024")

    # ── KEM API ───────────────────────────────────────────────────────────────

    def kem_keypair(self):
        """Generate a KEM keypair.

        Returns:
            Tuple[bytes, bytes]: (public_key_bytes, secret_key_bytes).
        """
        if self.kem_name in ("lwe", "hqc"):
            return lwe_kem.generate_keypair()
        raise ValueError(f"Unsupported KEM: {self.kem_name!r}")

    def kem_encapsulate(self, public_key: bytes):
        """Encapsulate a shared secret.

        Args:
            public_key (bytes): Public key from :meth:`kem_keypair`.

        Returns:
            Tuple[bytes, bytes]: (ciphertext_bytes, shared_secret_bytes).
        """
        return lwe_kem.encrypt(public_key)

    def kem_decapsulate(self, ciphertext: bytes, private_key: bytes):
        """Decapsulate the shared secret.

        Args:
            ciphertext (bytes): Ciphertext from :meth:`kem_encapsulate`.
            private_key (bytes): Secret key from :meth:`kem_keypair`.

        Returns:
            bytes: Recovered shared secret.
        """
        return lwe_kem.decrypt(ciphertext, private_key)

    # ── Signature API ─────────────────────────────────────────────────────────

    def sig_keypair(self):
        """Generate a signature keypair.

        Returns:
            Tuple[bytes, bytes]: (public_key_bytes, secret_key_bytes).
        """
        if self.sig_name in ("falcon",):
            return self._falcon.keygen()
        raise ValueError(f"Unsupported signature scheme: {self.sig_name!r}")

    def sign(self, secret_key: bytes, message):
        """Sign *message* with *secret_key*.

        Args:
            secret_key (bytes): Secret key from :meth:`sig_keypair`.
            message (bytes | str): Message to sign.

        Returns:
            bytes: Detached signature.
        """
        if isinstance(message, str):
            message = message.encode()
        return self._falcon.sign(secret_key, message)

    def verify(self, public_key: bytes, message, signature):
        """Verify *signature* over *message*.

        Args:
            public_key (bytes): Public key from :meth:`sig_keypair`.
            message (bytes | str): Original message.
            signature: Signature from :meth:`sign`.

        Returns:
            bool: ``True`` if valid, ``False`` otherwise.
        """
        if isinstance(message, str):
            message = message.encode()
        if not isinstance(signature, bytes):
            return False
        try:
            return self._falcon.verify(public_key, message, signature)
        except Exception:
            return False


if __name__ == "__main__":
    suite = PQCryptoSuite(kem="lwe", sig="falcon", level="LEVEL1")
    pk, sk = suite.kem_keypair()
    ct, ss = suite.kem_encapsulate(pk)
    recovered = suite.kem_decapsulate(ct, sk)
    print(f"KEM shared secret match: {ss == recovered}")
    sig_pk, sig_sk = suite.sig_keypair()
    sig = suite.sign(sig_sk, b"hello")
    print(f"Signature valid: {suite.verify(sig_pk, b'hello', sig)}")

