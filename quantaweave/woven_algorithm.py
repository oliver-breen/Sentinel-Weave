"""
The "QuantaWeave" Algorithm: A Robust Hybrid Scheme.

This module weaves together multiple cryptographic primitives into a single,
cohesive algorithm.  It combines:
- RSA-GCM (classical KEM) for broad compatibility.
- ML-KEM (lattice-based KEM) for quantum-hardness security.
- ML-DSA + Falcon-1024 (lattice-based signatures) for data authentication.

This hybrid approach ensures the system remains secure even if one of the
underlying mathematical problems is compromised.
"""

import os
from .safe_serialize import dumps as safe_dumps, loads as safe_loads
from typing import Tuple, Any, List, Dict, Optional

from .pq_unified_interface import PQScheme
from .pq_schemes import (
    UnifiedPQHybrid,
    LWEKEMScheme,
    FalconSignatureScheme,
    RSAGCMScheme,
    MLDSASignatureScheme,
    _aes_gcm_encrypt,
    _aes_gcm_decrypt,
)


class QuantaWeaveAlgorithm(PQScheme):
    """Hybrid post-quantum algorithm combining multiple KEMs and signatures."""

    def __init__(self):
        self.hybrid = UnifiedPQHybrid(
            kem_schemes=[
                RSAGCMScheme(),
                LWEKEMScheme(),
            ],
            sig_schemes=[
                MLDSASignatureScheme(),
                FalconSignatureScheme(),
            ],
        )
        self._kem_ids = [
            self.hybrid._get_scheme_id(s) for s in self.hybrid.kem_schemes
        ]
        self._sig_ids = [
            self.hybrid._get_scheme_id(s) for s in self.hybrid.sig_schemes
        ]

    # ── Key generation ────────────────────────────────────────────────────────

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate a unified public/secret key pair.

        Returns:
            (public_key_blob, secret_key_blob) where each blob is a pickled
            dict mapping scheme name → key bytes.
        """
        pub_keys_list, sec_keys_list = self.hybrid.generate_keypair()
        all_ids = self._kem_ids + self._sig_ids
        pub_key_blob = safe_dumps(
            {name: key for name, key in zip(all_ids, pub_keys_list)}
        )
        sec_key_blob = safe_dumps(
            {name: key for name, key in zip(all_ids, sec_keys_list)}
        )
        return pub_key_blob, sec_key_blob

    # ── KEM encapsulate / decapsulate ─────────────────────────────────────────

    def encapsulate(self, public_key: bytes) -> Tuple[Dict, Dict]:
        """Encapsulate a shared secret using all KEM schemes.

        Args:
            public_key (bytes): Pickled public key dict from :meth:`generate_keypair`.

        Returns:
            (ciphertexts_dict, result_dict) where *result_dict* is
            ``{'combined_secret': bytes}``.
        """
        try:
            pub_key_obj = safe_loads(public_key)
        except Exception:
            pub_key_obj = public_key
        if isinstance(pub_key_obj, dict):
            pk_map = {k: pub_key_obj[k] for k in self._kem_ids if k in pub_key_obj}
        else:
            pk_map = {name: k for name, k in zip(self._kem_ids, pub_key_obj)}
        ciphertexts, shared_secret = self.hybrid.encapsulate(pk_map)
        return ciphertexts, {'combined_secret': shared_secret}

    def decapsulate(self, ciphertext: Dict, secret_key: bytes) -> Dict:
        """Decapsulate the shared secret.

        Args:
            ciphertext: Ciphertexts dict from :meth:`encapsulate`.
            secret_key (bytes): Pickled secret key dict from :meth:`generate_keypair`.

        Returns:
            dict: ``{'combined_secret': bytes}`` with the recovered shared secret.
        """
        try:
            sec_key_obj = safe_loads(secret_key)
        except Exception:
            sec_key_obj = secret_key
        if isinstance(sec_key_obj, dict):
            sk_map = {k: sec_key_obj[k] for k in self._kem_ids if k in sec_key_obj}
        else:
            sk_map = {name: k for name, k in zip(self._kem_ids, sec_key_obj)}
        shared_secret = self.hybrid.decapsulate(ciphertext, sk_map)
        return {'combined_secret': shared_secret}

    # ── Hybrid KEM + AES-GCM encryption ──────────────────────────────────────

    def hybrid_encrypt(self, public_key: bytes, plaintext: bytes) -> Tuple[Dict, Dict]:
        """Encrypt *plaintext* using hybrid KEM + AES-256-GCM.

        Args:
            public_key (bytes): Pickled public key dict.
            plaintext (bytes): Plaintext to encrypt.

        Returns:
            (ciphertexts_dict, aes_gcm_dict)
        """
        ciphertexts, result = self.encapsulate(public_key)
        shared_secret = result['combined_secret']
        aes_gcm = _aes_gcm_encrypt(shared_secret, plaintext)
        return ciphertexts, aes_gcm

    def hybrid_decrypt(self, ciphertext: Dict, secret_key: bytes, aes_gcm: Dict) -> bytes:
        """Decrypt an AES-GCM ciphertext using the hybrid KEM shared secret.

        Args:
            ciphertext: Ciphertexts dict from :meth:`hybrid_encrypt`.
            secret_key (bytes): Pickled secret key dict.
            aes_gcm: AES-GCM envelope from :meth:`hybrid_encrypt`.

        Returns:
            bytes: Decrypted plaintext.
        """
        result = self.decapsulate(ciphertext, secret_key)
        shared_secret = result['combined_secret']
        return _aes_gcm_decrypt(shared_secret, aes_gcm)

    # ── Signatures ────────────────────────────────────────────────────────────

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign *message* with all signature schemes.

        Args:
            secret_key (bytes): Pickled secret key dict or raw bytes.

        Returns:
            bytes: Pickled list of signatures (or raw bytes for single scheme).
        """
        try:
            sec_key_obj = safe_loads(secret_key)
        except Exception:
            sec_key_obj = secret_key
        if isinstance(sec_key_obj, dict):
            # Pass the full ordered key list (KEM + sig) so sign() can apply its offset
            all_sks = [sec_key_obj[k] for k in self._kem_ids + self._sig_ids if k in sec_key_obj]
        elif isinstance(sec_key_obj, list):
            all_sks = sec_key_obj
        else:
            all_sks = [sec_key_obj]
        sigs = self.hybrid.sign(message, all_sks)
        return sigs[0] if len(sigs) == 1 else safe_dumps(sigs)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify *signature* over *message*.

        Args:
            signature (bytes): Signature from :meth:`sign`.
            public_key (bytes): Pickled public key dict or raw bytes.

        Returns:
            bool: ``True`` if all signatures are valid.
        """
        try:
            sigs = safe_loads(signature)
            if not isinstance(sigs, list):
                sigs = [signature]
        except Exception:
            sigs = [signature]
        try:
            pub_key_obj = safe_loads(public_key)
        except Exception:
            pub_key_obj = public_key
        if isinstance(pub_key_obj, dict):
            # Pass the full ordered key list (KEM + sig) so verify() can apply its offset
            all_pks = [pub_key_obj[k] for k in self._kem_ids + self._sig_ids if k in pub_key_obj]
        elif isinstance(pub_key_obj, list):
            all_pks = pub_key_obj
        else:
            all_pks = [pub_key_obj]
        return self.hybrid.verify(message, sigs, all_pks)
