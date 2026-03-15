
from typing import Optional, List, Tuple, Any
import hashlib
import os
import pickle
from .pq_unified_interface import PQScheme

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _AESGCM_AVAILABLE = True
except ImportError:
    _AESGCM_AVAILABLE = False

# Use the LWE KEM and Falcon signature implementations via the pqcrypto package
from kyber_dilithium_hqc import kem_keygen, kem_encaps, kem_decaps

# Use the real HQC implementation
from quantaweave.hqc.parameters import get_parameters
from quantaweave.hqc.kem import hqc_kem_keypair, hqc_kem_encaps, hqc_kem_decaps

from .falcon import FalconSig
from .rsa_gcm import RSAGCM


class LWEKEMScheme(PQScheme):
    def __init__(self):
        self.pk = None
        self.sk = None

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        result = kem_keygen()
        pk = result['public_key']
        sk = result['secret_key']
        self.pk = pk
        self.sk = sk
        return pk, sk

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        result = kem_encaps(public_key)
        return result['ciphertext'], result['shared_secret']

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        return kem_decaps(ciphertext, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("LWE KEM does not support signatures.")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("LWE KEM does not support signatures.")


class HQCScheme(PQScheme):
    def __init__(self, param_set: str = "HQC-1"):
        self.params = get_parameters(param_set)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return hqc_kem_keypair(self.params)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        return hqc_kem_encaps(self.params, public_key)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        return hqc_kem_decaps(self.params, ciphertext, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("HQC does not support signatures.")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("HQC does not support signatures.")


class FalconScheme(PQScheme):
    def __init__(self, param_set: str = "Falcon-1024"):
        self.falcon = FalconSig(param_set)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self.falcon.keygen()

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        raise NotImplementedError("Falcon does not support KEM.")

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        raise NotImplementedError("Falcon does not support KEM.")

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        return self.falcon.sign(secret_key, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return self.falcon.verify(public_key, message, signature)


class FalconSignatureScheme(PQScheme):
    """Falcon-1024 backed lattice signature scheme."""

    def __init__(self):
        self._falcon = FalconSig("Falcon-1024")

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self._falcon.keygen()

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        raise NotImplementedError("Falcon does not support KEM.")

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("Falcon does not support KEM.")

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        return self._falcon.sign(secret_key, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        try:
            return self._falcon.verify(public_key, message, signature)
        except Exception:
            return False


class RSAGCMScheme(PQScheme):
    def __init__(self, key_size=2048):
        self.rsa = RSAGCM(key_size)

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        return self.rsa.generate_keypair()

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        secret = os.urandom(32)
        enc_dict = self.rsa.encrypt(secret, public_key)
        return (pickle.dumps(enc_dict), secret)

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        enc_dict = pickle.loads(ciphertext)
        return self.rsa.decrypt(enc_dict, secret_key)

    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        raise NotImplementedError("RSA-GCM does not support signatures.")

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        raise NotImplementedError("RSA-GCM does not support signatures.")


def _aes_gcm_encrypt(key: bytes, plaintext: bytes) -> dict:
    """Encrypt *plaintext* with AES-256-GCM using *key*."""
    if not _AESGCM_AVAILABLE:
        raise ImportError(
            "The 'cryptography' package is required for AES-GCM encryption. "
            "Install it with: pip install cryptography"
        )
    nonce = os.urandom(12)
    aesgcm = AESGCM(key[:32])
    ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext, None)
    # AESGCM.encrypt appends the 16-byte tag to the ciphertext
    ct = ciphertext_and_tag[:-16]
    tag = ciphertext_and_tag[-16:]
    return {"nonce": nonce, "ciphertext": ct, "tag": tag}


def _aes_gcm_decrypt(key: bytes, aes_gcm: dict) -> bytes:
    """Decrypt an AES-256-GCM envelope previously produced by :func:`_aes_gcm_encrypt`."""
    if not _AESGCM_AVAILABLE:
        raise ImportError(
            "The 'cryptography' package is required for AES-GCM decryption. "
            "Install it with: pip install cryptography"
        )
    aesgcm = AESGCM(key[:32])
    return aesgcm.decrypt(
        aes_gcm["nonce"], aes_gcm["ciphertext"] + aes_gcm["tag"], None
    )


class UnifiedPQHybrid(PQScheme):
    def _get_scheme_id(self, scheme):
        if isinstance(scheme, LWEKEMScheme):
            return "LWE-KEM"
        elif isinstance(scheme, HQCScheme):
            return "HQC"
        elif isinstance(scheme, FalconScheme):
            return "Falcon"
        elif isinstance(scheme, FalconSignatureScheme):
            return "FalconSig"
        elif isinstance(scheme, RSAGCMScheme):
            return "RSA-GCM"
        else:
            return type(scheme).__name__

    def __init__(
        self,
        kem_schemes: List[PQScheme],
        sig_schemes: Optional[List[PQScheme]] = None,
        secret_combiner=None,
        sig_threshold: Optional[int] = None,
    ):
        self.kem_schemes = kem_schemes
        self.sig_schemes = sig_schemes or []

        def default_secret_combiner(secrets, schemes):
            pairs = [
                (str(type(scheme).__name__), s if isinstance(s, bytes) else s.encode())
                for scheme, s in zip(schemes, secrets)
            ]
            pairs.sort(key=lambda x: x[0])
            return hashlib.sha3_256(b"".join(p[1] for p in pairs)).digest()

        self.secret_combiner = secret_combiner or (
            lambda secrets: default_secret_combiner(secrets, self.kem_schemes)
        )
        self.sig_threshold = (
            sig_threshold if sig_threshold is not None else len(self.sig_schemes)
        )

    def generate_keypair(self) -> Tuple[list, list]:
        pub_keys = []
        sec_keys = []
        for scheme in self.kem_schemes + self.sig_schemes:
            pk, sk = scheme.generate_keypair()
            pub_keys.append(pk)
            sec_keys.append(sk)
        return pub_keys, sec_keys

    def encapsulate(self, public_keys, plaintext: bytes = b"") -> Tuple[dict, bytes]:
        """Encapsulate shared secrets via all KEM schemes.

        Returns:
            (ciphertexts_dict, combined_secret_bytes).
            If *plaintext* is provided, the combined secret is used to AES-GCM
            encrypt it and the result is stored in ``ciphertexts_dict["__aes_gcm__"]``.
        """
        if not public_keys:
            raise ValueError("public_keys must not be empty.")
        scheme_ids = [self._get_scheme_id(s) for s in self.kem_schemes]
        if isinstance(public_keys, dict):
            pk_map = public_keys
        else:
            pk_map = {name: key for name, key in zip(scheme_ids, public_keys)}
        ciphertexts = {}
        shared_secrets = []
        for scheme_id, scheme in zip(scheme_ids, self.kem_schemes):
            pk = pk_map[scheme_id]
            ct, ss = scheme.encapsulate(pk)
            ciphertexts[scheme_id] = ct
            shared_secrets.append(ss)
        combined_secret = self.secret_combiner(shared_secrets)
        if plaintext:
            ciphertexts["__aes_gcm__"] = _aes_gcm_encrypt(combined_secret, plaintext)
        return ciphertexts, combined_secret

    def decapsulate(self, ciphertexts, secret_keys, aes_gcm: dict = None) -> bytes:
        """Decapsulate shared secrets and optionally decrypt AES-GCM plaintext.

        Args:
            ciphertexts: Dict or list of ciphertexts (may include ``__aes_gcm__`` entry).
            secret_keys: Dict or list of secret keys.
            aes_gcm: Optional explicit AES-GCM envelope; if ``None``, the method
                     checks for ``ciphertexts["__aes_gcm__"]`` instead.

        Returns:
            Decrypted plaintext if AES-GCM data is present, otherwise the
            combined shared secret bytes.
        """
        if not ciphertexts:
            raise ValueError("ciphertexts must not be empty.")
        scheme_ids = [self._get_scheme_id(s) for s in self.kem_schemes]
        if isinstance(ciphertexts, dict):
            ct_map = ciphertexts
        else:
            ct_map = {name: ct for name, ct in zip(scheme_ids, ciphertexts)}
        if isinstance(secret_keys, dict):
            sk_map = secret_keys
        else:
            sk_map = {name: sk for name, sk in zip(scheme_ids, secret_keys)}
        shared_secrets = []
        for scheme_id, scheme in zip(scheme_ids, self.kem_schemes):
            ct = ct_map[scheme_id]
            sk = sk_map[scheme_id]
            ss = scheme.decapsulate(ct, sk)
            shared_secrets.append(ss)
        combined_secret = self.secret_combiner(shared_secrets)
        # Prefer explicit aes_gcm argument, then embedded entry
        gcm_data = aes_gcm or (ct_map.get("__aes_gcm__") if isinstance(ct_map, dict) else None)
        if gcm_data:
            return _aes_gcm_decrypt(combined_secret, gcm_data)
        return combined_secret

    def sign(self, message: bytes, secret_keys) -> list:
        sig_offset = len(self.kem_schemes)
        if isinstance(secret_keys, dict):
            scheme_ids = [self._get_scheme_id(s) for s in self.sig_schemes]
            sig_sks = [secret_keys[k] for k in scheme_ids]
        elif isinstance(secret_keys, list):
            sig_sks = secret_keys[sig_offset : sig_offset + len(self.sig_schemes)]
        else:
            sig_sks = [secret_keys]
        signatures = []
        for scheme, sk in zip(self.sig_schemes, sig_sks):
            sig = scheme.sign(message, sk)
            signatures.append(sig)
        return signatures

    def verify(self, message: bytes, signatures, public_keys) -> bool:
        sig_offset = len(self.kem_schemes)
        if isinstance(signatures, dict):
            scheme_ids = [self._get_scheme_id(s) for s in self.sig_schemes]
            signatures = [signatures[k] for k in scheme_ids]
        if isinstance(public_keys, dict):
            scheme_ids = [self._get_scheme_id(s) for s in self.sig_schemes]
            public_keys = [public_keys[k] for k in scheme_ids]
        elif isinstance(public_keys, list):
            public_keys = public_keys[sig_offset : sig_offset + len(self.sig_schemes)]
        else:
            public_keys = [public_keys]
        if not isinstance(signatures, list) or not isinstance(public_keys, list):
            raise ValueError("signatures and public_keys must be lists")
        valid_count = 0
        for scheme, sig, pk in zip(self.sig_schemes, signatures, public_keys):
            try:
                if isinstance(sig, bytes) and scheme.verify(message, sig, pk):
                    valid_count += 1
            except Exception:
                continue
        if self.sig_threshold == len(self.sig_schemes):
            return valid_count == len(self.sig_schemes)
        return valid_count >= self.sig_threshold
