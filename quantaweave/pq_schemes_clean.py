from typing import Optional, List, Tuple, Any
import hashlib
from .pq_unified_interface import PQScheme

# Use the LWE KEM implementation
from kyber_dilithium_hqc import kem_keygen, kem_encaps, kem_decaps

class LWEKEMScheme(PQScheme):
    def __init__(self):
        pass

    def generate_keypair(self) -> Tuple[Any, Any]:
        return kem_keygen()

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        if isinstance(public_key, str):
            public_key = public_key.encode()
        return kem_encaps(public_key)

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        if isinstance(ciphertext, str):
            ciphertext = ciphertext.encode()
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()
        return kem_decaps(ciphertext, secret_key)

    def sign(self, message: bytes, secret_key: Any) -> Any:
        raise NotImplementedError("LWE KEM does not support signatures.")

    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        raise NotImplementedError("LWE KEM does not support signatures.")


# Use the Falcon signature implementation
from kyber_dilithium_hqc import sig_keygen, sig_sign, sig_verify

class FalconSignatureScheme(PQScheme):
    def __init__(self):
        pass

    def generate_keypair(self) -> Tuple[Any, Any]:
        return sig_keygen()

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        raise NotImplementedError("Falcon does not support KEM.")

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        raise NotImplementedError("Falcon does not support KEM.")

    def sign(self, message: bytes, secret_key: Any) -> Any:
        if isinstance(secret_key, str):
            secret_key = secret_key.encode()
        if isinstance(message, str):
            message = message.encode()
        return sig_sign(secret_key, message)

    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        if isinstance(public_key, str):
            public_key = public_key.encode()
        if isinstance(message, str):
            message = message.encode()
        if isinstance(signature, str):
            signature = signature.encode()
        return sig_verify(public_key, message, signature)


# Use the real HQC implementation
from quantaweave.hqc.parameters import get_parameters
from quantaweave.hqc.kem import hqc_kem_keypair, hqc_kem_encaps, hqc_kem_decaps

class HQCScheme(PQScheme):
    def __init__(self, param_set: str = "HQC-1"):
        self.params = get_parameters(param_set)

    def generate_keypair(self) -> Tuple[Any, Any]:
        return hqc_kem_keypair(self.params)

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        return hqc_kem_encaps(self.params, public_key)

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        return hqc_kem_decaps(self.params, ciphertext, secret_key)

    def sign(self, message: bytes, secret_key: Any) -> Any:
        # HQC does not support signatures
        raise NotImplementedError("HQC does not support signatures.")

    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        # HQC does not support signatures
        raise NotImplementedError("HQC does not support signatures.")


# Use the Falcon implementation (or mock/backend)
from .falcon import FalconSig

class FalconScheme(PQScheme):
    def __init__(self, param_set: str = "Falcon-1024"):
        self.falcon = FalconSig(param_set)

    def generate_keypair(self) -> Tuple[Any, Any]:
        return self.falcon.keygen()

    def encapsulate(self, public_key: Any) -> Tuple[Any, Any]:
        # Falcon does not support KEM
        raise NotImplementedError("Falcon does not support KEM.")

    def decapsulate(self, ciphertext: Any, secret_key: Any) -> Any:
        # Falcon does not support KEM
        raise NotImplementedError("Falcon does not support KEM.")

    def sign(self, message: bytes, secret_key: Any) -> Any:
        return self.falcon.sign(secret_key, message)

    def verify(self, message: bytes, signature: Any, public_key: Any) -> bool:
        return self.falcon.verify(public_key, message, signature)


class UnifiedPQHybrid(PQScheme):
    def __init__(self, kem_schemes: List[PQScheme], sig_schemes: Optional[List[PQScheme]] = None, secret_combiner=None, sig_threshold: Optional[int] = None):
        self.kem_schemes = kem_schemes
        self.sig_schemes = sig_schemes or []
        self.secret_combiner = secret_combiner or (
            lambda secrets: hashlib.sha3_256(b"".join(
                s.encode() if isinstance(s, str) else s for s in secrets
            )).digest()
        )
        self.sig_threshold = sig_threshold if sig_threshold is not None else len(self.sig_schemes)

    def generate_keypair(self) -> Tuple[list, list]:
        pub_keys = []
        sec_keys = []
        for scheme in self.kem_schemes + self.sig_schemes:
            pk, sk = scheme.generate_keypair()
            pub_keys.append(pk)
            sec_keys.append(sk)
        return pub_keys, sec_keys

    def encapsulate(self, public_keys: list) -> Tuple[list, bytes]:
        if len(public_keys) < len(self.kem_schemes):
            raise ValueError(f"Expected at least {len(self.kem_schemes)} public keys, got {len(public_keys)}")
            
        ciphertexts = []
        shared_secrets = []
        for scheme, pk in zip(self.kem_schemes, public_keys[:len(self.kem_schemes)]):
            # Ensure pk is bytes
            if isinstance(pk, str):
                pk = pk.encode()
            ct, ss = scheme.encapsulate(pk)
            ciphertexts.append(ct)
            shared_secrets.append(ss)
        combined_secret = self.secret_combiner(shared_secrets)
        return ciphertexts, combined_secret

    def decapsulate(self, ciphertexts: list, secret_keys: list) -> bytes:
        if len(ciphertexts) < len(self.kem_schemes):
            raise ValueError(f"Expected at least {len(self.kem_schemes)} ciphertexts, got {len(ciphertexts)}")
        if len(secret_keys) < len(self.kem_schemes):
            raise ValueError(f"Expected at least {len(self.kem_schemes)} secret keys, got {len(secret_keys)}")
            
        shared_secrets = []
        for scheme, ct, sk in zip(self.kem_schemes, ciphertexts, secret_keys[:len(self.kem_schemes)]):
            ss = scheme.decapsulate(ct, sk)
            shared_secrets.append(ss)
        combined_secret = self.secret_combiner(shared_secrets)
        return combined_secret

    def sign(self, message: bytes, secret_keys: list) -> list:
        # Ensure message is bytes
        if isinstance(message, str):
            message = message.encode()
        signatures = []
        for scheme, sk in zip(self.sig_schemes, secret_keys[len(self.kem_schemes):]):
            # Ensure sk is bytes
            if isinstance(sk, str):
                sk = sk.encode()
            sig = scheme.sign(message, sk)
            signatures.append(sig)
        return signatures

    def verify(self, message: bytes, signatures: list, public_keys: list) -> bool:
        valid_count = 0
        for scheme, sig, pk in zip(self.sig_schemes, signatures, public_keys[len(self.kem_schemes):]):
            if scheme.verify(message, sig, pk):
                valid_count += 1
        return valid_count >= self.sig_threshold
