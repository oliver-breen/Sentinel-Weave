import pytest
from quantaweave.pq_schemes import LWEKEMScheme, FalconSignatureScheme, HQCScheme, UnifiedPQHybrid

def test_hybrid_kem_and_signature():
    lwe = LWEKEMScheme()
    hqc = HQCScheme(param_set="HQC-1")
    falcon_sig = FalconSignatureScheme()
    hybrid = UnifiedPQHybrid(kem_schemes=[lwe, hqc], sig_schemes=[falcon_sig])

    pub_keys, sec_keys = hybrid.generate_keypair()
    # Ensure all keys are bytes
    pub_keys = [pk.encode() if isinstance(pk, str) else pk for pk in pub_keys]
    sec_keys = [sk.encode() if isinstance(sk, str) else sk for sk in sec_keys]
    ciphertexts, shared_secret = hybrid.encapsulate(pub_keys)
    recovered_secret = hybrid.decapsulate(ciphertexts, sec_keys)
    assert shared_secret == recovered_secret, "Hybrid shared secret mismatch!"

    message = b"Automated test message."
    signatures = hybrid.sign(message, sec_keys)
    assert hybrid.verify(message, signatures, pub_keys), "Hybrid signature verification failed!"

# Additional customization: test with only one KEM or one signature scheme
def test_single_scheme_hybrid():
    lwe = LWEKEMScheme()
    falcon_sig = FalconSignatureScheme()
    hybrid = UnifiedPQHybrid(kem_schemes=[lwe], sig_schemes=[falcon_sig])

    pub_keys, sec_keys = hybrid.generate_keypair()
    pub_keys = [pk.encode() if isinstance(pk, str) else pk for pk in pub_keys]
    sec_keys = [sk.encode() if isinstance(sk, str) else sk for sk in sec_keys]
    ciphertexts, shared_secret = hybrid.encapsulate(pub_keys)
    recovered_secret = hybrid.decapsulate(ciphertexts, sec_keys)
    assert shared_secret == recovered_secret

    message = b"Single scheme test."
    signatures = hybrid.sign(message, sec_keys)
    assert hybrid.verify(message, signatures, pub_keys)

if __name__ == "__main__":
    pytest.main([__file__])
