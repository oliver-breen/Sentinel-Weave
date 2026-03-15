from quantaweave.pq_schemes import LWEKEMScheme, FalconSignatureScheme, UnifiedPQHybrid
import pytest

def test_threshold_signature_verification():
    # Use two signature schemes (for demonstration, use Falcon twice)
    sig1 = FalconSignatureScheme()
    sig2 = FalconSignatureScheme()
    hybrid = UnifiedPQHybrid(kem_schemes=[LWEKEMScheme()], sig_schemes=[sig1, sig2], sig_threshold=1)

    pub_keys, sec_keys = hybrid.generate_keypair()
    pub_keys = [pk.encode() if isinstance(pk, str) else pk for pk in pub_keys]
    sec_keys = [sk.encode() if isinstance(sk, str) else sk for sk in sec_keys]
    message = b"Threshold signature test."
    signatures = hybrid.sign(message, sec_keys)

    # All signatures valid: should verify
    assert hybrid.verify(message, signatures, pub_keys)

    # Corrupt one signature: should still verify (threshold=1)
    signatures[0] = b"corrupted"
    assert hybrid.verify(message, signatures, pub_keys)

    # Corrupt both signatures: should not verify
    signatures[1] = b"corrupted"
    assert not hybrid.verify(message, signatures, pub_keys)

    # Set threshold=2: only both valid signatures pass
    hybrid2 = UnifiedPQHybrid(kem_schemes=[LWEKEMScheme()], sig_schemes=[sig1, sig2], sig_threshold=2)
    pub_keys2, sec_keys2 = hybrid2.generate_keypair()
    pub_keys2 = [pk.encode() if isinstance(pk, str) else pk for pk in pub_keys2]
    sec_keys2 = [sk.encode() if isinstance(sk, str) else sk for sk in sec_keys2]
    signatures2 = hybrid2.sign(message, sec_keys2)
    assert hybrid2.verify(message, signatures2, pub_keys2)
    signatures2[0] = b"corrupted"
    assert not hybrid2.verify(message, signatures2, pub_keys2)

if __name__ == "__main__":
    pytest.main([__file__])
