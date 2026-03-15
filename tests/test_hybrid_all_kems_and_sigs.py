from quantaweave.pq_schemes import LWEKEMScheme, HQCScheme, FalconSignatureScheme, UnifiedPQHybrid
import pytest


def test_all_three_kems_multiple_sigs():
    lwe = LWEKEMScheme()
    hqc1 = HQCScheme(param_set="HQC-1")
    falcon_sig = FalconSignatureScheme()
    # Use two KEMs and two sig schemes (no dummy)
    hybrid = UnifiedPQHybrid(kem_schemes=[lwe, hqc1], sig_schemes=[falcon_sig, falcon_sig])

    pub_keys, sec_keys = hybrid.generate_keypair()
    pub_keys = [pk.encode() if isinstance(pk, str) else pk for pk in pub_keys]
    sec_keys = [sk.encode() if isinstance(sk, str) else sk for sk in sec_keys]
    kem_pub_keys = pub_keys[:len(hybrid.kem_schemes)]
    kem_sec_keys = sec_keys[:len(hybrid.kem_schemes)]

    # Debug: print individual KEM shared secrets for encapsulate
    ciphertexts = []
    encaps_secrets = []
    for scheme, pk in zip(hybrid.kem_schemes, kem_pub_keys):
        ct, ss = scheme.encapsulate(pk)
        ciphertexts.append(ct)
        encaps_secrets.append(ss)
    print("Encapsulate shared secrets:", [s.hex() for s in encaps_secrets])
    shared_secret = hybrid.secret_combiner(encaps_secrets)

    # Debug: print individual KEM shared secrets for decapsulate
    decaps_secrets = []
    for scheme, ct, sk in zip(hybrid.kem_schemes, ciphertexts, kem_sec_keys):
        ss = scheme.decapsulate(ct, sk)
        decaps_secrets.append(ss)
    print("Decapsulate shared secrets:", [s.hex() for s in decaps_secrets])
    recovered_secret = hybrid.secret_combiner(decaps_secrets)
    assert shared_secret == recovered_secret, "Hybrid shared secret mismatch!"

    message = b"Test with two KEMs and two signatures."
    signatures = hybrid.sign(message, sec_keys)
    assert hybrid.verify(message, signatures, pub_keys), "Hybrid signature verification failed!"

if __name__ == "__main__":
    pytest.main([__file__])
