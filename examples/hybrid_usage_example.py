from quantaweave.pq_schemes import LWEKEMScheme, FalconSignatureScheme, UnifiedPQHybrid

def main():
    # Instantiate individual schemes
    lwe = LWEKEMScheme()
    falcon_sig = FalconSignatureScheme()

    # Create a hybrid: LWE KEM for KEM, Falcon for signature
    hybrid = UnifiedPQHybrid(kem_schemes=[lwe], sig_schemes=[falcon_sig])

    # Key generation
    pub_keys, sec_keys = hybrid.generate_keypair()
    print("Public keys:", pub_keys)
    print("Secret keys:", sec_keys)

    # KEM: Encapsulation/Decapsulation
    ciphertexts, shared_secret = hybrid.encapsulate(pub_keys)
    print("Ciphertexts:", ciphertexts)
    print("Combined shared secret:", shared_secret.hex())

    recovered_secret = hybrid.decapsulate(ciphertexts, sec_keys)
    print("Recovered shared secret:", recovered_secret.hex())
    assert shared_secret == recovered_secret, "Shared secret mismatch!"

    # Signature: Sign/Verify
    message = b"Test message for hybrid PQ scheme."
    signatures = hybrid.sign(message, sec_keys)
    print("Signatures:", signatures)
    valid = hybrid.verify(message, signatures, pub_keys)
    print("Signature valid:", valid)
    assert valid, "Signature verification failed!"

if __name__ == "__main__":
    main()
