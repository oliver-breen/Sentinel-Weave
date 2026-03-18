
# Ensure project root is in sys.path for imports
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from quantaweave.pq_schemes import LWEKEMScheme, UnifiedPQHybrid
import hashlib

def xor_combiner(secrets):
    # XOR all shared secrets (assumes all are same length)
    if not secrets:
        return b''
    result = bytearray(secrets[0])
    for s in secrets[1:]:
        for i in range(len(result)):
            result[i] ^= s[i]
    return bytes(result)

def main():
    lwe = LWEKEMScheme()
    # Use XOR as the secret combiner
    hybrid = UnifiedPQHybrid(kem_schemes=[lwe], secret_combiner=xor_combiner)

    pub_keys, sec_keys = hybrid.generate_keypair()
    ciphertexts, shared_secret = hybrid.encapsulate(pub_keys)
    recovered_secret = hybrid.decapsulate(ciphertexts, sec_keys)
    print("Shared secret (XOR):", shared_secret.hex())
    assert shared_secret == recovered_secret, "Shared secret mismatch with XOR combiner!"

if __name__ == "__main__":
    main()
