import sys
import os
sys.path.insert(0, os.path.abspath(os.path.dirname(os.path.dirname(__file__))))
import pytest
from kyber_dilithium_hqc import kem_keygen, kem_encaps, kem_decaps, sig_keygen, sig_sign, sig_verify

def test_lwe_kem():
    keys = kem_keygen()
    pk = keys['public_key']
    sk = keys['secret_key']
    encap = kem_encaps(pk)
    ct = encap['ciphertext']
    ss1 = encap['shared_secret']
    ss2 = kem_decaps(ct, sk)
    assert ss1 == ss2

def test_falcon_signature():
    keys = sig_keygen()
    pk = keys['public_key']
    sk = keys['secret_key']
    msg = b"test message"
    sig = sig_sign(sk, msg)
    assert sig_verify(pk, msg, sig)
    # Negative test: tampered message
    assert not sig_verify(pk, b"tampered", sig)
