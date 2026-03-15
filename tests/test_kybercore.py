import unittest
from quantaweave.lwe_kem_core import LWEKEMCore
import os

class TestLWEKEMCore(unittest.TestCase):
    def setUp(self):
        self.kem = LWEKEMCore()

    def test_keypair_and_encapsulation(self):
        pk, sk = self.kem.keypair()
        self.assertIsInstance(pk, dict)
        self.assertIsInstance(sk, dict)
        ct, ss = self.kem.encaps(pk)
        self.assertIsInstance(ct, dict)
        self.assertIsInstance(ss, bytes)
        recovered_ss = self.kem.decaps(ct, sk)
        self.assertEqual(ss, recovered_ss)

    def test_encryption_and_decryption(self):
        pk, sk = self.kem.keypair()
        message = os.urandom(32)
        coins = os.urandom(32)
        ct = self.kem.encrypt(pk, message, coins)
        decrypted = self.kem.decrypt(sk, ct)
        self.assertEqual(message, decrypted)

    def test_parameter_variants(self):
        for params in [
            {'k':2, 'eta1':3, 'eta2':2, 'du':10, 'dv':4}, # Small (512-level)
            {'k':3, 'eta1':2, 'eta2':2, 'du':10, 'dv':4}, # Medium (768-level)
            {'k':4, 'eta1':2, 'eta2':2, 'du':11, 'dv':5}, # Large (1024-level)
        ]:
            kem = LWEKEMCore(**params)
            pk, sk = kem.keypair()
            ct, ss = kem.encaps(pk)
            recovered_ss = kem.decaps(ct, sk)
            self.assertEqual(ss, recovered_ss)

if __name__ == '__main__':
    unittest.main()
