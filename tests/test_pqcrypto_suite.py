import unittest
from pqcrypto.pqcrypto_suite import PQCryptoSuite


class TestPQCryptoSuite(unittest.TestCase):
    def test_kem_keypair_returns_bytes(self):
        suite = PQCryptoSuite(kem='kyber', sig='dilithium', level='LEVEL1')
        pk, sk = suite.kem_keypair()
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)

    def test_kem_encapsulate_and_decapsulate(self):
        suite = PQCryptoSuite(kem='kyber', sig='dilithium', level='LEVEL1')
        pk, sk = suite.kem_keypair()
        ct, ss = suite.kem_encapsulate(pk)
        self.assertIsInstance(ct, bytes)
        self.assertIsInstance(ss, bytes)
        recovered = suite.kem_decapsulate(ct, sk)
        self.assertEqual(ss, recovered)

    def test_sig_keypair_and_sign_verify(self):
        suite = PQCryptoSuite(kem='kyber', sig='falcon', level='LEVEL1')
        pk, sk = suite.sig_keypair()
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)
        msg = b"test message"
        sig = suite.sign(sk, msg)
        self.assertIsInstance(sig, bytes)
        self.assertTrue(suite.verify(pk, msg, sig))
        self.assertFalse(suite.verify(pk, msg, b"invalid_signature"))

    def test_verify_rejects_non_bytes_signature(self):
        suite = PQCryptoSuite(kem='kyber', sig='dilithium', level='LEVEL1')
        pk, sk = suite.sig_keypair()
        self.assertFalse(suite.verify(pk, b"msg", "not_bytes"))

    def test_unsupported_kem_raises(self):
        suite = PQCryptoSuite(kem='unknown', sig='falcon', level='LEVEL1')
        with self.assertRaises(ValueError):
            suite.kem_keypair()

    def test_unsupported_sig_raises(self):
        suite = PQCryptoSuite(kem='kyber', sig='unknown', level='LEVEL1')
        with self.assertRaises(ValueError):
            suite.sig_keypair()


if __name__ == '__main__':
    unittest.main()
