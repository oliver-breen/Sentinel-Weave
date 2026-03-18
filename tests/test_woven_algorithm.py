import unittest
from quantaweave.woven_algorithm import QuantaWeaveAlgorithm


class TestQuantaWeaveAlgorithm(unittest.TestCase):
    """
    Test suite for the Woven Algorithm (LWE-KEM + Falcon).
    """

    def setUp(self):
        self.algo = QuantaWeaveAlgorithm()

    def test_hybrid_aes_gcm_encryption(self):
        """Test hybrid KEM + AES-GCM encryption/decryption."""
        pk, sk = self.algo.generate_keypair()
        plaintext = b"Secret message for hybrid PQC AES-GCM weave!"
        ct, aes_gcm = self.algo.hybrid_encrypt(pk, plaintext)
        self.assertIsInstance(ct, dict)
        self.assertIsInstance(aes_gcm, dict)
        recovered = self.algo.hybrid_decrypt(ct, sk, aes_gcm)
        self.assertEqual(plaintext, recovered, "Hybrid AES-GCM decryption failed")

    def test_keypair_generation(self):
        """Test generation of serialized keys."""
        pk, sk = self.algo.generate_keypair()
        self.assertIsInstance(pk, bytes)
        self.assertIsInstance(sk, bytes)
        self.assertGreater(len(pk), 0)
        self.assertGreater(len(sk), 0)

    def test_encapsulation_decapsulation(self):
        """Test hybrid KEM functionality (LWE-KEM)."""
        pk, sk = self.algo.generate_keypair()
        ct, ss = self.algo.encapsulate(pk)
        self.assertIsInstance(ct, dict)
        # Accept new dict-based return for hybrid KEM
        self.assertIsInstance(ss, dict)
        self.assertIn('combined_secret', ss)
        self.assertIsInstance(ss['combined_secret'], bytes)
        ss_recovered = self.algo.decapsulate(ct, sk)
        self.assertIsInstance(ss_recovered, dict)
        self.assertIn('combined_secret', ss_recovered)
        self.assertEqual(ss['combined_secret'], ss_recovered['combined_secret'])

    def test_signature(self):
        """Test hybrid signature functionality (Falcon)."""
        pk, sk = self.algo.generate_keypair()
        message = b"Test message for woven signature"
        sig = self.algo.sign(message, sk)
        self.assertIsInstance(sig, bytes)
        self.assertGreater(len(sig), 0)
        valid = self.algo.verify(message, sig, pk)
        self.assertTrue(valid, "Signature verification failed")
        invalid = self.algo.verify(b"Tampered message", sig, pk)
        self.assertFalse(invalid, "Signature verification should fail for tampered message")

if __name__ == '__main__':
    unittest.main()
