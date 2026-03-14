"""
RSA-GCM hybrid cryptography module for QuantaWeave
- Key generation (RSA)
- Encryption (RSA-OAEP + AES-GCM)
- Decryption (RSA-OAEP + AES-GCM)

Requires: cryptography
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives import constant_time
import os

class RSAGCM:
    def __init__(self, key_size=2048):
        self.key_size = key_size

    def generate_keypair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return (
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
        )

    def encrypt(self, plaintext: bytes, public_key_bytes: bytes) -> dict:
        public_key = serialization.load_pem_public_key(public_key_bytes, backend=default_backend())
        aes_key = os.urandom(32)  # 256-bit AES key
        iv = os.urandom(12)  # 96-bit IV for GCM
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        wrapped_key = public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return {
            'wrapped_key': wrapped_key,
            'iv': iv,
            'ciphertext': ciphertext,
            'tag': tag
        }

    def decrypt(self, enc_dict: dict, private_key_bytes: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(private_key_bytes, password=None, backend=default_backend())
        aes_key = private_key.decrypt(
            enc_dict['wrapped_key'],
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(enc_dict['iv'], enc_dict['tag']),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(enc_dict['ciphertext']) + decryptor.finalize()
        return plaintext
