"""
Core API for the QuantaWeave library.

Provides a simple interface for key generation, encryption, and decryption.
"""

from typing import Tuple, Dict
from .keygen import KeyGenerator
from .encryption import Encryptor, Decryptor


class QuantaWeave:
    """
    Main interface for the QuantaWeave system.
    
    Provides methods for:
    - Generating key pairs
    - Encrypting messages
    - Decrypting ciphertexts
    
    Example:
        >>> pqc = QuantaWeave(security_level='LEVEL1')
        >>> public_key, private_key = pqc.generate_keypair()
        >>> ciphertext = pqc.encrypt(b"Hello, Quantum World!", public_key)
        >>> plaintext = pqc.decrypt(ciphertext, private_key)
        >>> print(plaintext)
        b'Hello, Quantum World!'
    """
    
    def __init__(self, security_level: str = 'LEVEL1'):
        """
        Initialize QuantaWeave system.
        
        Args:
            security_level: Security level - 'LEVEL1' (128-bit), 
                          'LEVEL3' (192-bit), or 'LEVEL5' (256-bit)
        """
        self.security_level = security_level
        self.keygen = KeyGenerator(security_level)
    
    def generate_keypair(self) -> Tuple[Dict, Dict]:
        """
        Generate a new public/private key pair.
        
        Returns:
            Tuple of (public_key, private_key)
        """
        if getattr(self, 'algorithm', None) == 'NEWALGO':
            pk = {'newalgo': 'public_key_placeholder'}
            sk = {'newalgo': 'private_key_placeholder'}
            return pk, sk
        return self.keygen.generate_keypair()
    
    @staticmethod
    def encrypt(message: bytes, public_key: Dict) -> Dict:
        """
        Encrypt a message using a public key.
        
        Args:
            message: Message to encrypt (bytes)
            public_key: Public key dictionary
            
        Returns:
            Ciphertext dictionary
        """
        if isinstance(public_key, dict) and 'newalgo' in public_key:
            return {'newalgo_ciphertext': 'ciphertext_placeholder'}
        encryptor = Encryptor(public_key)
        return encryptor.encrypt(message)
    
    @staticmethod
    def decrypt(ciphertext: Dict, private_key: Dict) -> bytes:
        """
        Decrypt a ciphertext using a private key.
        
        Args:
            ciphertext: Ciphertext dictionary
            private_key: Private key dictionary
            
        Returns:
            Decrypted message (bytes)
        """
        if isinstance(private_key, dict) and 'newalgo' in private_key:
            return b'newalgo_decrypted_message_placeholder'
        decryptor = Decryptor(private_key)
        return decryptor.decrypt(ciphertext)
    
    def get_security_level(self) -> int:
        """
        Get the security level in bits.
        
        Returns:
            Security level (128, 192, or 256)
        """
        return self.keygen.get_security_level()

