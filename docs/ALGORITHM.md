# QuantaWeave Algorithm

QuantaWeave is a Python implementation of a lattice-based post-quantum cryptography algorithm using the Learning With Errors (LWE) problem.

## Overview

This library implements a quantum-resistant encryption scheme designed to be secure against attacks from both classical and quantum computers. The LWE-based encryption is complemented by an ML-KEM Key Encapsulation Mechanism (KEM) for shared-secret establishment and a Falcon signature binding.

For formal proof sketches and reduction outlines, see [docs/PROOFS.md](PROOFS.md).

## Features

- **Quantum-Resistant**: Based on lattice problems that are hard for quantum computers
- **Multiple Security Levels**: Support for 128-bit, 192-bit, and 256-bit security
- **Simple API**: Easy-to-use interface for key generation, encryption, and decryption
- **Pure Python Core**: No external dependencies for the LWE-based library in `quantaweave/`
- **Falcon Signatures**: C++ binding for Falcon-512/1024 signatures
- **Examples Included**: Basic, benchmark, multi-party, and Falcon signature demos
- **Well-Tested**: Unit tests for math utilities, key generation, and encryption/decryption

## Algorithm Description

### Mathematical Foundation

The algorithm is based on the **Learning With Errors (LWE)** problem:

Given pairs (A, b) where b = As + e (mod q), it is computationally hard to recover the secret vector s, even with access to many such pairs.

### Key Components

1. **Polynomial Ring**: Operations are performed in R_q = Z_q[X]/(X^n + 1)
2. **Key Generation**: 
   - Secret key: s sampled from centered binomial distribution
   - Public key: (A, b) where b = As + e
3. **Encryption**: 
   - Ciphertext: (u, v) where u = Ar + e1 and v = br + e2 + encode(m)
4. **Decryption**: 
   - Message: decode(v - us)

### Security Levels

| Level | Dimension (n) | Modulus (q) | Security Bits |
|-------|---------------|-------------|---------------|
| LEVEL1 | 256 | 3329 | 128 |
| LEVEL3 | 512 | 7681 | 192 |
| LEVEL5 | 1024 | 12289 | 256 |

## Installation

Since this is a self-contained library, simply copy the `quantaweave` directory to your project:

```bash
git clone https://github.com/oliver-breen/New-Algorithm-for-Post-Quantum-Cryptography.git
cd New-Algorithm-for-Post-Quantum-Cryptography
```

## Usage

### Basic Example

```python
from quantaweave import QuantaWeave

# Initialize with desired security level
pqc = QuantaWeave(security_level='LEVEL1')

# Generate key pair
public_key, private_key = pqc.generate_keypair()

# Encrypt a message
message = b"Hello, Quantum World!"
ciphertext = pqc.encrypt(message, public_key)

# Decrypt the ciphertext
decrypted = pqc.decrypt(ciphertext, private_key)

assert message == decrypted
```

### Advanced Example

```python
from quantaweave import QuantaWeave

# Use higher security level for sensitive data
pqc = QuantaWeave(security_level='LEVEL5')  # 256-bit security

public_key, private_key = pqc.generate_keypair()

# Encrypt binary data
data = bytes([0x48, 0x65, 0x6c, 0x6c, 0x6f])
ciphertext = pqc.encrypt(data, public_key)

# Decrypt
plaintext = pqc.decrypt(ciphertext, private_key)
print(plaintext)  # b'Hello'
```

## Examples

Python snippets:

```python
from mlkem_mldsa_bridge import kem_keygen, kem_encaps, kem_decaps

public_key, secret_key = kem_keygen()
ciphertext, shared_secret = kem_encaps(public_key)
recovered = kem_decaps(ciphertext, secret_key)
assert recovered == shared_secret
```

```python
from quantaweave import FalconSig

falcon = FalconSig("Falcon-1024")
public_key, secret_key = falcon.keygen()
message = b"sign me"
signature = falcon.sign(secret_key, message)
assert falcon.verify(public_key, message, signature)
```

## Running Examples

```bash
# Basic usage example
python examples/basic_usage.py

# Performance benchmark
python examples/benchmark.py

# Multi-party messaging demo
python examples/multi_party.py

# Falcon signature demo (requires GMP + C++ build)
python examples/falcon_signature.py
```

## Running Tests

```bash
# Run all tests
python -m unittest tests/test_quantaweave.py
python -m unittest tests/test_kem_tests.py
python -m unittest tests/test_falcon_sig.py

# Run specific test class
python -m unittest tests.test_quantaweave.TestEncryptionDecryption

# Run with verbose output
python -m unittest tests/test_quantaweave.py -v
```

## API Reference

### QuantaWeave Class

Main interface for the cryptography system.

#### Methods

- `__init__(security_level='LEVEL1')`: Initialize with security level
- `generate_keypair()`: Generate public and private key pair
- `encrypt(message, public_key)`: Encrypt a message
- `decrypt(ciphertext, private_key)`: Decrypt a ciphertext
- `get_security_level()`: Get security level in bits

### FalconSig Class

Signature API backed by a C++ binding.

#### Methods

- `__init__(parameter_set="Falcon-1024")`: Choose Falcon-512 or Falcon-1024
- `keygen()`: Generate public and private keys
- `sign(secret_key, message)`: Sign a message
- `verify(public_key, message, signature)`: Verify a signature
- `sizes()`: Return key and signature sizes

### KeyGenerator Class

Handles key pair generation.

#### Methods

- `__init__(security_level='LEVEL1')`: Initialize key generator
- `generate_keypair()`: Generate a key pair
- `get_security_level()`: Get security level in bits

### Encryptor Class

Handles message encryption.

#### Methods

- `__init__(public_key)`: Initialize with public key
- `encrypt(message)`: Encrypt a message (max length n/8 bytes)

### Decryptor Class

Handles ciphertext decryption.

#### Methods

- `__init__(private_key)`: Initialize with private key
- `decrypt(ciphertext)`: Decrypt a ciphertext

## Security Considerations

### Strengths

1. **Quantum Resistance**: Based on lattice problems believed to be hard for quantum computers
2. **Provable Security**: Security can be reduced to well-studied hard problems
3. **Efficient**: Polynomial operations are relatively fast

### Limitations

1. **Message Length**: Limited by polynomial dimension (n/8 bytes)
2. **Ciphertext Size**: Larger than classical schemes like RSA
3. **Error Tolerance**: Small probability of decryption errors

### Best Practices

1. Use LEVEL3 or LEVEL5 for highly sensitive data
2. Regularly rotate keys
3. Combine with authenticated encryption in production systems
4. Keep private keys secure and never transmit them

## Performance

Use `examples/benchmark.py` to measure performance on your hardware. The `results_v2.md` file contains a baseline template with sample data only.

## Falcon Signatures

Falcon is a lattice-based signature scheme. The binding exposes Falcon-512 and Falcon-1024 key generation, signing, and verification, using the vendor C++ implementation. Building the extension requires GMP, pybind11, and a C++20 compiler.

### Usage

```python
from mlkem_mldsa_bridge import kem_keygen, kem_encaps, kem_decaps

public_key, secret_key = kem_keygen()
ciphertext, shared_secret = kem_encaps(public_key)
recovered_secret = kem_decaps(ciphertext, secret_key)

assert shared_secret == recovered_secret
```

## Implementation Details

### Polynomial Operations

- **Addition/Subtraction**: O(n) coefficient-wise operations
- **Multiplication**: O(n²) using naive algorithm (can be optimized with NTT)
- **Modular Reduction**: Reduction modulo X^n + 1

### Sampling

- **Uniform Sampling**: Uses cryptographically secure random number generator
- **Centered Binomial**: Generates small errors for security
- **Error Distribution**: Carefully calibrated to balance security and correctness

### Compression

- Ciphertexts are compressed to reduce size
- Compression parameters (du, dv) balance size and decryption accuracy

## Future Enhancements

Potential improvements for future versions:

1. **NTT Optimization**: Implement Number Theoretic Transform for O(n log n) multiplication
2. **Batch Operations**: Support encrypting multiple messages efficiently
3. **Key Serialization**: Add methods to save/load keys
4. **Side-Channel Resistance**: Add constant-time implementations
5. **Digital Signatures**: Implement signature schemes
6. **Key Exchange**: Add key encapsulation mechanism (KEM)

## Repository Notes

- The `encapsulation_decapsulation.py` demo uses RSA-OAEP for key wrapping, which is **not** post-quantum secure. It is provided for hybrid KEM workflow illustration only.
- Dependencies: the RSA demo requires the `cryptography` package; the LWE core in `quantaweave/` does not.
- The `key_generation.py` file is a disabled RSA keygen example (wrapped in a docstring).
- `mlkem_mldsa_bridge.py` provides the ML-KEM and ML-DSA Python API (C integration is work in progress).

## References

This implementation is inspired by:

1. Regev, O. (2005). "On lattices, learning with errors, random linear codes, and cryptography"
2. NIST Post-Quantum Cryptography Standardization
3. Lattice-based KEM constructions (module-LWE)
4. Lattice-based digital signature schemes

## License

MIT License - see LICENSE file for details

## Contributing

Contributions are welcome! Please ensure:

1. All tests pass
2. Code follows existing style
3. New features include tests
4. Documentation is updated

## Author

Oliver Breen

## Disclaimer

This is an educational implementation. For production use, consider:

1. Using established lattice-based algorithms with professional security audits
2. Professional security audits
3. Constant-time implementations
4. Side-channel attack resistance

**DO NOT USE IN PRODUCTION WITHOUT PROFESSIONAL SECURITY REVIEW**
