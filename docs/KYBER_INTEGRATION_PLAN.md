# KEM Integration Plan

## Overview

This document describes the current state and future plans for the Key Encapsulation Mechanism (KEM) integration in the QuantaWeave library.

## Current State

- **LWE KEM**: Pure-Python educational implementation in `quantaweave/lwe_kem_core.py` using the Learning With Errors (LWE) problem
- **Falcon Signatures**: Lattice-based signatures via a C++ binding in `quantaweave/falcon.py`
- **`mlkem_mldsa_bridge.py`**: ML-KEM/ML-DSA API module exposing `kem_keygen`, `kem_encaps`, `kem_decaps`, `sig_keygen`, `sig_sign`, `sig_verify`

## Planned C Integration

The C files for the LWE KEM and lattice signature scheme are currently being worked on.
Once the C random number generator is complete and tested, the Python bindings will be
updated to call the C implementations instead of the pure-Python fallback.

### Steps

1. Complete C random number generator implementation (`vendor/kyber_dilithium/`)
2. Build and test the C extension (`_pq_kem_sig`)
3. Update `mlkem_mldsa_bridge.py` to delegate to the C extension when available, falling back to the pure-Python implementation

## Usage

```python
from mlkem_mldsa_bridge import kem_keygen, kem_encaps, kem_decaps, sig_keygen, sig_sign, sig_verify

# KEM round-trip
keys = kem_keygen()
encap = kem_encaps(keys['public_key'])
ss = kem_decaps(encap['ciphertext'], keys['secret_key'])
assert encap['shared_secret'] == ss

# Signature round-trip
sig_keys = sig_keygen()
signature = sig_sign(sig_keys['secret_key'], b"hello")
assert sig_verify(sig_keys['public_key'], b"hello", signature)
```

## Security Note

The pure-Python implementations are **educational only** and are not suitable for production use.
They do not provide constant-time guarantees and have not undergone professional security audits.
