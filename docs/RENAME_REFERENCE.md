# QuantaWeave / PQCrypto — Rename Reference

This document records every identifier that was renamed when all
Kyber / Dilithium / ML-KEM / ML-DSA branding was removed from
client-facing code (March 2026).  Keep this file as a migration
guide until the C back-end is complete.

---

## File Renames

| Old path | New path | Notes |
|---|---|---|
| `quantaweave/kyber.py` | `quantaweave/lwe_kem_core.py` | Core LWE KEM implementation |
| `quantaweave/dilithium.py` | `quantaweave/lattice_sig_core.py` | Core lattice signature implementation |
| `pqcrypto/kem/kyber_768.py` | `pqcrypto/kem/lwe_kem.py` | Python KEM interface |
| `pqcrypto/kem/ml_kem_768.py` | *(deleted)* | Thin alias — no longer needed |
| `pqcrypto/dsa/dilithium3.py` | `pqcrypto/dsa/falcon_dsa.py` | Python DSA interface |

---

## Class / Symbol Renames

| Module | Old name | New name |
|---|---|---|
| `quantaweave/pq_schemes.py` | `KyberScheme` | `LWEKEMScheme` |
| `quantaweave/pq_schemes.py` | `DilithiumScheme` | `FalconSignatureScheme` |
| `quantaweave/pq_schemes_clean.py` | `KyberScheme` | `LWEKEMScheme` |
| `quantaweave/pq_schemes_clean.py` | `DilithiumScheme` | `FalconSignatureScheme` |
| `quantaweave/lwe_kem_core.py` | `KyberCore` | `LWEKEMCore` |
| `quantaweave/lattice_sig_core.py` | `DilithiumCore` | `LatticeSigCore` |
| `quantaweave/dilithium_bindings.py` | `DilithiumC` | `LatticeSignatureC` |

---

## Public API Renames (`kyber_dilithium_hqc.py`)

| Old function | New function | Description |
|---|---|---|
| `kyber_keygen()` | `kem_keygen()` | Generate a KEM key pair |
| `kyber_encaps(pk)` | `kem_encaps(pk)` | Encapsulate — returns `(ciphertext, shared_secret)` |
| `kyber_decaps(ct, sk)` | `kem_decaps(ct, sk)` | Decapsulate — returns `shared_secret` |
| `dilithium_keygen()` | `sig_keygen()` | Generate a signature key pair |
| `dilithium_sign(sk, msg)` | `sig_sign(sk, msg)` | Sign a message |
| `dilithium_verify(pk, msg, sig)` | `sig_verify(pk, msg, sig)` | Verify a signature |

---

## `PQCryptoSuite` Constructor Parameter Values

| Parameter | Old value | New value |
|---|---|---|
| `kem=` | `"kyber"` | `"lwe"` |
| `sig=` | `"dilithium"` | `"falcon"` |

---

## Build Artefacts (`setup.py`)

| Old identifier | New identifier |
|---|---|
| `kyber_sources` variable | `pq_kem_sources` variable |
| `dilithium_sources` variable | `pq_sig_sources` variable |
| `_kyber_dilithium` extension name | `_pq_kem_sig` extension name |

---

## Why the rename?

The C implementations of Kyber (ML-KEM) and Dilithium (ML-DSA) are
still being worked on — specifically the random-number generator in C.
Until the C back-end passes full test vectors it would be inaccurate to
label these implementations as *Kyber* or *Dilithium*.  The pure-Python
layer is backed by a **Learning With Errors (LWE) KEM** and a
**Falcon lattice signature** respectively, so the new names reflect the
actual algorithms in use today.

Once the C RNG and the full NIST reference implementation are integrated
and tested, the modules will be documented as ML-KEM / ML-DSA compliant.
