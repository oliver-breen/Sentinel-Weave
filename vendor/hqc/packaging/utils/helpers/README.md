# `helpers/` — Standalone KEM Utility Programs

This directory contains two small C programs that are compiled once per HQC
variant (hqc-1, hqc-3, hqc-5) as part of the packaging pipeline.

---

## `main_kat.c` — Known-Answer Test (KAT) Generator

**Purpose:** Generates the NIST-format `.req` / `.rsp` Known-Answer Test
vector files that live in `kats/`.

| File produced | Contents |
|---|---|
| `PQCkemKAT_<N>.req` | 100 seed entries used as input to the KEM |
| `PQCkemKAT_<N>.rsp` | Public keys, secret keys, ciphertexts and shared secrets derived from each seed |

Where `<N>` is `CRYPTO_SECRETKEYBYTES` for the chosen variant
(2321 for hqc-1, 4602 for hqc-3, 7333 for hqc-5).

**How it works:**

1. Initialises the NIST PRNG with a deterministic 48-byte entropy input
   (`0x00 … 0x2F`).
2. Draws 100 random seeds and writes them to `PQCkemKAT_<N>.req`.
3. Re-reads the `.req` file, then for each seed:
   - Re-seeds the PRNG.
   - Calls `crypto_kem_keypair`, `crypto_kem_enc`, and `crypto_kem_dec`.
   - Writes `pk`, `sk`, `ct`, and `ss` to `PQCkemKAT_<N>.rsp`.
4. Verifies that encapsulation and decapsulation agree on the shared secret.

The resulting files are copied into each variant sub-directory by
`packaging/build_nist_release.sh` as part of the NIST submission package.

---

## `main_hqc.c` — Interactive KEM Demo

**Purpose:** A simple interactive demonstration of a single HQC key
encapsulation / decapsulation round-trip using OS-supplied entropy.

It is useful for quick smoke-testing a freshly compiled HQC binary or for
demonstrating the API in isolation.

---

## Building

These helpers are not built standalone; they are compiled by the top-level
CMake configuration when packaging targets are requested.  See
`packaging/README.md` and the project root `README.md` for full build
instructions.
