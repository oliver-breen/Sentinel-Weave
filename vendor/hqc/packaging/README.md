# `build_nist_release.sh`

> Assemble the NIST release directory under `build-package`


## Overview

This script automates creation of the `build-package` tree, ready for NIST PQC release. It will produce:

- **Reference_Implementation/**  
  ├─ `hqc-1/`  
  ├─ `hqc-3/`  
  └─ `hqc-5/`

- **Optimized_Implementation/**  
  ├─ `hqc-1/`  
  ├─ `hqc-3/`  
  └─ `hqc-5/`

- **KATs/**
    - Copies `.req`/`.rsp` files from `kats/ref/...` into `Reference_Implementation/{hqc-*}`
    - Copies from `kats/x86_64/...` into `Optimized_Implementation/{hqc-*}`

- **Supporting_Documentation/**
    - Empty placeholder directory for `HQC_Submission.pdf`

---

## Related helpers

The `utils/helpers/` sub-directory contains two small C programs used during
the packaging and testing workflow:

| File | Purpose |
|---|---|
| `utils/helpers/main_kat.c` | Generates the NIST-format `PQCkemKAT_<N>.req` / `.rsp` Known-Answer Test vector files that end up in `kats/` |
| `utils/helpers/main_hqc.c` | Interactive smoke-test: runs a single KEM key-generation → encapsulation → decapsulation round-trip |

See [`utils/helpers/README.md`](utils/helpers/README.md) for full details.

---

## Usage

From the project root:

```bash
chmod +x packaging/build_nist_release.sh
./packaging/build_nist_release.sh
