# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | ✅ Yes    |
| < 0.4   | ❌ No     |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, report them privately by emailing **oliver.breen000@gmail.com** with:

- A description of the vulnerability and its impact
- Steps to reproduce (proof-of-concept code or a detailed description)
- Affected version(s)
- Any suggested mitigations

You should receive an acknowledgement within **72 hours** and a resolution
timeline within **7 days**.

## Security Analysis

For a full threat model, known attack surface, and hardening recommendations see
[`docs/SECURITY.md`](docs/SECURITY.md).

## Scope

This repository contains:

- **SentinelWeave** (`sentinel_weave/`) — AI-powered cybersecurity threat
  detection with post-quantum secure reporting.
- **QuantaWeave** (`quantaweave/`) — Post-quantum cryptography library (LWE
  encryption, HQC KEM, Falcon signatures, LWE KEM bindings).
- **Dashboard** (`dashboard/`) — Flask web dashboard for live threat metrics.

> ⚠️ **Note:** The QuantaWeave implementation is primarily educational.
> See `docs/SECURITY.md` for a detailed list of known limitations before
> using any component in production.
