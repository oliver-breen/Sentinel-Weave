# Production Guidance

This repository is an educational implementation. Use it as a reference and apply hardening before production use.

## Dependency Policy

- Runtime dependencies: core Python + optional Azure SDKs when Azure features are enabled
- Optional development dependencies: ruff, mypy, build
- Pin all development dependencies in CI

## API Stability

- Public API: `QuantaWeave` methods and Falcon signatures exported from `quantaweave`.
- Deprecation policy: maintain backward compatibility for one minor release before removal.
- Breaking changes require a version bump and changelog entry.

## Security Hardening

- Prefer constant-time implementations for sensitive code paths.
- Use secure key storage and rotation.
- Validate input sizes and enforce strict parsing.
- Validate Azure environment configuration before deployment.

## CI Gates

- Lint (ruff)
- Type checks (mypy)
- Unit tests
- Benchmarks with baseline thresholds

## Deploy Checklist

- Set `SENTINELWEAVE_API_KEY` and rotate it regularly.
- Validate ingress/TLS termination and restrict the dashboard to trusted networks.
- Run the full CI suite (lint, mypy, unit tests, benchmarks).
- Build the dashboard UI (`npm run build` in `sentinel_weave/dashboard_web`).
- Verify `/health` returns `status=ok` and `version` is correct.
- Confirm rate limits and input size limits match your threat model.
- Back up secrets and document recovery steps.

## Performance Targets

- Benchmarks are gated against `tests/benchmarks_baseline.json` with a tolerance factor.
- Update baselines only after confirming regressions are not introduced.
