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

## Performance Targets

- Benchmarks are gated against `tests/benchmarks_baseline.json` with a tolerance factor.
- Update baselines only after confirming regressions are not introduced.
