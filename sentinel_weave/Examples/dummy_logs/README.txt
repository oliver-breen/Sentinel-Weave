SentinelWeave Dummy Log Fixtures
================================

Purpose:
- Professional, synthetic log fixtures for demos, parser validation, and local testing.
- Covers major SentinelWeave areas: event analysis, web attacks, email scanning,
  availability monitoring, integrity chain activity, threat correlation, SIEM export,
  Azure integration telemetry, and red-team findings.
- Includes a high-volume weekly SOC simulation with mixed benign, medium, high,
  and critical events in randomized order:
  - 11_weekly_soc_mixed_840.log

Usage:
- Point CLI analysis/report commands at any *.log file in this directory.
- Files are independent and can be used individually.

Removal:
- This fixture set is fully isolated to this folder.
- Remove all dummy logs by deleting only this directory:
  sentinel_weave/Examples/dummy_logs/

Note:
- All entries are fabricated test data and safe for non-production environments.
