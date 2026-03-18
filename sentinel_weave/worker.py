"""
SentinelWeave background worker.

Runs periodic threat analysis against a log source and emits summary metrics to stdout.
Designed for container/Kubernetes use as a lightweight worker process.
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from .event_analyzer import EventAnalyzer
from .threat_detector import ThreatDetector, summarize_reports


def _read_lines(path: Path, max_lines: int) -> list[str]:
    with path.open(encoding="utf-8", errors="replace") as fh:
        lines = [line.strip() for line in fh if line.strip()]
    if max_lines > 0:
        return lines[:max_lines]
    return lines


def run_once(log_file: Path, max_lines: int, z_threshold: float, min_baseline: int) -> int:
    lines = _read_lines(log_file, max_lines=max_lines)
    if not lines:
        print(f"[worker] no lines found in {log_file}")
        return 1

    analyzer = EventAnalyzer()
    detector = ThreatDetector(z_threshold=z_threshold, min_baseline_samples=min_baseline)
    events = analyzer.parse_bulk(lines)
    reports = detector.analyze_bulk(events)
    summary = summarize_reports(reports)

    by_level = summary.get("by_level", {})
    print(
        "[worker] analyzed={total} ips={ips} max={max_score:.3f} "
        "critical={critical} high={high} medium={medium} low={low} benign={benign}".format(
            total=summary.get("total", 0),
            ips=summary.get("unique_ips", 0),
            max_score=summary.get("max_score", 0.0),
            critical=by_level.get("CRITICAL", 0),
            high=by_level.get("HIGH", 0),
            medium=by_level.get("MEDIUM", 0),
            low=by_level.get("LOW", 0),
            benign=by_level.get("BENIGN", 0),
        )
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m sentinel_weave.worker",
        description="Run periodic SentinelWeave threat analysis as a background worker.",
    )
    parser.add_argument(
        "--log-file",
        default="sentinel_weave/Examples/dummy_logs/11_weekly_soc_mixed_840.log",
        help="Path to the input log file",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=0,
        metavar="N",
        help="Maximum number of lines to analyze per run (0 = all)",
    )
    parser.add_argument(
        "--interval",
        type=int,
        default=30,
        metavar="SEC",
        help="Polling interval in seconds between analysis runs",
    )
    parser.add_argument(
        "--z-threshold",
        type=float,
        default=3.0,
        metavar="Z",
        help="Z-score threshold for anomaly detection",
    )
    parser.add_argument(
        "--min-baseline",
        type=int,
        default=10,
        metavar="N",
        help="Minimum baseline events before z-score scoring activates",
    )
    parser.add_argument("--once", action="store_true", help="Run one iteration and exit")
    args = parser.parse_args()

    log_file = Path(args.log_file)
    if not log_file.exists():
        raise FileNotFoundError(f"log file not found: {log_file}")

    while True:
        run_once(
            log_file=log_file,
            max_lines=args.batch_size,
            z_threshold=args.z_threshold,
            min_baseline=args.min_baseline,
        )
        if args.once:
            return
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    main()

