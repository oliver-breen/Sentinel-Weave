"""
CLI — SentinelWeave

Command-line interface for the SentinelWeave threat-detection pipeline.

Commands
--------
analyze     Analyse a log file (or stdin) and print a threat summary.
report      Generate and store an encrypted threat report from a log file.
decrypt     Retrieve and decrypt a stored threat report.
demo        Run a built-in demonstration with synthetic log lines.

Usage
-----
::

    python -m sentinel_weave.cli analyze /var/log/auth.log
    python -m sentinel_weave.cli report  /var/log/auth.log --title "Daily Auth Report"
    python -m sentinel_weave.cli decrypt report-20240115-daily-auth-report-abcd1234.bin
    python -m sentinel_weave.cli demo
"""

from __future__ import annotations

import argparse
import json
import sys
import os
import base64

from .event_analyzer import EventAnalyzer
from .threat_detector import ThreatDetector, summarize_reports, ThreatLevel
from .azure_integration import TextAnalyticsClient, SecurityTelemetry


# ---------------------------------------------------------------------------
# ANSI colour helpers
# ---------------------------------------------------------------------------

_COLOURS = {
    "RESET":    "\033[0m",
    "BOLD":     "\033[1m",
    "RED":      "\033[31m",
    "YELLOW":   "\033[33m",
    "GREEN":    "\033[32m",
    "CYAN":     "\033[36m",
    "MAGENTA":  "\033[35m",
    "DIM":      "\033[2m",
}

_LEVEL_COLOUR = {
    "CRITICAL": _COLOURS["RED"]    + _COLOURS["BOLD"],
    "HIGH":     _COLOURS["RED"],
    "MEDIUM":   _COLOURS["YELLOW"],
    "LOW":      _COLOURS["CYAN"],
    "BENIGN":   _COLOURS["DIM"],
}


def _c(text: str, colour: str) -> str:
    """Wrap *text* in an ANSI colour code (only when stdout is a TTY)."""
    if not sys.stdout.isatty():
        return text
    return _COLOURS.get(colour, "") + text + _COLOURS["RESET"]


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

def cmd_analyze(args: argparse.Namespace) -> int:
    """Analyse a log file (or stdin) and print a colour-coded threat summary."""
    analyzer = EventAnalyzer()
    detector = ThreatDetector(
        z_threshold=args.z_threshold,
        min_baseline_samples=args.min_baseline,
    )

    if args.file == "-":
        lines = sys.stdin.read().splitlines()
    else:
        with open(args.file, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()

    if not lines:
        print("No log lines found.", file=sys.stderr)
        return 1

    events  = analyzer.parse_bulk(lines)
    reports = detector.analyze_bulk(events)

    # Emit telemetry for high/critical events
    if args.telemetry:
        telemetry = SecurityTelemetry()
        for r in reports:
            if r.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
                telemetry.track_threat(
                    threat_level=r.threat_level.value,
                    source_ip=r.event.source_ip,
                    signatures=r.event.matched_sigs,
                    anomaly_score=r.anomaly_score,
                )

    summary = summarize_reports(reports)

    print(_c("\n═══ SentinelWeave Threat Analysis ═══", "BOLD"))
    print(f"  Log file  : {args.file}")
    print(f"  Total events  : {summary.get('total', 0)}")
    print(f"  Unique IPs    : {summary.get('unique_ips', 0)}")
    print(f"  Mean score    : {summary.get('mean_score', 0):.3f}")
    print(f"  Max score     : {summary.get('max_score', 0):.3f}")

    print(_c("\n  Threat distribution:", "BOLD"))
    for level, count in summary.get("by_level", {}).items():
        if count:
            col = _LEVEL_COLOUR.get(level, "")
            bar = "█" * min(40, count)
            print(f"    {col}{level:<10}{_COLOURS['RESET']}  {count:4d}  {bar}")

    if summary.get("top_signatures"):
        print(_c("\n  Top attack signatures:", "BOLD"))
        for sig, count in summary["top_signatures"]:
            print(f"    {_c(sig, 'YELLOW')}  ×{count}")

    if args.verbose:
        top = detector.top_threats(reports, n=args.top)
        if top:
            print(_c(f"\n  Top {len(top)} threats:", "BOLD"))
            for r in top:
                col = _LEVEL_COLOUR.get(r.threat_level.value, "")
                print(f"    {col}{r.summary()}{_COLOURS['RESET']}")
                if r.explanation:
                    for line in r.explanation:
                        print(f"      • {_c(line, 'DIM')}")

    print()
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Generate an encrypted threat report from a log file."""
    try:
        from .secure_reporter import SecureReporter
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    analyzer = EventAnalyzer()
    detector = ThreatDetector()

    with open(args.file, encoding="utf-8", errors="replace") as fh:
        lines = fh.read().splitlines()

    events  = analyzer.parse_bulk(lines)
    reports = detector.analyze_bulk(events)

    reporter = SecureReporter(security_level=args.level)
    pub, priv = reporter.generate_keys()

    report_id = reporter.create_and_store(
        title=args.title or f"Threat Report — {args.file}",
        events=reports,
        public_key=pub,
    )

    # Persist the private key so the user can decrypt later
    key_path = report_id.replace(".bin", ".key.json")
    with open(key_path, "w", encoding="utf-8") as fh:
        json.dump({
            "report_id": report_id,
            "private_key": {k: list(v) if isinstance(v, (list, tuple)) else v
                            for k, v in priv.items()},
        }, fh, indent=2)

    print(_c("✔ Encrypted report stored:", "GREEN"), report_id)
    print(_c("  Private key saved to:   ", "CYAN"), key_path)
    print("  Keep the private key file secure — it is required for decryption.")
    return 0


def cmd_decrypt(args: argparse.Namespace) -> int:
    """Retrieve and decrypt a stored threat report."""
    try:
        from .secure_reporter import SecureReporter
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    key_path = args.key or args.report_id.replace(".bin", ".key.json")
    if not os.path.exists(key_path):
        print(f"Private key file not found: {key_path}", file=sys.stderr)
        return 1

    with open(key_path, encoding="utf-8") as fh:
        key_data = json.load(fh)

    # Reconstruct private key (lists must be plain Python lists)
    priv = {}
    for k, v in key_data["private_key"].items():
        priv[k] = v

    reporter = SecureReporter()
    report   = reporter.retrieve_and_decrypt(args.report_id, priv)

    print(_c("\n═══ Decrypted Threat Report ═══", "BOLD"))
    print(f"  Title        : {report['title']}")
    print(f"  Generated    : {report['generated_at']}")
    summary = report.get("summary", {})
    print(f"  Total events : {summary.get('total_events', 0)}")
    print(f"  Max score    : {summary.get('max_anomaly_score', 0):.3f}")

    print(_c("\n  Threat distribution:", "BOLD"))
    for level, count in summary.get("by_threat_level", {}).items():
        if count:
            print(f"    {_LEVEL_COLOUR.get(level, '')}{level:<10}{_COLOURS['RESET']}  {count}")

    if args.full:
        print(_c("\n  All events:", "BOLD"))
        for ev in report.get("events", []):
            lv = ev.get("threat_level", "BENIGN")
            print(f"    [{_LEVEL_COLOUR.get(lv,'')}{lv}{_COLOURS['RESET']}] {ev['raw'][:120]}")
    print()
    return 0


def cmd_demo(_args: argparse.Namespace) -> int:
    """Run a built-in demonstration with synthetic security log lines."""
    DEMO_LINES = [
        "Jan 15 10:23:01 server sshd[12345]: Failed password for root from 192.168.1.100 port 52341 ssh2",
        "Jan 15 10:23:02 server sshd[12345]: Failed password for root from 192.168.1.100 port 52342 ssh2",
        "Jan 15 10:23:03 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100",
        "Jan 15 10:24:00 server kernel: iptables DROP IN=eth0 SRC=10.0.0.5 DPT=22 PROTO=TCP",
        "Jan 15 10:25:00 web-server nginx: 10.0.0.7 - GET /?id=1' UNION SELECT * FROM users--  HTTP/1.1 200",
        "Jan 15 10:26:00 web-server nginx: 192.168.2.1 - POST /login HTTP/1.1 401",
        "Jan 15 10:27:00 server auditd: type=SYSCALL msg=sudo chmod 777 /etc/passwd",
        "Jan 15 10:28:00 server syslog: Normal user login success for alice from 10.1.0.20",
        "Jan 15 10:29:00 server syslog: Scheduled backup completed successfully",
        "Jan 15 10:30:00 server syslog: <script>alert('xss')</script> detected in request from 172.16.0.5",
        "Jan 15 10:31:00 server syslog: Service nginx started successfully",
        "Jan 15 10:32:00 server sshd: Connection from 203.0.113.42 port 4444",
        "Jan 15 10:33:00 server syslog: Possible ransomware activity detected — high disk I/O on /home",
        "Jan 15 10:34:00 server syslog: Cron job completed: disk health check OK",
        "Jan 15 10:35:00 server syslog: Failed password for root from 192.168.1.100 port 52399 ssh2",
    ]

    print(_c("\n═══ SentinelWeave — Live Demo ═══\n", "BOLD"))

    analyzer  = EventAnalyzer()
    detector  = ThreatDetector(min_baseline_samples=3)
    nlp       = TextAnalyticsClient()

    # Feed a few benign events to warm the baseline
    benign = [
        "Normal user login success for alice from 10.1.0.20",
        "Service nginx started successfully",
        "Cron job completed: disk health check OK",
        "Scheduled backup completed successfully",
    ]
    for line in benign:
        detector.update_baseline(analyzer.parse(line))

    events  = analyzer.parse_bulk(DEMO_LINES)
    reports = detector.analyze_bulk(events)

    print(f"  Processed {len(reports)} log lines\n")

    for r in reports:
        col  = _LEVEL_COLOUR.get(r.threat_level.value, "")
        rst  = _COLOURS["RESET"]
        line = r.event.raw[:90] + ("…" if len(r.event.raw) > 90 else "")
        print(f"  {col}[{r.threat_level.value:<8}]{rst} {line}")
        if r.event.matched_sigs:
            print(f"             {_c('Sigs: ' + ', '.join(r.event.matched_sigs), 'YELLOW')}")

    summary = summarize_reports(reports)
    print(_c("\n  Summary:", "BOLD"))
    print(f"    CRITICAL : {summary['by_level']['CRITICAL']}")
    print(f"    HIGH     : {summary['by_level']['HIGH']}")
    print(f"    MEDIUM   : {summary['by_level']['MEDIUM']}")
    print(f"    LOW      : {summary['by_level']['LOW']}")
    print(f"    BENIGN   : {summary['by_level']['BENIGN']}")
    print(f"    Max anomaly score: {summary['max_score']:.3f}")

    print(_c("\n  NLP analysis (local mode):", "BOLD"))
    sample = "Failed password for root — possible brute-force attack from external IP"
    nlp_result = nlp.analyze(sample)
    print(f"    Input     : {sample}")
    print(f"    Sentiment : {nlp_result['sentiment']}")
    print(f"    Key phrases: {', '.join(nlp_result['key_phrases'][:5])}")
    print(f"    Source    : {nlp_result['source']}")

    print()
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel_weave",
        description="SentinelWeave — AI-powered cybersecurity threat detection with post-quantum encryption",
    )
    sub = parser.add_subparsers(dest="command")

    # analyze
    p_analyze = sub.add_parser("analyze", help="Analyse a log file for threats")
    p_analyze.add_argument("file", help="Log file path (use '-' for stdin)")
    p_analyze.add_argument("-v", "--verbose", action="store_true", help="Show top threats in detail")
    p_analyze.add_argument("--top", type=int, default=5, metavar="N", help="Number of top threats to show (default 5)")
    p_analyze.add_argument("--z-threshold", type=float, default=3.0, metavar="Z",
                           help="Z-score threshold for anomaly detection (default 3.0)")
    p_analyze.add_argument("--min-baseline", type=int, default=10, metavar="N",
                           help="Min events before z-score analysis activates (default 10)")
    p_analyze.add_argument("--telemetry", action="store_true",
                           help="Emit HIGH/CRITICAL events to Azure Monitor (requires credentials)")

    # report
    p_report = sub.add_parser("report", help="Generate an encrypted threat report")
    p_report.add_argument("file", help="Log file to analyse")
    p_report.add_argument("--title", default=None, help="Report title")
    p_report.add_argument("--level", default="LEVEL1", choices=["LEVEL1", "LEVEL3", "LEVEL5"],
                          help="QuantaWeave security level (default LEVEL1)")

    # decrypt
    p_decrypt = sub.add_parser("decrypt", help="Decrypt a stored threat report")
    p_decrypt.add_argument("report_id", help="Report blob name / file path")
    p_decrypt.add_argument("--key", default=None, help="Path to the .key.json file")
    p_decrypt.add_argument("--full", action="store_true", help="Show all events in the report")

    # demo
    sub.add_parser("demo", help="Run a built-in demonstration")

    return parser


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    handlers = {
        "analyze": cmd_analyze,
        "report":  cmd_report,
        "decrypt": cmd_decrypt,
        "demo":    cmd_demo,
    }

    handler = handlers.get(args.command)
    if handler is None:
        parser.print_help()
        sys.exit(0)

    sys.exit(handler(args))


if __name__ == "__main__":
    main()
