"""
SentinelWeave ML Pipeline — Interactive Demo
=============================================

Run this script to walk through the complete machine-learning threat-detection
pipeline from raw log lines all the way to a deployed Azure ML schema.

Usage
-----
    python examples/ml_demo.py           # full demo, no interaction
    python examples/ml_demo.py --fast    # fewer epochs (quicker)
    python examples/ml_demo.py --interact # add live log-line classifier at the end

What this demo covers
---------------------
  Phase 1  – Generate a realistic synthetic security log corpus
  Phase 2  – Parse raw log lines into SecurityEvent feature vectors
  Phase 3  – Auto-label events (threat vs. benign) with DatasetBuilder
  Phase 4  – Handle class imbalance via oversampling
  Phase 5  – Train/test split and SecurityClassifier training
  Phase 6  – ASCII learning curve (loss vs. epoch)
  Phase 7  – Full evaluation: confusion matrix + precision/recall/F1
  Phase 8  – Feature importance (ranked model weights)
  Phase 9  – Decision-threshold sensitivity sweep
  Phase 10 – Save model to JSON and reload, verify predictions match
  Phase 11 – Export Azure ML scoring schema
  Phase 12 – [optional --interact] Type your own log line and classify it live
"""

import argparse
import json
import math
import os
import sys
import tempfile

# Allow running from the repository root without installation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sentinel_weave.event_analyzer import EventAnalyzer
from sentinel_weave.threat_detector import ThreatDetector, ThreatLevel
from sentinel_weave.ml_pipeline import (
    DatasetBuilder,
    LabeledEvent,
    SecurityClassifier,
    evaluate_classifier,
)


# ─────────────────────────────────────────────────────────────────────────────
# Colour helpers (degrade gracefully on terminals that don't support ANSI)
# ─────────────────────────────────────────────────────────────────────────────

_ANSI = {
    "BOLD":  "\033[1m",
    "DIM":   "\033[2m",
    "RED":   "\033[31m",
    "GREEN": "\033[32m",
    "YELLOW":"\033[33m",
    "CYAN":  "\033[36m",
    "WHITE": "\033[37m",
    "RESET": "\033[0m",
}

def _c(text: str, colour: str) -> str:
    if sys.stdout.isatty():
        return _ANSI.get(colour, "") + text + _ANSI["RESET"]
    return text

def _header(title: str) -> None:
    width = 70
    print()
    print(_c("═" * width, "CYAN"))
    print(_c(f"  {title}", "BOLD"))
    print(_c("═" * width, "CYAN"))


# ─────────────────────────────────────────────────────────────────────────────
# Synthetic log corpus
# ─────────────────────────────────────────────────────────────────────────────

#: Realistic SSH brute-force log lines (threat)
_SSH_BRUTE_FORCE = [
    "Jan 15 10:23:01 web01 sshd[9811]: Failed password for root from 198.51.100.42 port 54321 ssh2",
    "Jan 15 10:23:02 web01 sshd[9811]: Failed password for root from 198.51.100.42 port 54322 ssh2",
    "Jan 15 10:23:03 web01 sshd[9811]: Failed password for invalid user admin from 198.51.100.42",
    "Jan 15 10:23:04 web01 sshd[9811]: Failed password for invalid user ubuntu from 198.51.100.42",
    "Jan 15 10:23:05 web01 sshd[9811]: Failed password for invalid user pi from 198.51.100.42",
    "Jan 15 10:23:06 web01 sshd[9811]: Failed password for root from 198.51.100.42 port 54323 ssh2",
    "Jan 15 10:24:00 web01 sshd[9812]: Failed password for mysql from 203.0.113.7 port 11911 ssh2",
    "Jan 15 10:24:01 web01 sshd[9812]: Failed password for postgres from 203.0.113.7 port 11912 ssh2",
    "Jan 15 10:24:02 web01 sshd[9812]: error: maximum authentication attempts exceeded for root from 203.0.113.7",
]

#: Web application attacks (threat)
_WEB_ATTACKS = [
    "Jan 15 10:25:00 web01 nginx: 10.0.0.99 GET /?id=1' UNION SELECT username,password FROM users-- HTTP/1.1 200",
    "Jan 15 10:25:01 web01 nginx: 10.0.0.99 GET /?search=<script>alert('xss')</script> HTTP/1.1 200",
    "Jan 15 10:25:02 web01 nginx: 10.0.0.99 GET /../../../../etc/passwd HTTP/1.1 404",
    "Jan 15 10:25:03 web01 nginx: 10.0.0.99 POST /login HTTP/1.1 200 - SQL_INJECTION detected",
    "Jan 15 10:25:04 web01 nginx: 172.16.0.5 GET /admin/config?cmd=ls%20-la HTTP/1.1 403",
    "Jan 15 10:25:05 web01 nginx: 172.16.0.5 GET /?q=<img+src=x+onerror=alert(1)> HTTP/1.1 200",
    "Jan 15 10:26:00 web01 apache: 10.20.30.40 - GET /wp-login.php HTTP/1.1 200 COMMAND_INJECTION",
    "Jan 15 10:26:01 web01 nginx: 192.0.2.88 POST /api/v1/exec HTTP/1.1 500 - path traversal attempt",
]

#: Privilege escalation and credential access (threat)
_ESCALATION = [
    "Jan 15 10:27:00 web01 auditd: type=SYSCALL msg=sudo chmod 4755 /bin/bash uid=1001 auid=1001",
    "Jan 15 10:27:01 web01 auditd: PRIVILEGE_ESCALATION detected - process spawned with elevated uid 0",
    "Jan 15 10:27:02 web01 syslog: /etc/passwd modification detected by AIDE integrity check",
    "Jan 15 10:28:00 web01 syslog: CREDENTIAL_DUMP attempt – /etc/shadow access from PID 4401",
    "Jan 15 10:28:01 web01 syslog: Suspicious chmod 777 /etc/sudoers detected from 10.0.0.99",
    "Jan 15 10:28:02 web01 kernel: audit: MALWARE_INDICATOR – outbound C2 beacon detected dst=185.220.101.5",
]

#: Port scanning / reconnaissance (threat)
_RECON = [
    "Jan 15 10:29:00 web01 kernel: iptables DROP IN=eth0 SRC=198.51.100.42 DST=10.0.0.1 DPT=22 PROTO=TCP",
    "Jan 15 10:29:01 web01 kernel: iptables DROP IN=eth0 SRC=198.51.100.42 DST=10.0.0.1 DPT=3306 PROTO=TCP",
    "Jan 15 10:29:02 web01 kernel: iptables DROP IN=eth0 SRC=198.51.100.42 DST=10.0.0.1 DPT=5432 PROTO=TCP",
    "Jan 15 10:29:03 web01 syslog: PORT_SCAN detected from 198.51.100.42 – 47 ports in 2s",
    "Jan 15 10:29:04 web01 kernel: iptables DROP SRC=203.0.113.7 DPT=443 — possible TLS fingerprint scan",
]

#: Normal, benign log lines
_BENIGN = [
    "Jan 15 10:30:00 web01 sshd[9900]: Accepted publickey for alice from 10.1.0.20 port 60001 ssh2",
    "Jan 15 10:30:01 web01 syslog: cron[1234]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)",
    "Jan 15 10:30:02 web01 syslog: Service nginx started successfully – worker processes: 4",
    "Jan 15 10:30:03 web01 syslog: Scheduled disk health check OK – no errors found",
    "Jan 15 10:30:04 web01 syslog: Backup completed: 14 GB archived to /mnt/backup/2024-01-15",
    "Jan 15 10:30:05 web01 syslog: Normal user login success for bob from 192.168.100.50",
    "Jan 15 10:30:06 web01 syslog: System clock synchronized via NTP server pool.ntp.org",
    "Jan 15 10:30:07 web01 syslog: Daily security report generated and emailed to admin@company.com",
    "Jan 15 10:30:08 web01 syslog: Memory usage: 42% – no anomalies detected",
    "Jan 15 10:31:00 web01 nginx: 10.1.0.20 GET /index.html HTTP/1.1 200 – 1234 bytes",
    "Jan 15 10:31:01 web01 nginx: 10.1.0.21 GET /api/v1/status HTTP/1.1 200",
    "Jan 15 10:31:02 web01 syslog: Package updates applied: 3 security, 2 bugfix",
    "Jan 15 10:31:03 web01 syslog: Docker container web-app restarted successfully",
    "Jan 15 10:31:04 web01 syslog: TLS certificate renewed for *.company.com – expires 2025-01-15",
    "Jan 15 10:31:05 web01 syslog: Audit trail: admin logged in from 192.168.1.1 – 2FA verified",
    "Jan 15 10:31:06 web01 syslog: Database connection pool healthy – 10/50 connections active",
    "Jan 15 10:32:00 web01 syslog: Firewall rule update applied by alice@company.com",
    "Jan 15 10:32:01 web01 syslog: Vulnerability scan complete – 0 critical, 2 informational",
    "Jan 15 10:32:02 web01 syslog: User account carol created by admin – initial password set",
    "Jan 15 10:32:03 web01 syslog: Weekly full backup started at 02:00 – estimated 45 min",
]

# Combine into one corpus — threats × 3 replication to demonstrate imbalance handling
THREAT_LINES = _SSH_BRUTE_FORCE + _WEB_ATTACKS + _ESCALATION + _RECON
ALL_LINES    = THREAT_LINES * 3 + _BENIGN * 6   # realistic 1:6 threat:benign ratio


# ─────────────────────────────────────────────────────────────────────────────
# Feature names (must mirror EventAnalyzer._build_features ordering)
# ─────────────────────────────────────────────────────────────────────────────

FEATURE_NAMES = [
    "text_length_norm",
    "digit_ratio",
    "special_char_ratio",
    "uppercase_ratio",
    "has_source_ip",
    "has_timestamp",
    "event_type_encoded",
    "signature_count_norm",
    "keyword_severity",
    "has_path_chars",
    "text_entropy",
    "ip_count_norm",
    "threat_keyword_density",
]


# ─────────────────────────────────────────────────────────────────────────────
# Pretty-print helpers
# ─────────────────────────────────────────────────────────────────────────────

def _bar(value: float, width: int = 30, fill: str = "█", empty: str = "░") -> str:
    """Render a float 0–1 as an ASCII progress bar."""
    filled = round(value * width)
    return fill * filled + empty * (width - filled)


def _ascii_loss_curve(history: list[float], width: int = 60, height: int = 12) -> str:
    """
    Render a loss-vs-epoch ASCII sparkline.

    The Y axis is scaled to the range [min_loss, max_loss].
    """
    if not history:
        return "(no history)"

    lo, hi = min(history), max(history)
    span   = hi - lo if hi != lo else 1.0
    cols   = width
    # Downsample if more epochs than terminal columns
    step     = max(1, len(history) // cols)
    sampled  = history[::step][:cols]
    rows     = height

    # Map each sample to a row index (0 = bottom = low loss)
    def to_row(v: float) -> int:
        return int((rows - 1) * (1.0 - (v - lo) / span))

    grid = [[" "] * len(sampled) for _ in range(rows)]
    for col, val in enumerate(sampled):
        r = to_row(val)
        grid[r][col] = "·"

    lines = []
    for row_idx, row in enumerate(grid):
        # Y-axis label on first, middle, and last rows
        if row_idx == 0:
            label = f"{hi:6.4f} │"
        elif row_idx == rows // 2:
            label = f"{(hi+lo)/2:6.4f} │"
        elif row_idx == rows - 1:
            label = f"{lo:6.4f} │"
        else:
            label = "       │"
        lines.append(label + "".join(row))

    x_axis = "       └" + "─" * len(sampled)
    n_cols   = len(sampled)
    left_pad = 8
    mid_left = n_cols // 2 - 3   # space before "epoch" label (len("0")+padding)
    mid_right = n_cols - mid_left - len("epoch") - 1
    epoch_label = (
        " " * left_pad
        + "0"
        + " " * mid_left
        + "epoch"
        + " " * mid_right
        + str(len(history))
    )
    return "\n".join(lines) + "\n" + x_axis + "\n" + epoch_label


def _confusion_matrix_str(tp: int, fp: int, tn: int, fn: int) -> str:
    """Render a 2×2 confusion matrix as a pretty ASCII table."""
    lines = [
        "                    Predicted",
        "                  Benign    Threat",
        "         ┌──────────────────────────┐",
        f"  Actual  │ TN={tn:>4}   │  FP={fp:>4}   │  ← Benign",
        "  label  ├──────────────────────────┤",
        f"         │ FN={fn:>4}   │  TP={tp:>4}   │  ← Threat",
        "         └──────────────────────────┘",
    ]
    return "\n".join(lines)


def _rank_features(weights: list[float], names: list[str]) -> list[tuple[str, float]]:
    """Return features sorted by absolute weight magnitude (most influential first)."""
    ranked = sorted(zip(names, weights), key=lambda x: abs(x[1]), reverse=True)
    return [(name, w) for name, w in ranked]


# ─────────────────────────────────────────────────────────────────────────────
# Main demo
# ─────────────────────────────────────────────────────────────────────────────

def run_demo(epochs: int = 250, interact: bool = False) -> None:
    analyzer = EventAnalyzer()
    detector = ThreatDetector()

    # ── Phase 1: corpus ────────────────────────────────────────────────────
    _header("Phase 1 — Synthetic Security Log Corpus")
    n_threat = len(THREAT_LINES) * 3
    n_benign = len(_BENIGN) * 6
    print(f"  Total log lines  : {len(ALL_LINES)}")
    print(f"  Threat lines     : {n_threat}  ({n_threat / len(ALL_LINES) * 100:.1f}%)")
    print(f"  Benign lines     : {n_benign}  ({n_benign / len(ALL_LINES) * 100:.1f}%)")
    print()
    print("  Sample threat lines:")
    for line in THREAT_LINES[:3]:
        print(f"    {_c('⚠', 'RED')} {line[:85]}{'…' if len(line) > 85 else ''}")
    print("  Sample benign lines:")
    for line in _BENIGN[:3]:
        print(f"    {_c('✓', 'GREEN')} {line[:85]}{'…' if len(line) > 85 else ''}")

    # ── Phase 2: parse ─────────────────────────────────────────────────────
    _header("Phase 2 — Event Parsing & Feature Extraction")
    events = analyzer.parse_bulk(ALL_LINES)
    reports = detector.analyze_bulk(events)
    print(f"  Events parsed     : {len(events)}")
    print(f"  Feature vector dim: {len(events[0].features)} features per event")
    print()
    print("  Feature names:")
    for i, name in enumerate(FEATURE_NAMES):
        sample_val = events[0].features[i]
        print(f"    [{i:2d}] {name:<28}  sample={sample_val:.4f}")

    # ── Phase 3: dataset builder ───────────────────────────────────────────
    _header("Phase 3 — Auto-Labeling with DatasetBuilder")
    dataset = DatasetBuilder.from_reports(reports)
    n_pos   = sum(1 for e in dataset if e.label == 1)
    n_neg   = sum(1 for e in dataset if e.label == 0)
    print(f"  Labeled examples  : {len(dataset)}")
    print(f"  Threat (label=1)  : {n_pos}  ({n_pos / max(1, len(dataset)) * 100:.1f}%)")
    print(f"  Benign  (label=0) : {n_neg}  ({n_neg / max(1, len(dataset)) * 100:.1f}%)")
    print()
    print("  Class imbalance ratio:", round(n_neg / max(1, n_pos), 1), "benign per threat")
    print("  → Oversampling will duplicate minority class to balance training.")

    # ── Phase 4: balance ───────────────────────────────────────────────────
    _header("Phase 4 — Class Balancing (Oversampling Minority Class)")
    balanced = DatasetBuilder.balance(dataset, strategy="oversample")
    b_pos = sum(1 for e in balanced if e.label == 1)
    b_neg = sum(1 for e in balanced if e.label == 0)
    print(f"  Before balancing  : {n_pos} threats, {n_neg} benign")
    print(f"  After balancing   : {b_pos} threats, {b_neg} benign")
    print(f"  Total examples    : {len(balanced)}")

    # ── Phase 5: split & train ─────────────────────────────────────────────
    _header("Phase 5 — Train / Test Split & Classifier Training")
    train_set, test_set = DatasetBuilder.split(balanced, test_ratio=0.20)
    print(f"  Training examples : {len(train_set)}")
    print(f"  Test examples     : {len(test_set)}")
    print(f"  Epochs            : {epochs}")
    print(f"  Learning rate     : 0.05")
    print(f"  L2 regularization : 0.01")
    print(f"  Batch size        : 32")
    print()
    print("  Training…", end="", flush=True)
    clf = SecurityClassifier(learning_rate=0.05, epochs=epochs, regularization=0.01)
    history = clf.train(train_set)
    print(_c(" done", "GREEN"))
    print(f"  Initial loss      : {history['initial_loss']:.6f}")
    print(f"  Final loss        : {history['final_loss']:.6f}")
    reduction_pct = (1 - history["final_loss"] / max(1e-9, history["initial_loss"])) * 100
    print(f"  Loss reduction    : {reduction_pct:.1f}%")

    # ── Phase 6: learning curve ────────────────────────────────────────────
    _header("Phase 6 — Learning Curve (Loss vs. Epoch)")
    print(_ascii_loss_curve(history["loss_history"], width=55, height=10))

    # ── Phase 7: evaluation ────────────────────────────────────────────────
    _header("Phase 7 — Test-Set Evaluation")
    metrics = clf.evaluate(test_set)
    tp = metrics["true_positives"]
    fp = metrics["false_positives"]
    tn = metrics["true_negatives"]
    fn = metrics["false_negatives"]

    print(_confusion_matrix_str(tp, fp, tn, fn))
    print()
    bar_w = 25
    print(f"  Accuracy  : {_bar(metrics['accuracy'],  bar_w)}  {metrics['accuracy']:.4f}")
    print(f"  Precision : {_bar(metrics['precision'], bar_w)}  {metrics['precision']:.4f}")
    print(f"  Recall    : {_bar(metrics['recall'],    bar_w)}  {metrics['recall']:.4f}")
    print(f"  F1 Score  : {_bar(metrics['f1'],        bar_w)}  {metrics['f1']:.4f}")
    print()
    total = tp + fp + tn + fn
    print(f"  Correct predictions : {tp + tn}/{total}")
    print(f"  Missed threats (FN) : {fn}")
    print(f"  False alarms   (FP) : {fp}")

    # ── Phase 8: feature importance ────────────────────────────────────────
    _header("Phase 8 — Feature Importance (Learned Weight Magnitudes)")
    feature_weights = clf.weights[:-1]   # strip bias
    ranked = _rank_features(feature_weights, FEATURE_NAMES)
    print("  Feature                       Weight     Influence")
    print("  " + "─" * 60)
    max_abs = max(abs(w) for _, w in ranked) or 1.0
    for name, w in ranked:
        direction = _c("+threat", "RED") if w > 0 else _c("-threat", "GREEN")
        bar = _bar(abs(w) / max_abs, 20)
        print(f"  {name:<30} {w:+.4f}   {bar}  {direction}")

    # ── Phase 9: threshold sweep ───────────────────────────────────────────
    _header("Phase 9 — Decision-Threshold Sensitivity Sweep")
    print("  Threshold  Precision  Recall     F1         Alerts")
    print("  " + "─" * 55)
    for thresh in [0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        tp_t = fp_t = tn_t = fn_t = 0
        for item in test_set:
            pred = 1 if clf.predict_proba(item.features) >= thresh else 0
            if   pred == 1 and item.label == 1: tp_t += 1
            elif pred == 1 and item.label == 0: fp_t += 1
            elif pred == 0 and item.label == 0: tn_t += 1
            else:                               fn_t += 1
        prec_t = tp_t / (tp_t + fp_t) if (tp_t + fp_t) else 0.0
        rec_t  = tp_t / (tp_t + fn_t) if (tp_t + fn_t) else 0.0
        f1_t   = 2 * prec_t * rec_t / (prec_t + rec_t) if (prec_t + rec_t) else 0.0
        mark   = _c(" ◀ default", "CYAN") if thresh == 0.5 else ""
        print(f"  {thresh:.1f}        {prec_t:.4f}     {rec_t:.4f}     {f1_t:.4f}     {tp_t+fp_t:4d}{mark}")
    print()
    print("  Tip: lower threshold → higher recall (catch more threats),")
    print("       higher threshold → higher precision (fewer false alarms).")

    # ── Phase 10: save & reload ────────────────────────────────────────────
    _header("Phase 10 — Model Serialization: Save → Load → Verify")
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as fh:
        model_path = fh.name
    try:
        clf.save(model_path)
        loaded = SecurityClassifier.load(model_path)

        # Verify every prediction matches
        mismatches = 0
        for item in test_set:
            if clf.predict(item.features) != loaded.predict(item.features):
                mismatches += 1

        size_kb = os.path.getsize(model_path) / 1024
        print(f"  Model saved to    : {model_path}")
        print(f"  File size         : {size_kb:.1f} KB")
        print(f"  Prediction check  : {len(test_set) - mismatches}/{len(test_set)} matched")
        if mismatches == 0:
            print("  " + _c("✔ Save/load round-trip verified — all predictions identical", "GREEN"))
        else:
            print("  " + _c(f"✘ {mismatches} prediction mismatches after reload!", "RED"))
    finally:
        os.unlink(model_path)

    # ── Phase 11: Azure ML export ──────────────────────────────────────────
    _header("Phase 11 — Azure ML Scoring Endpoint Export")
    schema = clf.to_azure_ml_schema()
    print("  Schema keys:")
    for key in schema:
        print(f"    • {key}")
    print()
    print("  Model spec:")
    spec = schema["model_spec"]
    print(f"    model_type     : {spec['model_type']}")
    print(f"    n_features     : {spec['n_features']}")
    print(f"    learning_rate  : {spec['learning_rate']}")
    print(f"    regularization : {spec['regularization']}")
    print(f"    bias           : {spec['bias']:.6f}")
    print()
    print("  score_function_stub (paste into Azure ML score.py):")
    print()
    for line in schema["score_function_stub"].splitlines():
        print("    " + _c(line, "DIM"))
    print()
    print("  " + _c("✔ Schema ready — drop model_spec into Azure ML as an artifact", "GREEN"))
    print("    and paste the score_function_stub into your score.py endpoint.")

    # ── Phase 12: interactive ──────────────────────────────────────────────
    if interact:
        _header("Phase 12 — Live Classifier: Type Your Own Log Line")
        print("  The trained model will classify any log line you enter.")
        print("  Press Ctrl+C or type 'quit' to exit.\n")
        while True:
            try:
                raw = input("  Log line> ").strip()
                if not raw or raw.lower() in {"quit", "exit", "q"}:
                    break
                event  = analyzer.parse(raw)
                report = detector.analyze(event)
                proba  = clf.predict_proba(event.features)
                label  = clf.predict(event.features)
                colour = "RED" if label == 1 else "GREEN"
                verdict = "THREAT" if label == 1 else "BENIGN"
                print(f"\n  Threat probability : {proba:.4f}  {_bar(proba, 25)}")
                print(f"  Prediction         : {_c(verdict, colour)}")
                print(f"  Detector level     : {report.threat_level.value}")
                print(f"  Signatures matched : {report.event.matched_sigs or ['none']}")
                print()
            except KeyboardInterrupt:
                print()
                break

    # ── Summary ────────────────────────────────────────────────────────────
    _header("Demo Complete — Summary")
    print(f"  Corpus size  : {len(ALL_LINES)} log lines")
    print(f"  Training set : {len(train_set)} balanced examples")
    print(f"  Test set     : {len(test_set)} examples")
    print(f"  Accuracy     : {metrics['accuracy']:.4f}")
    print(f"  F1 Score     : {metrics['f1']:.4f}")
    print(f"  Model size   : 14 floats (13 weights + 1 bias)")
    print()
    print("  " + _c("SentinelWeave ML pipeline — combining Python, Azure AI, and", "BOLD"))
    print("  " + _c("cybersecurity into a deployable threat-detection system.", "BOLD"))
    print()


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SentinelWeave ML Pipeline demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--fast",
        action="store_true",
        help="Use fewer epochs (50) for a quicker run",
    )
    parser.add_argument(
        "--interact",
        action="store_true",
        help="Add an interactive log-line classifier at the end",
    )
    args = parser.parse_args()
    run_demo(epochs=50 if args.fast else 250, interact=args.interact)


if __name__ == "__main__":
    main()
