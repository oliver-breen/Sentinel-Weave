#!/usr/bin/env python3
"""
SentinelWeave GUI
=================

A fully functional PyQt6 desktop application for the SentinelWeave
AI-powered cybersecurity threat-detection platform.

Tabs
----
1. Dashboard       — live event stats, alert feed, service health
2. Log Analyzer    — paste/load log lines, parse events, colour-coded table
3. Threat Detection— anomaly scores, z-score breakdown, campaign correlation
4. ML Pipeline     — train model in background thread, metrics, live classifier
5. Access Control  — interactive RBAC: role/action/resource → GRANTED / DENIED
6. Integrity       — HMAC event signing, tamper simulation, audit chain
7. Availability    — token-bucket rate-limiter demo, service heartbeat tracker

Run
---
    python gui/sentinel_weave_gui.py

Requirements
------------
    PyQt6>=6.6   (pip install PyQt6)
"""

from __future__ import annotations

import os
import sys
import time
import json
import random

# Allow running from the repo root without installation
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QTabWidget,
    QVBoxLayout, QHBoxLayout, QGridLayout, QFormLayout,
    QLabel, QPushButton, QPlainTextEdit, QLineEdit,
    QTableWidget, QTableWidgetItem, QHeaderView,
    QComboBox, QSpinBox, QDoubleSpinBox, QProgressBar,
    QGroupBox, QSplitter, QTextEdit, QScrollArea,
    QFrame, QListWidget, QListWidgetItem, QStatusBar,
    QSlider, QCheckBox,
)
from PyQt6.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSize,
)
from PyQt6.QtGui import (
    QColor, QFont, QPalette, QBrush, QIcon,
    QTextCursor, QTextCharFormat,
)

# ---------------------------------------------------------------------------
# SentinelWeave imports
# ---------------------------------------------------------------------------
from sentinel_weave.event_analyzer import EventAnalyzer, SecurityEvent
from sentinel_weave.threat_detector import ThreatDetector, ThreatReport, ThreatLevel
from sentinel_weave.threat_correlator import ThreatCorrelator, AttackCampaign
from sentinel_weave.ml_pipeline import (
    SecurityClassifier, DatasetBuilder, LabeledEvent,
    evaluate_classifier, k_fold_cross_validate,
)
from sentinel_weave.access_controller import AccessController, Role, Action
from sentinel_weave.integrity_monitor import IntegrityMonitor
from sentinel_weave.availability_monitor import (
    TokenBucketRateLimiter, AvailabilityMonitor, AlertSeverity,
)


# ===========================================================================
# Colour palette
# ===========================================================================

_C = {
    "bg":       "#1e1e2e",
    "surface":  "#2a2a3e",
    "border":   "#44475a",
    "text":     "#cdd6f4",
    "muted":    "#6c7086",
    "accent":   "#89b4fa",
    "green":    "#a6e3a1",
    "yellow":   "#f9e2af",
    "orange":   "#fab387",
    "red":      "#f38ba8",
    "critical": "#ff2a6d",
    "header":   "#313244",
}

_THREAT_COLOUR = {
    ThreatLevel.BENIGN:   _C["green"],
    ThreatLevel.LOW:      _C["accent"],
    ThreatLevel.MEDIUM:   _C["yellow"],
    ThreatLevel.HIGH:     _C["orange"],
    ThreatLevel.CRITICAL: _C["red"],
}

_ALERT_SEVERITY_COLOUR = {
    AlertSeverity.LOW:      _C["accent"],
    AlertSeverity.MEDIUM:   _C["yellow"],
    AlertSeverity.HIGH:     _C["orange"],
    AlertSeverity.CRITICAL: _C["red"],
}

# ---------------------------------------------------------------------------
# Sample synthetic log corpus used across several tabs
# ---------------------------------------------------------------------------

_SAMPLE_LOGS = """Jan 15 10:23:01 web01 sshd[9811]: Failed password for root from 198.51.100.42 port 54321 ssh2
Jan 15 10:23:02 web01 sshd[9812]: Failed password for root from 198.51.100.42 port 54322 ssh2
Jan 15 10:23:03 web01 sshd[9813]: Failed password for invalid user admin from 198.51.100.42 port 54323 ssh2
Jan 15 10:23:04 web01 sshd[9814]: Failed password for invalid user test from 198.51.100.42 port 54324 ssh2
Jan 15 10:23:05 web01 sshd[9815]: Failed password for invalid user ubuntu from 198.51.100.42 port 54325 ssh2
Jan 15 10:25:00 web01 nginx: 203.0.113.17 - - [GET /search?q=1 UNION SELECT * FROM users--] 400
Jan 15 10:26:00 web01 nginx: 203.0.113.17 - - [GET /admin.php?id=1' OR '1'='1] 403
Jan 15 10:27:00 web01 kernel: nmap scan detected from 10.10.10.5
Jan 15 10:28:00 web01 sudo: alice : TTY=pts/1 ; PWD=/root ; USER=root ; COMMAND=/bin/bash
Jan 15 10:29:00 web01 sshd[1234]: Accepted publickey for alice from 10.1.0.20 port 60000 ssh2
Jan 15 10:30:00 web01 syslog: cron[1234]: (root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)
Jan 15 10:31:00 web01 syslog: Service nginx started successfully -- worker processes: 4
Jan 15 10:32:00 web01 kernel: DDoS amplification attack detected from 45.33.32.156
Jan 15 10:33:00 web01 syslog: Backup completed successfully for /var/www/html
Jan 15 10:34:00 web01 audit: type=EXECVE argc=3 a0="mimikatz" a1="lsass" a2="dump"
Jan 15 10:35:00 web01 nginx: 172.16.0.1 - - [GET /api/users HTTP/1.1] 200
Jan 15 10:36:00 web01 sshd[2000]: Failed password for root from 198.51.100.42 port 55000 ssh2
Jan 15 10:37:00 web01 syslog: User bob logged in from 192.168.1.50""".strip()


# ===========================================================================
# Utility helpers
# ===========================================================================

def _make_label(text: str, bold: bool = False, colour: str | None = None) -> QLabel:
    lbl = QLabel(text)
    lbl.setStyleSheet(
        f"color: {colour or _C['text']};"
        + (" font-weight: bold;" if bold else "")
    )
    return lbl


def _make_button(text: str, colour: str | None = None) -> QPushButton:
    btn = QPushButton(text)
    bg = colour or _C["accent"]
    btn.setStyleSheet(
        f"QPushButton {{ background: {bg}; color: {_C['bg']}; border-radius: 4px;"
        f"  padding: 6px 12px; font-weight: bold; }}"
        f"QPushButton:hover {{ background: white; }}"
        f"QPushButton:pressed {{ background: {_C['muted']}; }}"
    )
    return btn


def _section(title: str) -> QGroupBox:
    box = QGroupBox(title)
    box.setStyleSheet(
        f"QGroupBox {{ color: {_C['accent']}; border: 1px solid {_C['border']};"
        f"  border-radius: 6px; margin-top: 8px; padding-top: 8px; }}"
        f"QGroupBox::title {{ subcontrol-origin: margin; left: 8px; }}"
    )
    return box


def _table(headers: list[str]) -> QTableWidget:
    tbl = QTableWidget(0, len(headers))
    tbl.setHorizontalHeaderLabels(headers)
    tbl.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    tbl.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
    tbl.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
    tbl.verticalHeader().setVisible(False)
    tbl.setStyleSheet(
        f"QTableWidget {{ background: {_C['surface']}; color: {_C['text']};"
        f"  gridline-color: {_C['border']}; border: none; }}"
        f"QTableWidget::item:selected {{ background: {_C['accent']}; color: {_C['bg']}; }}"
        f"QHeaderView::section {{ background: {_C['header']}; color: {_C['accent']};"
        f"  border: 1px solid {_C['border']}; padding: 4px; }}"
    )
    return tbl


def _add_row(tbl: QTableWidget, values: list[str], row_colour: str | None = None) -> None:
    row = tbl.rowCount()
    tbl.insertRow(row)
    for col, val in enumerate(values):
        item = QTableWidgetItem(str(val))
        if row_colour:
            item.setForeground(QBrush(QColor(row_colour)))
        tbl.setItem(row, col, item)


def _plain(placeholder: str = "", read_only: bool = False) -> QPlainTextEdit:
    pt = QPlainTextEdit()
    pt.setPlaceholderText(placeholder)
    pt.setReadOnly(read_only)
    pt.setStyleSheet(
        f"QPlainTextEdit {{ background: {_C['surface']}; color: {_C['text']};"
        f"  border: 1px solid {_C['border']}; border-radius: 4px; "
        f"  font-family: monospace; font-size: 12px; }}"
    )
    return pt


def _line(placeholder: str = "") -> QLineEdit:
    le = QLineEdit()
    le.setPlaceholderText(placeholder)
    le.setStyleSheet(
        f"QLineEdit {{ background: {_C['surface']}; color: {_C['text']};"
        f"  border: 1px solid {_C['border']}; border-radius: 4px; padding: 4px; }}"
    )
    return le


def _combo(choices: list[str]) -> QComboBox:
    cb = QComboBox()
    cb.addItems(choices)
    cb.setStyleSheet(
        f"QComboBox {{ background: {_C['surface']}; color: {_C['text']};"
        f"  border: 1px solid {_C['border']}; border-radius: 4px; padding: 4px; }}"
        f"QComboBox QAbstractItemView {{ background: {_C['surface']}; color: {_C['text']}; }}"
    )
    return cb


def _progress(colour: str) -> QProgressBar:
    pb = QProgressBar()
    pb.setTextVisible(True)
    pb.setStyleSheet(
        f"QProgressBar {{ background: {_C['border']}; border-radius: 4px; height: 14px; }}"
        f"QProgressBar::chunk {{ background: {colour}; border-radius: 4px; }}"
    )
    return pb


# ===========================================================================
# Global shared state (parsed events / reports flowing between tabs)
# ===========================================================================

class AppState:
    """Shared mutable state passed to each tab."""

    def __init__(self) -> None:
        self.analyzer    = EventAnalyzer()
        self.detector    = ThreatDetector()
        self.correlator  = ThreatCorrelator()
        self.events:   list[SecurityEvent] = []
        self.reports:  list[ThreatReport]  = []
        self.campaigns: list[AttackCampaign] = []
        self.classifier: SecurityClassifier | None = None

        # CIA triad modules
        self.access_ctrl  = AccessController()
        self.integrity    = IntegrityMonitor()
        self.avail        = AvailabilityMonitor(window_seconds=60.0, rate_threshold=5.0)
        self.limiter      = TokenBucketRateLimiter(rate=5.0, burst=10.0)
        self.signatures: dict[int, str] = {}   # id(event) → sig


# ===========================================================================
# Background worker for ML training
# ===========================================================================

class TrainWorker(QThread):
    progress = pyqtSignal(int, str)       # percent, message
    finished = pyqtSignal(dict, object)   # metrics, classifier

    def __init__(
        self,
        labeled: list[LabeledEvent],
        epochs: int,
        lr: float,
        reg: float,
    ) -> None:
        super().__init__()
        self._labeled = labeled
        self._epochs  = epochs
        self._lr      = lr
        self._reg     = reg

    def run(self) -> None:
        try:
            train, test = DatasetBuilder.split(self._labeled, test_ratio=0.20)
            if not train or not test:
                self.finished.emit({}, None)
                return

            clf = SecurityClassifier(
                learning_rate=self._lr,
                regularization=self._reg,
                epochs=self._epochs,
                patience=30,
            )
            self.progress.emit(5, f"Training on {len(train)} examples…")

            clf.train(train)

            self.progress.emit(80, "Evaluating…")
            metrics = clf.evaluate(test)
            self.progress.emit(100, "Done")
            self.finished.emit(metrics, clf)
        except Exception as exc:  # noqa: BLE001
            self.progress.emit(0, f"Error: {exc}")
            self.finished.emit({}, None)


# ===========================================================================
# Tab 1 — Dashboard
# ===========================================================================

class DashboardTab(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self._state = state
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QVBoxLayout()
        root.setSpacing(10)
        self.setLayout(root)

        # ── Top stat cards ────────────────────────────────────────────
        cards_layout = QHBoxLayout()
        self._card_events    = self._stat_card("Events Analyzed", "0", _C["accent"])
        self._card_threats   = self._stat_card("Threats Detected", "0", _C["red"])
        self._card_campaigns = self._stat_card("Campaigns", "0", _C["orange"])
        self._card_services  = self._stat_card("Services Monitored", "0", _C["green"])
        for card in (
            self._card_events,
            self._card_threats,
            self._card_campaigns,
            self._card_services,
        ):
            cards_layout.addWidget(card)
        root.addLayout(cards_layout)

        # ── Middle row ────────────────────────────────────────────────
        mid = QHBoxLayout()
        root.addLayout(mid)

        # Recent alerts panel
        alerts_box = _section("Recent Alerts")
        alerts_layout = QVBoxLayout()
        self._alerts_list = QListWidget()
        self._alerts_list.setStyleSheet(
            f"QListWidget {{ background: {_C['surface']}; color: {_C['text']};"
            f"  border: none; font-family: monospace; font-size: 11px; }}"
        )
        alerts_layout.addWidget(self._alerts_list)
        alerts_box.setLayout(alerts_layout)
        mid.addWidget(alerts_box, 3)

        # Threat-level distribution panel
        dist_box = _section("Threat Level Distribution")
        dist_layout = QVBoxLayout()
        self._bars: dict[str, QProgressBar] = {}
        for level in ("BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"):
            colour = _THREAT_COLOUR[ThreatLevel[level]]
            row = QHBoxLayout()
            lbl = QLabel(f"{level:<10}")
            lbl.setStyleSheet(f"color: {colour}; font-weight: bold; min-width: 80px;")
            pb = _progress(colour)
            pb.setRange(0, 100)
            pb.setValue(0)
            pb.setFormat("%v%")
            row.addWidget(lbl)
            row.addWidget(pb)
            dist_layout.addLayout(row)
            self._bars[level] = pb
        dist_box.setLayout(dist_layout)
        mid.addWidget(dist_box, 2)

        # ── Quick-scan button ─────────────────────────────────────────
        btn_row = QHBoxLayout()
        scan_btn = _make_button("⚡  Quick Scan (sample logs)", _C["accent"])
        scan_btn.clicked.connect(self._quick_scan)
        btn_row.addStretch()
        btn_row.addWidget(scan_btn)
        btn_row.addStretch()
        root.addLayout(btn_row)

        # ── Status bar hint ───────────────────────────────────────────
        hint = _make_label(
            "Tip: use the Log Analyzer tab to paste your own log lines, "
            "then return here for an overview.",
            colour=_C["muted"],
        )
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(hint)

    # ------------------------------------------------------------------
    def _stat_card(self, title: str, value: str, colour: str) -> QGroupBox:
        box = QGroupBox()
        box.setStyleSheet(
            f"QGroupBox {{ background: {_C['surface']}; border: 1px solid {_C['border']};"
            f"  border-radius: 8px; padding: 12px; }}"
        )
        v = QVBoxLayout()
        val_lbl = QLabel(value)
        val_lbl.setStyleSheet(
            f"font-size: 36px; font-weight: bold; color: {colour};"
        )
        val_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title_lbl = QLabel(title)
        title_lbl.setStyleSheet(
            f"font-size: 12px; color: {_C['muted']}; font-weight: bold;"
        )
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        v.addWidget(val_lbl)
        v.addWidget(title_lbl)
        box.setLayout(v)
        box._val_lbl = val_lbl   # type: ignore[attr-defined]
        return box

    def _update_card(self, box: QGroupBox, value: str) -> None:
        box._val_lbl.setText(value)  # type: ignore[attr-defined]

    def refresh(self) -> None:
        """Called by other tabs when state changes."""
        s = self._state
        self._update_card(self._card_events,    str(len(s.events)))
        self._update_card(self._card_threats,   str(sum(1 for r in s.reports if r.threat_level != ThreatLevel.BENIGN)))
        self._update_card(self._card_campaigns, str(len(s.campaigns)))
        self._update_card(self._card_services,  str(len(s.avail.registered_services())))

        # Fill recent alerts (last 30 threat reports)
        self._alerts_list.clear()
        threats = [r for r in s.reports if r.threat_level != ThreatLevel.BENIGN]
        for r in threats[-30:]:
            colour = _THREAT_COLOUR[r.threat_level]
            item = QListWidgetItem(
                f"[{r.threat_level.value:<8}] {r.event.source_ip or 'n/a':<15} "
                f"{r.event.event_type:<10} score={r.anomaly_score:.3f}"
            )
            item.setForeground(QBrush(QColor(colour)))
            self._alerts_list.addItem(item)
        self._alerts_list.scrollToBottom()

        # Threat distribution bars
        total = max(len(s.reports), 1)
        counts = {lv: 0 for lv in ThreatLevel}
        for r in s.reports:
            counts[r.threat_level] += 1
        for level_name, pb in self._bars.items():
            pct = int(counts[ThreatLevel[level_name]] * 100 / total)
            pb.setValue(pct)
            pb.setFormat(f"{counts[ThreatLevel[level_name]]}  ({pct}%)")

    def _quick_scan(self) -> None:
        s = self._state
        s.events = s.analyzer.parse_bulk(_SAMPLE_LOGS.splitlines())
        s.detector = ThreatDetector()
        s.reports = s.detector.analyze_bulk(s.events)
        s.correlator = ThreatCorrelator()
        s.correlator.add_reports(s.reports)
        s.campaigns = s.correlator.get_campaigns()
        self.refresh()


# ===========================================================================
# Tab 2 — Log Analyzer
# ===========================================================================

class LogAnalyzerTab(QWidget):
    events_updated = pyqtSignal()

    def __init__(self, state: AppState, dashboard: DashboardTab) -> None:
        super().__init__()
        self._state = state
        self._dash  = dashboard
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QSplitter(Qt.Orientation.Vertical)
        outer = QVBoxLayout()
        outer.addWidget(root)
        self.setLayout(outer)

        # ── Top: input + controls ─────────────────────────────────────
        top = QWidget()
        top_layout = QVBoxLayout()
        top.setLayout(top_layout)

        # Input area
        input_box = _section("Log Input  (one line per event)")
        input_v = QVBoxLayout()
        self._input = _plain(
            "Paste log lines here, one per line…\n\n"
            "Click 'Load Sample Logs' or paste your own, then click 'Analyze'."
        )
        self._input.setPlainText(_SAMPLE_LOGS)
        input_v.addWidget(self._input)
        btn_row = QHBoxLayout()
        load_btn  = _make_button("📂  Load Sample Logs", _C["muted"])
        clear_btn = _make_button("🗑  Clear", _C["muted"])
        analyze_btn = _make_button("🔍  Analyze", _C["accent"])
        load_btn.clicked.connect(self._load_sample)
        clear_btn.clicked.connect(self._input.clear)
        analyze_btn.clicked.connect(self._analyze)
        for b in (load_btn, clear_btn, analyze_btn):
            btn_row.addWidget(b)
        input_v.addLayout(btn_row)
        input_box.setLayout(input_v)
        top_layout.addWidget(input_box)
        root.addWidget(top)

        # ── Bottom: results table + detail panel ──────────────────────
        bottom = QSplitter(Qt.Orientation.Horizontal)
        root.addWidget(bottom)

        self._table = _table(["#", "Source IP", "Event Type", "Severity", "Signatures"])
        self._table.currentCellChanged.connect(lambda row, *_: self._on_row_selected(row))
        bottom.addWidget(self._table)

        detail_box = _section("Event Detail")
        detail_v = QVBoxLayout()
        self._detail = _plain(read_only=True)
        detail_v.addWidget(self._detail)
        detail_box.setLayout(detail_v)
        bottom.addWidget(detail_box)
        bottom.setSizes([600, 300])
        root.setSizes([250, 500])

        # Status label
        self._status = _make_label("", colour=_C["muted"])
        outer.addWidget(self._status)

    def _load_sample(self) -> None:
        self._input.setPlainText(_SAMPLE_LOGS)

    def _analyze(self) -> None:
        lines = [l.strip() for l in self._input.toPlainText().splitlines() if l.strip()]
        if not lines:
            return
        s = self._state
        s.events  = s.analyzer.parse_bulk(lines)
        s.detector = ThreatDetector()
        s.reports = s.detector.analyze_bulk(s.events)
        s.correlator = ThreatCorrelator()
        s.correlator.add_reports(s.reports)
        s.campaigns = s.correlator.get_campaigns()

        # Re-sign events in integrity monitor
        s.signatures = {}
        for ev in s.events:
            sig = s.integrity.sign_event(ev)
            s.signatures[id(ev)] = sig

        self._populate_table()
        self._status.setText(
            f"✔ Analyzed {len(s.events)} events — "
            f"{sum(1 for r in s.reports if r.threat_level != ThreatLevel.BENIGN)} threats"
        )
        self._dash.refresh()
        self.events_updated.emit()

    def _populate_table(self) -> None:
        self._table.setRowCount(0)
        for i, (ev, rep) in enumerate(zip(self._state.events, self._state.reports)):
            colour = _THREAT_COLOUR[rep.threat_level]
            sigs   = ", ".join(ev.matched_sigs) or "—"
            _add_row(
                self._table,
                [str(i + 1), ev.source_ip or "n/a", ev.event_type,
                 f"{ev.severity:.3f}", sigs],
                row_colour=colour,
            )

    def _on_row_selected(self, row: int) -> None:
        if row < 0 or row >= len(self._state.reports):
            return
        ev  = self._state.events[row]
        rep = self._state.reports[row]
        lines = [
            f"Raw:         {ev.raw}",
            f"Source IP:   {ev.source_ip or 'n/a'}",
            f"Event Type:  {ev.event_type}",
            f"Severity:    {ev.severity:.4f}",
            f"Signatures:  {', '.join(ev.matched_sigs) or 'none'}",
            "",
            f"Threat Level:   {rep.threat_level.value}",
            f"Anomaly Score:  {rep.anomaly_score:.4f}",
            "",
            "Explanation:",
        ] + [f"  • {e}" for e in rep.explanation]
        if rep.z_scores:
            lines += ["", "Z-scores:"]
            feature_names = [
                "text_length_norm", "digit_ratio", "special_char_ratio",
                "uppercase_ratio", "has_source_ip", "has_timestamp",
                "event_type_encoded", "signature_count_norm", "keyword_severity",
                "has_path_chars", "text_entropy", "ip_count_norm",
                "threat_keyword_density",
            ]
            for fname, z in zip(feature_names, rep.z_scores):
                lines.append(f"  {fname:<28} z={z:+.3f}")
        self._detail.setPlainText("\n".join(lines))


# ===========================================================================
# Tab 3 — Threat Detection
# ===========================================================================

class ThreatDetectionTab(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self._state = state
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QVBoxLayout()
        self.setLayout(root)

        top_row = QHBoxLayout()
        refresh_btn = _make_button("🔄  Refresh Reports", _C["accent"])
        refresh_btn.clicked.connect(self.refresh)
        top_row.addWidget(refresh_btn)

        corr_btn = _make_button("🕸  Correlate Campaigns", _C["orange"])
        corr_btn.clicked.connect(self._correlate)
        top_row.addWidget(corr_btn)
        top_row.addStretch()
        root.addLayout(top_row)

        splitter = QSplitter(Qt.Orientation.Vertical)
        root.addWidget(splitter)

        # ── Threat reports table ──────────────────────────────────────
        reports_box = _section("Threat Reports")
        rv = QVBoxLayout()
        self._rep_table = _table(
            ["#", "Level", "Score", "Source IP", "Event Type", "Signatures", "Explanation"]
        )
        self._rep_table.currentCellChanged.connect(lambda row, *_: self._on_row_selected(row))
        rv.addWidget(self._rep_table)
        reports_box.setLayout(rv)
        splitter.addWidget(reports_box)

        # ── Bottom: score bar + campaigns ────────────────────────────
        bot = QHBoxLayout()
        bot_widget = QWidget()
        bot_widget.setLayout(bot)
        splitter.addWidget(bot_widget)

        # Anomaly score detail
        score_box = _section("Selected Event — Anomaly Score Breakdown")
        sv = QVBoxLayout()
        self._score_bars: list[tuple[QLabel, QProgressBar]] = []
        feature_names = [
            "text_length_norm", "digit_ratio", "special_char_ratio",
            "uppercase_ratio", "has_source_ip", "has_timestamp",
            "event_type_encoded", "signature_count_norm", "keyword_severity",
            "has_path_chars", "text_entropy", "ip_count_norm",
            "threat_keyword_density",
        ]
        for fname in feature_names:
            row = QHBoxLayout()
            lbl = QLabel(f"{fname:<28}")
            lbl.setStyleSheet(f"color: {_C['text']}; font-family: monospace; font-size: 11px;")
            pb = _progress(_C["accent"])
            pb.setRange(-100, 100)
            pb.setValue(0)
            pb.setFormat("z=0.00")
            row.addWidget(lbl)
            row.addWidget(pb)
            sv.addLayout(row)
            self._score_bars.append((lbl, pb))
        score_box.setLayout(sv)
        bot.addWidget(score_box, 1)

        # Campaign panel
        camp_box = _section("Attack Campaigns")
        cv = QVBoxLayout()
        self._camp_table = _table(["Source IP", "Phase", "Events", "Level", "Signatures"])
        cv.addWidget(self._camp_table)
        camp_box.setLayout(cv)
        bot.addWidget(camp_box, 1)

        splitter.setSizes([300, 400])

    def refresh(self) -> None:
        self._rep_table.setRowCount(0)
        for i, rep in enumerate(self._state.reports):
            colour = _THREAT_COLOUR[rep.threat_level]
            sigs   = ", ".join(rep.event.matched_sigs) or "—"
            expl   = rep.explanation[0] if rep.explanation else "—"
            _add_row(
                self._rep_table,
                [str(i + 1), rep.threat_level.value,
                 f"{rep.anomaly_score:.3f}",
                 rep.event.source_ip or "n/a",
                 rep.event.event_type,
                 sigs,
                 expl],
                row_colour=colour,
            )

    def _correlate(self) -> None:
        s = self._state
        s.correlator = ThreatCorrelator()
        s.correlator.add_reports(s.reports)
        s.campaigns = s.correlator.get_campaigns()
        self._camp_table.setRowCount(0)
        for camp in s.campaigns:
            colour = _THREAT_COLOUR.get(camp.severity, _C["text"])
            sigs   = ", ".join(camp.signatures[:3]) + ("…" if len(camp.signatures) > 3 else "")
            _add_row(
                self._camp_table,
                [camp.attacker_ip, camp.kill_chain_phase,
                 str(camp.event_count), camp.severity.value, sigs],
                row_colour=colour,
            )

    def _on_row_selected(self, row: int) -> None:
        if row < 0 or row >= len(self._state.reports):
            return
        rep = self._state.reports[row]
        z   = rep.z_scores if rep.z_scores else [0.0] * 13
        for i, (_, pb) in enumerate(self._score_bars):
            val = int(z[i] * 10) if i < len(z) else 0
            val = max(-100, min(100, val))
            pb.setValue(val)
            raw_z = z[i] if i < len(z) else 0.0
            colour = _C["red"] if raw_z > 2 else (_C["yellow"] if raw_z > 1 else _C["green"])
            pb.setStyleSheet(
                f"QProgressBar {{ background: {_C['border']}; border-radius: 4px; height: 12px; }}"
                f"QProgressBar::chunk {{ background: {colour}; border-radius: 4px; }}"
            )
            pb.setFormat(f"z={raw_z:+.2f}")


# ===========================================================================
# Tab 4 — ML Pipeline
# ===========================================================================

class MLPipelineTab(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self._state  = state
        self._worker: TrainWorker | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QHBoxLayout()
        self.setLayout(root)

        # ── Left: training controls ────────────────────────────────────
        left = QVBoxLayout()
        left_widget = QWidget()
        left_widget.setLayout(left)
        left_widget.setMaximumWidth(320)
        root.addWidget(left_widget)

        config_box = _section("Training Configuration")
        form = QFormLayout()
        self._epochs_spin = QSpinBox()
        self._epochs_spin.setRange(10, 2000)
        self._epochs_spin.setValue(200)
        self._epochs_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        self._lr_spin = QDoubleSpinBox()
        self._lr_spin.setRange(0.0001, 1.0)
        self._lr_spin.setSingleStep(0.005)
        self._lr_spin.setDecimals(4)
        self._lr_spin.setValue(0.05)
        self._lr_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        self._reg_spin = QDoubleSpinBox()
        self._reg_spin.setRange(0.0, 1.0)
        self._reg_spin.setSingleStep(0.001)
        self._reg_spin.setDecimals(4)
        self._reg_spin.setValue(0.01)
        self._reg_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        for lbl_text, w in [("Epochs:", self._epochs_spin),
                             ("Learning Rate:", self._lr_spin),
                             ("L2 Regularization:", self._reg_spin)]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"color: {_C['text']};")
            form.addRow(lbl, w)
        config_box.setLayout(form)
        left.addWidget(config_box)

        train_btn = _make_button("🚀  Train Model", _C["accent"])
        train_btn.clicked.connect(self._start_training)
        left.addWidget(train_btn)

        self._progress = _progress(_C["accent"])
        self._progress.setRange(0, 100)
        self._progress.setValue(0)
        left.addWidget(self._progress)

        self._train_status = _make_label("Ready.", colour=_C["muted"])
        left.addWidget(self._train_status)

        # Metrics display
        metrics_box = _section("Evaluation Metrics")
        mf = QFormLayout()
        self._metric_labels: dict[str, QLabel] = {}
        for m in ("accuracy", "precision", "recall", "f1", "roc_auc"):
            lbl = QLabel("—")
            lbl.setStyleSheet(f"color: {_C['accent']}; font-weight: bold;")
            m_lbl = QLabel(m.replace("_", " ").title() + ":")
            m_lbl.setStyleSheet(f"color: {_C['text']};")
            mf.addRow(m_lbl, lbl)
            self._metric_labels[m] = lbl
        metrics_box.setLayout(mf)
        left.addWidget(metrics_box)
        left.addStretch()

        # ── Right: live classifier + loss ──────────────────────────────
        right = QVBoxLayout()
        root.addLayout(right)

        classify_box = _section("Live Classifier — Type a Log Line")
        cv = QVBoxLayout()
        self._clf_input = _line("e.g. Failed password for root from 10.0.0.1")
        classify_btn = _make_button("🔍  Classify", _C["accent"])
        classify_btn.clicked.connect(self._classify_line)
        self._clf_result_lbl = _make_label("Train a model first.", colour=_C["muted"])
        self._clf_result_lbl.setStyleSheet(
            f"font-size: 18px; font-weight: bold; color: {_C['muted']};"
        )
        self._clf_prob_bar = _progress(_C["red"])
        self._clf_prob_bar.setRange(0, 100)
        self._clf_prob_bar.setValue(0)
        self._clf_explain = _plain(read_only=True)
        self._clf_explain.setMaximumHeight(160)
        cv.addWidget(self._clf_input)
        cv.addWidget(classify_btn)
        cv.addWidget(self._clf_result_lbl)
        cv.addWidget(self._clf_prob_bar)
        cv.addWidget(self._clf_explain)
        classify_box.setLayout(cv)
        right.addWidget(classify_box)

        # Training log
        log_box = _section("Training Log")
        lv = QVBoxLayout()
        self._train_log = _plain(read_only=True)
        lv.addWidget(self._train_log)
        log_box.setLayout(lv)
        right.addWidget(log_box)

    def _start_training(self) -> None:
        if self._worker and self._worker.isRunning():
            return
        s = self._state
        if not s.events:
            self._train_log.appendPlainText("⚠ No events loaded. Parsing sample logs first…")
            s.events = s.analyzer.parse_bulk(_SAMPLE_LOGS.splitlines())
            s.detector = ThreatDetector()
            s.reports = s.detector.analyze_bulk(s.events)

        labeled = DatasetBuilder.from_reports(s.reports)
        labeled = DatasetBuilder.balance(labeled)
        if not labeled:
            self._train_log.appendPlainText("⚠ No labeled events. Run Log Analyzer first.")
            return

        self._train_log.appendPlainText(
            f"Training on {len(labeled)} examples  "
            f"(epochs={self._epochs_spin.value()}, "
            f"lr={self._lr_spin.value()}, "
            f"reg={self._reg_spin.value()})…"
        )
        self._progress.setValue(0)
        self._worker = TrainWorker(
            labeled,
            self._epochs_spin.value(),
            self._lr_spin.value(),
            self._reg_spin.value(),
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.start()

    def _on_progress(self, pct: int, msg: str) -> None:
        self._progress.setValue(pct)
        self._train_status.setText(msg)

    def _on_finished(self, metrics: dict, clf: object) -> None:
        if clf is None:
            self._train_log.appendPlainText("✗ Training failed.")
            return
        self._state.classifier = clf
        lines = ["✔ Training complete:"]
        for m, v in metrics.items():
            label = self._metric_labels.get(m)
            if label:
                label.setText(f"{v:.4f}")
            lines.append(f"   {m:<12}: {v:.4f}")
        self._train_log.appendPlainText("\n".join(lines))
        self._train_log.appendPlainText("")

    def _classify_line(self) -> None:
        text = self._clf_input.text().strip()
        if not text:
            return
        clf = self._state.classifier
        if clf is None:
            self._clf_result_lbl.setText("⚠ Train a model first.")
            return
        ev      = self._state.analyzer.parse(text)
        prob    = clf.predict_proba(ev.features)
        label   = clf.predict(ev.features)
        colour  = _C["red"] if label == 1 else _C["green"]
        verdict = "⚠  THREAT" if label == 1 else "✔  BENIGN"
        self._clf_result_lbl.setText(f"{verdict}  (p={prob:.4f})")
        self._clf_result_lbl.setStyleSheet(
            f"font-size: 20px; font-weight: bold; color: {colour};"
        )
        self._clf_prob_bar.setValue(int(prob * 100))
        self._clf_prob_bar.setFormat(f"Threat probability: {prob:.1%}")

        expl = clf.explain(ev.features)
        lines = [
            f"Matched signatures : {', '.join(ev.matched_sigs) or 'none'}",
            f"Top threat factor  : {expl.get('top_threat_factor') or '—'}",
            f"Top benign factor  : {expl.get('top_benign_factor') or '—'}",
        ]
        if expl.get("contributions"):
            lines.append("\nTop feature contributions:")
            for fname, contrib in sorted(
                expl["contributions"].items(),
                key=lambda x: abs(x[1]),
                reverse=True,
            )[:5]:
                lines.append(f"  {fname:<28} {contrib:+.4f}")
        self._clf_explain.setPlainText("\n".join(lines))


# ===========================================================================
# Tab 5 — Access Control (RBAC)
# ===========================================================================

class AccessControlTab(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self._state = state
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QHBoxLayout()
        self.setLayout(root)

        # ── Left: check panel ─────────────────────────────────────────
        left_box = _section("Access Control Check")
        left_v = QVBoxLayout()
        form = QFormLayout()

        self._role_combo = _combo([r.value for r in Role])
        self._action_combo = _combo([a.value for a in Action])
        self._resource_line = _line("e.g. report-2026-01.bin")
        self._resource_line.setText("report-2026-01.bin")
        self._subject_line = _line("e.g. alice")
        self._subject_line.setText("alice")
        for lbl_text, w in [
            ("Role:", self._role_combo),
            ("Action:", self._action_combo),
            ("Resource:", self._resource_line),
            ("Subject:", self._subject_line),
        ]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"color: {_C['text']};")
            form.addRow(lbl, w)
        left_v.addLayout(form)

        check_btn = _make_button("🔐  Check Access", _C["accent"])
        check_btn.clicked.connect(self._check_access)
        left_v.addWidget(check_btn)

        self._verdict_lbl = QLabel("—")
        self._verdict_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._verdict_lbl.setStyleSheet(
            f"font-size: 28px; font-weight: bold; color: {_C['muted']};"
            f" border: 1px solid {_C['border']}; border-radius: 8px; padding: 16px;"
        )
        left_v.addWidget(self._verdict_lbl)

        # Permission matrix display
        matrix_box = _section("Permission Matrix")
        grid = QGridLayout()
        roles   = list(Role)
        actions = list(Action)

        # Headers
        grid.addWidget(QLabel(""), 0, 0)
        for col, role in enumerate(roles):
            h = QLabel(role.value)
            h.setStyleSheet(f"color: {_C['accent']}; font-weight: bold; padding: 2px;")
            h.setAlignment(Qt.AlignmentFlag.AlignCenter)
            grid.addWidget(h, 0, col + 1)

        from sentinel_weave.access_controller import _PERMISSIONS
        for row_idx, action in enumerate(actions):
            row_lbl = QLabel(action.value)
            row_lbl.setStyleSheet(f"color: {_C['text']}; font-family: monospace;")
            grid.addWidget(row_lbl, row_idx + 1, 0)
            for col, role in enumerate(roles):
                allowed = action in _PERMISSIONS.get(role, frozenset())
                cell = QLabel("✔" if allowed else "✗")
                cell.setAlignment(Qt.AlignmentFlag.AlignCenter)
                cell.setStyleSheet(
                    f"color: {_C['green'] if allowed else _C['red']}; font-weight: bold;"
                )
                grid.addWidget(cell, row_idx + 1, col + 1)
        matrix_box.setLayout(grid)
        left_v.addWidget(matrix_box)
        left_v.addStretch()
        left_box.setLayout(left_v)
        root.addWidget(left_box, 1)

        # ── Right: audit log ──────────────────────────────────────────
        right_box = _section("Audit Log")
        right_v = QVBoxLayout()
        self._audit_table = _table(["Time", "Subject", "Role", "Action", "Resource", "Verdict"])
        right_v.addWidget(self._audit_table)
        btn_row = QHBoxLayout()
        clear_btn = _make_button("🗑  Clear Log", _C["muted"])
        clear_btn.clicked.connect(self._clear_audit)
        summary_btn = _make_button("📊  Summary", _C["accent"])
        summary_btn.clicked.connect(self._show_summary)
        btn_row.addWidget(clear_btn)
        btn_row.addWidget(summary_btn)
        right_v.addLayout(btn_row)
        self._summary_lbl = _make_label("", colour=_C["muted"])
        right_v.addWidget(self._summary_lbl)
        right_box.setLayout(right_v)
        root.addWidget(right_box, 2)

    def _check_access(self) -> None:
        role    = Role(self._role_combo.currentText())
        action  = Action(self._action_combo.currentText())
        resource = self._resource_line.text().strip() or "*"
        subject  = self._subject_line.text().strip() or "anonymous"
        granted  = self._state.access_ctrl.check(role, action, resource, subject)
        colour   = _C["green"] if granted else _C["red"]
        verdict  = "✔  GRANTED" if granted else "✗  DENIED"
        self._verdict_lbl.setText(verdict)
        self._verdict_lbl.setStyleSheet(
            f"font-size: 28px; font-weight: bold; color: {colour};"
            f" border: 2px solid {colour}; border-radius: 8px; padding: 16px;"
        )
        self._refresh_audit()

    def _refresh_audit(self) -> None:
        log = self._state.access_ctrl.get_audit_log()
        self._audit_table.setRowCount(0)
        for entry in log[-100:]:
            colour  = _C["green"] if entry.granted else _C["red"]
            verdict = "GRANTED" if entry.granted else "DENIED"
            ts_short = entry.timestamp[11:19]  # HH:MM:SS
            _add_row(
                self._audit_table,
                [ts_short, entry.subject, entry.role.value,
                 entry.action.value, entry.resource, verdict],
                row_colour=colour,
            )
        self._audit_table.scrollToBottom()

    def _clear_audit(self) -> None:
        self._state.access_ctrl.clear_audit_log()
        self._audit_table.setRowCount(0)
        self._summary_lbl.setText("Audit log cleared.")

    def _show_summary(self) -> None:
        s = self._state.access_ctrl.audit_summary()
        if s["total"] == 0:
            self._summary_lbl.setText("No audit entries yet.")
            return
        self._summary_lbl.setText(
            f"Total: {s['total']}  |  "
            f"Granted: {s['granted']}  |  "
            f"Denied: {s['denied']}  |  "
            f"Subjects: {s['unique_subjects']}  |  "
            f"Most Denied: {s['most_denied_action'] or '—'}"
        )


# ===========================================================================
# Tab 6 — Integrity Monitor
# ===========================================================================

class IntegrityTab(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self._state = state
        self._tampered_idx: int | None = None
        self._setup_ui()

    def _setup_ui(self) -> None:
        root = QVBoxLayout()
        self.setLayout(root)

        # ── Top row: event signing ────────────────────────────────────
        sign_box = _section("Event Signatures  (HMAC-SHA256)")
        sv = QVBoxLayout()
        btn_row = QHBoxLayout()
        sign_btn   = _make_button("✍  Sign All Events", _C["accent"])
        verify_btn = _make_button("✔  Verify Signatures", _C["green"])
        tamper_btn = _make_button("⚡  Tamper Random Event", _C["orange"])
        restore_btn = _make_button("↩  Restore", _C["muted"])
        sign_btn.clicked.connect(self._sign_events)
        verify_btn.clicked.connect(self._verify_sigs)
        tamper_btn.clicked.connect(self._tamper_event)
        restore_btn.clicked.connect(self._restore_event)
        for b in (sign_btn, verify_btn, tamper_btn, restore_btn):
            btn_row.addWidget(b)
        sv.addLayout(btn_row)
        self._sig_table = _table(["#", "Source IP", "Event Type", "Severity", "Signature (first 16…)", "Status"])
        sv.addWidget(self._sig_table)
        self._sig_status = _make_label("", colour=_C["muted"])
        sv.addWidget(self._sig_status)
        sign_box.setLayout(sv)
        root.addWidget(sign_box)

        # ── Bottom row: audit chain ───────────────────────────────────
        chain_box = _section("Tamper-Evident Audit Chain")
        cv = QVBoxLayout()
        chain_ctrl = QHBoxLayout()
        self._chain_entry = _line("Audit event description…")
        self._chain_subj  = _line("subject")
        self._chain_subj.setMaximumWidth(120)
        add_btn    = _make_button("➕  Append Entry", _C["accent"])
        ver_btn    = _make_button("🔒  Verify Chain", _C["green"])
        export_btn = _make_button("📥  Export JSON", _C["muted"])
        add_btn.clicked.connect(self._append_chain)
        ver_btn.clicked.connect(self._verify_chain)
        export_btn.clicked.connect(self._export_chain)
        chain_ctrl.addWidget(self._chain_entry)
        chain_ctrl.addWidget(QLabel("Subject:"))
        chain_ctrl.addWidget(self._chain_subj)
        chain_ctrl.addWidget(add_btn)
        chain_ctrl.addWidget(ver_btn)
        chain_ctrl.addWidget(export_btn)
        cv.addLayout(chain_ctrl)
        self._chain_table = _table(["Index", "Timestamp", "Subject", "Data", "prev_hash (8…)", "hash (8…)"])
        cv.addWidget(self._chain_table)
        self._chain_status = _make_label("Chain empty.", colour=_C["muted"])
        cv.addWidget(self._chain_status)
        chain_box.setLayout(cv)
        root.addWidget(chain_box)

    # ------------------------------------------------------------------
    def _sign_events(self) -> None:
        s = self._state
        if not s.events:
            self._sig_status.setText("⚠ No events. Run Log Analyzer first.")
            return
        s.signatures = {}
        for ev in s.events:
            s.signatures[id(ev)] = s.integrity.sign_event(ev)
        self._refresh_sig_table()
        self._sig_status.setText(f"✍ Signed {len(s.events)} events.")

    def _verify_sigs(self) -> None:
        s = self._state
        if not s.signatures:
            self._sig_status.setText("⚠ Sign events first.")
            return
        all_ok = True
        for ev in s.events:
            sig = s.signatures.get(id(ev))
            if sig is None or not s.integrity.verify_event(ev, sig):
                all_ok = False
                break
        if all_ok:
            self._sig_status.setText(f"✔ All {len(s.events)} signatures are VALID.")
        else:
            self._sig_status.setText("✗ Signature verification FAILED — tampering detected!")
        self._refresh_sig_table()

    def _tamper_event(self) -> None:
        s = self._state
        if not s.events:
            return
        idx = random.randrange(len(s.events))
        self._tampered_idx = idx
        self._orig_ip = s.events[idx].source_ip
        s.events[idx].source_ip = "10.13.37.99"
        self._sig_status.setText(f"⚡ Event #{idx + 1} tampered (source_ip changed to 10.13.37.99).")
        self._refresh_sig_table()

    def _restore_event(self) -> None:
        if self._tampered_idx is None:
            return
        self._state.events[self._tampered_idx].source_ip = self._orig_ip
        self._sig_status.setText(f"↩ Event #{self._tampered_idx + 1} restored.")
        self._tampered_idx = None
        self._refresh_sig_table()

    def _refresh_sig_table(self) -> None:
        s = self._state
        self._sig_table.setRowCount(0)
        for i, ev in enumerate(s.events):
            sig = s.signatures.get(id(ev), "")
            valid = s.integrity.verify_event(ev, sig) if sig else False
            colour = _C["green"] if valid else (_C["red"] if sig else _C["muted"])
            status = "✔ VALID" if valid else ("✗ INVALID" if sig else "—")
            _add_row(
                self._sig_table,
                [str(i + 1), ev.source_ip or "n/a", ev.event_type,
                 f"{ev.severity:.3f}", sig[:16] + "…" if sig else "—", status],
                row_colour=colour,
            )

    def _append_chain(self) -> None:
        text = self._chain_entry.text().strip()
        subj = self._chain_subj.text().strip() or "user"
        if not text:
            return
        entry = self._state.integrity.append_to_chain({"event": text}, subject=subj)
        self._chain_entry.clear()
        self._refresh_chain_table()
        self._chain_status.setText(f"Entry #{entry.index} appended.")

    def _verify_chain(self) -> None:
        result = self._state.integrity.verify_chain()
        if result.valid:
            self._chain_status.setText(
                f"✔ Chain VALID — {result.length} entries verified.  {result.reason}"
            )
            self._chain_status.setStyleSheet(f"color: {_C['green']};")
        else:
            self._chain_status.setText(
                f"✗ Chain BROKEN at entry {result.broken_at} — {result.reason}"
            )
            self._chain_status.setStyleSheet(f"color: {_C['red']};")

    def _export_chain(self) -> None:
        data = self._state.integrity.export_chain()
        text = json.dumps(data, indent=2)
        dlg = QWidget()
        dlg.setWindowTitle("Audit Chain Export")
        dlg.resize(600, 400)
        v = QVBoxLayout()
        pt = _plain(read_only=True)
        pt.setPlainText(text)
        v.addWidget(pt)
        dlg.setLayout(v)
        dlg.setStyleSheet(f"background: {_C['bg']};")
        dlg.show()
        self._export_dlg = dlg  # keep reference alive

    def _refresh_chain_table(self) -> None:
        chain = self._state.integrity.get_chain()
        self._chain_table.setRowCount(0)
        for entry in chain:
            ts_short = entry.timestamp[11:19] if len(entry.timestamp) > 18 else entry.timestamp
            _add_row(
                self._chain_table,
                [str(entry.index), ts_short, entry.subject,
                 json.dumps(entry.data),
                 entry.prev_hash[:8] + "…",
                 entry.entry_hash[:8] + "…"],
                row_colour=_C["text"],
            )
        self._chain_table.scrollToBottom()


# ===========================================================================
# Tab 7 — Availability Monitor
# ===========================================================================

class AvailabilityTab(QWidget):
    def __init__(self, state: AppState) -> None:
        super().__init__()
        self._state = state
        self._setup_ui()
        # Timer to refresh heartbeat ages
        self._timer = QTimer()
        self._timer.timeout.connect(self._tick)
        self._timer.start(2000)

    def _setup_ui(self) -> None:
        root = QHBoxLayout()
        self.setLayout(root)

        # ── Left: rate limiter ────────────────────────────────────────
        left_box = _section("Token-Bucket Rate Limiter")
        lv = QVBoxLayout()

        form = QFormLayout()
        self._rate_spin = QDoubleSpinBox()
        self._rate_spin.setRange(0.1, 1000.0)
        self._rate_spin.setValue(5.0)
        self._rate_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        self._burst_spin = QDoubleSpinBox()
        self._burst_spin.setRange(1.0, 1000.0)
        self._burst_spin.setValue(10.0)
        self._burst_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        self._subject_line_rl = _line("IP or identifier (e.g. 192.168.1.5)")
        self._subject_line_rl.setText("192.168.1.5")
        self._n_requests_spin = QSpinBox()
        self._n_requests_spin.setRange(1, 200)
        self._n_requests_spin.setValue(20)
        self._n_requests_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        for lbl_text, w in [
            ("Rate (tokens/s):", self._rate_spin),
            ("Burst (capacity):", self._burst_spin),
            ("Subject:", self._subject_line_rl),
            ("Requests to send:", self._n_requests_spin),
        ]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"color: {_C['text']};")
            form.addRow(lbl, w)
        lv.addLayout(form)

        rl_btn_row = QHBoxLayout()
        apply_btn  = _make_button("⚙  Apply Config", _C["muted"])
        send_btn   = _make_button("📤  Send Requests", _C["accent"])
        reset_btn  = _make_button("🔄  Reset Bucket", _C["muted"])
        apply_btn.clicked.connect(self._apply_config)
        send_btn.clicked.connect(self._send_requests)
        reset_btn.clicked.connect(self._reset_bucket)
        for b in (apply_btn, send_btn, reset_btn):
            rl_btn_row.addWidget(b)
        lv.addLayout(rl_btn_row)

        # Result bars
        result_box = _section("Last Flood Result")
        rv = QVBoxLayout()
        self._allowed_bar = _progress(_C["green"])
        self._allowed_bar.setRange(0, 100)
        self._allowed_bar.setFormat("Allowed: 0")
        self._denied_bar  = _progress(_C["red"])
        self._denied_bar.setRange(0, 100)
        self._denied_bar.setFormat("Denied: 0")
        rv.addWidget(QLabel("Allowed:"))
        rv.addWidget(self._allowed_bar)
        rv.addWidget(QLabel("Denied:"))
        rv.addWidget(self._denied_bar)
        result_box.setLayout(rv)
        lv.addWidget(result_box)

        # Rate monitor threshold
        rate_box = _section("Event Rate Monitor")
        rrf = QFormLayout()
        self._threshold_spin = QDoubleSpinBox()
        self._threshold_spin.setRange(0.1, 10000.0)
        self._threshold_spin.setValue(5.0)
        self._threshold_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        self._window_spin = QSpinBox()
        self._window_spin.setRange(1, 600)
        self._window_spin.setValue(60)
        self._window_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        for lbl_text, w in [
            ("Threshold (ev/s):", self._threshold_spin),
            ("Window (seconds):", self._window_spin),
        ]:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet(f"color: {_C['text']};")
            rrf.addRow(lbl, w)
        apply_rate_btn = _make_button("⚙  Apply Rate Config", _C["muted"])
        apply_rate_btn.clicked.connect(self._apply_rate_config)
        rate_box.setLayout(rrf)
        lv.addWidget(rate_box)
        lv.addWidget(apply_rate_btn)
        lv.addStretch()
        left_box.setLayout(lv)
        root.addWidget(left_box, 1)

        # ── Right: heartbeat tracker ──────────────────────────────────
        right_box = _section("Service Heartbeat Tracker")
        rv2 = QVBoxLayout()
        hb_ctrl = QHBoxLayout()
        self._svc_name_line = _line("Service name (e.g. threat-detector)")
        self._svc_name_line.setText("threat-detector")
        hb_btn = _make_button("💓  Register / Heartbeat", _C["green"])
        hb_btn.clicked.connect(self._heartbeat)
        hb_ctrl.addWidget(self._svc_name_line)
        hb_ctrl.addWidget(hb_btn)
        rv2.addLayout(hb_ctrl)

        chk_ctrl = QHBoxLayout()
        self._max_age_spin = QDoubleSpinBox()
        self._max_age_spin.setRange(1.0, 3600.0)
        self._max_age_spin.setValue(30.0)
        self._max_age_spin.setStyleSheet(f"background: {_C['surface']}; color: {_C['text']};")
        chk_btn = _make_button("🔍  Check Services", _C["orange"])
        chk_btn.clicked.connect(self._check_services)
        chk_ctrl.addWidget(QLabel("Max age (s):"))
        chk_ctrl.addWidget(self._max_age_spin)
        chk_ctrl.addWidget(chk_btn)
        rv2.addLayout(chk_ctrl)

        self._svc_table = _table(["Service", "Last Heartbeat", "Age (s)", "Status"])
        rv2.addWidget(self._svc_table)

        # Alert panel
        alert_box = _section("Availability Alerts")
        av = QVBoxLayout()
        self._alert_list = QListWidget()
        self._alert_list.setStyleSheet(
            f"QListWidget {{ background: {_C['surface']}; color: {_C['text']};"
            f"  border: none; font-family: monospace; font-size: 11px; }}"
        )
        flush_btn = _make_button("🗑  Flush Alerts", _C["muted"])
        flush_btn.clicked.connect(self._flush_alerts)
        av.addWidget(self._alert_list)
        av.addWidget(flush_btn)
        alert_box.setLayout(av)
        rv2.addWidget(alert_box)
        right_box.setLayout(rv2)
        root.addWidget(right_box, 1)

    # ------------------------------------------------------------------
    def _apply_config(self) -> None:
        self._state.limiter = TokenBucketRateLimiter(
            rate=self._rate_spin.value(),
            burst=self._burst_spin.value(),
        )

    def _apply_rate_config(self) -> None:
        self._state.avail = AvailabilityMonitor(
            window_seconds=float(self._window_spin.value()),
            rate_threshold=self._threshold_spin.value(),
        )

    def _send_requests(self) -> None:
        subject = self._subject_line_rl.text().strip() or "test-ip"
        n       = self._n_requests_spin.value()
        allowed = denied = 0
        for _ in range(n):
            result = self._state.limiter.check(subject)
            if result.allowed:
                allowed += 1
                alert = self._state.avail.record_event(subject, count=1)
                if alert:
                    colour = _ALERT_SEVERITY_COLOUR.get(alert.severity, _C["yellow"])
                    item = QListWidgetItem(alert.summary())
                    item.setForeground(QBrush(QColor(colour)))
                    self._alert_list.addItem(item)
                    self._alert_list.scrollToBottom()
            else:
                denied += 1

        total = allowed + denied
        self._allowed_bar.setValue(int(allowed * 100 / max(total, 1)))
        self._allowed_bar.setFormat(f"Allowed: {allowed}/{total}")
        self._denied_bar.setValue(int(denied * 100 / max(total, 1)))
        self._denied_bar.setFormat(f"Denied (rate-limited): {denied}/{total}")

    def _reset_bucket(self) -> None:
        subject = self._subject_line_rl.text().strip() or "test-ip"
        self._state.limiter.reset(subject)

    def _heartbeat(self) -> None:
        svc = self._svc_name_line.text().strip()
        if svc:
            self._state.avail.heartbeat(svc)
        self._refresh_svc_table()

    def _check_services(self) -> None:
        alerts = self._state.avail.check_services(
            max_age_seconds=self._max_age_spin.value()
        )
        for alert in alerts:
            colour = _ALERT_SEVERITY_COLOUR.get(alert.severity, _C["orange"])
            item = QListWidgetItem(alert.summary())
            item.setForeground(QBrush(QColor(colour)))
            self._alert_list.addItem(item)
        self._alert_list.scrollToBottom()
        self._refresh_svc_table()

    def _flush_alerts(self) -> None:
        self._state.avail.flush_alerts()
        self._alert_list.clear()

    def _refresh_svc_table(self) -> None:
        self._svc_table.setRowCount(0)
        now = time.time()
        for svc in self._state.avail.registered_services():
            state = self._state.avail._heartbeats.get(svc)
            if state is None:
                continue
            age = now - state
            max_age = self._max_age_spin.value()
            healthy = age <= max_age
            colour  = _C["green"] if healthy else _C["red"]
            status  = "UP ✔" if healthy else "STALE ✗"
            ts = time.strftime("%H:%M:%S", time.localtime(state))
            _add_row(
                self._svc_table,
                [svc, ts, f"{age:.0f}", status],
                row_colour=colour,
            )

    def _tick(self) -> None:
        """Called every 2 s to refresh service ages."""
        self._refresh_svc_table()


# ===========================================================================
# Main Window
# ===========================================================================

class SentinelWeaveApp(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("SentinelWeave  —  AI-Powered Cybersecurity Threat Detection")
        self.resize(1280, 860)
        self._setup_style()
        self._state = AppState()
        self._setup_ui()

    def _setup_style(self) -> None:
        self.setStyleSheet(
            f"QMainWindow, QWidget {{ background: {_C['bg']}; color: {_C['text']}; }}"
            f"QTabWidget::pane {{ border: 1px solid {_C['border']}; }}"
            f"QTabBar::tab {{ background: {_C['surface']}; color: {_C['muted']};"
            f"  padding: 8px 16px; border-radius: 4px 4px 0 0; }}"
            f"QTabBar::tab:selected {{ background: {_C['header']}; color: {_C['accent']};"
            f"  font-weight: bold; }}"
            f"QSplitter::handle {{ background: {_C['border']}; }}"
            f"QLabel {{ color: {_C['text']}; }}"
            f"QSpinBox, QDoubleSpinBox {{ background: {_C['surface']}; color: {_C['text']};"
            f"  border: 1px solid {_C['border']}; border-radius: 4px; padding: 2px; }}"
        )

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        main_v = QVBoxLayout()
        central.setLayout(main_v)

        # Title bar
        title = QLabel("🛡  SentinelWeave  —  AI-Powered Cybersecurity Threat Detection")
        title.setStyleSheet(
            f"font-size: 16px; font-weight: bold; color: {_C['accent']};"
            f"padding: 8px; background: {_C['header']}; border-radius: 4px;"
        )
        main_v.addWidget(title)

        # Tabs
        tabs = QTabWidget()
        main_v.addWidget(tabs)

        self._dash       = DashboardTab(self._state)
        self._log_tab    = LogAnalyzerTab(self._state, self._dash)
        self._threat_tab = ThreatDetectionTab(self._state)
        self._ml_tab     = MLPipelineTab(self._state)
        self._rbac_tab   = AccessControlTab(self._state)
        self._integ_tab  = IntegrityTab(self._state)
        self._avail_tab  = AvailabilityTab(self._state)

        tabs.addTab(self._dash,       "🏠  Dashboard")
        tabs.addTab(self._log_tab,    "📋  Log Analyzer")
        tabs.addTab(self._threat_tab, "🚨  Threat Detection")
        tabs.addTab(self._ml_tab,     "🤖  ML Pipeline")
        tabs.addTab(self._rbac_tab,   "🔑  Access Control")
        tabs.addTab(self._integ_tab,  "🔗  Integrity Monitor")
        tabs.addTab(self._avail_tab,  "📡  Availability")

        # Wire up signals so tabs stay in sync
        self._log_tab.events_updated.connect(self._threat_tab.refresh)
        self._log_tab.events_updated.connect(self._integ_tab._sign_events)
        tabs.currentChanged.connect(self._on_tab_change)

        # Status bar
        self._status_bar = QStatusBar()
        self._status_bar.setStyleSheet(f"color: {_C['muted']}; background: {_C['header']};")
        self._status_bar.showMessage(
            "SentinelWeave v0.3.0  |  Ready  |  "
            "Start with Log Analyzer → paste logs → Analyze"
        )
        self.setStatusBar(self._status_bar)

    def _on_tab_change(self, idx: int) -> None:
        if idx == 0:
            self._dash.refresh()
        elif idx == 2:
            self._threat_tab.refresh()


# ===========================================================================
# Entry point
# ===========================================================================

def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("SentinelWeave")
    window = SentinelWeaveApp()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
