"""
SentinelWeave Web Dashboard
============================

Flask application that exposes a live-updating web dashboard for the
SentinelWeave threat-detection platform.

REST endpoints
--------------
GET /                  — HTML dashboard (Chart.js SPA)
GET /api/summary       — JSON snapshot of current metrics
GET /api/events        — JSON list of recent threat reports (last N)
GET /api/stream        — Server-Sent Events (SSE) stream of live metrics
POST /api/ingest       — Accept JSON event payload and run threat analysis

Usage
-----
Direct run::

    python -m dashboard                          # localhost:5000
    python -m dashboard --host 0.0.0.0 --port 8080 --debug

Import and attach to an existing app::

    from dashboard.app import create_app
    app = create_app()
    app.run()
"""

from __future__ import annotations

import json
import queue
import random
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from flask import Flask, Response, jsonify, render_template, request

# ---------------------------------------------------------------------------
# Import SentinelWeave — relative to the repository root
# ---------------------------------------------------------------------------
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from sentinel_weave import (
    EventAnalyzer,
    ThreatDetector,
    ThreatLevel,
    ThreatReport,
    ThreatCorrelator,
    summarize_reports,
)
from sentinel_weave.email_scanner import EmailScanner, EmailScanResult

# ---------------------------------------------------------------------------
# In-memory metrics store
# ---------------------------------------------------------------------------

_MAX_EVENTS = 500        # cap on stored ThreatReports
_MAX_EMAIL  = 200        # cap on stored EmailScanResults
_TICK_SECS  = 2.0        # how often the background simulator fires (demo mode)


@dataclass
class DashboardMetrics:
    """Thread-safe metrics snapshot published via SSE."""
    total_events:      int   = 0
    benign:            int   = 0
    low:               int   = 0
    medium:            int   = 0
    high:              int   = 0
    critical:          int   = 0
    emails_scanned:    int   = 0
    email_threats:     int   = 0
    avg_anomaly_score: float = 0.0
    events_per_minute: float = 0.0
    top_sources:       list[tuple[str, int]] = None   # type: ignore[assignment]
    recent_sigs:       list[str]             = None   # type: ignore[assignment]

    def __post_init__(self) -> None:
        if self.top_sources is None:
            self.top_sources = []
        if self.recent_sigs is None:
            self.recent_sigs = []


class MetricsStore:
    """Thread-safe container for live threat-report history."""

    def __init__(self) -> None:
        self._lock          = threading.Lock()
        self._reports:   deque[ThreatReport]     = deque(maxlen=_MAX_EVENTS)
        self._emails:    deque[EmailScanResult]  = deque(maxlen=_MAX_EMAIL)
        self._sse_queues: list[queue.SimpleQueue[str]] = []
        self._timeline:  deque[tuple[float, int]] = deque(maxlen=60)  # (ts, count)

    # ------------------------------------------------------------------
    def add_report(self, report: ThreatReport) -> None:
        with self._lock:
            self._reports.append(report)
            self._timeline.append((time.time(), 1))
        self._broadcast()

    def add_email(self, result: EmailScanResult) -> None:
        with self._lock:
            self._emails.append(result)
        self._broadcast()

    def add_bulk(self, reports: list[ThreatReport]) -> None:
        with self._lock:
            self._reports.extend(reports)
        self._broadcast()

    # ------------------------------------------------------------------
    def snapshot(self) -> DashboardMetrics:
        with self._lock:
            reports = list(self._reports)
            emails  = list(self._emails)
            tl      = list(self._timeline)

        counts = {lvl: 0 for lvl in ThreatLevel}
        total_score = 0.0
        sig_freq: dict[str, int] = {}
        src_freq: dict[str, int] = {}

        for r in reports:
            counts[r.threat_level] += 1
            total_score += r.anomaly_score
            for s in r.event.matched_sigs:
                sig_freq[s] = sig_freq.get(s, 0) + 1
            ip = r.event.source_ip
            if ip:
                src_freq[ip] = src_freq.get(ip, 0) + 1

        email_threats = sum(
            1 for e in emails
            if e.threat_level not in (ThreatLevel.BENIGN, ThreatLevel.LOW)
        )

        # Events per minute from the last 60 s
        now = time.time()
        recent = [c for ts, c in tl if now - ts <= 60]
        epm = sum(recent) / 1.0 * (60.0 / max(60.0, now - (tl[0][0] if tl else now) + 1))

        return DashboardMetrics(
            total_events      = len(reports),
            benign            = counts[ThreatLevel.BENIGN],
            low               = counts[ThreatLevel.LOW],
            medium            = counts[ThreatLevel.MEDIUM],
            high              = counts[ThreatLevel.HIGH],
            critical          = counts[ThreatLevel.CRITICAL],
            emails_scanned    = len(emails),
            email_threats     = email_threats,
            avg_anomaly_score = total_score / max(len(reports), 1),
            events_per_minute = round(epm, 2),
            top_sources       = sorted(src_freq.items(), key=lambda x: -x[1])[:10],
            recent_sigs       = sorted(sig_freq.items(), key=lambda x: -x[1])[:10],
        )

    def recent_reports(self, n: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            reports = list(self._reports)[-n:]
        result = []
        for r in reversed(reports):
            result.append({
                "ts":          r.event.timestamp.isoformat() if r.event.timestamp else None,
                "source_ip":   r.event.source_ip,
                "event_type":  r.event.event_type,
                "threat_level":r.threat_level.value,
                "score":       round(r.anomaly_score, 4),
                "sigs":        r.event.matched_sigs,
                "summary":     r.summary(),
            })
        return result

    # ------------------------------------------------------------------
    def register_sse_queue(self) -> "queue.SimpleQueue[str]":
        q: queue.SimpleQueue[str] = queue.SimpleQueue()
        with self._lock:
            self._sse_queues.append(q)
        return q

    def unregister_sse_queue(self, q: "queue.SimpleQueue[str]") -> None:
        with self._lock:
            try:
                self._sse_queues.remove(q)
            except ValueError:
                pass

    def _broadcast(self) -> None:
        snap = self.snapshot()
        payload = json.dumps({
            "type":    "metrics",
            "data":    _metrics_to_dict(snap),
            "ts":      datetime.now(timezone.utc).isoformat(),
        })
        msg = f"data: {payload}\n\n"
        with self._lock:
            queues = list(self._sse_queues)
        for q in queues:
            try:
                q.put_nowait(msg)
            except Exception:  # noqa: BLE001
                pass


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _metrics_to_dict(m: DashboardMetrics) -> dict[str, Any]:
    return {
        "total_events":       m.total_events,
        "levels": {
            "BENIGN":   m.benign,
            "LOW":      m.low,
            "MEDIUM":   m.medium,
            "HIGH":     m.high,
            "CRITICAL": m.critical,
        },
        "emails_scanned":     m.emails_scanned,
        "email_threats":      m.email_threats,
        "avg_anomaly_score":  round(m.avg_anomaly_score, 4),
        "events_per_minute":  m.events_per_minute,
        "top_sources":        m.top_sources,
        "recent_sigs":        [{"sig": s, "count": c} for s, c in m.recent_sigs],
    }


# ---------------------------------------------------------------------------
# Demo / background simulator
# ---------------------------------------------------------------------------

_DEMO_LOG_LINES = [
    "Failed password for root from 10.0.0.{n} port 22 ssh2",
    "nmap scan detected from 192.168.1.{n}",
    "GET /index.php?id=1 UNION SELECT user,pass FROM users HTTP/1.1",
    "User admin logged in from 172.16.0.{n}",
    "System update applied kernel 6.{n}.0",
    "Firewall blocked 10.10.{n}.1 on port 445",
    "Failed login attempt from 198.51.{n}.1",
    "XSS payload detected in request from 203.0.{n}.0",
    "Normal traffic from 10.0.1.{n}",
    "Service restart: sshd pid={n}",
    "../../../etc/passwd traversal attempt from 10.0.0.{n}",
]


def _start_demo_simulator(store: MetricsStore) -> threading.Thread:
    """Start a background thread that generates synthetic events."""
    analyzer = EventAnalyzer()
    detector = ThreatDetector()

    def _worker() -> None:
        n = 1
        while True:
            time.sleep(_TICK_SECS + random.uniform(-0.5, 0.5))
            template = random.choice(_DEMO_LOG_LINES)
            line = template.format(n=n % 254 + 1)
            event  = analyzer.parse(line)
            report = detector.analyze(event)
            store.add_report(report)
            n += 1

    t = threading.Thread(target=_worker, daemon=True, name="sentinel-demo")
    t.start()
    return t


# ---------------------------------------------------------------------------
# Flask application factory
# ---------------------------------------------------------------------------

def create_app(demo_mode: bool = True) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        demo_mode: When ``True`` (default), a background thread generates
                   synthetic events so the dashboard always has live data.
                   Set to ``False`` in production; ingest events via
                   ``POST /api/ingest`` or import the store directly.

    Returns:
        Configured :class:`flask.Flask` instance.
    """
    # Locate templates/static relative to this file
    here = os.path.dirname(os.path.abspath(__file__))
    app  = Flask(
        __name__,
        template_folder=os.path.join(here, "templates"),
        static_folder  =os.path.join(here, "static"),
    )

    store      = MetricsStore()
    analyzer   = EventAnalyzer()
    detector   = ThreatDetector()
    email_scan = EmailScanner()

    if demo_mode:
        _start_demo_simulator(store)

    # Expose store on app for testing
    app.store = store  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ #
    # Routes                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.get("/api/summary")
    def api_summary() -> Response:
        snap = store.snapshot()
        return jsonify(_metrics_to_dict(snap))

    @app.get("/api/events")
    def api_events() -> Response:
        n = min(int(request.args.get("n", 50)), 500)
        return jsonify(store.recent_reports(n))

    @app.post("/api/ingest")
    def api_ingest() -> Response:
        """Accept a JSON payload and run through the threat pipeline."""
        payload = request.get_json(force=True, silent=True) or {}
        raw = payload.get("raw", "")
        if not raw:
            return jsonify({"error": "field 'raw' is required"}), 400
        event  = analyzer.parse(str(raw))
        report = detector.analyze(event)
        store.add_report(report)
        return jsonify({
            "threat_level": report.threat_level.value,
            "score":        round(report.anomaly_score, 4),
            "sigs":         report.event.matched_sigs,
        }), 201

    @app.post("/api/ingest/email")
    def api_ingest_email() -> Response:
        """Accept a raw RFC 5322 email string and return the threat scan."""
        payload = request.get_json(force=True, silent=True) or {}
        raw = payload.get("raw", "")
        if not raw:
            return jsonify({"error": "field 'raw' is required"}), 400
        result = email_scan.scan_raw(str(raw))
        store.add_email(result)
        return jsonify({
            "threat_level": result.threat_level.value,
            "risk_score":   round(result.risk_score, 4),
            "indicators":   [i.name for i in result.indicators],
        }), 201

    @app.get("/api/stream")
    def api_stream() -> Response:
        """
        Server-Sent Events endpoint.  The client receives a ``metrics``
        event every time new data is ingested, plus a keep-alive comment
        every 15 s.
        """
        q = store.register_sse_queue()

        def _generate():
            try:
                # Initial snapshot immediately on connect
                snap = store.snapshot()
                yield f"data: {json.dumps({'type': 'metrics', 'data': _metrics_to_dict(snap)})}\n\n"
                while True:
                    try:
                        msg = q.get(timeout=15)
                        yield msg
                    except queue.Empty:
                        yield ": keep-alive\n\n"
            finally:
                store.unregister_sse_queue(q)

        return Response(
            _generate(),
            mimetype="text/event-stream",
            headers={
                "Cache-Control":               "no-cache",
                "X-Accel-Buffering":           "no",
                "Access-Control-Allow-Origin": "*",
            },
        )

    @app.get("/health")
    def health() -> Response:
        return jsonify({"status": "ok", "version": "1.0"})

    return app
