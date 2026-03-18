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

import base64
import json
import logging
import queue
import random
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any

from flask import Flask, Response, jsonify, render_template, request, send_from_directory

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
from quantaweave import QuantaWeave
from mlkem_mldsa_bridge import (
    kem_keygen,
    kem_encaps,
    kem_decaps,
    sig_keygen,
    sig_sign,
    sig_verify,
)
from sentinel_weave.email_scanner import EmailScanner, EmailScanResult
from sentinel_weave.red_team_toolkit import (
    PortScanner,
    VulnerabilityAssessor,
    CredentialAuditor,
    ReconScanner,
    summarize_scan,
)
from sentinel_weave.advanced_offensive import (
    ShellcodeAnalyzer,
    YaraScanner,
    AnomalyDetector,
)
from sentinel_weave.threat_query import ThreatQueryEngine
from sentinel_weave.federated_intel import FederatedIntelHub

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


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


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
    logger = logging.getLogger("sentinelweave.dashboard")
    if not logger.handlers:
        logging.basicConfig(level=logging.INFO)
    ui_dist = os.path.abspath(os.path.join(here, "..", "dashboard_web", "dist"))

    store      = MetricsStore()
    analyzer   = EventAnalyzer()
    detector   = ThreatDetector()
    email_scan = EmailScanner()
    port_scanner    = PortScanner(timeout=1.0)
    vuln_assessor   = VulnerabilityAssessor()
    cred_auditor    = CredentialAuditor()
    recon_scanner   = ReconScanner(timeout=3.0)
    shellcode_analyzer = ShellcodeAnalyzer(arch="x86_64")
    yara_scanner       = YaraScanner()
    anomaly_detector   = AnomalyDetector()
    query_engine       = ThreatQueryEngine()
    fed_hub            = FederatedIntelHub()

    if demo_mode:
        _start_demo_simulator(store)

    api_token = (
        os.environ.get("SENTINELWEAVE_API_KEY")
        or os.environ.get("SENTINELWEAVE_DASHBOARD_API_KEY")
    )

    def _require_api_key() -> Response | None:
        if not api_token:
            return None
        token = request.headers.get("X-API-Key", "").strip()
        auth = request.headers.get("Authorization", "").strip()
        if auth.startswith("Bearer "):
            token = auth.split(" ", 1)[1].strip()
        if not token or token != api_token:
            return jsonify({"error": "unauthorized"}), 401
        return None

    # Expose store on app for testing
    app.store = store  # type: ignore[attr-defined]

    @app.before_request
    def _log_request_start() -> None:
        request.start_time = time.time()  # type: ignore[attr-defined]

    @app.after_request
    def _log_request_end(response: Response) -> Response:
        start = getattr(request, "start_time", None)
        elapsed_ms = (time.time() - start) * 1000 if start else 0.0
        logger.info(
            "%s %s -> %s (%.1f ms)",
            request.method,
            request.path,
            response.status_code,
            elapsed_ms,
        )
        return response

    # ------------------------------------------------------------------ #
    # Routes                                                               #
    # ------------------------------------------------------------------ #

    @app.get("/")
    def index() -> str:
        return render_template("index.html")

    @app.get("/ui")
    def ui_index() -> Response | str:
        if os.path.isdir(ui_dist):
            return send_from_directory(ui_dist, "index.html")
        return render_template("index.html")

    @app.get("/ui/<path:asset>")
    def ui_asset(asset: str) -> Response:
        if not os.path.isdir(ui_dist):
            return jsonify({"error": "ui not built"}), 404
        return send_from_directory(ui_dist, asset)

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

    @app.post("/api/quantaweave/keygen")
    def api_quantaweave_keygen() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        level = payload.get("level", "LEVEL1")
        if level not in {"LEVEL1", "LEVEL3", "LEVEL5"}:
            return jsonify({"error": "level must be LEVEL1, LEVEL3, or LEVEL5"}), 400
        try:
            pqc = QuantaWeave(security_level=level)
            public_key, private_key = pqc.generate_keypair()
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "public_key": public_key,
            "private_key": private_key,
            "level": level,
        }), 200

    @app.post("/api/quantaweave/encrypt")
    def api_quantaweave_encrypt() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        message = payload.get("message", "")
        public_key = payload.get("public_key")
        if not public_key:
            return jsonify({"error": "public_key is required"}), 400
        if not isinstance(message, str):
            return jsonify({"error": "message must be a string"}), 400
        try:
            ciphertext = QuantaWeave.encrypt(message.encode("utf-8"), public_key)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"ciphertext": ciphertext}), 200

    @app.post("/api/quantaweave/decrypt")
    def api_quantaweave_decrypt() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        ciphertext = payload.get("ciphertext")
        private_key = payload.get("private_key")
        if not ciphertext or not private_key:
            return jsonify({"error": "ciphertext and private_key are required"}), 400
        try:
            plaintext = QuantaWeave.decrypt(ciphertext, private_key)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "plaintext": plaintext.decode("utf-8", errors="replace"),
        }), 200

    @app.post("/api/mlkem/keygen")
    def api_mlkem_keygen() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        alg = payload.get("alg", "ML-KEM-512")
        try:
            public_key, secret_key = kem_keygen(alg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "alg": alg,
            "public_key_b64": _b64e(public_key),
            "secret_key_b64": _b64e(secret_key),
        }), 200

    @app.post("/api/mlkem/encaps")
    def api_mlkem_encaps() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        alg = payload.get("alg", "ML-KEM-512")
        public_key_b64 = payload.get("public_key_b64", "")
        if not public_key_b64:
            return jsonify({"error": "public_key_b64 is required"}), 400
        try:
            public_key = _b64d(public_key_b64)
            ciphertext, shared_secret = kem_encaps(public_key, alg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "ciphertext_b64": _b64e(ciphertext),
            "shared_secret_b64": _b64e(shared_secret),
        }), 200

    @app.post("/api/mlkem/decaps")
    def api_mlkem_decaps() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        alg = payload.get("alg", "ML-KEM-512")
        ciphertext_b64 = payload.get("ciphertext_b64", "")
        secret_key_b64 = payload.get("secret_key_b64", "")
        if not ciphertext_b64 or not secret_key_b64:
            return jsonify({"error": "ciphertext_b64 and secret_key_b64 are required"}), 400
        try:
            ciphertext = _b64d(ciphertext_b64)
            secret_key = _b64d(secret_key_b64)
            shared_secret = kem_decaps(ciphertext, secret_key, alg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "shared_secret_b64": _b64e(shared_secret),
        }), 200

    @app.post("/api/mldsa/keygen")
    def api_mldsa_keygen() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        alg = payload.get("alg", "ML-DSA-44")
        try:
            public_key, secret_key = sig_keygen(alg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "alg": alg,
            "public_key_b64": _b64e(public_key),
            "secret_key_b64": _b64e(secret_key),
        }), 200

    @app.post("/api/mldsa/sign")
    def api_mldsa_sign() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        alg = payload.get("alg", "ML-DSA-44")
        secret_key_b64 = payload.get("secret_key_b64", "")
        message = payload.get("message", "")
        if not secret_key_b64:
            return jsonify({"error": "secret_key_b64 is required"}), 400
        if not isinstance(message, str):
            return jsonify({"error": "message must be a string"}), 400
        try:
            secret_key = _b64d(secret_key_b64)
            signature = sig_sign(secret_key, message.encode("utf-8"), alg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({
            "signature_b64": _b64e(signature),
        }), 200

    @app.post("/api/mldsa/verify")
    def api_mldsa_verify() -> Response:
        payload = request.get_json(force=True, silent=True) or {}
        alg = payload.get("alg", "ML-DSA-44")
        public_key_b64 = payload.get("public_key_b64", "")
        signature_b64 = payload.get("signature_b64", "")
        message = payload.get("message", "")
        if not public_key_b64 or not signature_b64:
            return jsonify({"error": "public_key_b64 and signature_b64 are required"}), 400
        if not isinstance(message, str):
            return jsonify({"error": "message must be a string"}), 400
        try:
            public_key = _b64d(public_key_b64)
            signature = _b64d(signature_b64)
            valid = sig_verify(public_key, message.encode("utf-8"), signature, alg)
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"valid": bool(valid)}), 200

    @app.post("/api/ingest/imap")
    def api_ingest_imap() -> Response:
        """Connect to IMAP and scan the most recent inbox messages."""
        auth = _require_api_key()
        if auth is not None:
            return auth
        payload = request.get_json(force=True, silent=True) or {}
        host = payload.get("host", "")
        username = payload.get("username", "")
        password = payload.get("password", "")
        folder = payload.get("folder", "INBOX")
        limit = int(payload.get("limit", 20))
        port = int(payload.get("port", 993))
        if not host or not username or not password:
            return jsonify({"error": "host, username, and password are required"}), 400
        try:
            results = email_scan.connect_and_scan_imap(
                host=host,
                port=port,
                username=username,
                password=password,
                folder=folder,
                limit=limit,
            )
        except Exception as exc:
            return jsonify({"error": str(exc)}), 400

        for r in results:
            store.add_email(r)

        return jsonify({
            "count": len(results),
            "results": [
                {
                    "subject": r.email.subject,
                    "sender": r.email.sender,
                    "threat_level": r.threat_level.value,
                    "risk_score": round(r.risk_score, 4),
                    "indicator_count": len(r.indicators),
                }
                for r in results
            ],
        }), 200

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

    # ------------------------------------------------------------------ #
    # Red-team / offensive security endpoints (authorized use only)        #
    # ------------------------------------------------------------------ #

    @app.post("/api/redteam/portscan")
    def api_redteam_portscan() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        TCP-connect port scan a single host.

        Request JSON fields:
          ``host``        (str, required)  — target hostname or IP address.
          ``ports``       (list[int])      — explicit port list (optional).
          ``port_range``  ([start, end])   — inclusive port range (optional).

        If neither ``ports`` nor ``port_range`` is supplied the 30 most
        common service ports are scanned.

        Returns a scan summary plus per-port open/closed status.
        """
        payload = request.get_json(force=True, silent=True) or {}
        host = payload.get("host", "")
        if not host:
            return jsonify({"error": "field 'host' is required"}), 400

        ports      = payload.get("ports")
        port_range = payload.get("port_range")

        # Restrict scanned ports to a sane limit to prevent abuse
        _MAX_PORTS = 200
        if ports and len(ports) > _MAX_PORTS:
            return jsonify(
                {"error": f"port list too large (max {_MAX_PORTS})"}
            ), 400
        if port_range and (
            not isinstance(port_range, list)
            or len(port_range) != 2
            or (port_range[1] - port_range[0]) > _MAX_PORTS
        ):
            return jsonify(
                {"error": f"port_range span exceeds max of {_MAX_PORTS}"}
            ), 400

        results = port_scanner.scan(
            host,
            ports=ports,
            port_range=tuple(port_range) if port_range else None,
        )
        summary = summarize_scan(results)
        detail = [
            {
                "port":         r.port,
                "is_open":      r.is_open,
                "service_hint": r.service_hint,
                "banner":       r.banner[:80] if r.banner else "",
            }
            for r in results
        ]
        return jsonify({"summary": summary, "ports": detail}), 200

    @app.post("/api/redteam/vulnscan")
    def api_redteam_vulnscan() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Check a service banner string against known CVE patterns.

        Request JSON fields:
          ``banner``  (str, required) — raw service banner to assess.

        Returns a list of :class:`VulnerabilityFinding` dicts and the
        overall highest severity.
        """
        payload = request.get_json(force=True, silent=True) or {}
        banner = payload.get("banner", "")
        if not banner:
            return jsonify({"error": "field 'banner' is required"}), 400

        findings = vuln_assessor.assess(str(banner))
        return jsonify({
            "banner":           banner[:120],
            "finding_count":    len(findings),
            "highest_severity": VulnerabilityAssessor.highest_severity(findings),
            "findings": [
                {
                    "cve_id":      f.cve_id,
                    "severity":    f.severity,
                    "cvss_score":  f.cvss_score,
                    "service":     f.service,
                    "description": f.description,
                    "match_token": f.match_token,
                }
                for f in findings
            ],
        }), 200

    @app.post("/api/redteam/credaudit")
    def api_redteam_credaudit() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Audit one or more password strings for strength.

        Request JSON fields:
          ``passwords``  (list[str], required) — passwords to audit (max 50).

        Passwords are **never logged or stored**; only their SHA-256 hashes
        appear in the response.
        """
        payload = request.get_json(force=True, silent=True) or {}
        passwords = payload.get("passwords", [])
        if not passwords or not isinstance(passwords, list):
            return jsonify({"error": "field 'passwords' must be a non-empty list"}), 400
        if len(passwords) > 50:
            return jsonify({"error": "max 50 passwords per request"}), 400

        results = cred_auditor.audit_bulk([str(p) for p in passwords])
        return jsonify({
            "count": len(results),
            "results": [
                {
                    "index":         i,
                    "password_hash": r.password_hash,
                    "length":        r.length,
                    "entropy_bits":  r.entropy_bits,
                    "strength":      r.strength,
                    "is_common":     r.is_common,
                    "issues":        r.issues,
                    "suggestions":   r.suggestions,
                }
                for i, r in enumerate(results)
            ],
        }), 200

    @app.post("/api/redteam/recon")
    def api_redteam_recon() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Passive recon using DNS resolution and optional quick probes.

        Request JSON fields:
          ``target`` (str, required) — hostname or IP address.
          ``quick_ports`` (list[int], optional) — ports for quick probing.
        """
        payload = request.get_json(force=True, silent=True) or {}
        target = payload.get("target", "")
        if not target:
            return jsonify({"error": "field 'target' is required"}), 400
        quick_ports = payload.get("quick_ports")
        if quick_ports is not None and not isinstance(quick_ports, list):
            return jsonify({"error": "quick_ports must be a list of integers"}), 400

        result = recon_scanner.recon(
            str(target),
            quick_probe_ports=[int(p) for p in quick_ports] if quick_ports else None,
        )

        return jsonify({
            "target": result.target,
            "resolved_ips": result.resolved_ips,
            "reverse_hostnames": result.reverse_hostnames,
            "open_ports_hint": result.open_ports_hint,
            "ip_version": result.ip_version,
            "is_private": result.is_private,
            "metadata": result.metadata,
        }), 200

    @app.post("/api/redteam/shellcode")
    def api_redteam_shellcode() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Disassemble and classify shellcode bytes.

        Request JSON fields:
          ``hex``   (str, required)  — hex-encoded shellcode bytes
                                       (e.g. ``"4831c04889c7b03b0f05"``).
          ``arch``  (str, optional)  — one of ``"x86"``, ``"x86_64"``,
                                       ``"arm"``, ``"arm64"``
                                       (default: ``"x86_64"``).

        Returns disassembly, mnemonic summary, pattern matches, entropy,
        and a ``threat_level`` of ``"BENIGN"``, ``"SUSPICIOUS"``, or
        ``"MALICIOUS"``.
        """
        payload = request.get_json(force=True, silent=True) or {}
        hex_str = payload.get("hex", "")
        if not hex_str:
            return jsonify({"error": "field 'hex' is required"}), 400
        # Strip whitespace
        hex_str = hex_str.replace(" ", "").replace("\n", "")
        try:
            data = bytes.fromhex(hex_str)
        except ValueError:
            return jsonify({"error": "field 'hex' is not valid hex"}), 400
        if len(data) > 4096:
            return jsonify({"error": "shellcode too large (max 4 096 bytes)"}), 400

        arch = payload.get("arch", "x86_64")
        try:
            analyzer = ShellcodeAnalyzer(arch=arch)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        result = analyzer.analyze(data)
        return jsonify({
            "arch":               result.arch,
            "byte_count":         result.byte_count,
            "instruction_count":  result.instruction_count,
            "entropy":            result.entropy,
            "threat_level":       result.threat_level,
            "dangerous_mnemonics": result.dangerous_mnemonics,
            "matched_patterns":   result.matched_patterns,
            "mnemonic_summary":   result.mnemonic_summary,
            "notes":              result.notes,
            "instructions": [
                {
                    "address":   hex(i.address),
                    "mnemonic":  i.mnemonic,
                    "op_str":    i.op_str,
                    "bytes_hex": i.bytes_hex,
                }
                for i in result.instructions[:64]   # cap display to 64 insns
            ],
        }), 200

    @app.post("/api/redteam/yara")
    def api_redteam_yara() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Scan a content buffer against YARA rule sets.

        Request JSON fields:
          ``hex``        (str)         — hex-encoded content to scan.
          ``text``       (str)         — UTF-8 text content to scan
                                         (exactly one of ``hex`` or ``text``
                                         is required).
          ``rule_sets``  (list[str])   — subset of :data:`BUILTIN_RULE_NAMES`
                                         to use (default: all built-in sets).
          ``custom_rules`` (str)       — optional extra YARA source appended
                                         to the selected rule sets.

        Returns match count, severity, matched rule details.
        """
        payload = request.get_json(force=True, silent=True) or {}
        hex_str  = payload.get("hex", "")
        text_str = payload.get("text", "")

        if not hex_str and not text_str:
            return jsonify(
                {"error": "one of 'hex' or 'text' is required"}
            ), 400
        if hex_str and text_str:
            return jsonify(
                {"error": "supply either 'hex' or 'text', not both"}
            ), 400

        if hex_str:
            try:
                data = bytes.fromhex(hex_str.replace(" ", ""))
            except ValueError:
                return jsonify({"error": "field 'hex' is not valid hex"}), 400
        else:
            data = text_str.encode("utf-8", errors="replace")

        if len(data) > 10 * 1024 * 1024:
            return jsonify({"error": "content too large (max 10 MiB)"}), 400

        rule_sets    = payload.get("rule_sets")      # None → all built-ins
        custom_rules = payload.get("custom_rules", "")

        try:
            scanner = YaraScanner(rule_sets=rule_sets, extra_rules=custom_rules)
        except (ValueError, Exception) as exc:
            return jsonify({"error": str(exc)}), 400

        result = scanner.scan(data)
        return jsonify({
            "match_count":    result.match_count,
            "severity":       result.severity,
            "rule_sets_used": result.rule_sets_used,
            "matches": [
                {
                    "rule_name":   m.rule_name,
                    "rule_set":    m.rule_set,
                    "description": m.description,
                    "severity":    m.severity,
                    "offset":      m.offset,
                    "data_hex":    m.data_hex,
                }
                for m in result.matches
            ],
        }), 200

    @app.post("/api/redteam/anomaly")
    def api_redteam_anomaly() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Run unsupervised anomaly detection on a set of security observations.

        Request JSON fields:
          ``observations`` (list[dict], required) — each dict maps string
            feature names to numeric values.  All dicts should share the same
            keys; missing values are filled with 0.  Maximum 10 000 records.
          ``contamination`` (float, optional) — expected fraction of anomalies
            (0 < contamination < 0.5).  Defaults to IsolationForest ``"auto"``.

        Returns per-record anomaly scores and a roll-up summary.
        """
        payload = request.get_json(force=True, silent=True) or {}
        observations = payload.get("observations")
        if not observations or not isinstance(observations, list):
            return jsonify(
                {"error": "field 'observations' must be a non-empty list"}
            ), 400
        if len(observations) > 10_000:
            return jsonify(
                {"error": "too many observations (max 10 000)"}
            ), 400

        contamination = payload.get("contamination", "auto")
        if contamination != "auto":
            try:
                contamination = float(contamination)
                if not (0 < contamination < 0.5):
                    raise ValueError()
            except (TypeError, ValueError):
                return jsonify(
                    {"error": "contamination must be 'auto' or a float in (0, 0.5)"}
                ), 400

        try:
            detector = AnomalyDetector(contamination=contamination)
            report   = detector.detect(observations)
        except (ValueError, Exception) as exc:
            return jsonify({"error": str(exc)}), 400

        return jsonify({
            "total_observations": report.total_observations,
            "anomaly_count":      report.anomaly_count,
            "contamination":      report.contamination,
            "records": [
                {
                    "index":         r.index,
                    "anomaly_score": r.anomaly_score,
                    "is_anomaly":    r.is_anomaly,
                    "risk_label":    r.risk_label,
                }
                for r in report.records
            ],
        }), 200

    # ------------------------------------------------------------------
    # Threat hunting query endpoint
    # ------------------------------------------------------------------

    @app.post("/api/query")
    def api_query() -> Response:
        """
        Search stored threat reports with a query expression.

        Request JSON fields:
          ``q`` (str, required) — query expression, e.g.
            ``"threat_level = HIGH AND source_ip = 10.*"``

        Returns a list of matching event summaries.
        """
        payload = request.get_json(force=True, silent=True) or {}
        q = payload.get("q", "")
        if not isinstance(q, str):
            return jsonify({"error": "field 'q' must be a string"}), 400

        # Sync query engine with current store contents
        with store._lock:
            all_reports = list(store._reports)
        query_engine.clear()
        query_engine.add_bulk(all_reports)

        try:
            results = query_engine.query(q)
        except (ValueError, IndexError) as exc:
            return jsonify({"error": f"Query parse error: {exc}"}), 400

        return jsonify({
            "query":   q,
            "count":   len(results),
            "results": [
                {
                    "ts":          r.event.timestamp.isoformat() if r.event.timestamp else None,
                    "source_ip":   r.event.source_ip,
                    "event_type":  r.event.event_type,
                    "threat_level": r.threat_level.value,
                    "anomaly_score": round(r.anomaly_score, 4),
                    "signatures":   r.event.matched_sigs,
                    "summary":      r.summary(),
                }
                for r in results
            ],
        }), 200

    # ------------------------------------------------------------------
    # Federated threat intelligence endpoints
    # ------------------------------------------------------------------

    @app.post("/api/federated/peers")
    def api_federated_register_peer() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Register a peer node for federated threat-intel exchange.

        Request JSON fields:
          ``peer_id``   (str, required)  — unique identifier of the peer.
          ``shared_key_hex`` (str, required) — 64-char hex-encoded 32-byte key.
          ``host``      (str, optional)  — peer's hostname for HTTP push.
          ``port``      (int, optional)  — peer's HTTP port (default 5000).
        """
        payload = request.get_json(force=True, silent=True) or {}
        peer_id = payload.get("peer_id")
        key_hex = payload.get("shared_key_hex")
        if not peer_id or not key_hex:
            return jsonify({"error": "peer_id and shared_key_hex are required"}), 400
        try:
            key = bytes.fromhex(key_hex)
        except ValueError:
            return jsonify({"error": "shared_key_hex must be a valid hex string"}), 400
        try:
            fed_hub.register_peer(
                peer_id,
                key,
                host=payload.get("host"),
                port=int(payload.get("port", 5000)),
            )
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        return jsonify({"registered": peer_id}), 201

    @app.post("/api/federated/share")
    def api_federated_share() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Create an encrypted summary of stored reports and return it as JSON.

        Request JSON fields:
          ``peer_id`` (str, required) — registered peer to encrypt for.
          ``metadata`` (dict, optional) — extra key/value pairs to include.

        Returns the encrypted bundle bytes as a hex string.  Push it to the
        peer's ``POST /api/federated/receive`` endpoint.
        """
        payload = request.get_json(force=True, silent=True) or {}
        peer_id = payload.get("peer_id")
        if not peer_id:
            return jsonify({"error": "peer_id is required"}), 400

        with store._lock:
            all_reports = list(store._reports)

        try:
            bundle = fed_hub.create_summary(
                all_reports,
                peer_id=peer_id,
                metadata=payload.get("metadata"),
            )
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 404
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify({
            "sender_node_id": fed_hub.node_id,
            "peer_id":        peer_id,
            "report_count":   len(all_reports),
            "bundle_hex":     bundle.hex(),
        }), 200

    @app.post("/api/federated/receive")
    def api_federated_receive() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """
        Accept an encrypted threat-intel bundle from a peer and store it.

        Request body: raw JSON bundle bytes (as returned by a remote
        ``POST /api/federated/share`` or :meth:`FederatedIntelHub.create_summary`).
        """
        bundle_bytes = request.get_data()
        if not bundle_bytes:
            return jsonify({"error": "empty request body"}), 400
        try:
            summary = fed_hub.receive_bundle(bundle_bytes)
        except KeyError as exc:
            return jsonify({"error": str(exc)}), 403
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        except Exception as exc:
            return jsonify({"error": str(exc)}), 500

        return jsonify({
            "received_from":  summary.sender_id,
            "total_events":   summary.total_events,
            "max_anomaly":    summary.max_anomaly,
            "threat_counts":  summary.threat_counts,
        }), 201

    @app.get("/api/federated/summaries")
    def api_federated_summaries() -> Response:
        auth = _require_api_key()
        if auth is not None:
            return auth
        """Return all received federated threat-intel summaries."""
        return jsonify({
            "summaries": [s.to_dict() for s in fed_hub.list_summaries()],
            "stats":     fed_hub.summary_stats(),
        }), 200

    return app
