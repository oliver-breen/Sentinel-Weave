"""
Tests for dashboard.app (Flask dashboard)
==========================================

Uses Flask's built-in test client — no real HTTP server needed.

Covers:
- GET / returns 200 HTML
- GET /api/summary returns JSON with expected keys
- GET /api/events returns JSON list
- POST /api/ingest with valid payload → 201 + threat fields
- POST /api/ingest with missing raw field → 400
- POST /api/ingest/email with valid payload → 201
- POST /api/ingest/email with missing raw field → 400
- GET /health → 200 {"status": "ok"}
- MetricsStore: add_report increments total_events
- MetricsStore: add_email increments emails_scanned
- MetricsStore: snapshot levels sum to total_events
- MetricsStore: recent_reports returns ≤ requested count
- SSE stream returns text/event-stream content-type
- Ingest multiple events; summary reflects them
- Demo mode flag accepted by create_app (no error)
"""

from __future__ import annotations

import json
import pytest

# ---------------------------------------------------------------------------
# App fixture — demo_mode=False for deterministic tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def client():
    """Flask test client with demo mode disabled."""
    import sys, os
    repo_root = os.path.join(os.path.dirname(__file__), "..")
    if repo_root not in sys.path:
        sys.path.insert(0, repo_root)

    from dashboard.app import create_app
    app = create_app(demo_mode=False)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c, app


# ---------------------------------------------------------------------------
# HTML / health
# ---------------------------------------------------------------------------

class TestStaticRoutes:
    def test_index_returns_200(self, client):
        c, _ = client
        r = c.get("/")
        assert r.status_code == 200

    def test_index_returns_html(self, client):
        c, _ = client
        r = c.get("/")
        assert b"SentinelWeave" in r.data

    def test_health_returns_ok(self, client):
        c, _ = client
        r = c.get("/health")
        assert r.status_code == 200
        data = json.loads(r.data)
        assert data["status"] == "ok"

    def test_health_has_version(self, client):
        c, _ = client
        data = json.loads(c.get("/health").data)
        assert "version" in data


# ---------------------------------------------------------------------------
# /api/summary
# ---------------------------------------------------------------------------

class TestSummaryEndpoint:
    def test_summary_200(self, client):
        c, _ = client
        assert c.get("/api/summary").status_code == 200

    def test_summary_has_required_keys(self, client):
        c, _ = client
        data = json.loads(c.get("/api/summary").data)
        assert "total_events" in data
        assert "levels" in data
        assert "avg_anomaly_score" in data
        assert "emails_scanned" in data
        assert "email_threats" in data

    def test_summary_levels_has_five_buckets(self, client):
        c, _ = client
        data = json.loads(c.get("/api/summary").data)
        lvls = data["levels"]
        assert set(lvls.keys()) == {"BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


# ---------------------------------------------------------------------------
# /api/events
# ---------------------------------------------------------------------------

class TestEventsEndpoint:
    def test_events_returns_list(self, client):
        c, _ = client
        data = json.loads(c.get("/api/events").data)
        assert isinstance(data, list)

    def test_events_empty_when_no_data(self, client):
        c, _ = client
        assert json.loads(c.get("/api/events?n=10").data) == []


# ---------------------------------------------------------------------------
# /api/ingest  (log events)
# ---------------------------------------------------------------------------

class TestIngestEndpoint:
    def test_ingest_valid_returns_201(self, client):
        c, _ = client
        r = c.post("/api/ingest", json={"raw": "Normal service start: nginx"})
        assert r.status_code == 201

    def test_ingest_returns_threat_level(self, client):
        c, _ = client
        r = c.post("/api/ingest", json={"raw": "Normal service start"})
        data = json.loads(r.data)
        assert "threat_level" in data
        assert data["threat_level"] in ("BENIGN", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_ingest_returns_score(self, client):
        c, _ = client
        data = json.loads(c.post("/api/ingest", json={"raw": "x"}).data)
        assert "score" in data
        assert 0.0 <= data["score"] <= 1.0

    def test_ingest_returns_sigs(self, client):
        c, _ = client
        data = json.loads(c.post("/api/ingest", json={"raw": "x"}).data)
        assert "sigs" in data and isinstance(data["sigs"], list)

    def test_ingest_missing_raw_returns_400(self, client):
        c, _ = client
        r = c.post("/api/ingest", json={})
        assert r.status_code == 400

    def test_ingest_increments_total(self, client):
        c, _ = client
        before = json.loads(c.get("/api/summary").data)["total_events"]
        c.post("/api/ingest", json={"raw": "test event"})
        after  = json.loads(c.get("/api/summary").data)["total_events"]
        assert after == before + 1

    def test_ingest_ssh_elevates_level(self, client):
        c, _ = client
        r = c.post("/api/ingest", json={"raw": "Failed password for root from 10.0.0.1 port 22"})
        data = json.loads(r.data)
        assert data["threat_level"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
        assert "SSH_BRUTE_FORCE" in data["sigs"]


# ---------------------------------------------------------------------------
# /api/ingest/email
# ---------------------------------------------------------------------------

class TestIngestEmailEndpoint:
    def test_email_ingest_valid_returns_201(self, client):
        c, _ = client
        raw = "From: x@y.com\nSubject: Hello\n\nHi there"
        r = c.post("/api/ingest/email", json={"raw": raw})
        assert r.status_code == 201

    def test_email_ingest_returns_threat_level(self, client):
        c, _ = client
        raw = "From: x@y.com\nSubject: Hello\n\nHi there"
        data = json.loads(c.post("/api/ingest/email", json={"raw": raw}).data)
        assert "threat_level" in data

    def test_email_ingest_missing_raw_returns_400(self, client):
        c, _ = client
        r = c.post("/api/ingest/email", json={})
        assert r.status_code == 400

    def test_email_ingest_increments_emails_scanned(self, client):
        c, _ = client
        before = json.loads(c.get("/api/summary").data)["emails_scanned"]
        c.post("/api/ingest/email", json={"raw": "From: x@y.com\nSubject: Hi\n\nBody"})
        after  = json.loads(c.get("/api/summary").data)["emails_scanned"]
        assert after == before + 1


# ---------------------------------------------------------------------------
# SSE stream
# ---------------------------------------------------------------------------

class TestSseStream:
    def test_stream_content_type(self, client):
        c, _ = client
        r = c.get("/api/stream")
        assert "text/event-stream" in r.content_type


# ---------------------------------------------------------------------------
# MetricsStore internals via app.store
# ---------------------------------------------------------------------------

class TestMetricsStore:
    def test_add_report_increments_total(self, client):
        c, app = client
        from sentinel_weave import EventAnalyzer, ThreatDetector
        analyzer = EventAnalyzer()
        detector = ThreatDetector()
        before = app.store.snapshot().total_events
        app.store.add_report(detector.analyze(analyzer.parse("test")))
        assert app.store.snapshot().total_events == before + 1

    def test_add_email_increments_emails(self, client):
        c, app = client
        from sentinel_weave.email_scanner import EmailScanner
        result = EmailScanner().scan_raw("From: a@b.com\nSubject: Hi\n\nBody")
        before = app.store.snapshot().emails_scanned
        app.store.add_email(result)
        assert app.store.snapshot().emails_scanned == before + 1

    def test_snapshot_levels_sum_to_total(self, client):
        c, app = client
        snap = app.store.snapshot()
        total = snap.benign + snap.low + snap.medium + snap.high + snap.critical
        assert total == snap.total_events

    def test_recent_reports_respects_limit(self, client):
        c, app = client
        from sentinel_weave import EventAnalyzer, ThreatDetector
        analyzer = EventAnalyzer(); detector = ThreatDetector()
        for _ in range(10):
            app.store.add_report(detector.analyze(analyzer.parse("event")))
        assert len(app.store.recent_reports(5)) <= 5

    def test_create_app_demo_mode_accepted(self):
        from dashboard.app import create_app
        app = create_app(demo_mode=True)
        app.config["TESTING"] = True
        # Just verify it starts without error; give the thread a tick to spin up
        import time; time.sleep(0.1)
        with app.test_client() as c:
            assert c.get("/health").status_code == 200
