"""
Threat Detector — SentinelWeave

Statistical and rule-based anomaly detection engine for security event
streams.  No external ML libraries are required; everything is implemented
with the Python standard library and basic statistics.

Optional integration with Azure Machine Learning endpoints is supported when
the ``azure-ai-ml`` SDK is installed and credentials are provided via
environment variables.

Architecture
------------
1. **Baseline builder** – accumulates a rolling window of feature vectors
   and computes per-feature mean / standard deviation.
2. **Z-score anomaly detector** – flags events whose features deviate
   significantly from the baseline.
3. **Threat classifier** – converts anomaly scores + signature matches into
   a final :class:`ThreatReport`.
4. **Azure ML hook** – optionally forwards feature vectors to an Azure ML
   real-time inference endpoint for model-backed classification.
"""

from __future__ import annotations

import math
import statistics
import os
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .event_analyzer import SecurityEvent


# ---------------------------------------------------------------------------
# Threat levels
# ---------------------------------------------------------------------------

class ThreatLevel(Enum):
    """Categorical threat severity."""
    BENIGN   = "BENIGN"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Output data structure
# ---------------------------------------------------------------------------

@dataclass
class ThreatReport:
    """
    Result of running the detector on a single :class:`SecurityEvent`.

    Attributes:
        event:          The original security event.
        threat_level:   Categorical severity.
        anomaly_score:  0.0–1.0 composite score (higher = more anomalous).
        z_scores:       Per-feature z-score list.
        explanation:    Human-readable list of contributing factors.
        azure_score:    Score returned by Azure ML endpoint (None if unused).
    """
    event: SecurityEvent
    threat_level: ThreatLevel = ThreatLevel.BENIGN
    anomaly_score: float = 0.0
    z_scores: list[float] = field(default_factory=list)
    explanation: list[str] = field(default_factory=list)
    azure_score: Optional[float] = None

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        sig_str = ", ".join(self.event.matched_sigs) if self.event.matched_sigs else "none"
        return (
            f"[{self.threat_level.value}] "
            f"score={self.anomaly_score:.3f} "
            f"sigs=[{sig_str}] "
            f"src={self.event.source_ip or 'n/a'} "
            f"type={self.event.event_type}"
        )


# ---------------------------------------------------------------------------
# Baseline statistics tracker
# ---------------------------------------------------------------------------

class FeatureBaseline:
    """
    Maintains running per-feature statistics (mean and std dev) using
    Welford's online algorithm.

    This allows the detector to adapt to the observed traffic baseline
    without keeping the entire history in memory.
    """

    def __init__(self, n_features: int = 13) -> None:
        self.n_features = n_features
        self._count = 0
        self._mean: list[float] = [0.0] * n_features
        self._M2:   list[float] = [0.0] * n_features   # Welford accumulator

    def update(self, features: list[float]) -> None:
        """Incorporate a new feature vector into the running statistics."""
        if len(features) != self.n_features:
            return
        self._count += 1
        for i, x in enumerate(features):
            delta = x - self._mean[i]
            self._mean[i] += delta / self._count
            delta2 = x - self._mean[i]
            self._M2[i] += delta * delta2

    @property
    def count(self) -> int:
        return self._count

    def means(self) -> list[float]:
        return list(self._mean)

    def stds(self) -> list[float]:
        if self._count < 2:
            return [1.0] * self.n_features
        return [math.sqrt(m2 / (self._count - 1)) or 1e-9 for m2 in self._M2]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class ThreatDetector:
    """
    Detects anomalous and malicious security events using a combination of:

    * **Z-score analysis** against a learned feature baseline.
    * **Signature-based rules** from the event analyzer.
    * **Severity thresholding** from keyword matching.
    * *(optional)* **Azure ML inference** for model-backed scoring.

    Parameters
    ----------
    z_threshold:
        Number of standard deviations from the baseline mean that triggers
        an anomaly flag (default 3.0).
    min_baseline_samples:
        Minimum number of events needed before z-score analysis is used
        (default 10).  Until then, only rule-based detection fires.
    azure_endpoint:
        URL of an Azure ML real-time inference endpoint.  If *None* (default)
        Azure ML integration is disabled.  The value can also be set via the
        ``SENTINELWEAVE_AZURE_ENDPOINT`` environment variable.
    azure_api_key:
        API key for the Azure ML endpoint.  Can also be set via the
        ``SENTINELWEAVE_AZURE_API_KEY`` environment variable.

    Example
    -------
    ::

        from sentinel_weave.event_analyzer import EventAnalyzer
        from sentinel_weave.threat_detector import ThreatDetector

        analyzer = EventAnalyzer()
        detector = ThreatDetector()

        # Feed some baseline events so the detector can learn normal traffic
        normal_lines = [...]
        for line in normal_lines:
            detector.update_baseline(analyzer.parse(line))

        # Now detect threats in new events
        suspicious = "Failed password for root from 10.0.0.5"
        event = analyzer.parse(suspicious)
        report = detector.analyze(event)
        print(report.summary())
    """

    def __init__(
        self,
        z_threshold: float = 3.0,
        min_baseline_samples: int = 10,
        azure_endpoint: Optional[str] = None,
        azure_api_key: Optional[str] = None,
    ) -> None:
        self.z_threshold = z_threshold
        self.min_baseline_samples = min_baseline_samples
        self.baseline = FeatureBaseline()

        # Azure ML endpoint (env vars take precedence over constructor args)
        self._endpoint = (
            azure_endpoint
            or os.environ.get("SENTINELWEAVE_AZURE_ENDPOINT")
        )
        self._api_key = (
            azure_api_key
            or os.environ.get("SENTINELWEAVE_AZURE_API_KEY")
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def update_baseline(self, event: SecurityEvent) -> None:
        """
        Add an event to the baseline statistics.

        Call this with *known-benign* events so the detector learns what
        normal traffic looks like.
        """
        if event.features:
            self.baseline.update(event.features)

    def analyze(self, event: SecurityEvent) -> ThreatReport:
        """
        Analyse a security event and return a :class:`ThreatReport`.

        Args:
            event: A parsed :class:`SecurityEvent`.

        Returns:
            :class:`ThreatReport` with threat level, anomaly score, and
            human-readable explanation.
        """
        report = ThreatReport(event=event)
        explanation: list[str] = []

        # 1. Signature-based contribution
        sig_score = min(1.0, len(event.matched_sigs) * 0.25)
        for sig in event.matched_sigs:
            explanation.append(f"Matched attack signature: {sig}")

        # 2. Keyword severity contribution
        kw_score = event.severity
        if kw_score > 0:
            explanation.append(f"Keyword severity score: {kw_score:.2f}")

        # 3. Z-score anomaly detection (only when baseline is warm)
        z_scores: list[float] = []
        zscore_score = 0.0
        if self.baseline.count >= self.min_baseline_samples and event.features:
            means = self.baseline.means()
            stds  = self.baseline.stds()
            z_scores = [
                abs((f - m) / s)
                for f, m, s in zip(event.features, means, stds)
            ]
            n_anomalous = sum(z > self.z_threshold for z in z_scores)
            if n_anomalous:
                zscore_score = min(1.0, n_anomalous / len(z_scores) * 2)
                explanation.append(
                    f"{n_anomalous}/{len(z_scores)} features exceed "
                    f"z-threshold ({self.z_threshold})"
                )

        report.z_scores = z_scores

        # 4. Optional Azure ML scoring
        azure_score: Optional[float] = None
        if self._endpoint and self._api_key and event.features:
            azure_score = self._query_azure_ml(event.features)
            if azure_score is not None:
                explanation.append(f"Azure ML model score: {azure_score:.3f}")

        report.azure_score = azure_score

        # 5. Composite score — weighted combination
        weights = {"sig": 0.40, "kw": 0.25, "zscore": 0.25, "azure": 0.10}
        composite = (
            weights["sig"]    * sig_score
            + weights["kw"]   * kw_score
            + weights["zscore"] * zscore_score
            + weights["azure"] * (azure_score if azure_score is not None else 0.0)
        )
        # If no Azure, redistribute its weight to the others proportionally
        if azure_score is None:
            composite = (
                0.45 * sig_score
                + 0.30 * kw_score
                + 0.25 * zscore_score
            )

        report.anomaly_score = round(min(1.0, composite), 4)
        report.threat_level  = self._score_to_level(report.anomaly_score, event)
        report.explanation   = explanation

        return report

    def analyze_bulk(self, events: list[SecurityEvent]) -> list[ThreatReport]:
        """Analyse a list of events, returning one report per event."""
        return [self.analyze(e) for e in events]

    def top_threats(
        self,
        reports: list[ThreatReport],
        n: int = 10,
    ) -> list[ThreatReport]:
        """Return the *n* highest-scored :class:`ThreatReport` objects."""
        return sorted(reports, key=lambda r: r.anomaly_score, reverse=True)[:n]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_level(score: float, event: SecurityEvent) -> ThreatLevel:
        """Map a composite score + event context to a :class:`ThreatLevel`."""
        # Signature matches always elevate to at least MEDIUM
        if event.matched_sigs and score < 0.30:
            score = 0.30
        if score >= 0.80:
            return ThreatLevel.CRITICAL
        if score >= 0.60:
            return ThreatLevel.HIGH
        if score >= 0.35:
            return ThreatLevel.MEDIUM
        if score >= 0.10:
            return ThreatLevel.LOW
        return ThreatLevel.BENIGN

    def _query_azure_ml(self, features: list[float]) -> Optional[float]:
        """
        Send a feature vector to an Azure ML real-time endpoint.

        The endpoint is expected to accept a JSON payload of the form::

            {"input": [[f1, f2, ..., f13]]}

        and return::

            {"score": 0.73}

        Returns *None* on any error so the pipeline degrades gracefully.
        """
        try:
            import json
            import urllib.request

            payload = json.dumps({"input": [features]}).encode()
            req = urllib.request.Request(
                self._endpoint,
                data=payload,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {self._api_key}",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
                body = json.loads(resp.read())
                return float(body.get("score", 0.0))
        except Exception:  # noqa: BLE001
            return None


# ---------------------------------------------------------------------------
# Convenience: batch statistics summary
# ---------------------------------------------------------------------------

def summarize_reports(reports: list[ThreatReport]) -> dict:
    """
    Produce a summary dict over a collection of threat reports.

    Returns a dict with keys:
      ``total``, ``by_level``, ``top_signatures``, ``mean_score``,
      ``max_score``, ``unique_ips``.
    """
    if not reports:
        return {}

    by_level: dict[str, int] = {lvl.value: 0 for lvl in ThreatLevel}
    sig_counts: dict[str, int] = {}
    ips: set[str] = set()
    scores: list[float] = []

    for r in reports:
        by_level[r.threat_level.value] += 1
        scores.append(r.anomaly_score)
        if r.event.source_ip:
            ips.add(r.event.source_ip)
        for sig in r.event.matched_sigs:
            sig_counts[sig] = sig_counts.get(sig, 0) + 1

    top_sigs = sorted(sig_counts.items(), key=lambda x: x[1], reverse=True)[:5]

    return {
        "total":          len(reports),
        "by_level":       by_level,
        "top_signatures": top_sigs,
        "mean_score":     round(statistics.mean(scores), 4),
        "max_score":      round(max(scores), 4),
        "unique_ips":     len(ips),
    }
