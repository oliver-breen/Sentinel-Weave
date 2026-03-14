"""
Threat Correlator — SentinelWeave

Detects coordinated *attack campaigns* by correlating :class:`ThreatReport`
objects across configurable time windows and source IP addresses.

Real-world Security Operations Centres (SOCs) call this process *event
correlation* or *alert enrichment*.  Rather than treating each anomalous log
line in isolation, the correlator asks: "Is this IP driving a sustained
attack?  Which phase of the kill-chain have they reached?"

Architecture
------------
1. **Time-windowed bucketing** — reports are grouped into fixed-width time
   buckets (default 5 minutes).  All reports from the same source IP within
   the same bucket are candidates for a single campaign.
2. **Campaign builder** — contiguous / overlapping buckets from the same IP
   are merged into an :class:`AttackCampaign`.
3. **Kill-chain classifier** — the unique set of attack signatures determines
   which MITRE ATT&CK-inspired kill-chain phase the campaign has reached.
4. **Severity escalation** — campaigns with many events *or* many distinct
   attack types are escalated above the maximum single-event threat level.

Learning value
--------------
* Mirrors real SIEM correlation rule engines (Splunk, Microsoft Sentinel,
  Elastic SIEM).
* Demonstrates Python data-modelling, defaultdict grouping, and sliding
  window algorithms.
* The kill-chain mapping directly corresponds to MITRE ATT&CK tactics,
  giving practical threat-intelligence context.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

from .threat_detector import ThreatReport, ThreatLevel


# ---------------------------------------------------------------------------
# Kill-chain phase mapping  (MITRE ATT&CK-inspired)
# ---------------------------------------------------------------------------

_SIG_TO_PHASE: dict[str, str] = {
    "PORT_SCAN":            "RECONNAISSANCE",
    "SSH_BRUTE_FORCE":      "INITIAL_ACCESS",
    "SQL_INJECTION":        "EXPLOITATION",
    "XSS_ATTEMPT":          "EXPLOITATION",
    "PATH_TRAVERSAL":       "EXPLOITATION",
    "COMMAND_INJECTION":    "EXECUTION",
    "PRIVILEGE_ESCALATION": "PRIVILEGE_ESCALATION",
    "CREDENTIAL_DUMP":      "CREDENTIAL_ACCESS",
    "MALWARE_INDICATOR":    "PERSISTENCE",
    "DDoS_INDICATOR":       "IMPACT",
}

# Phases ordered from earliest to most advanced in the kill-chain
_PHASE_ORDER: list[str] = [
    "RECONNAISSANCE",
    "INITIAL_ACCESS",
    "EXPLOITATION",
    "EXECUTION",
    "PRIVILEGE_ESCALATION",
    "CREDENTIAL_ACCESS",
    "PERSISTENCE",
    "IMPACT",
]


# ---------------------------------------------------------------------------
# Data structure
# ---------------------------------------------------------------------------

@dataclass
class AttackCampaign:
    """
    A correlated sequence of threat events originating from one source IP.

    Attributes:
        attacker_ip:      Source IP address driving the campaign.
        first_seen:       Timestamp of the earliest event (``None`` if absent).
        last_seen:        Timestamp of the most recent event (``None`` if absent).
        event_count:      Total number of :class:`ThreatReport` objects in the campaign.
        signatures:       Deduplicated, order-preserving list of matched attack
                          signature names seen across all events.
        peak_score:       Highest anomaly score (0.0–1.0) observed.
        campaign_type:    High-level category string (e.g. ``"BRUTE_FORCE"``,
                          ``"MULTI_VECTOR"``).
        kill_chain_phase: Most advanced MITRE kill-chain phase reached.
        severity:         Escalated :class:`ThreatLevel` for the whole campaign.
        reports:          All contributing :class:`ThreatReport` instances
                          (excluded from ``repr`` to keep output readable).
    """

    attacker_ip: str
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    event_count: int
    signatures: list[str]
    peak_score: float
    campaign_type: str
    kill_chain_phase: str
    severity: ThreatLevel
    reports: list[ThreatReport] = field(default_factory=list, repr=False)

    @property
    def duration_seconds(self) -> Optional[float]:
        """Total campaign duration in seconds (``None`` if timestamps absent)."""
        if self.first_seen and self.last_seen:
            return (self.last_seen - self.first_seen).total_seconds()
        return None

    def summary(self) -> str:
        """Return a one-line human-readable campaign summary."""
        dur = f"{self.duration_seconds:.0f}s" if self.duration_seconds is not None else "n/a"
        sigs = ", ".join(self.signatures[:3]) + ("…" if len(self.signatures) > 3 else "")
        return (
            f"[{self.severity.value}] {self.attacker_ip} "
            f"| {self.event_count} events | {dur} | "
            f"{self.kill_chain_phase} | sigs=[{sigs}]"
        )


# ---------------------------------------------------------------------------
# Correlator
# ---------------------------------------------------------------------------

class ThreatCorrelator:
    """
    Correlates :class:`ThreatReport` objects into :class:`AttackCampaign`
    instances using time-windowed, per-IP grouping.

    Parameters
    ----------
    time_window_seconds:
        Width of each time bucket in seconds.  Reports from the same IP
        within the same bucket are treated as one campaign.  Default: 300
        (5 minutes).
    min_events:
        Minimum number of qualifying threat events from one IP in a single
        window before they are elevated to a campaign.  Default: 2.
    min_score:
        Minimum anomaly score for a report to qualify for campaign
        correlation.  Events below this score are counted for statistics
        but do not trigger campaigns.  Default: 0.05.

    Example
    -------
    ::

        from sentinel_weave import EventAnalyzer, ThreatDetector
        from sentinel_weave.threat_correlator import ThreatCorrelator

        analyzer   = EventAnalyzer()
        detector   = ThreatDetector()
        correlator = ThreatCorrelator()

        for line in open("/var/log/auth.log"):
            event  = analyzer.parse(line)
            report = detector.analyze(event)
            correlator.add_report(report)

        for campaign in correlator.get_campaigns():
            print(campaign.summary())
    """

    def __init__(
        self,
        time_window_seconds: int = 300,
        min_events: int = 2,
        min_score: float = 0.05,
    ) -> None:
        self.time_window_seconds = time_window_seconds
        self.min_events          = min_events
        self.min_score           = min_score

        # ip → list of qualifying reports
        self._reports: dict[str, list[ThreatReport]] = defaultdict(list)
        # ip → total event count (regardless of score) for stats
        self._total_counts: dict[str, int] = defaultdict(int)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_report(self, report: ThreatReport) -> None:
        """
        Add a :class:`ThreatReport` to the correlator.

        Only reports that include a source IP are eligible for campaign
        detection.  All reports are counted for the top-attacker statistics.

        Args:
            report: A scored threat report produced by :class:`ThreatDetector`.
        """
        ip = report.event.source_ip
        if ip:
            self._total_counts[ip] += 1
            if report.anomaly_score >= self.min_score:
                self._reports[ip].append(report)

    def add_reports(self, reports: list[ThreatReport]) -> None:
        """Add multiple :class:`ThreatReport` objects in bulk."""
        for r in reports:
            self.add_report(r)

    def get_campaigns(self) -> list[AttackCampaign]:
        """
        Compute and return all detected attack campaigns.

        Returns:
            List of :class:`AttackCampaign` objects sorted by severity
            (most severe first), then by event count (descending).
        """
        campaigns: list[AttackCampaign] = []
        for ip, reports in self._reports.items():
            campaigns.extend(self._build_campaigns(ip, reports))

        level_rank = {lvl: i for i, lvl in enumerate(ThreatLevel)}
        campaigns.sort(
            key=lambda c: (level_rank.get(c.severity, 0), c.event_count),
            reverse=True,
        )
        return campaigns

    def get_top_attackers(self, n: int = 10) -> list[tuple[str, int]]:
        """
        Return the top-*n* source IPs sorted by total event count.

        Args:
            n: Maximum number of results to return.

        Returns:
            List of ``(ip_address, event_count)`` tuples, descending order.
        """
        return sorted(
            self._total_counts.items(), key=lambda x: x[1], reverse=True
        )[:n]

    def summary_stats(self) -> dict:
        """
        Return aggregate statistics across all ingested reports.

        Returns:
            Dict with keys: ``unique_ips``, ``total_reports``,
            ``campaign_count``, ``top_campaign_severity``,
            ``most_common_phase``.
        """
        campaigns = self.get_campaigns()
        total     = sum(self._total_counts.values())
        top_sev   = campaigns[0].severity.value if campaigns else "NONE"

        phase_counts: dict[str, int] = defaultdict(int)
        for c in campaigns:
            phase_counts[c.kill_chain_phase] += 1

        most_common = (
            max(phase_counts, key=lambda p: phase_counts[p])
            if phase_counts else "NONE"
        )
        return {
            "unique_ips":            len(self._total_counts),
            "total_reports":         total,
            "campaign_count":        len(campaigns),
            "top_campaign_severity": top_sev,
            "most_common_phase":     most_common,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_campaigns(
        self, ip: str, reports: list[ThreatReport]
    ) -> list[AttackCampaign]:
        """Split an IP's reports into time-windowed campaigns."""
        if not reports:
            return []

        def _ts_key(r: ThreatReport) -> float:
            ts = r.event.timestamp
            return ts.timestamp() if ts else float("inf")

        sorted_reports = sorted(reports, key=_ts_key)

        # Separate timestamped and non-timestamped reports
        timestamped:    list[ThreatReport] = [r for r in sorted_reports if r.event.timestamp]
        no_timestamp:   list[ThreatReport] = [r for r in sorted_reports if not r.event.timestamp]

        buckets: list[list[ThreatReport]] = []
        current: list[ThreatReport] = []
        bucket_start: float | None = None

        for r in timestamped:
            t = r.event.timestamp.timestamp()  # guaranteed non-None here
            if bucket_start is None:
                bucket_start = t
                current = [r]
            elif t - bucket_start <= self.time_window_seconds:
                current.append(r)
            else:
                if current:
                    buckets.append(current)
                current      = [r]
                bucket_start = t

        if current:
            buckets.append(current)

        # All no-timestamp reports share a single "unknown-time" bucket
        if no_timestamp:
            buckets.append(no_timestamp)

        return [
            self._make_campaign(ip, bucket)
            for bucket in buckets
            if len(bucket) >= self.min_events
        ]

    def _make_campaign(
        self, ip: str, reports: list[ThreatReport]
    ) -> AttackCampaign:
        """Synthesise an :class:`AttackCampaign` from a bucket of reports."""
        timestamps = [r.event.timestamp for r in reports if r.event.timestamp]
        first_seen = min(timestamps) if timestamps else None
        last_seen  = max(timestamps) if timestamps else None

        all_sigs: list[str] = []
        for r in reports:
            all_sigs.extend(r.event.matched_sigs)
        unique_sigs = list(dict.fromkeys(all_sigs))  # preserve order

        peak_score = max(r.anomaly_score for r in reports)

        campaign_type    = self._classify_campaign_type(unique_sigs, reports)
        kill_chain_phase = self._detect_kill_chain_phase(unique_sigs)
        severity         = self._escalate_severity(reports, unique_sigs)

        return AttackCampaign(
            attacker_ip      = ip,
            first_seen       = first_seen,
            last_seen        = last_seen,
            event_count      = len(reports),
            signatures       = unique_sigs,
            peak_score       = round(peak_score, 4),
            campaign_type    = campaign_type,
            kill_chain_phase = kill_chain_phase,
            severity         = severity,
            reports          = reports,
        )

    @staticmethod
    def _classify_campaign_type(
        sigs: list[str], reports: list[ThreatReport]
    ) -> str:
        """Return a high-level campaign type string."""
        sig_set = set(sigs)
        if len(sig_set) >= 4:
            return "MULTI_VECTOR"
        if "SSH_BRUTE_FORCE" in sig_set and len(sig_set) == 1:
            return "BRUTE_FORCE"
        if "PORT_SCAN" in sig_set:
            return "RECONNAISSANCE"
        if sig_set & {"SQL_INJECTION", "XSS_ATTEMPT", "PATH_TRAVERSAL", "COMMAND_INJECTION"}:
            return "WEB_ATTACK"
        if "PRIVILEGE_ESCALATION" in sig_set or "CREDENTIAL_DUMP" in sig_set:
            return "ESCALATION"
        if "MALWARE_INDICATOR" in sig_set:
            return "MALWARE"
        if "DDoS_INDICATOR" in sig_set:
            return "DDOS"
        if reports and max(r.anomaly_score for r in reports) > 0.3:
            return "ANOMALOUS"
        return "SUSPICIOUS"

    @staticmethod
    def _detect_kill_chain_phase(sigs: list[str]) -> str:
        """Return the most advanced kill-chain phase represented in *sigs*."""
        phases = [_SIG_TO_PHASE[s] for s in sigs if s in _SIG_TO_PHASE]
        if not phases:
            return "UNKNOWN"
        return max(
            phases,
            key=lambda p: _PHASE_ORDER.index(p) if p in _PHASE_ORDER else -1,
        )

    @staticmethod
    def _escalate_severity(
        reports: list[ThreatReport], sigs: list[str]
    ) -> ThreatLevel:
        """
        Campaign-level severity escalation.

        A campaign with 4+ events *or* 4+ distinct attack types is escalated
        one level above the worst single-event threat level (capped at
        ``CRITICAL``).
        """
        order = list(ThreatLevel)
        base_idx = max(order.index(r.threat_level) for r in reports)

        escalation = 0
        if len(reports) >= 4:
            escalation += 1
        if len(set(sigs)) >= 4:
            escalation += 1

        new_idx = min(len(order) - 1, base_idx + escalation)
        return order[new_idx]
