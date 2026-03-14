"""
Availability Monitor — SentinelWeave
Availability pillar of the CIA triad.

Provides three complementary mechanisms for **detecting and mitigating
availability attacks**:

1. **Token-bucket rate limiter** — per-subject flood protection.  Each
   subject gets a replenishing token bucket; requests that exhaust the
   bucket are denied with a ``retry_after_seconds`` hint.

2. **Sliding-window event-rate monitor** — tracks how many events per
   second originate from each subject over a configurable time window.
   When the rate exceeds a threshold an :class:`AvailabilityAlert` is
   emitted.  This complements the token-bucket by detecting *sustained*
   high-volume floods rather than short bursts.

3. **Service heartbeat tracker** — monitored services periodically call
   :meth:`AvailabilityMonitor.heartbeat`.  Calling
   :meth:`AvailabilityMonitor.check_services` returns alerts for any service
   whose last heartbeat is older than ``max_age_seconds``.

Why does this matter?
---------------------
A DDoS attack or a runaway log-generator can overwhelm a SIEM pipeline,
causing genuine threat alerts to be dropped — a classic availability failure.
By rate-limiting inbound events and monitoring service liveness, SentinelWeave
can shed load gracefully and alert operators before availability degrades.

Example
-------
::

    from sentinel_weave.availability_monitor import (
        TokenBucketRateLimiter,
        AvailabilityMonitor,
    )

    # Rate-limit inbound log events: 50 events/s, burst of 100
    limiter = TokenBucketRateLimiter(rate=50.0, burst=100.0)

    for event in inbound_stream:
        result = limiter.check(event.source_ip or "unknown")
        if not result.allowed:
            drop(event)
            continue
        process(event)

    # Monitor event rates in a 60-second sliding window
    monitor = AvailabilityMonitor(window_seconds=60.0, rate_threshold=200.0)
    monitor.heartbeat("threat-detector")

    alerts = monitor.check_services(max_age_seconds=30.0)
"""

from __future__ import annotations

import time as _time_module
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional


# ---------------------------------------------------------------------------
# Alert severity
# ---------------------------------------------------------------------------

class AlertSeverity(Enum):
    """Severity level of an :class:`AvailabilityAlert`."""
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class RateLimitResult:
    """
    Result of a single rate-limit check.

    Attributes:
        allowed:               ``True`` if the request was permitted.
        subject:               The subject (IP, user, service) checked.
        current_tokens:        Remaining token count after this check.
        retry_after_seconds:   Approximate wait time before the next allowed
                               request (0.0 when *allowed* is ``True``).
    """

    allowed:             bool
    subject:             str
    current_tokens:      float
    retry_after_seconds: float


@dataclass
class AvailabilityAlert:
    """
    An alert raised by the availability monitor.

    Attributes:
        subject:       Entity that triggered the alert (IP, service name, …).
        alert_type:    ``"RATE_EXCEEDED"``, ``"SERVICE_DOWN"``, or
                       ``"BURST_DETECTED"``.
        severity:      :class:`AlertSeverity` level.
        current_rate:  Observed event rate (events/second) at alert time.
        threshold:     The configured threshold that was crossed.
        message:       Human-readable description.
        raised_at:     Unix timestamp when the alert was raised.
    """

    subject:      str
    alert_type:   str
    severity:     AlertSeverity
    current_rate: float
    threshold:    float
    message:      str
    raised_at:    float = field(default_factory=_time_module.time)

    def summary(self) -> str:
        """Return a one-line human-readable summary."""
        return (
            f"[{self.severity.value}] {self.alert_type} "
            f"subject={self.subject!r} "
            f"rate={self.current_rate:.2f}/s "
            f"threshold={self.threshold:.2f}/s — {self.message}"
        )


# ---------------------------------------------------------------------------
# Token-bucket rate limiter
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """
    Per-subject token-bucket rate limiter.

    Each subject starts with *burst* tokens.  Tokens replenish at *rate*
    per second (continuous).  Each call to :meth:`check` consumes one token.
    When the bucket is empty the call is denied.

    Parameters
    ----------
    rate:
        Token replenishment rate (tokens per second).
    burst:
        Maximum bucket capacity (also the initial token count).
    clock:
        Zero-argument callable returning the current time in seconds since
        the epoch.  Defaults to :func:`time.time`.  Inject a fake clock in
        tests for deterministic behaviour.

    Example
    -------
    ::

        limiter = TokenBucketRateLimiter(rate=10.0, burst=20.0)
        result = limiter.check("192.168.1.5")
        if not result.allowed:
            print(f"Rate limited; retry in {result.retry_after_seconds:.1f}s")
    """

    def __init__(
        self,
        rate: float,
        burst: float,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if rate <= 0:
            raise ValueError(f"rate must be positive; got {rate}")
        if burst <= 0:
            raise ValueError(f"burst must be positive; got {burst}")
        self._rate  = rate
        self._burst = burst
        self._clock = clock or _time_module.time

        # subject → (tokens, last_refill_time)
        self._buckets: dict[str, tuple[float, float]] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, subject: str) -> RateLimitResult:
        """
        Consume one token for *subject* and return the result.

        Args:
            subject: Any string identifier (IP address, user name, …).

        Returns:
            :class:`RateLimitResult`.
        """
        now = self._clock()
        tokens, last_refill = self._buckets.get(subject, (self._burst, now))

        # Refill proportionally to elapsed time
        elapsed = now - last_refill
        tokens  = min(self._burst, tokens + elapsed * self._rate)

        if tokens >= 1.0:
            tokens -= 1.0
            self._buckets[subject] = (tokens, now)
            return RateLimitResult(
                allowed=True,
                subject=subject,
                current_tokens=tokens,
                retry_after_seconds=0.0,
            )

        # Denied — compute how long until at least one token is available
        self._buckets[subject] = (tokens, now)
        deficit = 1.0 - tokens
        retry_after = deficit / self._rate
        return RateLimitResult(
            allowed=False,
            subject=subject,
            current_tokens=tokens,
            retry_after_seconds=retry_after,
        )

    def reset(self, subject: str) -> None:
        """
        Reset *subject*'s bucket to the full burst capacity.

        Useful when an IP is unblocked after a manual review.

        Args:
            subject: The subject identifier to reset.
        """
        self._buckets.pop(subject, None)

    def bucket_state(self, subject: str) -> dict:
        """
        Return the current token count and last-refill time for *subject*.

        Returns an empty dict if the subject has no bucket yet.

        Args:
            subject: The subject identifier.

        Returns:
            Dict with keys ``tokens`` and ``last_refill``.
        """
        if subject not in self._buckets:
            return {}
        tokens, last_refill = self._buckets[subject]
        return {"tokens": tokens, "last_refill": last_refill}


# ---------------------------------------------------------------------------
# Availability / rate monitor
# ---------------------------------------------------------------------------

class AvailabilityMonitor:
    """
    Sliding-window event-rate monitor and service heartbeat tracker.

    Parameters
    ----------
    window_seconds:
        Duration of the sliding rate-measurement window (default: 60 s).
    rate_threshold:
        Events-per-second rate that triggers a ``RATE_EXCEEDED`` alert
        (default: 100.0).
    clock:
        Zero-argument callable returning the current time in seconds since
        the epoch.  Defaults to :func:`time.time`.

    Example
    -------
    ::

        monitor = AvailabilityMonitor(window_seconds=60.0, rate_threshold=50.0)

        for event in stream:
            alert = monitor.record_event(event.source_ip or "unknown")
            if alert:
                notify_soc(alert)

        monitor.heartbeat("threat-detector")
        down = monitor.check_services(max_age_seconds=30.0)
    """

    def __init__(
        self,
        window_seconds: float = 60.0,
        rate_threshold: float = 100.0,
        clock: Optional[Callable[[], float]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError(f"window_seconds must be positive; got {window_seconds}")
        if rate_threshold <= 0:
            raise ValueError(f"rate_threshold must be positive; got {rate_threshold}")
        self._window    = window_seconds
        self._threshold = rate_threshold
        self._clock     = clock or _time_module.time

        # subject → deque of (event_time, count) pairs
        self._windows: dict[str, deque[tuple[float, int]]] = defaultdict(deque)
        # service_name → last heartbeat time
        self._heartbeats: dict[str, float] = {}
        # Accumulated alerts
        self._alerts: list[AvailabilityAlert] = []

    # ------------------------------------------------------------------
    # Event rate monitoring
    # ------------------------------------------------------------------

    def record_event(self, subject: str, count: int = 1) -> Optional[AvailabilityAlert]:
        """
        Record *count* events for *subject* and check if the rate threshold
        is exceeded.

        Args:
            subject: Identifier for the event source (IP, user, …).
            count:   Number of events to record (default: 1).

        Returns:
            An :class:`AvailabilityAlert` if the rate threshold is exceeded,
            otherwise ``None``.
        """
        now = self._clock()
        dq  = self._windows[subject]

        # Append this batch
        dq.append((now, count))

        # Evict entries outside the window
        cutoff = now - self._window
        while dq and dq[0][0] < cutoff:
            dq.popleft()

        # Compute current rate
        total  = sum(c for _, c in dq)
        rate   = total / self._window

        if rate > self._threshold:
            severity = self._rate_severity(rate)
            alert = AvailabilityAlert(
                subject      = subject,
                alert_type   = "RATE_EXCEEDED",
                severity     = severity,
                current_rate = round(rate, 4),
                threshold    = self._threshold,
                message      = (
                    f"Subject {subject!r} is sending {rate:.1f} events/s "
                    f"(threshold: {self._threshold:.1f}/s)."
                ),
                raised_at    = now,
            )
            self._alerts.append(alert)
            return alert

        return None

    def get_current_rate(self, subject: str) -> float:
        """
        Return the current event rate (events/second) for *subject* over
        the configured sliding window.

        Args:
            subject: The subject identifier.

        Returns:
            Rate in events/second (0.0 if no events recorded).
        """
        now    = self._clock()
        dq     = self._windows.get(subject)
        if not dq:
            return 0.0
        cutoff = now - self._window
        total  = sum(c for t, c in dq if t >= cutoff)
        return total / self._window

    # ------------------------------------------------------------------
    # Service heartbeat tracking
    # ------------------------------------------------------------------

    def heartbeat(self, service_name: str) -> None:
        """
        Register a liveness heartbeat for *service_name*.

        Services should call this method periodically.  If they fail to
        do so within ``max_age_seconds`` they are flagged as ``SERVICE_DOWN``.

        Args:
            service_name: Unique identifier for the monitored service.
        """
        self._heartbeats[service_name] = self._clock()

    def check_services(
        self,
        max_age_seconds: float = 60.0,
    ) -> list[AvailabilityAlert]:
        """
        Return alerts for services whose last heartbeat is stale.

        Args:
            max_age_seconds: Maximum acceptable age of a heartbeat.

        Returns:
            List of :class:`AvailabilityAlert` objects (one per stale service).
        """
        if max_age_seconds <= 0:
            raise ValueError(
                f"max_age_seconds must be positive; got {max_age_seconds}"
            )
        now     = self._clock()
        alerts: list[AvailabilityAlert] = []
        for svc, last in self._heartbeats.items():
            age = now - last
            if age > max_age_seconds:
                severity = AlertSeverity.CRITICAL if age > max_age_seconds * 3 else AlertSeverity.HIGH
                alert = AvailabilityAlert(
                    subject      = svc,
                    alert_type   = "SERVICE_DOWN",
                    severity     = severity,
                    current_rate = 0.0,
                    threshold    = max_age_seconds,
                    message      = (
                        f"Service {svc!r} last heartbeat was {age:.1f}s ago "
                        f"(max allowed: {max_age_seconds:.1f}s)."
                    ),
                    raised_at    = now,
                )
                self._alerts.append(alert)
                alerts.append(alert)
        return alerts

    def registered_services(self) -> list[str]:
        """
        Return the names of all services that have ever sent a heartbeat.

        Returns:
            Sorted list of service name strings.
        """
        return sorted(self._heartbeats)

    # ------------------------------------------------------------------
    # Alert access
    # ------------------------------------------------------------------

    def flush_alerts(self) -> list[AvailabilityAlert]:
        """
        Return and clear all accumulated :class:`AvailabilityAlert` objects.

        Returns:
            List of alerts since the last flush.
        """
        alerts = list(self._alerts)
        self._alerts.clear()
        return alerts

    def get_alerts(self) -> list[AvailabilityAlert]:
        """
        Return all accumulated :class:`AvailabilityAlert` objects without
        clearing them.

        Returns:
            List of all alerts raised so far.
        """
        return list(self._alerts)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _rate_severity(self, rate: float) -> AlertSeverity:
        """Map a rate value to an :class:`AlertSeverity` level."""
        ratio = rate / self._threshold
        if ratio >= 5.0:
            return AlertSeverity.CRITICAL
        if ratio >= 2.0:
            return AlertSeverity.HIGH
        if ratio >= 1.5:
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW
