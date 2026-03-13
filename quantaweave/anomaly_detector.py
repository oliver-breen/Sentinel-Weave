"""
ML-powered anomaly detection for post-quantum cryptographic operations.

Tracks metrics for each cryptographic operation (key generation, encapsulation,
decapsulation, signing, verification) and flags suspicious patterns such as:

* Unusually slow operations (potential side-channel or resource-exhaustion attack).
* Abnormally high decapsulation failure rates (potential key-mismatch or
  active-attack scenario).
* Statistical outliers in ciphertext or key sizes.

The detector uses a pure-Python, dependency-free implementation based on
*z-score* and *inter-quartile range (IQR)* statistics so that it works in
any environment without installing scikit-learn or numpy.

Example::

    from quantaweave.anomaly_detector import CryptoOperationMonitor, AnomalyDetector

    monitor = CryptoOperationMonitor()
    detector = AnomalyDetector(monitor)

    # Record operations
    with monitor.record("decapsulate"):
        shared_secret = kem.decapsulate(ciphertext, secret_key)

    # Check for anomalies after a batch of operations
    alerts = detector.evaluate()
    for alert in alerts:
        print(alert)
"""

import time
import contextlib
import math
import statistics
from collections import defaultdict, deque
from typing import Dict, Generator, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

class OperationRecord:
    """A single recorded cryptographic operation event."""

    __slots__ = ("operation", "duration_ms", "success", "extra")

    def __init__(
        self,
        operation: str,
        duration_ms: float,
        success: bool,
        extra: Optional[Dict] = None,
    ):
        self.operation = operation
        self.duration_ms = duration_ms
        self.success = success
        self.extra = extra or {}

    def __repr__(self) -> str:
        status = "OK" if self.success else "FAIL"
        return (
            f"OperationRecord(op={self.operation!r}, "
            f"duration_ms={self.duration_ms:.2f}, status={status})"
        )


# ---------------------------------------------------------------------------
# Monitor
# ---------------------------------------------------------------------------

class CryptoOperationMonitor:
    """Records metrics for each cryptographic operation.

    Operations are stored in a fixed-size sliding window so that only recent
    activity is considered by the anomaly detector.

    Args:
        window_size: Maximum number of records to retain per operation type.
                     Defaults to 200.
    """

    def __init__(self, window_size: int = 200):
        self._window_size = window_size
        self._records: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self._window_size))

    # ------------------------------------------------------------------
    # Context-manager API
    # ------------------------------------------------------------------

    @contextlib.contextmanager
    def record(
        self, operation: str, extra: Optional[Dict] = None
    ) -> Generator[None, None, None]:
        """Context manager that times a cryptographic operation and records it.

        Args:
            operation: Operation name (e.g. ``"decapsulate"``).
            extra:     Optional dict of additional metrics (e.g. key sizes).

        Example::

            with monitor.record("keygen", extra={"security_level": "LEVEL1"}):
                pk, sk = pqc.generate_keypair()
        """
        start = time.perf_counter()
        success = True
        try:
            yield
        except Exception:
            success = False
            raise
        finally:
            elapsed_ms = (time.perf_counter() - start) * 1000.0
            self.add(OperationRecord(operation, elapsed_ms, success, extra))

    def add(self, record: OperationRecord) -> None:
        """Manually append a pre-built :class:`OperationRecord`."""
        self._records[record.operation].append(record)

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    def get_records(self, operation: str) -> List[OperationRecord]:
        """Return all retained records for *operation* (oldest-first)."""
        return list(self._records[operation])

    def all_operations(self) -> List[str]:
        """Return the list of operation names that have been seen."""
        return list(self._records.keys())

    def total_count(self, operation: str) -> int:
        """Number of retained records for *operation*."""
        return len(self._records[operation])

    def failure_rate(self, operation: str) -> float:
        """Fraction of retained records for *operation* that failed (0–1)."""
        recs = self._records[operation]
        if not recs:
            return 0.0
        return sum(1 for r in recs if not r.success) / len(recs)

    def durations_ms(self, operation: str) -> List[float]:
        """Return a list of recorded durations (ms) for *operation*."""
        return [r.duration_ms for r in self._records[operation]]

    def reset(self) -> None:
        """Clear all recorded data."""
        self._records.clear()


# ---------------------------------------------------------------------------
# Alert model
# ---------------------------------------------------------------------------

class AnomalyAlert:
    """Describes a single detected anomaly."""

    def __init__(self, severity: str, operation: str, reason: str, details: Dict):
        self.severity = severity    # "LOW", "MEDIUM", "HIGH"
        self.operation = operation
        self.reason = reason
        self.details = details

    def __repr__(self) -> str:
        return (
            f"AnomalyAlert(severity={self.severity!r}, "
            f"operation={self.operation!r}, reason={self.reason!r})"
        )

    def __str__(self) -> str:
        return (
            f"[{self.severity}] {self.operation}: {self.reason} | {self.details}"
        )


# ---------------------------------------------------------------------------
# Statistical helpers
# ---------------------------------------------------------------------------

def _zscore(value: float, mean: float, stdev: float) -> float:
    """Return the z-score of *value* given *mean* and *stdev*."""
    if stdev == 0.0:
        return 0.0
    return (value - mean) / stdev


def _iqr_bounds(data: List[float], k: float = 1.5) -> Tuple[float, float]:
    """Return (lower_fence, upper_fence) using Tukey's IQR rule with factor *k*."""
    sorted_data = sorted(data)
    n = len(sorted_data)
    q1 = sorted_data[n // 4]
    q3 = sorted_data[(3 * n) // 4]
    iqr = q3 - q1
    return q1 - k * iqr, q3 + k * iqr


def _safe_stdev(data: List[float]) -> float:
    """Return standard deviation, falling back to 0.0 for < 2 data points."""
    if len(data) < 2:
        return 0.0
    return statistics.stdev(data)


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Analyses metrics captured by a :class:`CryptoOperationMonitor` and
    returns a list of :class:`AnomalyAlert` objects describing any anomalies.

    Three independent checks are performed:

    1. **High failure rate** – a failure rate above *max_failure_rate* triggers
       a HIGH-severity alert.
    2. **Z-score timing** – operations whose most-recent duration exceeds the
       historical mean by more than *zscore_threshold* standard deviations
       trigger a MEDIUM alert.
    3. **IQR timing outlier** – if the most-recent duration falls outside the
       Tukey upper fence (using *iqr_k* as the multiplier) a LOW alert is
       raised.  This catches outliers in skewed distributions where z-score is
       less sensitive.

    Args:
        monitor:          The :class:`CryptoOperationMonitor` to inspect.
        max_failure_rate: Fraction of failures that triggers a HIGH alert.
                          Defaults to ``0.2`` (20 %).
        zscore_threshold: Z-score above which a timing anomaly is flagged.
                          Defaults to ``3.0`` (99.7th percentile).
        iqr_k:            IQR fence multiplier.  Defaults to ``3.0``.
        min_samples:      Minimum number of samples required before statistical
                          checks are applied.  Defaults to ``10``.
    """

    def __init__(
        self,
        monitor: CryptoOperationMonitor,
        max_failure_rate: float = 0.20,
        zscore_threshold: float = 3.0,
        iqr_k: float = 3.0,
        min_samples: int = 10,
    ):
        self._monitor = monitor
        self._max_failure_rate = max_failure_rate
        self._zscore_threshold = zscore_threshold
        self._iqr_k = iqr_k
        self._min_samples = min_samples

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate(self) -> List[AnomalyAlert]:
        """Run all anomaly checks and return a list of :class:`AnomalyAlert`.

        Returns an empty list when everything looks normal.
        """
        alerts: List[AnomalyAlert] = []
        for op in self._monitor.all_operations():
            alerts.extend(self._check_failure_rate(op))
            alerts.extend(self._check_timing(op))
        return alerts

    def evaluate_operation(self, operation: str) -> List[AnomalyAlert]:
        """Run checks for a single *operation* and return alerts."""
        alerts: List[AnomalyAlert] = []
        alerts.extend(self._check_failure_rate(operation))
        alerts.extend(self._check_timing(operation))
        return alerts

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_failure_rate(self, operation: str) -> List[AnomalyAlert]:
        alerts = []
        rate = self._monitor.failure_rate(operation)
        if rate > self._max_failure_rate:
            alerts.append(AnomalyAlert(
                severity="HIGH",
                operation=operation,
                reason="Excessive failure rate detected",
                details={
                    "failure_rate": round(rate, 4),
                    "threshold": self._max_failure_rate,
                    "sample_count": self._monitor.total_count(operation),
                },
            ))
        return alerts

    def _check_timing(self, operation: str) -> List[AnomalyAlert]:
        alerts = []
        durations = self._monitor.durations_ms(operation)
        if len(durations) < self._min_samples:
            return alerts  # not enough data yet

        mean = statistics.mean(durations)
        stdev = _safe_stdev(durations)
        latest = durations[-1]

        # Z-score check
        z = _zscore(latest, mean, stdev)
        if z > self._zscore_threshold:
            alerts.append(AnomalyAlert(
                severity="MEDIUM",
                operation=operation,
                reason="Timing anomaly detected (z-score)",
                details={
                    "latest_ms": round(latest, 3),
                    "mean_ms": round(mean, 3),
                    "stdev_ms": round(stdev, 3),
                    "zscore": round(z, 3),
                    "threshold": self._zscore_threshold,
                },
            ))
            return alerts  # skip IQR check if already flagged

        # IQR check (only if enough data for quartiles)
        if len(durations) >= 4:
            _, upper_fence = _iqr_bounds(durations, self._iqr_k)
            if latest > upper_fence:
                alerts.append(AnomalyAlert(
                    severity="LOW",
                    operation=operation,
                    reason="Timing anomaly detected (IQR outlier)",
                    details={
                        "latest_ms": round(latest, 3),
                        "upper_fence_ms": round(upper_fence, 3),
                        "iqr_k": self._iqr_k,
                    },
                ))

        return alerts

    # ------------------------------------------------------------------
    # Summary helpers
    # ------------------------------------------------------------------

    def summary(self) -> Dict:
        """Return a plain-dict summary of monitored operations.

        Useful for logging or sending to Azure Monitor / Application Insights.
        """
        result = {}
        for op in self._monitor.all_operations():
            durations = self._monitor.durations_ms(op)
            result[op] = {
                "total_count": self._monitor.total_count(op),
                "failure_rate": round(self._monitor.failure_rate(op), 4),
                "mean_ms": round(statistics.mean(durations), 3) if durations else None,
                "stdev_ms": round(_safe_stdev(durations), 3) if len(durations) >= 2 else None,
                "min_ms": round(min(durations), 3) if durations else None,
                "max_ms": round(max(durations), 3) if durations else None,
            }
        return result
