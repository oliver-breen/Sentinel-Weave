"""
Integrity Monitor — SentinelWeave
Integrity pillar of the CIA triad.

Provides two complementary mechanisms for **detecting data tampering**:

1. **Event signing** — HMAC-SHA256 signatures for individual
   :class:`~sentinel_weave.event_analyzer.SecurityEvent` objects.  Any
   mutation of the event's meaningful fields (raw text, source IP, event
   type, severity, matched signatures) will invalidate the signature.

2. **Append-only audit chain** — a Merkle-inspired linked-hash chain where
   every audit entry includes the hash of its predecessor.  This makes
   retroactive insertion or modification of entries detectable by a single
   pass of :meth:`IntegrityMonitor.verify_chain`.

Why does this matter?
---------------------
Adversaries who gain write access to log stores routinely delete or alter
evidence of their activity ("log wiping").  By signing events at ingestion
time and chaining audit entries, SentinelWeave makes such tampering
*detectable* — a core requirement of the Integrity pillar of the CIA triad.

Example
-------
::

    from sentinel_weave.integrity_monitor import IntegrityMonitor

    monitor = IntegrityMonitor()

    # Sign a security event at parse time
    sig = monitor.sign_event(event)
    assert monitor.verify_event(event, sig)

    # Build an audit chain of analyst actions
    monitor.append_to_chain({"action": "opened_report", "report_id": "report-001.bin"},
                            subject="alice")
    monitor.append_to_chain({"action": "acknowledged_threat", "report_id": "report-001.bin"},
                            subject="alice")

    result = monitor.verify_chain()
    print(result.valid, result.length)   # True  2
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from typing import Callable, Optional

from .event_analyzer import SecurityEvent


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AuditEntry:
    """
    A single entry in the tamper-evident audit chain.

    Attributes:
        index:      Zero-based position in the chain.
        timestamp:  ISO-8601 UTC string recorded at insertion time.
        subject:    Identifier of the entity that triggered the audit event.
        data:       Arbitrary JSON-serialisable metadata dict.
        prev_hash:  ``entry_hash`` of the immediately preceding entry
                    (or ``"0" * 64`` for the genesis entry).
        entry_hash: HMAC-SHA256 of the concatenated canonical representation
                    of all other fields.  Verifying this hash detects any
                    in-place mutation of the entry.
    """

    index:      int
    timestamp:  str
    subject:    str
    data:       dict
    prev_hash:  str
    entry_hash: str

    def to_dict(self) -> dict:
        """Return a JSON-serialisable representation."""
        return {
            "index":      self.index,
            "timestamp":  self.timestamp,
            "subject":    self.subject,
            "data":       self.data,
            "prev_hash":  self.prev_hash,
            "entry_hash": self.entry_hash,
        }


@dataclass
class ChainVerificationResult:
    """
    Result of a full audit-chain integrity check.

    Attributes:
        valid:      ``True`` if every entry's HMAC and predecessor link are
                    intact; ``False`` otherwise.
        length:     Total number of entries examined.
        broken_at:  Index of the first broken entry, or ``None`` if valid.
        reason:     Human-readable description of the result.
    """

    valid:      bool
    length:     int
    broken_at:  Optional[int]
    reason:     str


# ---------------------------------------------------------------------------
# Genesis hash constant
# ---------------------------------------------------------------------------

_GENESIS_PREV_HASH = "0" * 64


# ---------------------------------------------------------------------------
# IntegrityMonitor
# ---------------------------------------------------------------------------

class IntegrityMonitor:
    """
    Signs security events and maintains a tamper-evident audit chain.

    Parameters
    ----------
    secret_key:
        32-byte HMAC key.  If *None*, a random key is generated at
        construction time.  For cross-session verification supply a stable
        key; for single-session use the random default is fine.
    clock:
        Zero-argument callable returning an ISO-8601 UTC timestamp string.
        Defaults to the system clock.  Override in tests to get deterministic
        timestamps.

    Notes
    -----
    All HMAC operations use SHA-256, which is available in Python's standard
    library ``hashlib`` / ``hmac`` modules (no external dependencies).
    """

    def __init__(
        self,
        secret_key: Optional[bytes] = None,
        clock: Optional[Callable[[], str]] = None,
    ) -> None:
        self._key: bytes = secret_key if secret_key is not None else os.urandom(32)
        self._clock: Callable[[], str] = clock or _utc_now
        self._chain: list[AuditEntry] = []

    # ------------------------------------------------------------------
    # Event signing
    # ------------------------------------------------------------------

    def sign_event(self, event: SecurityEvent) -> str:
        """
        Compute an HMAC-SHA256 signature for a :class:`SecurityEvent`.

        Only the semantically meaningful fields are included in the signature
        (``raw``, ``source_ip``, ``event_type``, ``severity``,
        ``matched_sigs``).  Derived fields such as ``features`` and
        ``metadata`` are excluded to avoid spurious signature failures caused
        by floating-point precision.

        Args:
            event: A parsed :class:`SecurityEvent`.

        Returns:
            Lower-case hex HMAC-SHA256 string (64 characters).
        """
        canonical = _canonical_event(event)
        return _hmac_hex(self._key, canonical)

    def verify_event(self, event: SecurityEvent, signature: str) -> bool:
        """
        Verify that *signature* matches the current state of *event*.

        Args:
            event:     :class:`SecurityEvent` to verify.
            signature: Hex string returned by :meth:`sign_event`.

        Returns:
            ``True`` if the signature is valid; ``False`` if the event has
            been modified or the signature is forged.
        """
        expected = self.sign_event(event)
        # Use hmac.compare_digest to resist timing attacks
        try:
            return hmac.compare_digest(expected.lower(), signature.lower())
        except (TypeError, AttributeError):
            return False

    # ------------------------------------------------------------------
    # Audit chain
    # ------------------------------------------------------------------

    def append_to_chain(
        self,
        data: dict,
        subject: str = "system",
    ) -> AuditEntry:
        """
        Append a new entry to the tamper-evident audit chain.

        The entry's ``entry_hash`` is computed over the concatenation of
        ``index``, ``timestamp``, ``subject``, the JSON-serialised ``data``,
        and the predecessor's ``entry_hash``.

        Args:
            data:    JSON-serialisable dict describing the audit event.
            subject: Identifier of the entity responsible for the event.

        Returns:
            The newly created :class:`AuditEntry`.
        """
        index     = len(self._chain)
        timestamp = self._clock()
        prev_hash = (
            self._chain[-1].entry_hash if self._chain else _GENESIS_PREV_HASH
        )
        entry_hash = _compute_entry_hash(
            self._key, index, timestamp, subject, data, prev_hash
        )
        entry = AuditEntry(
            index=index,
            timestamp=timestamp,
            subject=subject,
            data=data,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )
        self._chain.append(entry)
        return entry

    def verify_chain(self) -> ChainVerificationResult:
        """
        Walk the entire audit chain and verify every entry.

        For each entry, two checks are performed:

        1. The stored ``entry_hash`` matches a freshly computed HMAC of the
           entry's content → detects in-place field mutation.
        2. The stored ``prev_hash`` matches the ``entry_hash`` of the
           preceding entry → detects insertion, deletion, or reordering.

        Returns:
            :class:`ChainVerificationResult` describing the outcome.
        """
        if not self._chain:
            return ChainVerificationResult(
                valid=True, length=0, broken_at=None,
                reason="Chain is empty — nothing to verify."
            )

        for i, entry in enumerate(self._chain):
            # Check 1: recompute the HMAC
            expected_hash = _compute_entry_hash(
                self._key,
                entry.index,
                entry.timestamp,
                entry.subject,
                entry.data,
                entry.prev_hash,
            )
            if not hmac.compare_digest(expected_hash, entry.entry_hash):
                return ChainVerificationResult(
                    valid=False,
                    length=len(self._chain),
                    broken_at=i,
                    reason=f"Entry {i}: HMAC mismatch — entry has been tampered with.",
                )

            # Check 2: predecessor link
            expected_prev = (
                self._chain[i - 1].entry_hash if i > 0 else _GENESIS_PREV_HASH
            )
            if not hmac.compare_digest(expected_prev, entry.prev_hash):
                return ChainVerificationResult(
                    valid=False,
                    length=len(self._chain),
                    broken_at=i,
                    reason=f"Entry {i}: prev_hash mismatch — chain link is broken.",
                )

        return ChainVerificationResult(
            valid=True,
            length=len(self._chain),
            broken_at=None,
            reason=f"All {len(self._chain)} entries verified successfully.",
        )

    def export_chain(self) -> list[dict]:
        """
        Return a JSON-serialisable list of all audit chain entries.

        Use this to persist the chain to disk or a remote audit store.

        Returns:
            List of :class:`AuditEntry` dicts, oldest first.
        """
        return [e.to_dict() for e in self._chain]

    def get_chain(self) -> list[AuditEntry]:
        """Return a copy of the internal chain (oldest first)."""
        return list(self._chain)

    @property
    def chain_length(self) -> int:
        """Number of entries currently in the audit chain."""
        return len(self._chain)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _canonical_event(event: SecurityEvent) -> bytes:
    """
    Produce a stable, canonical JSON byte-string for an event.

    Only deterministic, semantically important fields are included.
    """
    obj = {
        "raw":         event.raw,
        "source_ip":   event.source_ip,
        "event_type":  event.event_type,
        "severity":    round(event.severity, 6),
        "matched_sigs": sorted(event.matched_sigs),
    }
    return json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()


def _hmac_hex(key: bytes, message: bytes) -> str:
    """Return lower-case hex HMAC-SHA256 of *message* under *key*."""
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _compute_entry_hash(
    key: bytes,
    index: int,
    timestamp: str,
    subject: str,
    data: dict,
    prev_hash: str,
) -> str:
    """Compute the canonical HMAC for an audit-chain entry."""
    canonical = json.dumps(
        {
            "index":     index,
            "timestamp": timestamp,
            "subject":   subject,
            "data":      data,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        ensure_ascii=False,
    ).encode()
    return _hmac_hex(key, canonical)
