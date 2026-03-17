"""
Access Controller — SentinelWeave
Confidentiality pillar of the CIA triad.

Provides a **Role-Based Access Control (RBAC)** engine that gates every
operation performed on threat reports, key material, and system configuration.

Roles (lowest → highest privilege)
-----------------------------------
* ``VIEWER``    — may only list report IDs.
* ``ANALYST``   — may list, read, and export reports.
* ``RESPONDER`` — may additionally acknowledge / close incidents.
* ``ADMIN``     — full access including key management and reconfiguration.

Each access decision (grant *or* denial) is appended to an in-memory audit
log so that administrators can later replay who accessed what and when.

Example
-------
::

    from sentinel_weave.access_controller import AccessController, Role, Action

    ac = AccessController()

    # An analyst may read a report
    ac.assert_permitted(Role.ANALYST, Action.READ, "report-2026-01-01.bin")

    # A viewer may NOT manage keys — this raises PermissionError
    try:
        ac.assert_permitted(Role.VIEWER, Action.MANAGE_KEYS)
    except PermissionError as exc:
        print(exc)

    # Inspect the audit trail
    for entry in ac.get_audit_log():
        print(entry)
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class Role(Enum):
    """User roles in ascending order of privilege."""
    VIEWER    = "VIEWER"
    ANALYST   = "ANALYST"
    RESPONDER = "RESPONDER"
    ADMIN     = "ADMIN"


class Action(Enum):
    """Actions that can be performed on system resources."""
    LIST         = "LIST"
    READ         = "READ"
    EXPORT       = "EXPORT"
    ACKNOWLEDGE  = "ACKNOWLEDGE"
    MANAGE_KEYS  = "MANAGE_KEYS"
    CONFIGURE    = "CONFIGURE"
    DELETE       = "DELETE"


# ---------------------------------------------------------------------------
# Permission matrix
# ---------------------------------------------------------------------------

_PERMISSIONS: dict[Role, frozenset[Action]] = {
    Role.VIEWER:    frozenset({Action.LIST}),
    Role.ANALYST:   frozenset({Action.LIST, Action.READ, Action.EXPORT}),
    Role.RESPONDER: frozenset({
        Action.LIST, Action.READ, Action.EXPORT, Action.ACKNOWLEDGE,
    }),
    Role.ADMIN:     frozenset(Action),  # every action
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class AccessRequest:
    """
    A single access-control decision recorded in the audit log.

    Attributes:
        subject:   Identifier of the caller (username, service account, …).
        role:      The :class:`Role` presented by the caller.
        action:    The :class:`Action` being attempted.
        resource:  Resource identifier (e.g. report ID or ``"*"``).
        granted:   ``True`` if access was permitted, ``False`` otherwise.
        reason:    Human-readable explanation of the decision.
        timestamp: UTC timestamp of the decision.
    """

    subject:   str
    role:      Role
    action:    Action
    resource:  str
    granted:   bool
    reason:    str
    timestamp: str = field(
        default_factory=lambda: datetime.datetime.now(
            datetime.timezone.utc
        ).isoformat()
    )

    def __str__(self) -> str:
        verdict = "GRANTED" if self.granted else "DENIED"
        return (
            f"[{self.timestamp}] {verdict} "
            f"subject={self.subject!r} role={self.role.value} "
            f"action={self.action.value} resource={self.resource!r} "
            f"— {self.reason}"
        )


@dataclass(frozen=True)
class SubjectProfile:
    """Authoritative subject profile used to validate role claims."""

    subject: str
    role: Role
    department: str


# ---------------------------------------------------------------------------
# AccessController
# ---------------------------------------------------------------------------

class AccessController:
    """
    Enforces RBAC policies and maintains a tamper-evident audit log.

    Parameters
    ----------
    audit_enabled:
        When ``True`` (default), every access decision is appended to the
        internal audit log.  Disable only in high-throughput scenarios where
        the audit overhead is unacceptable and an external audit sink is used.

    Example
    -------
    ::

        ac = AccessController()
        allowed = ac.check(Role.ANALYST, Action.READ, "report-abc.bin", "alice")
        if allowed:
            ...
    """

    def __init__(
        self,
        audit_enabled: bool = True,
        enforce_subjects: bool = True,
        subject_profiles: Optional[dict[str, SubjectProfile]] = None,
    ) -> None:
        self._audit_enabled = audit_enabled
        self._enforce_subjects = enforce_subjects
        self._log: list[AccessRequest] = []
        self._subjects: dict[str, SubjectProfile] = (
            subject_profiles
            if subject_profiles is not None
            else {
                "alice": SubjectProfile("alice", Role.ANALYST, "SOC"),
                "bob": SubjectProfile("bob", Role.VIEWER, "IT"),
                "carol": SubjectProfile("carol", Role.RESPONDER, "IR"),
                "dana": SubjectProfile("dana", Role.ADMIN, "SECOPS"),
            }
        )

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def check(
        self,
        role: Role,
        action: Action,
        resource: str = "*",
        subject: str = "anonymous",
    ) -> bool:
        """
        Return ``True`` if *role* is permitted to perform *action* on
        *resource*; ``False`` otherwise.

        A record is always appended to the audit log (when enabled).

        Args:
            role:     Caller's assigned :class:`Role`.
            action:   :class:`Action` being requested.
            resource: Resource identifier (optional, used for audit trail only).
            subject:  Human-readable caller identifier (optional).

        Returns:
            ``True`` if the action is permitted, ``False`` otherwise.
        """
        profile = self.get_subject_profile(subject)
        if profile is None:
            if self._enforce_subjects:
                reason = "Unknown subject; access denied"
                self._record(subject, role, action, resource, False, reason)
                return False
        elif role != profile.role:
            reason = (
                f"Role mismatch for subject {profile.subject!r}: "
                f"expected {profile.role.value}, got {role.value}"
            )
            self._record(subject, role, action, resource, False, reason)
            return False

        allowed_actions = _PERMISSIONS.get(role, frozenset())
        granted = action in allowed_actions
        reason = (
            f"Role {role.value} is permitted to {action.value}"
            if granted
            else f"Role {role.value} is NOT permitted to {action.value}"
        )
        self._record(subject, role, action, resource, granted, reason)
        return granted

    def assert_permitted(
        self,
        role: Role,
        action: Action,
        resource: str = "*",
        subject: str = "anonymous",
    ) -> None:
        """
        Assert that *role* may perform *action* on *resource*.

        Raises:
            PermissionError: If the action is not permitted for the role.
        """
        if not self.check(role, action, resource, subject):
            raise PermissionError(
                f"Role {role.value!r} is not permitted to perform "
                f"{action.value!r} on {resource!r}."
            )

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    def permitted_actions(self, role: Role) -> frozenset[Action]:
        """
        Return the complete set of :class:`Action`\\s permitted for *role*.

        Args:
            role: A :class:`Role` value.

        Returns:
            Frozen set of allowed :class:`Action` values.
        """
        return _PERMISSIONS.get(role, frozenset())

    def get_audit_log(self) -> list[AccessRequest]:
        """
        Return a *copy* of the audit log (oldest entry first).

        Returns:
            List of :class:`AccessRequest` objects.
        """
        return list(self._log)

    def clear_audit_log(self) -> None:
        """Purge the in-memory audit log (e.g. after persisting it)."""
        self._log.clear()

    def audit_summary(self) -> dict:
        """
        Return aggregate statistics over the audit log.

        Returns:
            Dict with keys ``total``, ``granted``, ``denied``,
            ``unique_subjects``, ``most_denied_action``.
        """
        if not self._log:
            return {
                "total": 0,
                "granted": 0,
                "denied": 0,
                "unique_subjects": 0,
                "most_denied_action": None,
            }

        granted  = sum(1 for e in self._log if e.granted)
        denied   = len(self._log) - granted
        subjects = {e.subject for e in self._log}

        denial_counts: dict[str, int] = {}
        for e in self._log:
            if not e.granted:
                denial_counts[e.action.value] = (
                    denial_counts.get(e.action.value, 0) + 1
                )
        most_denied = (
            max(denial_counts, key=lambda k: denial_counts[k])
            if denial_counts else None
        )
        return {
            "total":               len(self._log),
            "granted":             granted,
            "denied":              denied,
            "unique_subjects":     len(subjects),
            "most_denied_action":  most_denied,
        }

    def list_subjects(self) -> list[str]:
        """Return a sorted list of known subjects."""
        return sorted(self._subjects.keys())

    def get_subject_profile(self, subject: str) -> Optional[SubjectProfile]:
        """Return the SubjectProfile for a subject (case-insensitive)."""
        key = (subject or "").strip().lower()
        return self._subjects.get(key)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _record(
        self,
        subject: str,
        role: Role,
        action: Action,
        resource: str,
        granted: bool,
        reason: str,
    ) -> None:
        if not self._audit_enabled:
            return
        self._log.append(
            AccessRequest(
                subject=subject,
                role=role,
                action=action,
                resource=resource,
                granted=granted,
                reason=reason,
            )
        )
