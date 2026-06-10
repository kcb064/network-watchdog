"""Shared value types passed between collectors, the engine, and notifiers."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# Check statuses
OK = "ok"
WARN = "warn"
FAIL = "fail"

# Severities (for incidents/notifications)
INFO = "info"
SEV_WARN = "warn"
CRITICAL = "critical"


@dataclass
class Sample:
    """A single numeric metric observation."""

    metric: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class CheckResult:
    """Outcome of one health check on one poll.

    meta keys understood by the engine:
      depends_on:   list[str] of check keys; if one is fail-open, this check's
                    incident is attributed to it and not separately notified.
      remediation:  dict passed to the remediation registry (e.g. container id).
      detail:       extra human-readable context appended to notifications.
    """

    key: str
    status: str  # OK | WARN | FAIL
    message: str = ""
    severity: str = CRITICAL  # severity if failing: SEV_WARN | CRITICAL
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    """One-off notification not tied to check state (e.g. a new TrueNAS alert).

    Deduplicated by key: the same key is not re-sent within dedup_minutes.
    """

    key: str
    title: str
    message: str
    severity: str = INFO
    dedup_minutes: int = 1440


@dataclass
class CollectorOutput:
    samples: list[Sample] = field(default_factory=list)
    checks: list[CheckResult] = field(default_factory=list)
    events: list[Event] = field(default_factory=list)
