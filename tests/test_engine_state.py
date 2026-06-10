"""State machine: hysteresis, escalation, flap detection, root-cause lookup."""
import time

from netwatch.config import StateConfig
from netwatch.engine import apply_result, find_root_cause, new_state_row
from netwatch.models import FAIL, OK, WARN, CheckResult

CFG = StateConfig()  # open_after=3, close_after=2, flap_threshold=6
T0 = 1_750_000_000.0


def step(row, status, t, severity="critical", message="m"):
    return apply_result(row, CheckResult("svc.x", status, message, severity=severity), t, CFG)


def test_opens_only_after_consecutive_fails():
    row = new_state_row("svc.x", T0)
    assert step(row, FAIL, T0) == []
    assert step(row, FAIL, T0 + 30) == []
    events = step(row, FAIL, T0 + 60)
    assert ("open", "critical") in events
    row["incident_id"] = 1
    # further fails don't re-open
    assert step(row, FAIL, T0 + 90) == []


def test_ok_resets_fail_streak():
    row = new_state_row("svc.x", T0)
    step(row, FAIL, T0)
    step(row, FAIL, T0 + 30)
    step(row, OK, T0 + 60)
    assert step(row, FAIL, T0 + 90) == []
    assert step(row, FAIL, T0 + 120) == []
    assert ("open", "critical") in step(row, FAIL, T0 + 150)


def test_close_requires_consecutive_oks():
    row = new_state_row("svc.x", T0)
    for i in range(3):
        step(row, FAIL, T0 + i * 30)
    row["incident_id"] = 7
    assert step(row, OK, T0 + 100) == []
    events = step(row, OK, T0 + 130)
    assert ("close", None) in events


def test_warn_opens_warn_incident_and_escalates():
    row = new_state_row("svc.x", T0)
    for i in range(2):
        assert step(row, WARN, T0 + i * 30, severity="warn") == []
    events = step(row, WARN, T0 + 60, severity="warn")
    assert ("open", "warn") in events
    row["incident_id"] = 3
    events = step(row, FAIL, T0 + 90, severity="critical")
    assert ("escalate", "critical") in events
    assert row["severity"] == "critical"


def test_flap_detection_and_calm():
    row = new_state_row("svc.x", T0)
    statuses = [FAIL, OK, FAIL, OK, FAIL, OK, FAIL]
    flap_events = []
    for i, st in enumerate(statuses):
        flap_events += [e for e in step(row, st, T0 + i * 60) if e[0].startswith("flap")]
    assert ("flap_start", None) in flap_events
    assert row["flapping"] == 1
    # calms after a quiet period with no further status changes
    calm_t = T0 + len(statuses) * 60 + CFG.flap_calm_minutes * 60 + 1
    events = step(row, FAIL, calm_t)
    assert ("flap_end", None) in events
    assert row["flapping"] == 0


def test_transitions_pruned_to_window():
    row = new_state_row("svc.x", T0)
    step(row, FAIL, T0)
    step(row, OK, T0 + 10)
    much_later = T0 + CFG.flap_window_minutes * 60 + 100
    step(row, OK, much_later)
    assert row["transitions"] == []


def test_find_root_cause():
    meta = {"depends_on": ["wan.ping", "wan.dns"]}
    assert find_root_cause(meta, {"wan.ping"}) == "wan.ping"
    assert find_root_cause(meta, {"other"}) is None
    assert find_root_cause({}, {"wan.ping"}) is None


def test_new_check_starting_failed_opens():
    # A check first seen in a failed state should still open after hysteresis.
    row = new_state_row("svc.y", T0)
    step(row, FAIL, T0)
    step(row, FAIL, T0 + 30)
    assert ("open", "critical") in step(row, FAIL, T0 + 60)
    assert row["since"] == T0  # status never changed, so 'since' is first sighting
