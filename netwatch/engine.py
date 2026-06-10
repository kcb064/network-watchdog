"""Health engine: state machine with hysteresis + flap detection, incident
lifecycle, scheduling of collectors, predictions, reminders, and cleanup."""
from __future__ import annotations

import asyncio
import json
import logging
import random
import time
from typing import Any

import httpx

from .config import Config, StateConfig
from .db import Database
from .models import FAIL, OK, WARN, CheckResult, CollectorOutput

log = logging.getLogger("netwatch.engine")


# --------------------------------------------------------------------------
# Pure state-machine logic (unit-tested without I/O)
# --------------------------------------------------------------------------

def new_state_row(key: str, now: float) -> dict[str, Any]:
    return {
        "key": key, "status": OK, "severity": "critical", "since": now,
        "message": "", "fails": 0, "oks": 0, "flapping": 0,
        "transitions": [], "incident_id": None, "last_seen": now, "meta": {},
    }


def incident_severity(result: CheckResult) -> str:
    if result.status == FAIL and result.severity == "critical":
        return "critical"
    return "warn"


def apply_result(
    row: dict[str, Any], result: CheckResult, now: float, cfg: StateConfig
) -> list[tuple[str, Any]]:
    """Mutates row, returns lifecycle events:
    ("open", severity) ("close", None) ("escalate", severity)
    ("flap_start", None) ("flap_end", None)
    """
    events: list[tuple[str, Any]] = []
    prev = row["status"]
    row["last_seen"] = now
    row["message"] = result.message
    row["meta"] = result.meta

    if result.status != prev:
        row["transitions"].append(now)
        row["since"] = now

    window_start = now - cfg.flap_window_minutes * 60
    row["transitions"] = [t for t in row["transitions"] if t >= window_start]

    if not row["flapping"] and len(row["transitions"]) >= cfg.flap_threshold:
        row["flapping"] = 1
        events.append(("flap_start", None))
    elif row["flapping"]:
        last_change = max(row["transitions"]) if row["transitions"] else 0
        if now - last_change >= cfg.flap_calm_minutes * 60:
            row["flapping"] = 0
            events.append(("flap_end", None))

    row["status"] = result.status
    if result.status == OK:
        row["oks"] += 1
        row["fails"] = 0
    else:
        row["fails"] += 1
        row["oks"] = 0

    not_ok = result.status in (WARN, FAIL)
    sev = incident_severity(result)

    if not_ok and row["incident_id"] is None and row["fails"] >= cfg.open_after:
        row["severity"] = sev
        events.append(("open", sev))
    elif not_ok and row["incident_id"] is not None:
        if sev == "critical" and row["severity"] != "critical":
            row["severity"] = sev
            events.append(("escalate", sev))
    elif result.status == OK and row["incident_id"] is not None and row["oks"] >= cfg.close_after:
        events.append(("close", None))

    return events


def find_root_cause(meta: dict, open_keys: set[str]) -> str | None:
    """If a declared dependency already has an open incident, attribute to it."""
    for dep in meta.get("depends_on", []):
        if dep in open_keys:
            return dep
    return None


# --------------------------------------------------------------------------
# Engine (I/O orchestration)
# --------------------------------------------------------------------------

class Engine:
    def __init__(self, db: Database, cfg: Config, notifier, remediator, collectors: dict):
        self.db = db
        self.cfg = cfg
        self.notifier = notifier
        self.remediator = remediator
        self.collectors = collectors  # id -> collector instance
        self._tasks: list[asyncio.Task] = []
        self.started = time.time()

    # -- persistence helpers --------------------------------------------------

    def _load_row(self, key: str, now: float) -> dict[str, Any]:
        raw = self.db.query_one("SELECT * FROM check_states WHERE key=?", (key,))
        if not raw:
            return new_state_row(key, now)
        raw["transitions"] = json.loads(raw["transitions"])
        raw["meta"] = json.loads(raw["meta"])
        return raw

    def _save_row(self, row: dict[str, Any]) -> None:
        self.db.execute(
            """INSERT INTO check_states
               (key,status,severity,since,message,fails,oks,flapping,transitions,
                incident_id,last_seen,meta)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
               ON CONFLICT(key) DO UPDATE SET
                 status=excluded.status, severity=excluded.severity, since=excluded.since,
                 message=excluded.message, fails=excluded.fails, oks=excluded.oks,
                 flapping=excluded.flapping, transitions=excluded.transitions,
                 incident_id=excluded.incident_id, last_seen=excluded.last_seen,
                 meta=excluded.meta""",
            (
                row["key"], row["status"], row["severity"], row["since"], row["message"],
                row["fails"], row["oks"], row["flapping"], json.dumps(row["transitions"]),
                row["incident_id"], row["last_seen"], json.dumps(row["meta"]),
            ),
        )

    def open_incident_keys(self) -> set[str]:
        rows = self.db.query("SELECT key FROM incidents WHERE closed IS NULL")
        return {r["key"] for r in rows}

    # -- incident lifecycle ----------------------------------------------------

    def open_incident(
        self, key: str, kind: str, severity: str, title: str, detail: str,
        root_cause: str | None = None, notify: bool = True,
    ) -> int:
        now = time.time()
        cur = self.db.execute(
            "INSERT INTO incidents (key,kind,severity,title,detail,opened,root_cause,last_notified)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (key, kind, severity, title, detail, now, root_cause, now if notify else 0),
        )
        inc_id = cur.lastrowid
        log.warning("incident OPEN [%s] %s: %s", severity, title, detail)
        return inc_id

    def close_incident(self, incident_id: int) -> dict | None:
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (incident_id,))
        if not inc or inc["closed"]:
            return inc
        now = time.time()
        self.db.execute("UPDATE incidents SET closed=? WHERE id=?", (now, incident_id))
        inc["closed"] = now
        log.info("incident CLOSE %s", inc["title"])
        return inc

    # -- check processing -------------------------------------------------------

    async def process_output(self, collector_id: str, out: CollectorOutput) -> None:
        now = time.time()
        if out.samples:
            self.db.add_samples(
                [(now, s.metric, json.dumps(s.labels), float(s.value)) for s in out.samples]
            )
        for check in out.checks:
            await self._apply_check(check, now)
        for ev in out.events:
            self.notifier.event(ev.key, ev.title, ev.message, ev.severity, ev.dedup_minutes)

    async def _apply_check(self, result: CheckResult, now: float) -> None:
        row = self._load_row(result.key, now)
        was_flapping = bool(row["flapping"])
        events = apply_result(row, result, now, self.cfg.state)

        name = result.meta.get("name") or result.key

        for kind, arg in events:
            if kind == "flap_start":
                self.notifier.raw(
                    title=f"{name} is flapping",
                    message=(f"{name} changed state {len(row['transitions'])} times in the last "
                             f"{self.cfg.state.flap_window_minutes} min. Up/down alerts for it are "
                             f"muted until it stays stable for {self.cfg.state.flap_calm_minutes} min. "
                             "Automatic fixes still run and will be announced."),
                    priority=4, tags=["repeat"],
                )
            elif kind == "flap_end":
                self.notifier.raw(
                    title=f"{name} stabilized",
                    message=f"{name} has been stable for {self.cfg.state.flap_calm_minutes} min "
                            f"(now: {row['status']}).",
                    priority=2, tags=["white_check_mark"],
                )
            elif kind == "open":
                await self._on_open(row, result, arg, suppress=was_flapping or bool(row["flapping"]))
            elif kind == "escalate":
                self.db.execute(
                    "UPDATE incidents SET severity=? WHERE id=?", (arg, row["incident_id"])
                )
                if not row["flapping"]:
                    self.notifier.incident_escalated(name, result.message)
                    self.db.execute(
                        "UPDATE incidents SET last_notified=? WHERE id=?",
                        (now, row["incident_id"]),
                    )
            elif kind == "close":
                inc = self.close_incident(row["incident_id"])
                row["incident_id"] = None
                if inc and not row["flapping"]:
                    annotation = self._recent_action_annotation(inc["id"])
                    if inc["last_notified"] > 0:
                        self.notifier.incident_closed(inc, annotation)

        # An open incident may gain a remediation option later (retry after
        # backoff, the next rung of a fallback chain, a grace period
        # elapsing), so re-consider while open. consider() itself gates on
        # in-flight/active actions per spec.
        if row["incident_id"] is not None and row["status"] != OK:
            inc = self.db.query_one(
                "SELECT * FROM incidents WHERE id=?", (row["incident_id"],)
            )
            if inc and not inc["root_cause"]:
                plan = await self.remediator.consider(
                    inc, result, auto_only=bool(row["flapping"])
                )
                if plan and plan[0] == "auto":
                    await self.remediator.execute(plan[1])
                elif plan and plan[0] == "approve":
                    # A fix became available after the incident opened — the
                    # approval buttons must actually reach the user.
                    self.notifier.incident_opened(inc, result, approval=plan[1])
                    self.db.execute(
                        "UPDATE incidents SET last_notified=? WHERE id=?",
                        (time.time(), inc["id"]),
                    )

        self._save_row(row)

    async def _on_open(self, row, result: CheckResult, severity: str, suppress: bool) -> None:
        name = result.meta.get("name") or result.key
        root = find_root_cause(result.meta, self.open_incident_keys())
        title = f"{name} {'DOWN' if result.status == FAIL else 'degraded'}"
        notify = not suppress and root is None
        inc_id = self.open_incident(
            result.key, result.meta.get("kind", "availability"), severity,
            title, result.message, root_cause=root, notify=notify,
        )
        row["incident_id"] = inc_id

        if root is not None:
            return  # quiet: the root-cause incident drives fixing/notifying
        inc = self.db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        if not notify:
            # Flap-muted: state-change alerts stay quiet, but automatic fixes
            # still run (execute() announces "Fix applied/FAILED" on its own).
            plan = await self.remediator.consider(inc, result, auto_only=True)
            if plan and plan[0] == "auto":
                await self.remediator.execute(plan[1])
            return
        plan = await self.remediator.consider(inc, result)
        if plan is None:
            self.notifier.incident_opened(inc, result)
        elif plan[0] == "auto":
            self.notifier.incident_opened(inc, result, fix_note=f"Auto-fix: {plan[1]['label']}")
            await self.remediator.execute(plan[1])
        elif plan[0] == "approve":
            self.notifier.incident_opened(inc, result, approval=plan[1])
        elif plan[0] == "off":
            self.notifier.incident_opened(inc, result, fix_note=f"Suggested fix: {plan[1]}")

    def _recent_action_annotation(self, incident_id: int) -> str:
        act = self.db.query_one(
            "SELECT * FROM actions WHERE incident_id=? AND executed IS NOT NULL "
            "ORDER BY executed DESC LIMIT 1", (incident_id,),
        )
        if act and time.time() - (act["executed"] or 0) < 3600:
            return f" (after fix: {act['label']})"
        return ""

    # -- background loops --------------------------------------------------------

    async def start(self) -> None:
        for col in self.collectors.values():
            self._tasks.append(asyncio.create_task(self._loop_collector(col)))
        self._tasks.append(asyncio.create_task(self._loop_sweeper()))
        self._tasks.append(asyncio.create_task(self._loop_predictions()))
        self._tasks.append(asyncio.create_task(self._loop_prune()))
        self._tasks.append(asyncio.create_task(self.notifier.run_queue()))
        if self.cfg.server.heartbeat_url:
            self._tasks.append(asyncio.create_task(self._loop_heartbeat()))
        if self.cfg.ntfy.startup_message:
            self.notifier.startup()
        log.info("engine started with collectors: %s", ", ".join(self.collectors) or "none")

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def _loop_collector(self, col) -> None:
        key = f"watchdog.collector.{col.id}"
        await asyncio.sleep(random.uniform(0.5, 3.0))
        while True:
            started = time.time()
            try:
                out = await asyncio.wait_for(col.collect(), timeout=90)
                await self.process_output(col.id, out)
                await self._apply_check(
                    CheckResult(key, OK, "collector healthy", severity="warn",
                                meta={"name": f"Collector {col.id}"}),
                    time.time(),
                )
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 — surface as its own check
                log.exception("collector %s failed", col.id)
                await self._apply_check(
                    CheckResult(
                        key, FAIL, f"{type(exc).__name__}: {exc}", severity="warn",
                        meta={"name": f"Collector {col.id}"},
                    ),
                    time.time(),
                )
            elapsed = time.time() - started
            await asyncio.sleep(max(5.0, col.interval - elapsed) * random.uniform(0.95, 1.05))

    async def _loop_sweeper(self) -> None:
        while True:
            try:
                now = time.time()
                self._remind_open_incidents(now)
                self._expire_actions(now)
                await self._verify_actions(now)
                await self.remediator.revert_orphans()
                self._drop_stale_checks(now)
            except Exception:  # noqa: BLE001
                log.exception("sweeper error")
            await asyncio.sleep(60)

    def _remind_open_incidents(self, now: float) -> None:
        hours = self.cfg.state.remind_hours
        if hours <= 0:
            return
        rows = self.db.query(
            "SELECT * FROM incidents WHERE closed IS NULL AND severity='critical' "
            "AND root_cause IS NULL AND last_notified > 0 AND last_notified < ?",
            (now - hours * 3600,),
        )
        for inc in rows:
            self.notifier.incident_reminder(inc, now)
            self.db.execute("UPDATE incidents SET last_notified=? WHERE id=?", (now, inc["id"]))

    def _expire_actions(self, now: float) -> None:
        self.db.execute(
            "UPDATE actions SET status='expired' WHERE status='pending' AND expires < ?", (now,)
        )

    async def _verify_actions(self, now: float) -> None:
        rows = self.db.query(
            "SELECT * FROM actions WHERE status='succeeded' AND verify_deadline IS NOT NULL "
            "AND verify_deadline < ?", (now,),
        )
        for act in rows:
            inc = self.db.query_one(
                "SELECT * FROM incidents WHERE id=? AND closed IS NULL", (act["incident_id"],)
            )
            if inc:
                self.notifier.raw(
                    title=f"Fix did not resolve: {inc['title']}",
                    message=(f"“{act['label']}” ran "
                             f"{int((now - (act['executed'] or now)) / 60)} min ago but the issue "
                             f"is still present. Manual attention needed."),
                    priority=5, tags=["x"],
                )
                self.db.execute("UPDATE actions SET status='unresolved' WHERE id=?", (act["id"],))
            else:
                self.db.execute(
                    "UPDATE actions SET verify_deadline=NULL WHERE id=?", (act["id"],)
                )

    def _drop_stale_checks(self, now: float) -> None:
        # Checks not reported for a while (renamed/removed container, disabled
        # device) get their incidents closed and rows removed.
        cutoff = now - max(self.cfg.poll.medium, self.cfg.poll.fast) * 10 - 600
        rows = self.db.query("SELECT * FROM check_states WHERE last_seen < ?", (cutoff,))
        for row in rows:
            if row["incident_id"]:
                self.close_incident(row["incident_id"])
            self.db.execute("DELETE FROM check_states WHERE key=?", (row["key"],))
            log.info("dropped stale check %s", row["key"])

    async def _loop_predictions(self) -> None:
        from . import predict
        await asyncio.sleep(120)
        while True:
            try:
                predict.run(self)
            except Exception:  # noqa: BLE001
                log.exception("prediction error")
            await asyncio.sleep(self.cfg.poll.slow)

    async def _loop_prune(self) -> None:
        while True:
            try:
                self.db.prune(self.cfg.server.retention_days)
            except Exception:  # noqa: BLE001
                log.exception("prune error")
            await asyncio.sleep(86400)

    async def _loop_heartbeat(self) -> None:
        async with httpx.AsyncClient(timeout=10) as client:
            while True:
                try:
                    await client.get(self.cfg.server.heartbeat_url)
                except Exception as exc:  # noqa: BLE001
                    log.debug("heartbeat ping failed: %s", exc)
                await asyncio.sleep(60)
