"""ntfy notifications with a persistent retry queue.

Alerts are queued in SQLite and flushed with backoff, so notifications about a
WAN outage are delivered once connectivity returns (or immediately if you
self-host ntfy on the LAN). Includes approve/deny action buttons when a
remediation needs sign-off.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from .config import Config
from .db import Database

log = logging.getLogger("netwatch.notify")

PRIORITY = {"critical": 5, "warn": 4, "info": 3}


def human_duration(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 90:
        return f"{seconds}s"
    if seconds < 5400:
        return f"{seconds // 60}m"
    if seconds < 172800:
        return f"{seconds / 3600:.1f}h"
    return f"{seconds / 86400:.1f}d"


class Notifier:
    def __init__(self, db: Database, cfg: Config):
        self.db = db
        self.cfg = cfg
        self.ntfy = cfg.ntfy
        headers = {}
        if self.ntfy.token:
            headers["Authorization"] = f"Bearer {self.ntfy.token}"
        auth = (
            (self.ntfy.username, self.ntfy.password)
            if self.ntfy.username and not self.ntfy.token else None
        )
        self._http = httpx.AsyncClient(timeout=15, headers=headers, auth=auth)

    @property
    def enabled(self) -> bool:
        return self.ntfy.enabled and bool(self.ntfy.topic)

    def _dashboard_url(self) -> str:
        return self.cfg.server.public_url.rstrip("/") if self.cfg.server.public_url else ""

    # -- payload builders ----------------------------------------------------------

    def raw(self, title: str, message: str, priority: int = 3,
            tags: list[str] | None = None, actions: list[dict] | None = None) -> None:
        payload = {
            "topic": self.ntfy.topic,
            "title": title,
            "message": message[:3500],
            "priority": priority,
            "tags": tags or [],
        }
        if self._dashboard_url():
            payload["click"] = self._dashboard_url()
        if actions:
            payload["actions"] = actions
        self._enqueue(payload)

    def _approval_actions(self, action_row: dict) -> tuple[list[dict], str]:
        base = self._dashboard_url()
        ttl_min = int(max(0, (action_row.get("expires") or 0) - time.time()) / 60)
        if not base:
            return [], (f"\n\nApprove/deny from the dashboard (Approvals panel) "
                        f"within {ttl_min} min.")
        token = action_row["token"]
        aid = action_row["id"]
        return [
            {"action": "http", "label": "✅ Approve fix",
             "url": f"{base}/api/actions/{aid}/approve?token={token}",
             "method": "POST", "clear": True},
            {"action": "http", "label": "❌ Deny",
             "url": f"{base}/api/actions/{aid}/deny?token={token}",
             "method": "POST", "clear": True},
        ], f"\n\nProposed fix: {action_row['label']} (buttons valid {ttl_min} min)"

    # -- high-level notifications ----------------------------------------------------

    def incident_opened(self, inc: dict, result=None, fix_note: str = "",
                        approval: dict | None = None) -> None:
        sev = inc["severity"]
        prio = PRIORITY.get(sev, 4)
        tags = ["rotating_light"] if sev == "critical" else ["warning"]
        if inc.get("kind") == "prediction":
            tags = ["crystal_ball"]
            prio = 4
        message = inc["detail"] or inc["title"]
        actions = None
        if fix_note:
            message += f"\n\n{fix_note}"
        if approval:
            actions, note = self._approval_actions(approval)
            message += note
        self.raw(inc["title"], message, prio, tags, actions)

    def incident_closed(self, inc: dict, annotation: str = "") -> None:
        if not self.ntfy.notify_recoveries:
            return
        duration = human_duration((inc.get("closed") or time.time()) - inc["opened"])
        self.raw(
            f"Resolved: {inc['title']}",
            f"Recovered after {duration}{annotation}.",
            priority=2, tags=["white_check_mark"],
        )

    def incident_escalated(self, name: str, message: str) -> None:
        self.raw(f"Escalated: {name}", message, priority=5, tags=["rotating_light"])

    def incident_reminder(self, inc: dict, now: float) -> None:
        self.raw(
            f"Still open: {inc['title']}",
            f"{inc['detail']}\n\nOpen for {human_duration(now - inc['opened'])}.",
            priority=4, tags=["hourglass_flowing_sand"],
        )

    def action_result(self, act: dict, ok: bool, detail: str) -> None:
        if ok:
            self.raw(f"Fix applied: {act['label']}",
                     f"{detail}\nWatching to confirm it resolves the issue.",
                     priority=3, tags=["wrench"])
        else:
            self.raw(f"Fix FAILED: {act['label']}", detail, priority=4, tags=["x"])

    def event(self, key: str, title: str, message: str, severity: str = "info",
              dedup_minutes: int = 1440) -> None:
        kv_key = f"ev_sent:{key}"
        last = float(self.db.kv_get(kv_key) or 0)
        if time.time() - last < dedup_minutes * 60:
            return
        self.db.kv_set(kv_key, str(time.time()))
        tags = {"critical": ["rotating_light"], "warn": ["warning"]}.get(severity, ["information_source"])
        self.raw(title, message, PRIORITY.get(severity, 3), tags)

    def startup(self) -> None:
        from . import __version__
        msg = "Network Watchdog is online and monitoring."
        if self._dashboard_url():
            msg += f"\nDashboard: {self._dashboard_url()}"
        self.raw(f"Watchdog online (v{__version__})", msg, priority=2, tags=["dog"])

    # -- queue ------------------------------------------------------------------------

    def _enqueue(self, payload: dict) -> None:
        if not self.enabled:
            log.info("NOTIFY (ntfy disabled): %s — %s", payload["title"], payload["message"])
            return
        self.db.execute(
            "INSERT INTO notify_queue (created, payload, attempts, next_attempt) VALUES (?,?,0,0)",
            (time.time(), json.dumps(payload)),
        )

    async def _post(self, payload: dict) -> None:
        r = await self._http.post(self.ntfy.server.rstrip("/"), json=payload)
        r.raise_for_status()

    async def run_queue(self) -> None:
        max_age = self.ntfy.max_queue_age_hours * 3600
        while True:
            try:
                now = time.time()
                rows = self.db.query(
                    "SELECT * FROM notify_queue WHERE next_attempt <= ? ORDER BY id LIMIT 10",
                    (now,),
                )
                for row in rows:
                    if now - row["created"] > max_age:
                        log.warning("dropping stale notification id=%s", row["id"])
                        self.db.execute("DELETE FROM notify_queue WHERE id=?", (row["id"],))
                        continue
                    try:
                        await self._post(json.loads(row["payload"]))
                        self.db.execute("DELETE FROM notify_queue WHERE id=?", (row["id"],))
                    except Exception as exc:  # noqa: BLE001
                        attempts = row["attempts"] + 1
                        delay = min(30 * 2 ** attempts, 900)
                        log.warning("ntfy delivery failed (attempt %d): %s", attempts, exc)
                        self.db.execute(
                            "UPDATE notify_queue SET attempts=?, next_attempt=? WHERE id=?",
                            (attempts, now + delay, row["id"]),
                        )
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("notify queue error")
            await asyncio.sleep(10)

    async def aclose(self) -> None:
        await self._http.aclose()
