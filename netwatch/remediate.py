"""Tiered remediation: match problems to fixes, run safe ones automatically,
ask approval for risky ones, audit everything.

Tiers per action: auto | approve | off
Global modes: tiered (defaults apply) | approve_all | off
"""
from __future__ import annotations

import fnmatch
import json
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Any, Callable

from .config import Config
from .db import Database
from .models import CheckResult

log = logging.getLogger("netwatch.remediate")


@dataclass
class ActionSpec:
    id: str
    default_tier: str  # auto | approve
    label: Callable[[dict], str]
    matcher: Callable[[CheckResult, "Remediator"], dict | None]
    executor: Callable  # async (remediator, ctx) -> str


# -- matchers -------------------------------------------------------------------

def _match_restart_container(check: CheckResult, rem: "Remediator") -> dict | None:
    ctx = (check.meta.get("remediation") or {})
    if ctx.get("kind") != "restart_container" or "docker" not in rem.collectors:
        return None
    name = ctx.get("name", "")
    if any(fnmatch.fnmatch(name, pat) for pat in rem.cfg.remediation.never_touch):
        return None
    return dict(ctx)


def _match_enable_protection(check: CheckResult, rem: "Remediator") -> dict | None:
    ctx = (check.meta.get("remediation") or {})
    if ctx.get("kind") != "enable_protection" or "adguard" not in rem.collectors:
        return None
    if not ctx.get("eligible"):
        return None  # grace period not elapsed (or auto re-enable disabled)
    return dict(ctx)


def _match_ha_restart(check: CheckResult, rem: "Remediator") -> dict | None:
    ctx = (check.meta.get("remediation") or {})
    if ctx.get("kind") != "ha_restart" or "docker" not in rem.collectors:
        return None
    if not ctx.get("name"):
        return None
    return dict(ctx)


def _match_restart_device(check: CheckResult, rem: "Remediator") -> dict | None:
    ctx = (check.meta.get("remediation") or {})
    if ctx.get("kind") != "restart_device" or "unifi" not in rem.collectors:
        return None
    if not ctx.get("mac"):
        return None
    return dict(ctx)


# -- executors ------------------------------------------------------------------

async def _exec_restart_container(rem: "Remediator", ctx: dict) -> str:
    docker = rem.collectors["docker"]
    if ctx.get("id"):
        try:
            return await docker.restart_container(ctx["id"])
        except Exception:  # noqa: BLE001 — id may be stale after recreate
            pass
    return await docker.restart_by_name(ctx["name"])


async def _exec_enable_protection(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["adguard"].set_protection(True)


async def _exec_ha_restart(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["docker"].restart_by_name(ctx["name"])


async def _exec_restart_device(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["unifi"].restart_device(ctx["mac"])


SPECS: list[ActionSpec] = [
    ActionSpec(
        "docker.restart_container", "auto",
        lambda c: f"Restart container {c.get('name', '?')}",
        _match_restart_container, _exec_restart_container,
    ),
    ActionSpec(
        "adguard.enable_protection", "auto",
        lambda c: "Re-enable AdGuard protection",
        _match_enable_protection, _exec_enable_protection,
    ),
    ActionSpec(
        "ha.restart_container", "approve",
        lambda c: f"Restart Home Assistant container ({c.get('name', '?')})",
        _match_ha_restart, _exec_ha_restart,
    ),
    ActionSpec(
        "unifi.restart_device", "approve",
        lambda c: f"Reboot UniFi device {c.get('name', '?')}",
        _match_restart_device, _exec_restart_device,
    ),
]


class Remediator:
    def __init__(self, db: Database, cfg: Config, collectors: dict, notifier):
        self.db = db
        self.cfg = cfg
        self.collectors = collectors
        self.notifier = notifier
        self._specs = {s.id: s for s in SPECS}

    # -- tier policy ------------------------------------------------------------

    def resolve_tier(self, action_id: str, default_tier: str, force_approve: bool) -> str:
        rcfg = self.cfg.remediation
        if rcfg.mode == "off":
            return "off"
        tier = rcfg.overrides.get(action_id, default_tier)
        if tier not in ("auto", "approve", "off"):
            tier = default_tier
        if rcfg.mode == "approve_all" and tier == "auto":
            tier = "approve"
        if force_approve and tier == "auto":
            tier = "approve"
        return tier

    def _cooldown_active(self, action_id: str, target: str, now: float) -> bool:
        last = float(self.db.kv_get(f"act_cd:{action_id}:{target}") or 0)
        return now - last < self.cfg.remediation.auto_cooldown_minutes * 60

    # -- planning -----------------------------------------------------------------

    async def consider(self, incident: dict, check: CheckResult):
        """Returns None | ("auto", row) | ("approve", row) | ("off", label)."""
        now = time.time()
        for spec in SPECS:
            ctx = spec.matcher(check, self)
            if ctx is None:
                continue
            target = ctx.get("name") or ctx.get("mac") or ctx.get("id") or "?"
            force_approve = bool(ctx.get("restart_loop"))
            tier = self.resolve_tier(spec.id, spec.default_tier, force_approve)
            if tier == "off":
                return ("off", spec.label(ctx))
            if tier == "auto" and self._cooldown_active(spec.id, target, now):
                log.info("%s on %s on cooldown — requiring approval", spec.id, target)
                tier = "approve"

            row = self._create_action(spec, ctx, target, tier, incident["id"], now)
            return (tier, row)
        return None

    def _create_action(self, spec: ActionSpec, ctx: dict, target: str, tier: str,
                       incident_id: int, now: float) -> dict:
        token = secrets.token_urlsafe(24)
        expires = now + self.cfg.remediation.approval_ttl_minutes * 60
        status = "approved" if tier == "auto" else "pending"
        cur = self.db.execute(
            "INSERT INTO actions (created, action, target, label, tier, status, incident_id,"
            " token, expires, ctx) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now, spec.id, target, spec.label(ctx), tier, status, incident_id, token, expires,
             json.dumps(ctx)),
        )
        return self.db.query_one("SELECT * FROM actions WHERE id=?", (cur.lastrowid,))

    # -- execution -------------------------------------------------------------------

    async def execute(self, act: dict) -> tuple[bool, str]:
        spec = self._specs.get(act["action"])
        if spec is None:
            return False, f"unknown action {act['action']}"
        ctx = json.loads(act.get("ctx") or "{}")
        now = time.time()
        try:
            detail = await spec.executor(self, ctx)
            ok, status = True, "succeeded"
        except Exception as exc:  # noqa: BLE001
            detail = f"{type(exc).__name__}: {exc}"
            ok, status = False, "failed"
        verify_deadline = (
            now + self.cfg.remediation.verify_minutes * 60 if ok else None
        )
        self.db.execute(
            "UPDATE actions SET status=?, executed=?, result=?, verify_deadline=? WHERE id=?",
            (status, now, detail, verify_deadline, act["id"]),
        )
        self.db.kv_set(f"act_cd:{act['action']}:{act['target']}", str(now))
        log.warning("action %s on %s: %s (%s)", act["action"], act["target"], status, detail)
        self.notifier.action_result(act, ok, detail)
        return ok, detail

    async def approve(self, action_id: int, token: str) -> tuple[bool, str]:
        act = self.db.query_one("SELECT * FROM actions WHERE id=?", (action_id,))
        if not act or not secrets.compare_digest(act.get("token") or "", token):
            return False, "invalid token"
        if act["status"] != "pending":
            return False, f"action already {act['status']}"
        if time.time() > (act["expires"] or 0):
            self.db.execute("UPDATE actions SET status='expired' WHERE id=?", (action_id,))
            return False, "approval window expired"
        self.db.execute("UPDATE actions SET status='approved' WHERE id=?", (action_id,))
        act["status"] = "approved"
        return await self.execute(act)

    async def deny(self, action_id: int, token: str) -> tuple[bool, str]:
        act = self.db.query_one("SELECT * FROM actions WHERE id=?", (action_id,))
        if not act or not secrets.compare_digest(act.get("token") or "", token):
            return False, "invalid token"
        if act["status"] != "pending":
            return False, f"action already {act['status']}"
        self.db.execute("UPDATE actions SET status='denied' WHERE id=?", (action_id,))
        return True, "denied"
