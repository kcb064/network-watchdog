"""Tiered remediation: match problems to fixes, run safe ones automatically,
ask approval for risky ones, audit everything.

Tiers per action: auto | approve | off
Global modes: tiered (defaults apply) | approve_all | off
"""
from __future__ import annotations

import asyncio
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
    matcher: Callable[[dict, "Remediator"], dict | None]  # (ctx, rem) -> ctx
    executor: Callable  # async (remediator, ctx) -> str
    # Lifeline fixes restore the connectivity that notifications themselves
    # depend on (DNS, WAN, network gear). When repeated, they back off and
    # retry automatically instead of degrading to an approval request that
    # may be undeliverable mid-outage.
    lifeline: bool = False
    # Mitigations (e.g. DNS failover) are undone when their incident closes.
    # They don't claim to resolve the incident, so they skip fix-verification.
    reverter: Callable | None = None  # async (remediator, ctx) -> str
    # verify=False also skips the "fix didn't help" check for actions whose
    # effect is slower than the verify window (e.g. memory-trend restarts).
    verify: bool = True


# -- matchers (receive one remediation ctx dict from the check's ladder) ---------

def _match_restart_container(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "restart_container" or "docker" not in rem.collectors:
        return None
    name = ctx.get("name", "")
    if any(fnmatch.fnmatch(name, pat) for pat in rem.cfg.remediation.never_touch):
        return None
    return dict(ctx)


def _match_enable_protection(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "enable_protection" or "adguard" not in rem.collectors:
        return None
    if not ctx.get("eligible"):
        return None  # grace period not elapsed (or auto re-enable disabled)
    return dict(ctx)


def _match_ha_restart(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "ha_restart" or "docker" not in rem.collectors:
        return None
    if not ctx.get("name"):
        return None
    return dict(ctx)


def _match_restart_device(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "restart_device" or "unifi" not in rem.collectors:
        return None
    if not ctx.get("mac"):
        return None
    return dict(ctx)


def _match_poe_cycle(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "poe_cycle" or "unifi" not in rem.collectors:
        return None
    if not ctx.get("switch_mac") or not ctx.get("port_idx"):
        return None
    return dict(ctx)


def _match_ha_addon_restart(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "ha_addon_restart" or "ha" not in rem.collectors:
        return None
    if not ctx.get("addon"):
        return None
    return dict(ctx)


def _match_wan_power_cycle(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "wan_power_cycle" or "ha" not in rem.collectors:
        return None
    if not ctx.get("entity"):
        return None
    return dict(ctx)


def _match_dns_failover(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "dns_failover" or "unifi" not in rem.collectors:
        return None
    candidates = list(ctx.get("candidates") or [])
    if not candidates and ctx.get("failover_dns"):
        candidates = [ctx["failover_dns"]]
    if not ctx.get("adguard_ip") or not candidates:
        return None
    return dict(ctx, candidates=candidates)


def _match_reload_entries(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "ha_reload_entries" or "ha" not in rem.collectors:
        return None
    if not ctx.get("entries"):
        return None
    return dict(ctx)


def _match_ha_restart_core(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "ha_restart_core" or "ha" not in rem.collectors:
        return None
    return dict(ctx)


def _match_memleak_restart(ctx: dict, rem: "Remediator") -> dict | None:
    if ctx.get("kind") != "memleak_restart" or "docker" not in rem.collectors:
        return None
    name = ctx.get("name", "")
    if not name or any(fnmatch.fnmatch(name, pat)
                       for pat in rem.cfg.remediation.never_touch):
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


async def _exec_poe_cycle(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["unifi"].power_cycle_port(
        ctx["switch_mac"], ctx["port_idx"]
    )


async def _exec_ha_addon_restart(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["ha"].restart_addon(ctx["addon"])


async def _dns_responds(server: str, timeout: float = 3.0) -> bool:
    import dns.asyncresolver

    resolver = dns.asyncresolver.Resolver(configure=False)
    resolver.nameservers = [server]
    resolver.lifetime = timeout
    try:
        await resolver.resolve("example.com", "A")
        return True
    except Exception:  # noqa: BLE001
        return False


async def _pick_dns_candidate(candidates: list[str]) -> str | None:
    """First candidate that actually answers DNS, in preference order."""
    for server in candidates:
        if await _dns_responds(server):
            return server
    return None


async def _exec_dns_failover(rem: "Remediator", ctx: dict) -> str:
    candidates = ctx["candidates"]
    target = await _pick_dns_candidate(candidates)
    if target is None:
        raise RuntimeError(
            f"no failover DNS candidate is answering: {', '.join(candidates)}"
        )
    detail = await rem.collectors["unifi"].dns_failover(ctx["adguard_ip"], target)
    rem.db.kv_set_json("unifi.dns_failover_active", {
        "current": target, "candidates": candidates,
        "adguard_ip": ctx["adguard_ip"], "pending": 0, "pending_target": "",
    })
    return detail


async def _revert_dns_failover(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["unifi"].dns_failback()


async def _exec_reload_entries(rem: "Remediator", ctx: dict) -> str:
    ha = rem.collectors["ha"]
    results = []
    for entry in ctx["entries"][:5]:
        try:
            await ha.reload_config_entry(entry["id"])
            results.append(f"{entry.get('title', entry['id'])}: reloaded")
        except Exception as exc:  # noqa: BLE001 — report per-entry outcomes
            results.append(f"{entry.get('title', entry['id'])}: {exc}")
    return "; ".join(results)


async def _exec_ha_restart_core(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["ha"].restart_core()


async def _exec_memleak_restart(rem: "Remediator", ctx: dict) -> str:
    return await rem.collectors["docker"].restart_by_name(ctx["name"])


async def _exec_wan_power_cycle(rem: "Remediator", ctx: dict) -> str:
    ha = rem.collectors["ha"]
    entity = ctx["entity"]
    domain = entity.split(".", 1)[0]
    off_s = rem.cfg.wan.power_cycle_off_seconds
    await ha.call_service(domain, "turn_off", {"entity_id": entity})
    await asyncio.sleep(off_s)
    # Failing to power back ON would leave the modem dead — retry hard.
    last_exc: Exception | None = None
    for _ in range(4):
        try:
            await ha.call_service(domain, "turn_on", {"entity_id": entity})
            return f"power-cycled {entity} (off {off_s}s, back on)"
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            await asyncio.sleep(5)
    raise RuntimeError(
        f"{entity} was turned OFF but could not be turned back ON: {last_exc}. "
        "Turn it on manually!"
    )


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
        _match_restart_device, _exec_restart_device, lifeline=True,
    ),
    ActionSpec(
        "unifi.poe_cycle", "approve",
        lambda c: f"PoE power-cycle {c.get('name', '?')} "
                  f"(port {c.get('port_idx', '?')} on upstream switch)",
        _match_poe_cycle, _exec_poe_cycle, lifeline=True,
    ),
    ActionSpec(
        "adguard.restart_ha_addon", "auto",
        lambda c: "Restart the AdGuard Home add-on via Home Assistant",
        _match_ha_addon_restart, _exec_ha_addon_restart, lifeline=True,
    ),
    ActionSpec(
        "wan.power_cycle", "approve",
        lambda c: f"Power-cycle the modem/router ({c.get('entity', '?')})",
        _match_wan_power_cycle, _exec_wan_power_cycle, lifeline=True,
    ),
    ActionSpec(
        "unifi.dns_failover", "auto",
        lambda c: "Fail over LAN DNS ("
                  + " → ".join(c.get("candidates") or ["?"])
                  + ", best healthy wins; reverts when AdGuard recovers)",
        _match_dns_failover, _exec_dns_failover, lifeline=True,
        reverter=_revert_dns_failover,
    ),
    ActionSpec(
        "ha.reload_integration", "auto",
        lambda c: "Reload failed HA integration(s): " + ", ".join(
            e.get("title", "?") for e in (c.get("entries") or [])[:5]),
        _match_reload_entries, _exec_reload_entries,
    ),
    ActionSpec(
        "ha.restart_core", "approve",
        lambda c: "Restart Home Assistant Core (integration reloads didn't stick)",
        _match_ha_restart_core, _exec_ha_restart_core,
    ),
    ActionSpec(
        "docker.restart_memleak", "approve",
        lambda c: f"Restart {c.get('name', '?')} to reclaim leaked memory",
        _match_memleak_restart, _exec_memleak_restart, verify=False,
    ),
]


class Remediator:
    def __init__(self, db: Database, cfg: Config, collectors: dict, notifier):
        self.db = db
        self.cfg = cfg
        self.collectors = collectors
        self.notifier = notifier
        self.analyst = None  # set by main; fix failures trigger AI diagnosis
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

    ATTEMPT_WINDOW = 6 * 3600  # attempts older than this no longer count

    def _attempts(self, action_id: str, target: str, now: float) -> list[float]:
        hist = self.db.kv_get_json(f"act_hist:{action_id}:{target}", [])
        return [t for t in hist if now - t < self.ATTEMPT_WINDOW]

    def _record_attempt(self, action_id: str, target: str, now: float) -> None:
        hist = self._attempts(action_id, target, now)
        hist.append(now)
        self.db.kv_set_json(f"act_hist:{action_id}:{target}", hist)

    # -- planning -----------------------------------------------------------------

    @staticmethod
    def _rungs(check: CheckResult) -> list[dict]:
        """The check's remediation ladder: primary fix, then fallbacks."""
        rungs = []
        if check.meta.get("remediation"):
            rungs.append(check.meta["remediation"])
        rungs.extend(check.meta.get("remediation_fallbacks") or [])
        return rungs

    def _match_spec(self, raw_ctx: dict) -> tuple[ActionSpec, dict] | None:
        for spec in SPECS:
            ctx = spec.matcher(dict(raw_ctx), self)
            if ctx is not None:
                return spec, ctx
        return None

    def _spec_blocked(self, incident_id: int, spec: ActionSpec) -> bool:
        """Is this spec already represented for the incident?"""
        rows = self.db.query(
            "SELECT status, reverted FROM actions WHERE incident_id=? AND action=?",
            (incident_id, spec.id),
        )
        for r in rows:
            if r["status"] in ("pending", "approved"):
                return True  # in flight / awaiting human
            if r["status"] == "succeeded" and spec.reverter and not r["reverted"]:
                return True  # mitigation currently active
            if r["status"] == "unresolved" and not spec.lifeline:
                return True  # ran fine, didn't help — don't repeat blindly
        return False

    async def consider(self, incident: dict, check: CheckResult, auto_only: bool = False):
        """Returns None | ("auto", row) | ("approve", row) | ("off", label).

        Walks the check's remediation ladder. A rung yields to the next when
        it is exhausted (attempt budget spent), blocked, or switched off.
        auto_only: used while a check is flapping — only fully-automatic fixes
        may proceed (no silent pending approvals, no notification spam).
        """
        now = time.time()
        rungs = self._rungs(check)
        cooldown = self.cfg.remediation.auto_cooldown_minutes * 60
        max_attempts = self.cfg.remediation.max_auto_attempts

        for i, raw_ctx in enumerate(rungs):
            matched = self._match_spec(raw_ctx)
            if matched is None:
                continue
            spec, ctx = matched
            has_next = i + 1 < len(rungs)
            target = ctx.get("name") or ctx.get("mac") or ctx.get("id") or "?"
            force_approve = bool(ctx.get("restart_loop"))
            tier = self.resolve_tier(spec.id, spec.default_tier, force_approve)
            attempts = self._attempts(spec.id, target, now)
            spent = len(attempts) >= max_attempts

            if tier == "off":
                if has_next:
                    continue
                return ("off", spec.label(ctx))
            if self._spec_blocked(incident["id"], spec):
                # A blocked rung (in flight, active mitigation, or proven
                # unhelpful) yields to the rest of the ladder.
                if has_next:
                    continue
                return None
            if tier == "auto" and attempts:
                if spec.lifeline:
                    # Approval may be undeliverable while DNS/WAN is the thing
                    # that's broken — retry with doubling backoff, hand over to
                    # the next rung when the budget is spent.
                    if spent:
                        if has_next:
                            continue
                        log.warning("%s on %s: %d auto attempts exhausted — "
                                    "requiring approval", spec.id, target, len(attempts))
                        tier = "approve"
                    elif now - max(attempts) < cooldown * 2 ** (len(attempts) - 1):
                        return None  # back off quietly; reconsidered next poll
                elif now - max(attempts) < cooldown:
                    if has_next:
                        continue
                    log.info("%s on %s on cooldown — requiring approval",
                             spec.id, target)
                    tier = "approve"
            if auto_only and tier != "auto":
                if has_next:
                    continue
                return None

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
        # Mitigations (reverter set) don't claim to resolve the incident, so
        # they skip the "fix didn't help" verification.
        verify_deadline = (
            now + self.cfg.remediation.verify_minutes * 60
            if ok and spec.reverter is None and spec.verify else None
        )
        self.db.execute(
            "UPDATE actions SET status=?, executed=?, result=?, verify_deadline=? WHERE id=?",
            (status, now, detail, verify_deadline, act["id"]),
        )
        self._record_attempt(act["action"], act["target"], now)
        log.warning("action %s on %s: %s (%s)", act["action"], act["target"], status, detail)
        self.notifier.action_result(act, ok, detail)
        if not ok and self.analyst and act.get("incident_id"):
            self.analyst.spawn(act["incident_id"], "fix_failed")
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

    async def revert_orphans(self) -> None:
        """Undo mitigations whose incident has closed (e.g. restore AdGuard as
        DHCP DNS once it's healthy again). Runs from the sweeper, so failed
        reverts retry automatically; failures alert at most hourly."""
        rows = self.db.query(
            "SELECT a.* FROM actions a JOIN incidents i ON i.id = a.incident_id "
            "WHERE a.status='succeeded' AND a.reverted IS NULL AND i.closed IS NOT NULL"
        )
        for act in rows:
            spec = self._specs.get(act["action"])
            if spec is None or spec.reverter is None:
                continue
            ctx = json.loads(act.get("ctx") or "{}")
            try:
                detail = await spec.reverter(self, ctx)
            except Exception as exc:  # noqa: BLE001
                self.notifier.event(
                    f"revertfail.{act['id']}", f"Revert FAILED: {act['label']}",
                    f"{type(exc).__name__}: {exc} — will keep retrying.",
                    severity="critical", dedup_minutes=60,
                )
                continue
            self.db.execute(
                "UPDATE actions SET reverted=? WHERE id=?", (time.time(), act["id"])
            )
            log.warning("reverted action %s on %s: %s", act["action"], act["target"], detail)
            self.notifier.raw(f"Reverted: {act['label']}", detail,
                              priority=3, tags=["rewind"])

    async def maintain_failover(self) -> None:
        """While DNS failover is active, keep LAN DNS on the best healthy
        candidate: abandon the current target if it dies, return to a
        preferred (earlier) candidate when it recovers. Two consecutive
        sweeps must agree before re-pointing (damping)."""
        state = self.db.kv_get_json("unifi.dns_failover_active") or {}
        if not state.get("current") or "unifi" not in self.collectors:
            return
        best = await _pick_dns_candidate(state["candidates"])
        if best is None or best == state["current"]:
            state["pending"], state["pending_target"] = 0, ""
            self.db.kv_set_json("unifi.dns_failover_active", state)
            return
        if state.get("pending_target") == best:
            state["pending"] = state.get("pending", 0) + 1
        else:
            state["pending"], state["pending_target"] = 1, best
        if state["pending"] >= 2:
            previous = state["current"]
            detail = await self.collectors["unifi"].dns_failover(
                state["adguard_ip"], best
            )
            state = {"current": best, "candidates": state["candidates"],
                     "adguard_ip": state["adguard_ip"],
                     "pending": 0, "pending_target": ""}
            log.warning("DNS failover re-pointed %s -> %s", previous, best)
            self.notifier.raw(
                f"DNS failover re-pointed: {previous} → {best}", detail,
                priority=4, tags=["arrows_counterclockwise"],
            )
        self.db.kv_set_json("unifi.dns_failover_active", state)

    async def deny(self, action_id: int, token: str) -> tuple[bool, str]:
        act = self.db.query_one("SELECT * FROM actions WHERE id=?", (action_id,))
        if not act or not secrets.compare_digest(act.get("token") or "", token):
            return False, "invalid token"
        if act["status"] != "pending":
            return False, f"action already {act['status']}"
        self.db.execute("UPDATE actions SET status='denied' WHERE id=?", (action_id,))
        return True, "denied"
