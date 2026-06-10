"""Remediation policy: tier resolution, matching, cooldowns, approval flow."""
import asyncio
import time

import pytest

from netwatch.config import Config
from netwatch.db import Database
from netwatch.models import FAIL, CheckResult
from netwatch.remediate import Remediator


class FakeNotifier:
    def __init__(self):
        self.results = []

    def action_result(self, act, ok, detail):
        self.results.append((act["action"], ok, detail))


class FakeDocker:
    def __init__(self):
        self.restarted = []

    async def restart_container(self, cid):
        self.restarted.append(cid)
        return "restarted"

    async def restart_by_name(self, name):
        self.restarted.append(name)
        return "restarted"


@pytest.fixture
def env(tmp_path):
    db = Database(tmp_path / "t.db")
    cfg = Config()
    docker = FakeDocker()
    rem = Remediator(db, cfg, {"docker": docker}, FakeNotifier())
    incident = {"id": 1}
    yield db, cfg, docker, rem, incident
    db.close()


def crash_check(name="plex"):
    return CheckResult(
        f"docker.container.{name}", FAIL, "crashed", severity="warn",
        meta={"name": f"Container {name}",
              "remediation": {"kind": "restart_container", "id": "abc123",
                              "name": name, "reason": "crashed"}},
    )


def test_tier_resolution_modes():
    db_cfg = Config()
    rem = Remediator.__new__(Remediator)
    rem.cfg = db_cfg

    assert rem.resolve_tier("docker.restart_container", "auto", False) == "auto"
    assert rem.resolve_tier("x", "auto", True) == "approve"  # force_approve

    db_cfg.remediation.mode = "approve_all"
    assert rem.resolve_tier("x", "auto", False) == "approve"

    db_cfg.remediation.mode = "off"
    assert rem.resolve_tier("x", "auto", False) == "off"

    db_cfg.remediation.mode = "tiered"
    db_cfg.remediation.overrides = {"x": "off", "y": "approve"}
    assert rem.resolve_tier("x", "auto", False) == "off"
    assert rem.resolve_tier("y", "auto", False) == "approve"


def test_auto_plan_and_execute(env):
    db, cfg, docker, rem, incident = env
    plan = asyncio.run(rem.consider(incident, crash_check()))
    assert plan is not None and plan[0] == "auto"
    ok, detail = asyncio.run(rem.execute(plan[1]))
    assert ok
    assert docker.restarted == ["abc123"]
    row = db.query_one("SELECT * FROM actions WHERE id=?", (plan[1]["id"],))
    assert row["status"] == "succeeded"
    assert row["verify_deadline"] is not None


def test_restart_loop_forces_approval(env):
    db, cfg, docker, rem, incident = env
    check = crash_check()
    check.meta["remediation"]["restart_loop"] = True
    plan = asyncio.run(rem.consider(incident, check))
    assert plan[0] == "approve"
    assert plan[1]["status"] == "pending"
    assert plan[1]["token"]


def test_never_touch_blocks_match(env):
    db, cfg, docker, rem, incident = env
    cfg.remediation.never_touch = ["plex*"]
    plan = asyncio.run(rem.consider(incident, crash_check("plex")))
    assert plan is None


def test_cooldown_downgrades_to_approval(env):
    db, cfg, docker, rem, incident = env
    db.kv_set("act_cd:docker.restart_container:plex", str(time.time()))
    plan = asyncio.run(rem.consider(incident, crash_check("plex")))
    assert plan[0] == "approve"


def test_approve_flow(env):
    db, cfg, docker, rem, incident = env
    cfg.remediation.mode = "approve_all"
    plan = asyncio.run(rem.consider(incident, crash_check()))
    assert plan[0] == "approve"
    act = plan[1]

    ok, msg = asyncio.run(rem.approve(act["id"], "wrong-token"))
    assert not ok

    ok, msg = asyncio.run(rem.approve(act["id"], act["token"]))
    assert ok
    assert docker.restarted  # executed after approval

    # double-approve rejected
    ok, msg = asyncio.run(rem.approve(act["id"], act["token"]))
    assert not ok and "already" in msg


def test_deny_flow(env):
    db, cfg, docker, rem, incident = env
    cfg.remediation.mode = "approve_all"
    plan = asyncio.run(rem.consider(incident, crash_check()))
    act = plan[1]
    ok, msg = asyncio.run(rem.deny(act["id"], act["token"]))
    assert ok
    assert not docker.restarted
    row = db.query_one("SELECT status FROM actions WHERE id=?", (act["id"],))
    assert row["status"] == "denied"


def test_expired_approval_rejected(env):
    db, cfg, docker, rem, incident = env
    cfg.remediation.mode = "approve_all"
    plan = asyncio.run(rem.consider(incident, crash_check()))
    act = plan[1]
    db.execute("UPDATE actions SET expires=? WHERE id=?", (time.time() - 10, act["id"]))
    ok, msg = asyncio.run(rem.approve(act["id"], act["token"]))
    assert not ok and "expired" in msg


def test_off_mode_returns_suggestion(env):
    db, cfg, docker, rem, incident = env
    cfg.remediation.mode = "off"
    plan = asyncio.run(rem.consider(incident, crash_check()))
    assert plan[0] == "off"
    assert "Restart container" in plan[1]


def test_adguard_grace_gating(env):
    db, cfg, docker, rem, incident = env

    class FakeAdguard:
        async def set_protection(self, enabled):
            return "protection enabled"

    rem.collectors["adguard"] = FakeAdguard()
    check = CheckResult(
        "adguard.protection", FAIL, "disabled", severity="warn",
        meta={"remediation": {"kind": "enable_protection", "eligible": False,
                              "name": "AdGuard protection"}},
    )
    assert asyncio.run(rem.consider(incident, check)) is None
    check.meta["remediation"]["eligible"] = True
    plan = asyncio.run(rem.consider(incident, check))
    assert plan[0] == "auto"
