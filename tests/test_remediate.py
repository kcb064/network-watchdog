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


class FakeUnifi:
    def __init__(self):
        self.cycled = []

    async def power_cycle_port(self, switch_mac, port_idx):
        self.cycled.append((switch_mac, port_idx))
        return "cycled"


class FakeHA:
    def __init__(self):
        self.addons = []
        self.calls = []

    async def restart_addon(self, slug):
        self.addons.append(slug)
        return f"add-on {slug} restart requested"

    async def call_service(self, domain, service, data):
        self.calls.append((domain, service, data.get("entity_id")))


def offline_ap_check():
    return CheckResult(
        "unifi.device.Office-AP", FAIL, "offline", severity="warn",
        meta={"name": "UniFi Office AP",
              "remediation": {"kind": "poe_cycle", "name": "Office AP", "mac": "aa:bb",
                              "switch_mac": "cc:dd:ee", "port_idx": 7}},
    )


def test_poe_cycle_defaults_to_approval_then_executes(env):
    db, cfg, docker, rem, incident = env
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    plan = asyncio.run(rem.consider(incident, offline_ap_check()))
    assert plan[0] == "approve"
    ok, detail = asyncio.run(rem.approve(plan[1]["id"], plan[1]["token"]))
    assert ok
    assert unifi.cycled == [("cc:dd:ee", 7)]


def test_poe_cycle_auto_via_override(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["unifi"] = FakeUnifi()
    cfg.remediation.overrides = {"unifi.poe_cycle": "auto"}
    plan = asyncio.run(rem.consider(incident, offline_ap_check()))
    assert plan[0] == "auto"


def test_ha_addon_restart_is_auto(env):
    db, cfg, docker, rem, incident = env
    ha = FakeHA()
    rem.collectors["ha"] = ha
    check = CheckResult(
        "adguard.api", FAIL, "unreachable",
        meta={"remediation": {"kind": "ha_addon_restart", "addon": "a0d7b954_adguard",
                              "name": "AdGuard Home add-on"}},
    )
    plan = asyncio.run(rem.consider(incident, check))
    assert plan[0] == "auto"
    ok, _ = asyncio.run(rem.execute(plan[1]))
    assert ok and ha.addons == ["a0d7b954_adguard"]


def test_wan_power_cycle_off_then_on(env):
    db, cfg, docker, rem, incident = env
    ha = FakeHA()
    rem.collectors["ha"] = ha
    cfg.wan.power_cycle_off_seconds = 0
    cfg.remediation.overrides = {"wan.power_cycle": "auto"}
    check = CheckResult(
        "wan.ping", FAIL, "Internet unreachable",
        meta={"remediation": {"kind": "wan_power_cycle", "entity": "switch.modem_plug",
                              "name": "modem/router power"}},
    )
    plan = asyncio.run(rem.consider(incident, check))
    assert plan[0] == "auto"
    ok, detail = asyncio.run(rem.execute(plan[1]))
    assert ok
    assert ha.calls == [("switch", "turn_off", "switch.modem_plug"),
                        ("switch", "turn_on", "switch.modem_plug")]


def test_wan_power_cycle_needs_ha_collector(env):
    db, cfg, docker, rem, incident = env  # no "ha" collector registered
    check = CheckResult(
        "wan.ping", FAIL, "Internet unreachable",
        meta={"remediation": {"kind": "wan_power_cycle", "entity": "switch.modem_plug"}},
    )
    assert asyncio.run(rem.consider(incident, check)) is None


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
