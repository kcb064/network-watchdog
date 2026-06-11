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
        self.raws = []
        self.events = []

    def action_result(self, act, ok, detail):
        self.results.append((act["action"], ok, detail))

    def raw(self, title, message, priority=3, tags=None, actions=None):
        self.raws.append(title)

    def event(self, key, title, message, severity="info", dedup_minutes=1440):
        self.events.append(title)


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
    db.kv_set_json("act_hist:docker.restart_container:plex", [time.time()])
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
        self.failovers = []
        self.failbacks = 0

    async def power_cycle_port(self, switch_mac, port_idx):
        self.cycled.append((switch_mac, port_idx))
        return "cycled"

    async def dns_failover(self, dns_ip, failover_dns):
        self.failovers.append((dns_ip, failover_dns))
        return "failed over"

    async def dns_failback(self):
        self.failbacks += 1
        return "restored"


class FakeHA:
    def __init__(self):
        self.addons = []
        self.calls = []
        self.reloaded = []
        self.core_restarts = 0

    async def restart_addon(self, slug):
        self.addons.append(slug)
        return f"add-on {slug} restart requested"

    async def call_service(self, domain, service, data):
        self.calls.append((domain, service, data.get("entity_id")))

    async def reload_config_entry(self, entry_id):
        self.reloaded.append(entry_id)

    async def restart_core(self):
        self.core_restarts += 1
        return "Home Assistant Core restart requested"


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


def test_auto_only_allows_auto_tier(env):
    db, cfg, docker, rem, incident = env
    plan = asyncio.run(rem.consider(incident, crash_check(), auto_only=True))
    assert plan is not None and plan[0] == "auto"


def test_auto_only_skips_approval_tier_without_creating_action(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["unifi"] = FakeUnifi()
    plan = asyncio.run(rem.consider(incident, offline_ap_check(), auto_only=True))
    assert plan is None
    assert db.query("SELECT * FROM actions") == []  # no silent pending row


def test_auto_only_respects_cooldown(env):
    db, cfg, docker, rem, incident = env
    db.kv_set_json("act_hist:docker.restart_container:plex", [time.time()])
    plan = asyncio.run(rem.consider(incident, crash_check(), auto_only=True))
    assert plan is None


def addon_down_check():
    return CheckResult(
        "adguard.api", FAIL, "unreachable",
        meta={"remediation": {"kind": "ha_addon_restart", "addon": "a0d7b954_adguard",
                              "name": "AdGuard Home add-on"}},
    )


def test_lifeline_backs_off_instead_of_asking(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["ha"] = FakeHA()
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on",
                   [time.time() - 60])  # 1 min ago, cooldown is 30 min
    plan = asyncio.run(rem.consider(incident, addon_down_check()))
    assert plan is None  # waiting, NOT downgraded to an undeliverable approval
    assert db.query("SELECT * FROM actions") == []


def test_lifeline_retries_auto_after_backoff(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["ha"] = FakeHA()
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on",
                   [time.time() - 31 * 60])  # past the 30-min gap
    plan = asyncio.run(rem.consider(incident, addon_down_check()))
    assert plan is not None and plan[0] == "auto"


def test_lifeline_second_gap_doubles(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["ha"] = FakeHA()
    now = time.time()
    # two attempts; second was 45 min ago — required gap is now 60 min
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on",
                   [now - 120 * 60, now - 45 * 60])
    assert asyncio.run(rem.consider(incident, addon_down_check())) is None
    # ...but a 61-min-old second attempt clears it
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on",
                   [now - 120 * 60, now - 61 * 60])
    plan = asyncio.run(rem.consider(incident, addon_down_check()))
    assert plan is not None and plan[0] == "auto"


def test_lifeline_exhausted_falls_back_to_approval(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["ha"] = FakeHA()
    now = time.time()
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on",
                   [now - 3 * 3600, now - 2 * 3600, now - 3600])
    plan = asyncio.run(rem.consider(incident, addon_down_check()))
    assert plan is not None and plan[0] == "approve"


def chained_adguard_check():
    return CheckResult(
        "adguard.api", FAIL, "unreachable",
        meta={
            "name": "AdGuard Home",
            "remediation": {"kind": "ha_addon_restart", "addon": "a0d7b954_adguard",
                            "name": "AdGuard Home add-on"},
            "remediation_fallbacks": [
                {"kind": "dns_failover", "adguard_ip": "192.168.1.28",
                 "failover_dns": "1.1.1.1", "name": "LAN DNS"},
            ],
        },
    )


def seed_restart_attempts(db, when: list[float]):
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on", when)


def patch_dns_health(monkeypatch, healthy: set):
    async def fake_responds(server, timeout=3.0):
        return server in healthy

    monkeypatch.setattr("netwatch.remediate._dns_responds", fake_responds)


def test_chain_advances_to_dns_failover_when_restarts_exhausted(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    patch_dns_health(monkeypatch, {"1.1.1.1"})
    rem.collectors["ha"] = FakeHA()
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    now = time.time()
    seed_restart_attempts(db, [now - 3 * 3600, now - 2 * 3600, now - 3600])
    plan = asyncio.run(rem.consider(incident, chained_adguard_check()))
    assert plan is not None and plan[0] == "auto"
    assert plan[1]["action"] == "unifi.dns_failover"
    ok, _ = asyncio.run(rem.execute(plan[1]))
    assert ok and unifi.failovers == [("192.168.1.28", "1.1.1.1")]
    row = db.query_one("SELECT * FROM actions WHERE id=?", (plan[1]["id"],))
    assert row["verify_deadline"] is None  # mitigation: no "didn't help" alarm


def multi_candidate_check():
    return CheckResult(
        "adguard.api", FAIL, "unreachable",
        meta={
            "name": "AdGuard Home",
            "remediation_fallbacks": [
                {"kind": "dns_failover", "adguard_ip": "192.168.1.28",
                 "candidates": ["192.168.1.250", "1.1.1.1"], "name": "LAN DNS"},
            ],
        },
    )


def test_failover_picks_first_healthy_candidate(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    patch_dns_health(monkeypatch, {"192.168.1.250", "1.1.1.1"})
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    plan = asyncio.run(rem.consider(incident, multi_candidate_check()))
    assert plan is not None and plan[0] == "auto"
    ok, _ = asyncio.run(rem.execute(plan[1]))
    assert ok and unifi.failovers == [("192.168.1.28", "192.168.1.250")]
    state = db.kv_get_json("unifi.dns_failover_active")
    assert state["current"] == "192.168.1.250"


def test_failover_skips_dead_candidate(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    patch_dns_health(monkeypatch, {"1.1.1.1"})  # secondary AdGuard also down
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    plan = asyncio.run(rem.consider(incident, multi_candidate_check()))
    ok, _ = asyncio.run(rem.execute(plan[1]))
    assert ok and unifi.failovers == [("192.168.1.28", "1.1.1.1")]


def test_failover_fails_when_nothing_answers(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    patch_dns_health(monkeypatch, set())
    rem.collectors["unifi"] = FakeUnifi()
    plan = asyncio.run(rem.consider(incident, multi_candidate_check()))
    ok, detail = asyncio.run(rem.execute(plan[1]))
    assert not ok and "no failover DNS candidate" in detail


def seed_active_failover(db, current: str):
    db.kv_set_json("unifi.dns_failover_active", {
        "current": current, "candidates": ["192.168.1.250", "1.1.1.1"],
        "adguard_ip": "192.168.1.28", "pending": 0, "pending_target": "",
    })


def test_maintain_failover_escalates_when_target_dies(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    seed_active_failover(db, "192.168.1.250")
    patch_dns_health(monkeypatch, {"1.1.1.1"})  # current target went dark
    asyncio.run(rem.maintain_failover())
    assert unifi.failovers == []  # damping: first strike only
    asyncio.run(rem.maintain_failover())
    assert unifi.failovers == [("192.168.1.28", "1.1.1.1")]
    assert db.kv_get_json("unifi.dns_failover_active")["current"] == "1.1.1.1"
    assert any("re-pointed" in t for t in rem.notifier.raws)


def test_maintain_failover_upgrades_back_to_preferred(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    seed_active_failover(db, "1.1.1.1")
    patch_dns_health(monkeypatch, {"192.168.1.250", "1.1.1.1"})  # secondary is back
    asyncio.run(rem.maintain_failover())
    asyncio.run(rem.maintain_failover())
    assert unifi.failovers == [("192.168.1.28", "192.168.1.250")]


def test_maintain_failover_steady_state_noop(env, monkeypatch):
    db, cfg, docker, rem, incident = env
    rem.collectors["unifi"] = FakeUnifi()
    seed_active_failover(db, "192.168.1.250")
    patch_dns_health(monkeypatch, {"192.168.1.250", "1.1.1.1"})
    asyncio.run(rem.maintain_failover())
    asyncio.run(rem.maintain_failover())
    assert rem.collectors["unifi"].failovers == []


def test_chain_does_not_advance_before_exhaustion(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["ha"] = FakeHA()
    rem.collectors["unifi"] = FakeUnifi()
    seed_restart_attempts(db, [time.time() - 60])  # one recent attempt: backing off
    assert asyncio.run(rem.consider(incident, chained_adguard_check())) is None


def test_restarts_resume_while_failover_active(env):
    db, cfg, docker, rem, incident = env
    ha = FakeHA()
    rem.collectors["ha"] = ha
    rem.collectors["unifi"] = FakeUnifi()
    now = time.time()
    # failover already active for this incident
    db.execute(
        "INSERT INTO actions (created, action, target, tier, status, incident_id, ctx)"
        " VALUES (?,?,?,?,?,?,?)",
        (now - 3600, "unifi.dns_failover", "LAN DNS", "auto", "succeeded",
         incident["id"], "{}"),
    )
    # restart attempts exhausted and still recent -> nothing fires
    seed_restart_attempts(db, [now - 3 * 3600, now - 2 * 3600, now - 3600])
    assert asyncio.run(rem.consider(incident, chained_adguard_check())) is None
    # attempts age out -> restart retries resume (failover rung stays blocked)
    seed_restart_attempts(db, [now - 9 * 3600, now - 8 * 3600, now - 7 * 3600])
    plan = asyncio.run(rem.consider(incident, chained_adguard_check()))
    assert plan is not None and plan[0] == "auto"
    assert plan[1]["action"] == "adguard.restart_ha_addon"


def test_revert_orphans_restores_dns(env):
    db, cfg, docker, rem, incident = env
    unifi = FakeUnifi()
    rem.collectors["unifi"] = unifi
    now = time.time()
    cur = db.execute(
        "INSERT INTO incidents (key, severity, title, opened, closed)"
        " VALUES (?,?,?,?,?)",
        ("adguard.api", "critical", "AdGuard Home DOWN", now - 7200, now - 60),
    )
    db.execute(
        "INSERT INTO actions (created, action, target, label, tier, status, incident_id, ctx)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (now - 7000, "unifi.dns_failover", "LAN DNS", "Fail over LAN DNS to 1.1.1.1",
         "auto", "succeeded", cur.lastrowid, "{}"),
    )
    asyncio.run(rem.revert_orphans())
    assert unifi.failbacks == 1
    row = db.query_one("SELECT reverted FROM actions WHERE action='unifi.dns_failover'")
    assert row["reverted"] is not None
    assert any("Reverted" in t for t in rem.notifier.raws)
    # second sweep is a no-op
    asyncio.run(rem.revert_orphans())
    assert unifi.failbacks == 1


def test_lifeline_old_attempts_age_out(env):
    db, cfg, docker, rem, incident = env
    rem.collectors["ha"] = FakeHA()
    now = time.time()
    db.kv_set_json("act_hist:adguard.restart_ha_addon:AdGuard Home add-on",
                   [now - 7 * 3600, now - 8 * 3600, now - 9 * 3600])  # outside 6 h window
    plan = asyncio.run(rem.consider(incident, addon_down_check()))
    assert plan is not None and plan[0] == "auto"


def test_wan_power_cycle_needs_ha_collector(env):
    db, cfg, docker, rem, incident = env  # no "ha" collector registered
    check = CheckResult(
        "wan.ping", FAIL, "Internet unreachable",
        meta={"remediation": {"kind": "wan_power_cycle", "entity": "switch.modem_plug"}},
    )
    assert asyncio.run(rem.consider(incident, check)) is None


def integrations_check():
    return CheckResult(
        "ha.integrations", FAIL, "2 integrations failed", severity="warn",
        meta={"name": "HA integrations",
              "remediation": {"kind": "ha_reload_entries", "name": "HA integrations",
                              "entries": [{"id": "e1", "title": "Plex"},
                                          {"id": "e2", "title": "UniFi"}]},
              "remediation_fallbacks": [{"kind": "ha_restart_core",
                                         "name": "Home Assistant core"}]},
    )


def test_reload_integrations_auto_then_executes(env):
    db, cfg, docker, rem, incident = env
    ha = FakeHA()
    rem.collectors["ha"] = ha
    plan = asyncio.run(rem.consider(incident, integrations_check()))
    assert plan is not None and plan[0] == "auto"
    ok, detail = asyncio.run(rem.execute(plan[1]))
    assert ok
    assert ha.reloaded == ["e1", "e2"]


def test_ladder_advances_past_unresolved_reload_to_core_restart(env):
    db, cfg, docker, rem, incident = env
    ha = FakeHA()
    rem.collectors["ha"] = ha
    # rung 1 already ran and didn't help
    db.execute(
        "INSERT INTO actions (created, action, target, tier, status, incident_id)"
        " VALUES (?,?,?,?,?,?)",
        (time.time() - 900, "ha.reload_integration", "HA integrations", "auto",
         "unresolved", incident["id"]),
    )
    db.kv_set_json("act_hist:ha.reload_integration:HA integrations",
                   [time.time() - 900])
    plan = asyncio.run(rem.consider(incident, integrations_check()))
    assert plan is not None and plan[0] == "approve"
    assert plan[1]["action"] == "ha.restart_core"
    ok, _ = asyncio.run(rem.approve(plan[1]["id"], plan[1]["token"]))
    assert ok and ha.core_restarts == 1


def test_memleak_restart_defaults_to_approval_and_skips_verify(env):
    db, cfg, docker, rem, incident = env
    check = CheckResult(
        "predict.memleak.plex", FAIL, "leaking", severity="warn",
        meta={"name": "Container plex",
              "remediation": {"kind": "memleak_restart", "name": "plex"}},
    )
    plan = asyncio.run(rem.consider(incident, check))
    assert plan is not None and plan[0] == "approve"
    ok, _ = asyncio.run(rem.approve(plan[1]["id"], plan[1]["token"]))
    assert ok and docker.restarted == ["plex"]
    row = db.query_one("SELECT verify_deadline FROM actions WHERE id=?", (plan[1]["id"],))
    assert row["verify_deadline"] is None  # trend recovers slower than verify window


def test_memleak_restart_respects_never_touch(env):
    db, cfg, docker, rem, incident = env
    cfg.remediation.never_touch = ["plex"]
    check = CheckResult(
        "predict.memleak.plex", FAIL, "leaking", severity="warn",
        meta={"remediation": {"kind": "memleak_restart", "name": "plex"}},
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
