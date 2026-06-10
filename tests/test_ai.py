"""AI analyst: gating, budgets, bundle building, log demuxing."""
import asyncio
import time

import pytest

from netwatch.ai import Analyst, _clip
from netwatch.collectors.docker_ import demux_docker_logs
from netwatch.config import Config
from netwatch.db import Database


class FakeNotifier:
    def __init__(self):
        self.raws = []

    def raw(self, title, message, priority=3, tags=None, actions=None):
        self.raws.append((title, message))


@pytest.fixture
def env(tmp_path, monkeypatch):
    db = Database(tmp_path / "ai.db")
    cfg = Config()
    cfg.ai.api_key = "sk-test"
    notifier = FakeNotifier()
    analyst = Analyst(db, cfg, notifier, {})

    async def fake_call(bundle):
        analyst.last_bundle = bundle
        return "Probable cause: test diagnosis"

    monkeypatch.setattr(analyst, "_call_claude", fake_call)
    cur = db.execute(
        "INSERT INTO incidents (key, severity, title, detail, opened) VALUES (?,?,?,?,?)",
        ("adguard.api", "critical", "AdGuard Home DOWN", "unreachable", time.time() - 300),
    )
    yield db, cfg, notifier, analyst, cur.lastrowid
    db.close()


def test_disabled_without_key(tmp_path):
    db = Database(tmp_path / "x.db")
    analyst = Analyst(db, Config(), FakeNotifier(), {})
    assert analyst.enabled is False
    assert asyncio.run(analyst.analyze_incident(1, "manual")) is None
    db.close()


def test_analyze_stores_and_notifies(env):
    db, cfg, notifier, analyst, inc_id = env
    text = asyncio.run(analyst.analyze_incident(inc_id, "incident_opened"))
    assert text == "Probable cause: test diagnosis"
    row = db.query_one("SELECT analysis FROM incidents WHERE id=?", (inc_id,))
    assert row["analysis"] == text
    assert any("Analysis" in t for t, _ in notifier.raws)


def test_bundle_contains_context(env):
    db, cfg, notifier, analyst, inc_id = env
    db.execute(
        "INSERT INTO check_states (key,status,severity,since,message,last_seen)"
        " VALUES (?,?,?,?,?,?)",
        ("adguard.api", "fail", "critical", time.time() - 300, "unreachable: refused",
         time.time()),
    )
    db.execute(
        "INSERT INTO actions (created, action, target, tier, status, incident_id, result)"
        " VALUES (?,?,?,?,?,?,?)",
        (time.time() - 200, "adguard.restart_ha_addon", "AdGuard Home add-on", "auto",
         "failed", inc_id, "HTTP 401"),
    )
    asyncio.run(analyst.analyze_incident(inc_id, "fix_failed"))
    b = analyst.last_bundle
    assert "AdGuard Home DOWN" in b
    assert "TRIGGER: fix_failed" in b
    assert "adguard.restart_ha_addon" in b and "HTTP 401" in b
    assert "unreachable: refused" in b
    assert "UNTRUSTED" not in b  # no log sections without collectors


def test_per_incident_gap(env):
    db, cfg, notifier, analyst, inc_id = env
    assert asyncio.run(analyst.analyze_incident(inc_id, "incident_opened")) is not None
    # second automatic analysis within the gap window is suppressed
    assert asyncio.run(analyst.analyze_incident(inc_id, "fix_failed")) is None
    # but a manual (forced) one goes through
    assert asyncio.run(analyst.analyze_incident(inc_id, "manual", force=True)) is not None


def test_daily_cap(env):
    db, cfg, notifier, analyst, inc_id = env
    cfg.ai.max_per_day = 1
    assert asyncio.run(analyst.analyze_incident(inc_id, "incident_opened")) is not None
    cur = db.execute(
        "INSERT INTO incidents (key, severity, title, detail, opened) VALUES (?,?,?,?,?)",
        ("wan.ping", "critical", "Internet DOWN", "all targets", time.time()),
    )
    assert asyncio.run(analyst.analyze_incident(cur.lastrowid, "incident_opened")) is None


def test_clip():
    assert _clip("short", 100) == "short"
    clipped = _clip("x" * 200, 50)
    assert len(clipped) == 51 and clipped.startswith("…")


def test_demux_docker_logs_framed():
    line1 = b"hello from stdout\n"
    line2 = b"error line\n"
    raw = (b"\x01\x00\x00\x00" + len(line1).to_bytes(4, "big") + line1
           + b"\x02\x00\x00\x00" + len(line2).to_bytes(4, "big") + line2)
    assert demux_docker_logs(raw) == "hello from stdout\nerror line\n"


def test_demux_docker_logs_tty_plain():
    raw = b"plain tty output, no framing\n"
    assert demux_docker_logs(raw) == "plain tty output, no framing\n"
