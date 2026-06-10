"""Notifier: durations, dedup, queueing, approval buttons."""
import json
import time

import pytest

from netwatch.config import Config
from netwatch.db import Database
from netwatch.notify import Notifier, human_duration


@pytest.fixture
def notifier(tmp_path):
    db = Database(tmp_path / "n.db")
    cfg = Config()
    cfg.ntfy.topic = "test-topic"
    cfg.server.public_url = "http://nas:8787"
    n = Notifier(db, cfg)
    yield db, n
    db.close()


def test_human_duration():
    assert human_duration(45) == "45s"
    assert human_duration(300) == "5m"
    assert human_duration(7200) == "2.0h"
    assert human_duration(200000) == "2.3d"


def test_enqueue_and_payload(notifier):
    db, n = notifier
    n.raw("Title", "Message", priority=5, tags=["rotating_light"])
    rows = db.query("SELECT * FROM notify_queue")
    assert len(rows) == 1
    payload = json.loads(rows[0]["payload"])
    assert payload["topic"] == "test-topic"
    assert payload["priority"] == 5
    assert payload["click"] == "http://nas:8787"


def test_disabled_does_not_queue(tmp_path):
    db = Database(tmp_path / "n2.db")
    cfg = Config()  # no topic set
    n = Notifier(db, cfg)
    n.raw("T", "M")
    assert db.query("SELECT * FROM notify_queue") == []
    db.close()


def test_event_dedup(notifier):
    db, n = notifier
    n.event("k1", "Title", "msg", dedup_minutes=60)
    n.event("k1", "Title", "msg", dedup_minutes=60)
    assert len(db.query("SELECT * FROM notify_queue")) == 1
    # different key still goes through
    n.event("k2", "Title", "msg")
    assert len(db.query("SELECT * FROM notify_queue")) == 2


def test_incident_opened_with_approval_buttons(notifier):
    db, n = notifier
    inc = {"id": 1, "key": "docker.container.plex", "kind": "availability",
           "severity": "warn", "title": "Container plex DOWN", "detail": "crashed",
           "opened": time.time()}
    act = {"id": 9, "token": "tok123", "label": "Restart container plex",
           "expires": time.time() + 3600}
    n.incident_opened(inc, approval=act)
    payload = json.loads(db.query("SELECT * FROM notify_queue")[0]["payload"])
    assert "actions" in payload
    urls = [a["url"] for a in payload["actions"]]
    assert any("/api/actions/9/approve?token=tok123" in u for u in urls)
    assert any("/api/actions/9/deny" in u for u in urls)


def test_incident_opened_without_public_url(tmp_path):
    db = Database(tmp_path / "n3.db")
    cfg = Config()
    cfg.ntfy.topic = "t"
    n = Notifier(db, cfg)
    inc = {"id": 1, "key": "k", "kind": "availability", "severity": "critical",
           "title": "X DOWN", "detail": "d", "opened": time.time()}
    act = {"id": 2, "token": "t", "label": "Fix it", "expires": time.time() + 60}
    n.incident_opened(inc, approval=act)
    payload = json.loads(db.query("SELECT * FROM notify_queue")[0]["payload"])
    assert "actions" not in payload
    assert "dashboard" in payload["message"].lower()
    db.close()


def test_recovery_notification_toggle(notifier):
    db, n = notifier
    n.cfg.ntfy.notify_recoveries = False
    inc = {"id": 1, "title": "X", "opened": time.time() - 100, "closed": time.time()}
    n.incident_closed(inc)
    assert db.query("SELECT * FROM notify_queue") == []
