"""Database housekeeping."""
import time

from netwatch.db import Database


def test_prune_removes_old_keeps_pending(tmp_path):
    db = Database(tmp_path / "p.db")
    old = time.time() - 90 * 86400
    db.add_samples([(old, "m", "{}", 1.0), (time.time(), "m", "{}", 2.0)])
    db.execute(
        "INSERT INTO incidents (key, severity, title, opened, closed) VALUES (?,?,?,?,?)",
        ("k", "warn", "t", old, old + 60),
    )
    db.execute(
        "INSERT INTO actions (created, action, target, tier, status) VALUES (?,?,?,?,?)",
        (old, "a", "t", "auto", "succeeded"),
    )
    db.execute(
        "INSERT INTO actions (created, action, target, tier, status) VALUES (?,?,?,?,?)",
        (old, "a", "t", "approve", "pending"),
    )
    db.prune(retention_days=30)
    assert len(db.query("SELECT * FROM samples")) == 1
    assert db.query("SELECT * FROM incidents") == []
    statuses = [r["status"] for r in db.query("SELECT * FROM actions")]
    assert statuses == ["pending"]
    db.close()


def test_kv_roundtrip(tmp_path):
    db = Database(tmp_path / "kv.db")
    assert db.kv_get("x") is None
    db.kv_set("x", "1")
    assert db.kv_get("x") == "1"
    db.kv_set_json("y", {"a": [1, 2]})
    assert db.kv_get_json("y") == {"a": [1, 2]}
    db.close()
