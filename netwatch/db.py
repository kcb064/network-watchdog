"""SQLite persistence: metric samples, check states, incidents, actions, notify queue."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS samples (
    ts REAL NOT NULL,
    metric TEXT NOT NULL,
    labels TEXT NOT NULL DEFAULT '{}',
    value REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_metric_ts ON samples (metric, ts);

CREATE TABLE IF NOT EXISTS check_states (
    key TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'critical',
    since REAL NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    fails INTEGER NOT NULL DEFAULT 0,
    oks INTEGER NOT NULL DEFAULT 0,
    flapping INTEGER NOT NULL DEFAULT 0,
    transitions TEXT NOT NULL DEFAULT '[]',
    incident_id INTEGER,
    last_seen REAL NOT NULL DEFAULT 0,
    meta TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT NOT NULL,
    kind TEXT NOT NULL DEFAULT 'availability',  -- availability | prediction | alert
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    opened REAL NOT NULL,
    closed REAL,
    root_cause TEXT,
    last_notified REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_incidents_open ON incidents (closed, opened);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    tier TEXT NOT NULL,
    status TEXT NOT NULL,  -- pending|approved|denied|expired|succeeded|failed|unresolved
    incident_id INTEGER,
    token TEXT,
    expires REAL,
    executed REAL,
    verify_deadline REAL,
    result TEXT NOT NULL DEFAULT '',
    ctx TEXT NOT NULL DEFAULT '{}',
    reverted REAL
);
CREATE INDEX IF NOT EXISTS idx_actions_status ON actions (status);

CREATE TABLE IF NOT EXISTS notify_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created REAL NOT NULL,
    payload TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    next_attempt REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class Database:
    """Thin synchronous SQLite wrapper; guarded by a lock, safe across asyncio tasks."""

    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._conn.executescript("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")
            self._conn.executescript(SCHEMA)
            # migrations for databases created before a column existed
            try:
                self._conn.execute("ALTER TABLE actions ADD COLUMN reverted REAL")
            except sqlite3.OperationalError:
                pass
            self._conn.commit()

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.execute(sql, params)
            self._conn.commit()
            return cur

    def executemany(self, sql: str, rows: list[tuple]) -> None:
        if not rows:
            return
        with self._lock:
            self._conn.executemany(sql, rows)
            self._conn.commit()

    def query(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return [dict(r) for r in cur.fetchall()]

    def query_one(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        rows = self.query(sql, params)
        return rows[0] if rows else None

    # -- samples ------------------------------------------------------------

    def add_samples(self, samples: list[tuple[float, str, str, float]]) -> None:
        self.executemany(
            "INSERT INTO samples (ts, metric, labels, value) VALUES (?,?,?,?)", samples
        )

    def series(self, metric: str, since: float, labels: dict | None = None) -> list[dict]:
        rows = self.query(
            "SELECT ts, labels, value FROM samples WHERE metric=? AND ts>=? ORDER BY ts",
            (metric, since),
        )
        if labels:
            want = {k: str(v) for k, v in labels.items()}
            rows = [
                r for r in rows
                if all(json.loads(r["labels"]).get(k) == v for k, v in want.items())
            ]
        return rows

    def metric_names(self) -> list[str]:
        return [r["metric"] for r in self.query("SELECT DISTINCT metric FROM samples")]

    def prune(self, retention_days: int) -> None:
        cutoff = time.time() - retention_days * 86400
        self.execute("DELETE FROM samples WHERE ts < ?", (cutoff,))
        self.execute("DELETE FROM incidents WHERE closed IS NOT NULL AND closed < ?", (cutoff,))
        self.execute(
            "DELETE FROM actions WHERE created < ? AND status != 'pending'", (cutoff,)
        )
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")

    # -- kv -------------------------------------------------------------------

    def kv_get(self, key: str, default: str | None = None) -> str | None:
        row = self.query_one("SELECT value FROM kv WHERE key=?", (key,))
        return row["value"] if row else default

    def kv_set(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO kv (key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    def kv_get_json(self, key: str, default: Any = None) -> Any:
        raw = self.kv_get(key)
        return json.loads(raw) if raw is not None else default

    def kv_set_json(self, key: str, value: Any) -> None:
        self.kv_set(key, json.dumps(value))

    def close(self) -> None:
        with self._lock:
            self._conn.close()
