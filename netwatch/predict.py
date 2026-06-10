"""Predictive checks: spot problems before they happen.

- Disk fill: linear trend on pool usage → "pool full in ~N days" warnings
- Memory leaks: steadily climbing container RSS projected against host RAM
- WAN latency degradation: recent latency vs. 7-day baseline (z-score)

All math is plain least-squares / mean-std — no external deps, unit-testable.
"""
from __future__ import annotations

import json
import logging
import math
import time
from collections import defaultdict

log = logging.getLogger("netwatch.predict")

LEAK_WARN_DAYS = 7.0   # warn when a leak would exhaust host RAM within a week
HOST_RAM_CEILING = 0.9  # treat 90% of host RAM as "exhausted"


# -- pure math ------------------------------------------------------------------

def linear_fit(points: list[tuple[float, float]]) -> tuple[float, float, float]:
    """Least squares over (ts, value). Returns (slope_per_sec, intercept, r2)."""
    n = len(points)
    if n < 2:
        return 0.0, points[0][1] if points else 0.0, 0.0
    t0 = points[0][0]
    xs = [p[0] - t0 for p in points]
    ys = [p[1] for p in points]
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    if sxx == 0:
        return 0.0, my, 0.0
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    slope = sxy / sxx
    intercept = my - slope * mx
    ss_tot = sum((y - my) ** 2 for y in ys)
    if ss_tot == 0:
        return slope, intercept, 1.0
    ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(xs, ys))
    return slope, intercept, max(0.0, 1 - ss_res / ss_tot)


def fill_eta_days(points: list[tuple[float, float]], capacity: float,
                  min_points: int = 12, min_span_hours: float = 24.0,
                  min_r2: float = 0.5) -> float | None:
    """Days until `capacity` is reached at the current linear growth rate."""
    if len(points) < min_points or capacity <= 0:
        return None
    span = points[-1][0] - points[0][0]
    if span < min_span_hours * 3600:
        return None
    slope, _, r2 = linear_fit(points)
    if slope <= 0 or r2 < min_r2:
        return None
    remaining = capacity - points[-1][1]
    if remaining <= 0:
        return 0.0
    return remaining / slope / 86400


def mean_std(values: list[float]) -> tuple[float, float]:
    n = len(values)
    if n == 0:
        return 0.0, 0.0
    m = sum(values) / n
    var = sum((v - m) ** 2 for v in values) / n
    return m, math.sqrt(var)


def latency_anomaly(baseline: list[float], recent: list[float],
                    z_threshold: float = 3.0) -> tuple[bool, str]:
    """True when recent latency is statistically and practically elevated."""
    if len(baseline) < 50 or len(recent) < 5:
        return False, "insufficient data"
    bm, bs = mean_std(baseline)
    rm, _ = mean_std(recent)
    if bs == 0:
        return False, "flat baseline"
    z = (rm - bm) / bs
    elevated = z >= z_threshold and rm >= bm * 1.5 and rm - bm >= 5.0
    msg = f"recent avg {rm:.0f} ms vs baseline {bm:.0f}±{bs:.0f} ms (z={z:.1f})"
    return elevated, msg


# -- prediction incident management ------------------------------------------------

def _manage(engine, key: str, active: bool, title: str, detail: str,
            metric_value: float | None = None) -> None:
    """Open/refresh/close a prediction incident; re-notify only if it worsens 25%."""
    db = engine.db
    inc = db.query_one(
        "SELECT * FROM incidents WHERE key=? AND closed IS NULL", (key,)
    )
    sig_key = f"predict_sig:{key}"
    if active and inc is None:
        inc_id = engine.open_incident(key, "prediction", "warn", title, detail, notify=True)
        inc = db.query_one("SELECT * FROM incidents WHERE id=?", (inc_id,))
        engine.notifier.incident_opened(inc)
        if metric_value is not None:
            db.kv_set(sig_key, str(metric_value))
    elif active and inc is not None:
        db.execute("UPDATE incidents SET detail=?, title=? WHERE id=?",
                   (detail, title, inc["id"]))
        last = db.kv_get(sig_key)
        if metric_value is not None and last is not None and metric_value < float(last) * 0.75:
            engine.notifier.raw(f"Worsening: {title}", detail, priority=4,
                                tags=["crystal_ball"])
            db.kv_set(sig_key, str(metric_value))
            db.execute("UPDATE incidents SET last_notified=? WHERE id=?",
                       (time.time(), inc["id"]))
    elif not active and inc is not None:
        engine.close_incident(inc["id"])
        engine.notifier.incident_closed(inc, annotation=" — trend back to normal")


def _series_by_label(db, metric: str, since: float, label: str) -> dict[str, list]:
    groups: dict[str, list[tuple[float, float]]] = defaultdict(list)
    for row in db.query(
        "SELECT ts, labels, value FROM samples WHERE metric=? AND ts>=? ORDER BY ts",
        (metric, since),
    ):
        name = json.loads(row["labels"]).get(label, "")
        groups[name].append((row["ts"], row["value"]))
    return groups


# -- main entry ---------------------------------------------------------------------

def run(engine) -> None:
    cfg = engine.cfg.predictions
    if not cfg.enabled:
        return
    now = time.time()
    _disk_fill(engine, now, cfg)
    _memory_leaks(engine, now, cfg)
    _wan_latency(engine, now, cfg)


def _disk_fill(engine, now: float, cfg) -> None:
    db = engine.db
    used = _series_by_label(db, "truenas.pool.used_bytes", now - 7 * 86400, "pool")
    sizes = _series_by_label(db, "truenas.pool.size_bytes", now - 7 * 86400, "pool")
    for pool, points in used.items():
        size_points = sizes.get(pool)
        if not size_points:
            continue
        capacity = size_points[-1][1]
        eta = fill_eta_days(points, capacity, cfg.disk_min_points, 24.0)
        active = eta is not None and eta < cfg.disk_warn_days
        if eta is not None:
            log.info("pool %s fill ETA: %.1f days", pool, eta)
        used_pct = points[-1][1] / capacity * 100 if capacity else 0
        detail = (
            f"Pool '{pool}' is {used_pct:.0f}% full and trending to 100% in "
            f"~{eta:.1f} days at the current growth rate. Free up space or expand "
            f"before ZFS performance degrades." if eta is not None else ""
        )
        _manage(engine, f"predict.disk.{pool}", active,
                f"Pool {pool} filling up (~{eta:.0f}d left)" if eta is not None else
                f"Pool {pool} fill trend", detail, metric_value=eta)


def _memory_leaks(engine, now: float, cfg) -> None:
    db = engine.db
    window = cfg.mem_leak_window_hours * 3600
    series = _series_by_label(db, "docker.container.mem_bytes", now - window, "name")
    host_rows = db.query(
        "SELECT value FROM samples WHERE metric='truenas.host.mem_total_bytes' "
        "ORDER BY ts DESC LIMIT 1"
    )
    if not host_rows:
        return
    host_total = host_rows[0]["value"]
    for name, points in series.items():
        if len(points) < 12 or points[-1][0] - points[0][0] < window * 0.5:
            continue
        slope, _, r2 = linear_fit(points)
        if slope <= 0 or r2 < cfg.mem_leak_min_r2:
            _manage(engine, f"predict.memleak.{name}", False, "", "")
            continue
        per_hour = slope * 3600
        if per_hour < 512 * 1024:  # ignore < 0.5 MB/h drift
            _manage(engine, f"predict.memleak.{name}", False, "", "")
            continue
        current = points[-1][1]
        eta_days = (host_total * HOST_RAM_CEILING - current) / slope / 86400
        active = 0 <= eta_days < LEAK_WARN_DAYS
        detail = (
            f"Container '{name}' memory is climbing steadily "
            f"(+{per_hour / 1024 / 1024:.0f} MB/h, fit r²={r2:.2f}, "
            f"now {current / 1024 / 1024:.0f} MB). At this rate host RAM is exhausted in "
            f"~{eta_days:.1f} days. Likely a memory leak — a restart will reclaim it."
        )
        _manage(engine, f"predict.memleak.{name}", active,
                f"Possible memory leak: {name}", detail, metric_value=eta_days)


def _wan_latency(engine, now: float, cfg) -> None:
    db = engine.db
    rows = db.query(
        "SELECT ts, value FROM samples WHERE metric='wan.ping.latency_ms' AND ts>=? ORDER BY ts",
        (now - 7 * 86400,),
    )
    hour_ago = now - 3600
    baseline = [r["value"] for r in rows if r["ts"] < hour_ago]
    recent = [r["value"] for r in rows if r["ts"] >= hour_ago]
    elevated, msg = latency_anomaly(baseline, recent, cfg.latency_z_threshold)
    detail = (
        f"Internet latency is significantly above normal: {msg}. "
        "Possible ISP degradation, line trouble, or local congestion."
    )
    _manage(engine, "predict.wan.latency", elevated, "Internet latency degrading", detail)
