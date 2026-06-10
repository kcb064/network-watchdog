"""FastAPI app: dashboard, JSON API, and approval endpoints."""
from __future__ import annotations

import json
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from . import __version__

GROUPS = [
    ("wan", "Internet"),
    ("unifi", "UniFi Network"),
    ("ha", "Home Assistant"),
    ("adguard", "AdGuard Home"),
    ("docker", "Docker"),
    ("truenas", "TrueNAS"),
    ("watchdog", "Watchdog"),
]

_basic = HTTPBasic(auto_error=False)


def create_app(engine) -> FastAPI:
    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await engine.start()
        try:
            yield
        finally:
            await engine.stop()
            for col in engine.collectors.values():
                await col.aclose()
            await engine.notifier.aclose()

    app = FastAPI(title="Network Watchdog", version=__version__, lifespan=lifespan)
    app.state.engine = engine
    base = Path(__file__).parent
    templates = Jinja2Templates(directory=str(base / "templates"))
    app.mount("/static", StaticFiles(directory=str(base / "static")), name="static")

    def auth(credentials: HTTPBasicCredentials | None = Depends(_basic)) -> None:
        password = engine.cfg.server.password
        if not password:
            return
        if credentials is None or not (
            secrets.compare_digest(credentials.username, "admin")
            and secrets.compare_digest(credentials.password, password)
        ):
            raise HTTPException(
                status_code=401, headers={"WWW-Authenticate": "Basic realm=netwatch"}
            )

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    @app.get("/", dependencies=[Depends(auth)])
    def index(request: Request):
        return templates.TemplateResponse(
            request, "index.html", {"version": __version__}
        )

    @app.get("/api/overview", dependencies=[Depends(auth)])
    def overview():
        db = engine.db
        now = time.time()
        states = db.query("SELECT * FROM check_states ORDER BY key")
        rank = {"fail": 2, "warn": 1, "ok": 0}
        groups = []
        for gid, label in GROUPS:
            checks = [s for s in states if s["key"].split(".", 1)[0] == gid
                      or (gid == "watchdog" and s["key"].startswith("watchdog."))]
            if not checks and gid != "wan":
                continue
            for c in checks:
                c["meta"] = json.loads(c.get("meta") or "{}")
                c.pop("transitions", None)
            worst = max((rank.get(c["status"], 0) for c in checks), default=0)
            groups.append({
                "id": gid, "label": label,
                "status": {2: "fail", 1: "warn", 0: "ok"}[worst],
                "checks": checks,
            })

        open_inc = db.query(
            "SELECT * FROM incidents WHERE closed IS NULL ORDER BY opened DESC"
        )
        recent = db.query(
            "SELECT * FROM incidents WHERE closed IS NOT NULL ORDER BY closed DESC LIMIT 15"
        )
        approvals = db.query(
            "SELECT id, created, action, target, label, expires, token FROM actions "
            "WHERE status='pending' AND expires > ? ORDER BY created DESC", (now,),
        )
        audit = db.query(
            "SELECT id, created, action, target, label, tier, status, executed, result "
            "FROM actions ORDER BY created DESC LIMIT 30"
        )
        queue = db.query_one("SELECT COUNT(*) AS n FROM notify_queue")

        metric_latest = {}
        for name in [
            "wan.ping.latency_ms", "unifi.clients", "unifi.devices_upgradable",
            "ha.entities_total", "ha.entities_unavailable", "ha.updates_available",
            "ha.api_latency_ms", "adguard.queries_24h", "adguard.blocked_pct",
            "adguard.avg_processing_ms", "docker.containers_running",
            "docker.containers_total", "truenas.host.cpu_pct", "truenas.host.mem_pct",
            "truenas.pool.used_pct", "unifi.www.xput_down_mbps",
        ]:
            rows = db.query(
                "SELECT ts, labels, value FROM samples WHERE metric=? AND ts >= ? "
                "ORDER BY ts DESC LIMIT 12", (name, now - 1800),
            )
            seen: dict[str, dict] = {}
            for r in rows:
                if r["labels"] not in seen:
                    seen[r["labels"]] = {"labels": json.loads(r["labels"]),
                                         "value": r["value"], "ts": r["ts"]}
            if seen:
                metric_latest[name] = list(seen.values())

        return {
            "app": {
                "version": __version__, "now": now, "started": engine.started,
                "ntfy": engine.notifier.enabled, "notify_queue": queue["n"] if queue else 0,
            },
            "groups": groups,
            "incidents": {"open": open_inc, "recent": recent},
            "approvals": approvals,
            "audit": audit,
            "metrics": metric_latest,
        }

    @app.get("/api/metrics", dependencies=[Depends(auth)])
    def metrics(names: str = Query(...), hours: float = Query(24, le=24 * 30)):
        db = engine.db
        since = time.time() - hours * 3600
        result = {}
        for name in [n.strip() for n in names.split(",") if n.strip()][:12]:
            rows = db.query(
                "SELECT ts, labels, value FROM samples WHERE metric=? AND ts>=? ORDER BY ts",
                (name, since),
            )
            by_label: dict[str, list] = {}
            for r in rows:
                labels = json.loads(r["labels"])
                label = ", ".join(str(v) for v in labels.values()) or ""
                by_label.setdefault(label, []).append((r["ts"], r["value"]))
            series = []
            for label, points in by_label.items():
                series.append({"label": label, "points": _downsample(points, 150)})
            result[name] = series
        return result

    @app.post("/api/incidents/{incident_id}/analyze", dependencies=[Depends(auth)])
    async def analyze(incident_id: int):
        analyst = engine.analyst
        if not analyst or not analyst.enabled:
            return JSONResponse(
                {"ok": False,
                 "message": "AI analysis is not configured — set ANTHROPIC_API_KEY."},
                status_code=400,
            )
        text = await analyst.analyze_incident(incident_id, "manual", force=True)
        if not text:
            return JSONResponse(
                {"ok": False, "message": "analysis failed — check the watchdog logs"},
                status_code=502,
            )
        return {"ok": True, "analysis": text}

    @app.post("/api/actions/{action_id}/approve")
    async def approve(action_id: int, token: str = Query(...)):
        ok, msg = await engine.remediator.approve(action_id, token)
        status = 200 if ok else 400
        return JSONResponse({"ok": ok, "message": msg}, status_code=status)

    @app.post("/api/actions/{action_id}/deny")
    async def deny(action_id: int, token: str = Query(...)):
        ok, msg = await engine.remediator.deny(action_id, token)
        return JSONResponse({"ok": ok, "message": msg}, status_code=200 if ok else 400)

    return app


def _downsample(points: list[tuple[float, float]], max_points: int) -> list[list[float]]:
    if len(points) <= max_points:
        return [[round(t, 1), v] for t, v in points]
    bucket = len(points) / max_points
    out = []
    i = 0.0
    while int(i) < len(points):
        chunk = points[int(i):int(i + bucket)] or [points[int(i)]]
        out.append([
            round(sum(p[0] for p in chunk) / len(chunk), 1),
            sum(p[1] for p in chunk) / len(chunk),
        ])
        i += bucket
    return out
