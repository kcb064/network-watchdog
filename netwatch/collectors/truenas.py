"""TrueNAS SCALE collector: pool health/capacity, system alerts (SMART etc.),
reboot detection, plus host CPU/RAM via /proc (we run on the NAS itself).

Talks JSON-RPC 2.0 over WebSocket (/api/current, TrueNAS 25.04+) — the
supported API. Falls back to the deprecated REST /api/v2.0 on older
versions; REST is removed in TrueNAS 26.04.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Event, Sample
from .base import Collector, slug

log = logging.getLogger("netwatch.truenas")

ALERT_BAD = {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}


def ws_url(base: str) -> str:
    """The JSON-RPC WebSocket endpoint for a TrueNAS web UI URL."""
    base = base.rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    return base + "/api/current"


def classify_pool(pool: dict, warn_pct: float) -> tuple[str, str, str]:
    """Returns (status, severity, message) for a pool dict."""
    name = pool.get("name", "?")
    status = (pool.get("status") or "UNKNOWN").upper()
    healthy = pool.get("healthy", status == "ONLINE")
    size = pool.get("size") or 0
    allocated = pool.get("allocated") or 0
    pct = allocated / size * 100 if size else 0.0
    cap = f"{pct:.0f}% used"

    if status in ("OFFLINE", "FAULTED", "UNAVAIL", "REMOVED"):
        return FAIL, "critical", f"pool {name} {status} — data at risk"
    if status == "DEGRADED" or not healthy:
        return FAIL, "critical", (
            f"pool {name} DEGRADED ({cap}) — likely a failed/failing disk, check TrueNAS alerts"
        )
    if pct >= warn_pct:
        return WARN, "warn", f"pool {name} {cap} (warn at {warn_pct:.0f}%) — ZFS slows when full"
    return OK, "critical", f"{status}, {cap}"


def alert_severity(level: str) -> str:
    return "critical" if level.upper() in ALERT_BAD else "warn"


class TruenasCollector(Collector):
    id = "truenas"

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.interval = cfg.poll.medium
        self.tcfg = cfg.truenas
        self._http = httpx.AsyncClient(
            base_url=self.tcfg.url.rstrip("/") + "/api/v2.0",
            headers={"Authorization": f"Bearer {self.tcfg.api_key}"},
            verify=self.tcfg.verify_ssl, timeout=20,
        )
        self._mode: str | None = None  # "rpc" | "rest", decided on first success
        self._rpc_id = 0
        if self.tcfg.host_metrics:
            try:
                import psutil
                psutil.cpu_percent(interval=None)  # prime the counter
            except Exception:  # noqa: BLE001
                pass

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- transports ----------------------------------------------------------------

    async def _fetch_rpc(self) -> dict:
        import ssl as ssl_mod

        import websockets

        url = ws_url(self.tcfg.url)
        kwargs: dict = {"open_timeout": 10, "close_timeout": 5, "max_size": 2 ** 24}
        if url.startswith("wss://") and not self.tcfg.verify_ssl:
            ctx = ssl_mod.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl_mod.CERT_NONE
            kwargs["ssl"] = ctx

        async with websockets.connect(url, **kwargs) as ws:
            async def call(method: str, params: list):
                self._rpc_id += 1
                rid = self._rpc_id
                await ws.send(json.dumps(
                    {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
                ))
                while True:  # skip server notifications; match our request id
                    msg = json.loads(await asyncio.wait_for(ws.recv(), timeout=20))
                    if msg.get("id") == rid:
                        if "error" in msg:
                            err = msg["error"] or {}
                            raise RuntimeError(err.get("message") or str(err))
                        return msg.get("result")

            try:
                authed = await call("auth.login_with_api_key", [self.tcfg.api_key])
            except RuntimeError as exc:
                raise PermissionError(
                    f"API key rejected ({exc}) — check TRUENAS_API_KEY"
                ) from exc
            if authed is not True:
                raise PermissionError("API key rejected — check TRUENAS_API_KEY")

            data: dict = {"info": await call("system.info", [])}
            for key, method, params in (
                ("pools", "pool.query", []),
                ("alerts", "alert.list", []),
                ("temps", "disk.temperatures", [[]]),
            ):
                try:
                    data[key] = await call(method, params)
                except Exception as exc:  # noqa: BLE001 — partial data is fine
                    log.debug("%s failed: %s", method, exc)
                    data[key] = None
            return data

    async def _fetch_rest(self) -> dict:
        r = await self._http.get("/system/info")
        if r.status_code in (401, 403):
            raise PermissionError(f"HTTP {r.status_code} — check TRUENAS_API_KEY")
        r.raise_for_status()
        data: dict = {"info": r.json(), "pools": None, "alerts": None, "temps": None}
        for key, fetch in (
            ("pools", lambda: self._http.get("/pool")),
            ("alerts", lambda: self._http.get("/alert/list")),
            ("temps", lambda: self._http.post("/disk/temperatures", json={"names": []})),
        ):
            try:
                rr = await fetch()
                rr.raise_for_status()
                data[key] = rr.json()
            except Exception as exc:  # noqa: BLE001
                log.debug("REST %s failed: %s", key, exc)
        return data

    async def _fetch(self) -> dict:
        if self._mode == "rest":
            return await self._fetch_rest()
        try:
            data = await self._fetch_rpc()
            if self._mode is None:
                log.info("TrueNAS: using JSON-RPC over WebSocket (/api/current)")
                self._mode = "rpc"
            return data
        except PermissionError:
            raise  # bad key fails on every transport; don't mask it
        except Exception as exc:
            if self._mode == "rpc":
                raise  # RPC was working — surface the outage, don't flap transports
            data = await self._fetch_rest()  # raises too if TrueNAS is down
            log.warning(
                "TrueNAS JSON-RPC unavailable (%s) — using deprecated REST API "
                "(removed in TrueNAS 26.04)", exc,
            )
            self._mode = "rest"
            return data

    # -- collection -------------------------------------------------------------------

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        try:
            data = await self._fetch()
        except PermissionError as exc:
            out.checks.append(CheckResult("truenas.api", FAIL, str(exc), severity="warn",
                                          meta={"name": "TrueNAS API"}))
            self._host_metrics(out)
            return out
        except Exception as exc:  # noqa: BLE001
            out.checks.append(CheckResult(
                "truenas.api", FAIL, f"unreachable: {exc}", severity="warn",
                meta={"name": "TrueNAS API"},
            ))
            self._host_metrics(out)
            return out

        info = data.get("info") or {}
        version = info.get("version", "?")
        uptime = float(info.get("uptime_seconds") or 0)
        api_note = "JSON-RPC" if self._mode == "rpc" else "REST (deprecated)"
        out.checks.append(CheckResult(
            "truenas.api", OK,
            f"{version}, up {uptime / 86400:.1f} d, via {api_note}", severity="warn",
            meta={"name": "TrueNAS API"},
        ))
        prev_uptime = float(self.db.kv_get("truenas.uptime") or 0)
        if uptime and prev_uptime and uptime < prev_uptime - 60:
            out.events.append(Event(
                f"truenas.reboot.{int(time.time() // 3600)}", "NAS rebooted",
                f"TrueNAS uptime reset (now {uptime / 60:.0f} min). Power blip or manual reboot?",
                severity="warn", dedup_minutes=60,
            ))
        self.db.kv_set("truenas.uptime", str(uptime))
        loadavg = info.get("loadavg") or []
        if loadavg:
            out.samples.append(Sample("truenas.load1", float(loadavg[0])))

        self._host_metrics(out)
        if data.get("pools") is not None:
            self._process_pools(out, data["pools"])
        if data.get("alerts") is not None:
            self._process_alerts(out, data["alerts"])
        if data.get("temps"):
            self._process_temps(out, data["temps"])
        return out

    def _host_metrics(self, out: CollectorOutput) -> None:
        if not self.tcfg.host_metrics:
            return
        try:
            import psutil

            out.samples.append(Sample("truenas.host.cpu_pct", psutil.cpu_percent(interval=None)))
            vm = psutil.virtual_memory()
            out.samples.append(Sample("truenas.host.mem_pct", vm.percent))
            out.samples.append(Sample("truenas.host.mem_total_bytes", float(vm.total)))
            out.samples.append(Sample("truenas.host.mem_used_bytes", float(vm.used)))
        except Exception as exc:  # noqa: BLE001
            log.debug("host metrics failed: %s", exc)

    def _process_pools(self, out: CollectorOutput, pools: list[dict]) -> None:
        for pool in pools:
            name = pool.get("name", "?")
            status, sev, msg = classify_pool(pool, self.tcfg.pool_capacity_warn_pct)
            out.checks.append(CheckResult(
                f"truenas.pool.{slug(name)}", status, msg, severity=sev,
                meta={"name": f"Pool {name}"},
            ))
            size = pool.get("size") or 0
            allocated = pool.get("allocated") or 0
            if size:
                out.samples.append(Sample("truenas.pool.size_bytes", size, {"pool": name}))
                out.samples.append(
                    Sample("truenas.pool.used_bytes", allocated, {"pool": name})
                )
                out.samples.append(
                    Sample("truenas.pool.used_pct", allocated / size * 100, {"pool": name})
                )

    def _process_alerts(self, out: CollectorOutput, all_alerts: list[dict]) -> None:
        alerts = [a for a in all_alerts if not a.get("dismissed")]
        out.samples.append(Sample("truenas.alerts_active", len(alerts)))
        bad = [a for a in alerts if (a.get("level") or "").upper() in ALERT_BAD]
        warnish = [a for a in alerts if (a.get("level") or "").upper() == "WARNING"]

        def fmt(items: list[dict]) -> str:
            return "; ".join((a.get("formatted") or a.get("klass") or "?")[:160] for a in items[:3])

        if bad:
            out.checks.append(CheckResult(
                "truenas.alerts", FAIL, f"{len(bad)} serious TrueNAS alert(s): {fmt(bad)}",
                severity="critical", meta={"name": "TrueNAS alerts", "kind": "alert"},
            ))
        elif warnish:
            out.checks.append(CheckResult(
                "truenas.alerts", WARN, f"{len(warnish)} warning(s): {fmt(warnish)}",
                severity="warn", meta={"name": "TrueNAS alerts", "kind": "alert"},
            ))
        else:
            out.checks.append(CheckResult(
                "truenas.alerts", OK, "no active alerts", severity="warn",
                meta={"name": "TrueNAS alerts"},
            ))

        # Push each *new* non-INFO alert individually (SMART failures, scrub
        # errors, etc.), deduped by alert uuid.
        seen: list[str] = self.db.kv_get_json("truenas.seen_alerts", [])
        new_seen = []
        for a in alerts:
            uid = a.get("uuid") or a.get("id") or ""
            level = (a.get("level") or "INFO").upper()
            new_seen.append(uid)
            if uid and uid not in seen and level != "INFO":
                out.events.append(Event(
                    f"truenas.alert.{uid}", f"TrueNAS alert ({level})",
                    (a.get("formatted") or a.get("klass") or "")[:500],
                    severity="critical" if level in ALERT_BAD else "warn",
                    dedup_minutes=7 * 24 * 60,
                ))
        self.db.kv_set_json("truenas.seen_alerts", new_seen[-200:])

    def _process_temps(self, out: CollectorOutput, temps: dict) -> None:
        for disk, temp in (temps or {}).items():
            if isinstance(temp, (int, float)):
                out.samples.append(Sample("truenas.disk.temp_c", temp, {"disk": disk}))
