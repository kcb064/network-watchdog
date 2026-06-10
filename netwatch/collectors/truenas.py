"""TrueNAS SCALE collector: pool health/capacity, system alerts (SMART etc.),
reboot detection, plus host CPU/RAM via /proc (we run on the NAS itself)."""
from __future__ import annotations

import logging
import time

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Event, Sample
from .base import Collector, slug

log = logging.getLogger("netwatch.truenas")

ALERT_BAD = {"ERROR", "CRITICAL", "ALERT", "EMERGENCY"}


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
        if self.tcfg.host_metrics:
            try:
                import psutil
                psutil.cpu_percent(interval=None)  # prime the counter
            except Exception:  # noqa: BLE001
                pass

    async def aclose(self) -> None:
        await self._http.aclose()

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        try:
            r = await self._http.get("/system/info")
            r.raise_for_status()
            info = r.json()
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}"
            if exc.response.status_code in (401, 403):
                msg += " — check TRUENAS_API_KEY"
            out.checks.append(CheckResult("truenas.api", FAIL, msg, severity="warn",
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

        version = info.get("version", "?")
        uptime = float(info.get("uptime_seconds") or 0)
        out.checks.append(CheckResult(
            "truenas.api", OK, f"{version}, up {uptime / 86400:.1f} d", severity="warn",
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
        await self._pools(out)
        await self._alerts(out)
        await self._disk_temps(out)
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

    async def _pools(self, out: CollectorOutput) -> None:
        try:
            r = await self._http.get("/pool")
            r.raise_for_status()
            pools = r.json()
        except Exception as exc:  # noqa: BLE001
            log.debug("pool query failed: %s", exc)
            return
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

    async def _alerts(self, out: CollectorOutput) -> None:
        try:
            r = await self._http.get("/alert/list")
            r.raise_for_status()
            alerts = [a for a in r.json() if not a.get("dismissed")]
        except Exception as exc:  # noqa: BLE001
            log.debug("alert query failed: %s", exc)
            return

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

    async def _disk_temps(self, out: CollectorOutput) -> None:
        try:
            r = await self._http.post("/disk/temperatures", json={"names": []})
            r.raise_for_status()
            temps = r.json() or {}
            for disk, temp in temps.items():
                if isinstance(temp, (int, float)):
                    out.samples.append(Sample("truenas.disk.temp_c", temp, {"disk": disk}))
        except Exception as exc:  # noqa: BLE001
            log.debug("disk temps unavailable: %s", exc)
