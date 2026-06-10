"""AdGuard Home collector: availability, protection status, query stats.

If protection is found disabled it can auto re-enable after a configurable
grace period (so intentionally pausing it for testing doesn't fight you).
"""
from __future__ import annotations

import logging
import time

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Sample
from .base import Collector

log = logging.getLogger("netwatch.adguard")


def normalize_processing_ms(value: float) -> float:
    """AdGuard versions disagree on units; small values are seconds."""
    return value * 1000 if value < 10 else value


class AdguardCollector(Collector):
    id = "adguard"

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.interval = cfg.poll.fast
        self.acfg = cfg.adguard
        auth = (self.acfg.username, self.acfg.password) if self.acfg.username else None
        self._http = httpx.AsyncClient(base_url=self.acfg.url, auth=auth, timeout=10)
        self._disabled_since: float | None = None

    async def aclose(self) -> None:
        await self._http.aclose()

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        now = time.time()
        t0 = time.perf_counter()
        try:
            r = await self._http.get("/control/status")
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}"
            if exc.response.status_code in (401, 403):
                msg += " — check ADGUARD_USERNAME / ADGUARD_PASSWORD"
            out.checks.append(CheckResult("adguard.api", FAIL, msg,
                                          meta={"name": "AdGuard Home"}))
            return out
        except Exception as exc:  # noqa: BLE001
            out.checks.append(CheckResult("adguard.api", FAIL, f"unreachable: {exc}",
                                          meta={"name": "AdGuard Home"}))
            return out

        latency_ms = (time.perf_counter() - t0) * 1000
        status = r.json()
        out.samples.append(Sample("adguard.api_latency_ms", latency_ms))
        out.checks.append(CheckResult(
            "adguard.api", OK, f"v{status.get('version', '?')}, {latency_ms:.0f} ms",
            meta={"name": "AdGuard Home"},
        ))

        # Protection state + auto re-enable grace logic
        if status.get("protection_enabled", True):
            self._disabled_since = None
            out.checks.append(CheckResult(
                "adguard.protection", OK, "protection enabled", severity="warn",
                meta={"name": "AdGuard protection"},
            ))
        else:
            if self._disabled_since is None:
                self._disabled_since = now
            minutes = (now - self._disabled_since) / 60
            grace = self.acfg.auto_reenable_after_minutes
            eligible = grace >= 0 and minutes >= grace
            if grace < 0:
                note = "auto re-enable is off"
            elif eligible:
                note = "auto re-enable due"
            else:
                note = f"auto re-enable in {max(grace - minutes, 0):.0f} min"
            out.checks.append(CheckResult(
                "adguard.protection", FAIL,
                f"protection DISABLED for {minutes:.0f} min ({note})", severity="warn",
                meta={
                    "name": "AdGuard protection",
                    "remediation": {"kind": "enable_protection", "eligible": eligible,
                                    "name": "AdGuard protection"},
                },
            ))

        # Stats: query volume, block rate, processing latency
        try:
            r = await self._http.get("/control/stats")
            r.raise_for_status()
            stats = r.json()
        except Exception as exc:  # noqa: BLE001
            log.debug("adguard stats failed: %s", exc)
            return out

        queries = stats.get("num_dns_queries") or 0
        blocked = stats.get("num_blocked_filtering") or 0
        out.samples.append(Sample("adguard.queries_24h", queries))
        if queries:
            out.samples.append(Sample("adguard.blocked_pct", blocked / queries * 100))
        avg = stats.get("avg_processing_time")
        if avg is not None:
            avg_ms = normalize_processing_ms(float(avg))
            out.samples.append(Sample("adguard.avg_processing_ms", avg_ms))
            if avg_ms > self.acfg.avg_processing_warn_ms:
                out.checks.append(CheckResult(
                    "adguard.latency", WARN,
                    f"slow DNS processing: avg {avg_ms:.0f} ms "
                    f"(threshold {self.acfg.avg_processing_warn_ms:.0f} ms) — "
                    "upstream DNS may be struggling",
                    severity="warn",
                    meta={"name": "AdGuard DNS latency", "depends_on": ["wan.ping"]},
                ))
            else:
                out.checks.append(CheckResult(
                    "adguard.latency", OK, f"avg {avg_ms:.1f} ms", severity="warn",
                    meta={"name": "AdGuard DNS latency"},
                ))
        return out

    # -- remediation executor ------------------------------------------------------

    async def set_protection(self, enabled: bool) -> str:
        r = await self._http.post("/control/protection", json={"enabled": enabled})
        if r.status_code == 404:  # older AdGuard Home
            verb = "enable" if enabled else "disable"
            r = await self._http.post(f"/control/{verb}_protection")
        r.raise_for_status()
        self._disabled_since = None
        return f"protection {'enabled' if enabled else 'disabled'}"
