"""WAN / internet quality: ICMP (or TCP fallback) ping, DNS, and HTTP probes.

Lets you answer "is it my network, my DNS, or my ISP?":
  wan.ping — raw reachability/loss to public IPs (no DNS involved)
  wan.dns  — resolution via your AdGuard *and* a public resolver, compared
  wan.http — full-stack HTTP fetch (depends on wan.ping; suppressed if ping is down)
"""
from __future__ import annotations

import asyncio
import logging
import statistics
import time
from urllib.parse import urlparse

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Sample
from .base import Collector

log = logging.getLogger("netwatch.wan")


class WanCollector(Collector):
    id = "wan"

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.interval = cfg.poll.fast
        self.wcfg = cfg.wan
        self._icmp_ok: bool | None = None if self.wcfg.method == "auto" else (
            self.wcfg.method == "icmp"
        )
        self._http = httpx.AsyncClient(timeout=8, follow_redirects=True)

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- probes ----------------------------------------------------------------

    async def _ping_icmp(self, target: str) -> tuple[float | None, float]:
        from icmplib import async_ping

        res = await async_ping(
            target, count=self.wcfg.ping_count, interval=0.15, timeout=2, privileged=True
        )
        latency = res.avg_rtt if res.packets_received else None
        return latency, res.packet_loss * 100.0

    async def _ping_tcp(self, target: str, port: int = 443) -> tuple[float | None, float]:
        attempts, latencies = 3, []
        for _ in range(attempts):
            t0 = time.perf_counter()
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(target, port), timeout=2
                )
                latencies.append((time.perf_counter() - t0) * 1000)
                writer.close()
            except Exception:  # noqa: BLE001
                pass
        loss = (attempts - len(latencies)) / attempts * 100.0
        return (statistics.fmean(latencies) if latencies else None), loss

    async def _ping(self, target: str) -> tuple[float | None, float]:
        if self._icmp_ok is not False:
            try:
                result = await self._ping_icmp(target)
                self._icmp_ok = True
                return result
            except Exception as exc:  # noqa: BLE001 — no raw-socket privilege etc.
                if self._icmp_ok is None:
                    log.warning("ICMP ping unavailable (%s) — falling back to TCP ping", exc)
                self._icmp_ok = False
        return await self._ping_tcp(target)

    def _dns_servers(self) -> list[str]:
        servers = list(self.wcfg.dns_servers)
        if not servers:
            if self.cfg.adguard.enabled:
                host = urlparse(self.cfg.adguard.url).hostname
                if host:
                    servers.append(host)
            servers.append("1.1.1.1")
        return servers

    async def _dns_query(self, server: str, domain: str) -> float | None:
        import dns.asyncresolver

        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.lifetime = 3
        t0 = time.perf_counter()
        try:
            await resolver.resolve(domain, "A")
            return (time.perf_counter() - t0) * 1000
        except Exception:  # noqa: BLE001
            return None

    # -- collection --------------------------------------------------------------

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        await asyncio.gather(
            self._collect_ping(out), self._collect_dns(out), self._collect_http(out)
        )
        return out

    async def _collect_ping(self, out: CollectorOutput) -> None:
        targets = self.wcfg.ping_targets
        results = await asyncio.gather(*(self._ping(t) for t in targets))
        details = []
        losses = []
        for target, (latency, loss) in zip(targets, results):
            losses.append(loss)
            out.samples.append(Sample("wan.ping.loss_pct", loss, {"target": target}))
            if latency is not None:
                out.samples.append(Sample("wan.ping.latency_ms", latency, {"target": target}))
                details.append(f"{target}: {latency:.0f} ms, {loss:.0f}% loss")
            else:
                details.append(f"{target}: unreachable")

        best_loss = min(losses) if losses else 100.0
        msg = "; ".join(details)
        meta: dict = {"name": "Internet (ping)"}
        if best_loss >= self.wcfg.loss_fail_pct:
            status, sev = FAIL, "critical"
            msg = f"Internet unreachable — {msg}"
            if self.wcfg.power_cycle_entity and self.cfg.home_assistant.enabled:
                meta["remediation"] = {
                    "kind": "wan_power_cycle",
                    "entity": self.wcfg.power_cycle_entity,
                    "name": "modem/router power",
                }
        elif any(l >= self.wcfg.loss_warn_pct for l in losses):
            status, sev = WARN, "warn"
            msg = f"Packet loss — {msg}"
        else:
            status, sev = OK, "critical"
        out.checks.append(CheckResult("wan.ping", status, msg, severity=sev, meta=meta))

    async def _collect_dns(self, out: CollectorOutput) -> None:
        servers = self._dns_servers()
        domain = self.wcfg.dns_test_domain
        results = await asyncio.gather(*(self._dns_query(s, domain) for s in servers))
        details, failures = [], []
        for server, ms in zip(servers, results):
            if ms is None:
                failures.append(server)
                details.append(f"{server}: FAIL")
            else:
                out.samples.append(Sample("wan.dns.latency_ms", ms, {"server": server}))
                details.append(f"{server}: {ms:.0f} ms")
        msg = f"resolve {domain} — " + "; ".join(details)
        if len(failures) == len(servers):
            status, sev = FAIL, "critical"
        elif failures:
            status, sev = WARN, "warn"
        else:
            status, sev = OK, "critical"
        out.checks.append(
            CheckResult(
                "wan.dns", status, msg, severity=sev,
                meta={"name": "DNS resolution", "depends_on": ["wan.ping"]},
            )
        )

    async def _collect_http(self, out: CollectorOutput) -> None:
        async def fetch(url: str) -> float | None:
            t0 = time.perf_counter()
            try:
                r = await self._http.get(url)
                if r.status_code < 500:
                    return (time.perf_counter() - t0) * 1000
            except Exception:  # noqa: BLE001
                pass
            return None

        targets = self.wcfg.http_targets
        if not targets:
            return
        results = await asyncio.gather(*(fetch(u) for u in targets))
        details, ok_count = [], 0
        for url, ms in zip(targets, results):
            host = urlparse(url).hostname or url
            if ms is None:
                details.append(f"{host}: FAIL")
            else:
                ok_count += 1
                out.samples.append(Sample("wan.http.latency_ms", ms, {"target": host}))
                details.append(f"{host}: {ms:.0f} ms")
        status = OK if ok_count else FAIL
        out.checks.append(
            CheckResult(
                "wan.http", status, "; ".join(details), severity="warn",
                meta={"name": "HTTP connectivity", "depends_on": ["wan.ping", "wan.dns"]},
            )
        )
