"""UniFi Network collector: controller, WAN/internet subsystems, devices
(APs/switches/gateways) with CPU/memory, client counts, pending upgrades.

Supports both UniFi OS consoles (UDM/UDR/CloudKey2: /proxy/network/...) and
legacy self-hosted controllers, auto-detected at login.
"""
from __future__ import annotations

import logging
import time

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Sample
from .base import Collector, slug

log = logging.getLogger("netwatch.unifi")

# stat/device "state" field
DEVICE_STATES = {
    0: "offline", 1: "connected", 2: "pending adoption", 4: "upgrading",
    5: "provisioning", 6: "heartbeat missed", 7: "adopting", 9: "adoption failed",
    11: "isolated",
}


def map_subsystem(status: str) -> tuple[str, str]:
    if status == "ok":
        return OK, "critical"
    if status == "warning":
        return WARN, "warn"
    if status in ("error", "critical"):
        return FAIL, "critical"
    return OK, "critical"  # 'unknown' = subsystem unused; don't alert


class UnifiClient:
    def __init__(self, cfg):
        self.cfg = cfg
        self._http = httpx.AsyncClient(
            base_url=cfg.url.rstrip("/"), verify=cfg.verify_ssl, timeout=15
        )
        self._is_unifi_os: bool | None = None
        self._csrf = ""

    async def aclose(self) -> None:
        await self._http.aclose()

    async def login(self) -> None:
        creds = {"username": self.cfg.username, "password": self.cfg.password}
        r = await self._http.post("/api/auth/login", json=creds)
        if r.status_code == 200:
            self._is_unifi_os = True
            self._csrf = r.headers.get("x-csrf-token", "")
            return
        if r.status_code in (400, 401, 403) and self._is_unifi_os is not False:
            r.raise_for_status()
        r = await self._http.post("/api/login", json=creds)
        r.raise_for_status()
        self._is_unifi_os = False

    def _site_path(self, path: str) -> str:
        base = "/proxy/network/api" if self._is_unifi_os else "/api"
        return f"{base}/s/{self.cfg.site}/{path}"

    async def _request(self, method: str, path: str, json_body: dict | None = None) -> dict:
        if self._is_unifi_os is None:
            await self.login()
        headers = {"X-Csrf-Token": self._csrf} if (self._csrf and method != "GET") else {}
        r = await self._http.request(method, self._site_path(path), json=json_body,
                                     headers=headers)
        if r.status_code in (401, 403):
            await self.login()
            headers = {"X-Csrf-Token": self._csrf} if (self._csrf and method != "GET") else {}
            r = await self._http.request(method, self._site_path(path), json=json_body,
                                         headers=headers)
        r.raise_for_status()
        return r.json()

    async def get(self, path: str) -> list[dict]:
        return (await self._request("GET", path)).get("data", [])

    async def post(self, path: str, body: dict) -> list[dict]:
        return (await self._request("POST", path, body)).get("data", [])


class UnifiCollector(Collector):
    id = "unifi"

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.interval = cfg.poll.fast
        self.ucfg = cfg.unifi
        self.client = UnifiClient(self.ucfg)

    async def aclose(self) -> None:
        await self.client.aclose()

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        t0 = time.perf_counter()
        try:
            health = await self.client.get("stat/health")
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}"
            if exc.response.status_code in (400, 401, 403):
                msg += " — login failed (use a local admin account, not UniFi Cloud SSO)"
            out.checks.append(CheckResult("unifi.controller", FAIL, msg,
                                          meta={"name": "UniFi controller"}))
            return out
        except Exception as exc:  # noqa: BLE001
            out.checks.append(CheckResult(
                "unifi.controller", FAIL, f"unreachable: {exc}",
                meta={"name": "UniFi controller"},
            ))
            return out

        latency_ms = (time.perf_counter() - t0) * 1000
        out.samples.append(Sample("unifi.api_latency_ms", latency_ms))
        out.checks.append(CheckResult(
            "unifi.controller", OK, f"API up, {latency_ms:.0f} ms",
            meta={"name": "UniFi controller"},
        ))
        self._handle_health(out, health)

        try:
            devices = await self.client.get("stat/device")
            self._handle_devices(out, devices)
        except Exception as exc:  # noqa: BLE001
            log.debug("unifi devices failed: %s", exc)
        try:
            clients = await self.client.get("stat/sta")
            out.samples.append(Sample("unifi.clients", len(clients)))
        except Exception as exc:  # noqa: BLE001
            log.debug("unifi clients failed: %s", exc)
        return out

    def _handle_health(self, out: CollectorOutput, health: list[dict]) -> None:
        for sub in health:
            name = sub.get("subsystem")
            status = sub.get("status", "unknown")
            if name == "wan":
                st, sev = map_subsystem(status)
                gw_version = sub.get("gw_version", "")
                out.checks.append(CheckResult(
                    "unifi.wan", st, f"gateway WAN status: {status} {gw_version}".strip(),
                    severity=sev, meta={"name": "UniFi WAN"},
                ))
            elif name == "www":
                st, sev = map_subsystem(status)
                bits = [f"internet (controller view): {status}"]
                if isinstance(sub.get("latency"), (int, float)):
                    out.samples.append(Sample("unifi.www.latency_ms", sub["latency"]))
                    bits.append(f"{sub['latency']:.0f} ms")
                if isinstance(sub.get("xput_down"), (int, float)):
                    out.samples.append(Sample("unifi.www.xput_down_mbps", sub["xput_down"]))
                    out.samples.append(Sample("unifi.www.xput_up_mbps", sub.get("xput_up", 0)))
                out.checks.append(CheckResult(
                    "unifi.www", st, ", ".join(bits), severity=sev,
                    meta={"name": "UniFi internet", "depends_on": ["unifi.wan"]},
                ))

    def _handle_devices(self, out: CollectorOutput, devices: list[dict]) -> None:
        upgradable = 0
        for dev in devices:
            name = dev.get("name") or dev.get("mac", "unknown")
            key = f"unifi.device.{slug(name)}"
            state = dev.get("state", 0)
            state_name = DEVICE_STATES.get(state, f"state {state}")
            stats = dev.get("system-stats") or {}
            try:
                cpu = float(stats.get("cpu") or 0)
                mem = float(stats.get("mem") or 0)
            except (TypeError, ValueError):
                cpu = mem = 0.0
            if dev.get("upgradable"):
                upgradable += 1

            if state == 1:
                out.samples.append(Sample("unifi.device.cpu_pct", cpu, {"name": name}))
                out.samples.append(Sample("unifi.device.mem_pct", mem, {"name": name}))
                if mem >= 95 or cpu >= 98:
                    out.checks.append(CheckResult(
                        key, WARN,
                        f"resource pressure: cpu {cpu:.0f}%, mem {mem:.0f}% — may be hung; "
                        "a reboot usually clears it",
                        severity="warn",
                        meta={"name": f"UniFi {name}",
                              "remediation": {"kind": "restart_device",
                                              "mac": dev.get("mac", ""), "name": name}},
                    ))
                else:
                    out.checks.append(CheckResult(
                        key, OK, f"connected, cpu {cpu:.0f}%, mem {mem:.0f}%",
                        severity="warn", meta={"name": f"UniFi {name}"},
                    ))
            elif state == 0:
                out.checks.append(CheckResult(
                    key, FAIL, "offline (power/PoE, cable, or device hang)",
                    severity=self.ucfg.device_offline_severity,
                    meta={"name": f"UniFi {name}"},
                ))
            else:
                out.checks.append(CheckResult(
                    key, WARN, state_name, severity="warn",
                    meta={"name": f"UniFi {name}"},
                ))
        out.samples.append(Sample("unifi.devices_upgradable", upgradable))

    # -- remediation executor --------------------------------------------------

    async def restart_device(self, mac: str) -> str:
        await self.client.post("cmd/devmgr", {"cmd": "restart", "mac": mac.lower()})
        return "restart command sent"
