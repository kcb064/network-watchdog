"""Docker collector: container states, health, crash/restart-loop detection,
per-container CPU/memory. Talks to the engine socket directly (no SDK)."""
from __future__ import annotations

import asyncio
import fnmatch
import logging
import time

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Sample
from .base import Collector

log = logging.getLogger("netwatch.docker")


def container_name(info: dict) -> str:
    names = info.get("Names") or ["/unknown"]
    return names[0].lstrip("/")


def demux_docker_logs(raw: bytes) -> str:
    """Docker log endpoints frame non-tty output as 8-byte-header chunks
    [stream, 0, 0, 0, len_be32]; tty containers send plain bytes."""
    framed = len(raw) >= 8 and raw[0] in (0, 1, 2) and raw[1:4] == b"\x00\x00\x00"
    if not framed:
        return raw.decode("utf-8", "replace")
    chunks = []
    i = 0
    while i + 8 <= len(raw):
        size = int.from_bytes(raw[i + 4:i + 8], "big")
        chunks.append(raw[i + 8:i + 8 + size])
        i += 8 + size
    return b"".join(chunks).decode("utf-8", "replace")


def classify_container(info: dict, inspect: dict | None) -> tuple[str, str, str, dict]:
    """Returns (status, severity, message, remediation_ctx)."""
    name = container_name(info)
    state = info.get("State", "")
    status_text = info.get("Status", state)
    rem: dict = {}

    if state == "running":
        if "(unhealthy)" in status_text:
            rem = {"kind": "restart_container", "id": info["Id"], "name": name,
                   "reason": "unhealthy"}
            return FAIL, "warn", f"unhealthy — {status_text}", rem
        return OK, "warn", status_text, rem
    if state == "restarting":
        rem = {"kind": "restart_container", "id": info["Id"], "name": name,
               "reason": "restart_loop", "restart_loop": True}
        return FAIL, "warn", f"restart loop — {status_text}", rem
    if state == "paused":
        return WARN, "warn", status_text, rem
    if state in ("exited", "dead"):
        exit_code = 0
        if inspect:
            exit_code = (inspect.get("State") or {}).get("ExitCode", 0)
        if exit_code != 0 or state == "dead":
            rem = {"kind": "restart_container", "id": info["Id"], "name": name,
                   "reason": "crashed"}
            return FAIL, "warn", f"crashed — {status_text} (exit {exit_code})", rem
        return OK, "warn", f"stopped — {status_text}", rem
    return WARN, "warn", f"state: {state} — {status_text}", rem


class DockerCollector(Collector):
    id = "docker"

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.interval = cfg.poll.fast
        self.dcfg = cfg.docker
        transport = httpx.AsyncHTTPTransport(uds=self.dcfg.socket)
        self._http = httpx.AsyncClient(transport=transport, base_url="http://docker", timeout=15)
        self._poll_n = 0
        self._restart_counts: dict[str, list[tuple[float, int]]] = {}

    async def aclose(self) -> None:
        await self._http.aclose()

    def _excluded(self, name: str) -> bool:
        return any(fnmatch.fnmatch(name, pat) for pat in self.dcfg.exclude)

    async def _get(self, path: str, **kw) -> httpx.Response:
        r = await self._http.get(path, **kw)
        r.raise_for_status()
        return r

    def _track_restart_loop(self, cid: str, restart_count: int, now: float) -> bool:
        window = self.dcfg.restart_loop_window_minutes * 60
        hist = [h for h in self._restart_counts.get(cid, []) if now - h[0] <= window]
        hist.append((now, restart_count))
        self._restart_counts[cid] = hist
        return restart_count - hist[0][1] >= self.dcfg.restart_loop_count

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        now = time.time()
        self._poll_n += 1
        try:
            r = await self._get("/containers/json", params={"all": "true"})
        except Exception as exc:  # noqa: BLE001
            out.checks.append(CheckResult(
                "docker.engine", FAIL, f"Docker socket unreachable: {exc}",
                severity="warn", meta={"name": "Docker engine"},
            ))
            return out
        containers = r.json()
        out.checks.append(CheckResult(
            "docker.engine", OK, f"{len(containers)} containers", severity="warn",
            meta={"name": "Docker engine"},
        ))

        running = 0
        watched = []
        for info in containers:
            name = container_name(info)
            if self._excluded(name):
                continue
            watched.append(info)
            if info.get("State") == "running":
                running += 1

        out.samples.append(Sample("docker.containers_running", running))
        out.samples.append(Sample("docker.containers_total", len(watched)))

        # Inspect only problem containers (exit codes, restart counts)
        async def inspect_if_needed(info: dict) -> tuple[dict, dict | None]:
            state = info.get("State", "")
            needs = state in ("exited", "dead", "restarting") or "(unhealthy)" in info.get(
                "Status", ""
            )
            if not needs:
                return info, None
            try:
                r = await self._get(f"/containers/{info['Id']}/json")
            except Exception:  # noqa: BLE001
                return info, None
            return info, r.json()

        inspected = await asyncio.gather(*(inspect_if_needed(i) for i in watched))
        for info, inspect in inspected:
            name = container_name(info)
            status, sev, msg, rem = classify_container(info, inspect)
            if inspect is not None:
                rc = (inspect.get("RestartCount")
                      or (inspect.get("State") or {}).get("RestartCount") or 0)
                if rc and self._track_restart_loop(info["Id"], int(rc), now):
                    rem = dict(rem, restart_loop=True, reason="restart_loop")
                    status, msg = FAIL, f"restart loop — {msg}"
            meta = {"name": f"Container {name}"}
            if rem:
                meta["remediation"] = rem
            out.checks.append(CheckResult(f"docker.container.{name}", status, msg,
                                          severity=sev, meta=meta))

        if self.dcfg.stats and self._poll_n % 4 == 1:
            await self._collect_stats(out, [i for i in watched if i.get("State") == "running"])
        return out

    async def _collect_stats(self, out: CollectorOutput, running: list[dict]) -> None:
        sem = asyncio.Semaphore(8)

        async def one(info: dict) -> None:
            name = container_name(info)
            async with sem:
                try:
                    r = await self._get(f"/containers/{info['Id']}/stats",
                                        params={"stream": "false"})
                except Exception:  # noqa: BLE001
                    return
            s = r.json()
            try:
                cpu = s["cpu_stats"]["cpu_usage"]["total_usage"] - \
                    s["precpu_stats"]["cpu_usage"]["total_usage"]
                sys_d = s["cpu_stats"]["system_cpu_usage"] - \
                    s["precpu_stats"]["system_cpu_usage"]
                ncpu = s["cpu_stats"].get("online_cpus") or 1
                if sys_d > 0:
                    out.samples.append(
                        Sample("docker.container.cpu_pct", cpu / sys_d * ncpu * 100,
                               {"name": name})
                    )
            except (KeyError, TypeError):
                pass
            mem = s.get("memory_stats") or {}
            usage = mem.get("usage")
            if usage is not None:
                # cgroup v2 reports cache in inactive_file; exclude it
                usage -= (mem.get("stats") or {}).get("inactive_file", 0)
                out.samples.append(
                    Sample("docker.container.mem_bytes", max(usage, 0), {"name": name})
                )

        await asyncio.gather(*(one(i) for i in running))

    # -- remediation executors -----------------------------------------------------

    async def restart_container(self, container_id: str) -> str:
        r = await self._http.post(f"/containers/{container_id}/restart", params={"t": 10},
                                  timeout=60)
        r.raise_for_status()
        return "restarted"

    async def restart_by_name(self, name: str) -> str:
        r = await self._get("/containers/json", params={"all": "true"})
        for info in r.json():
            if container_name(info) == name:
                return await self.restart_container(info["Id"])
        raise RuntimeError(f"container {name!r} not found")

    async def logs_tail(self, name: str, lines: int = 80) -> str:
        r = await self._get("/containers/json", params={"all": "true"})
        for info in r.json():
            if container_name(info) == name:
                lr = await self._http.get(
                    f"/containers/{info['Id']}/logs",
                    params={"stdout": "1", "stderr": "1", "tail": str(lines),
                            "timestamps": "1"},
                )
                lr.raise_for_status()
                return demux_docker_logs(lr.content)
        return ""
