"""Home Assistant collector: API availability/latency, unavailable-entity
spikes, pending updates, version-change events."""
from __future__ import annotations

import logging
import time
from collections import Counter

import httpx

from ..models import FAIL, OK, WARN, CheckResult, CollectorOutput, Event, Sample
from .base import Collector

log = logging.getLogger("netwatch.ha")


BAD_ENTRY_STATES = {"setup_error", "setup_retry", "migration_error"}


def failed_entries(entries: list[dict]) -> list[dict]:
    """Config entries (integrations) that failed to set up, excluding ones the
    user disabled on purpose."""
    return [e for e in entries
            if e.get("state") in BAD_ENTRY_STATES and not e.get("disabled_by")]


def summarize_unavailable(states: list[dict]) -> tuple[int, int, str]:
    """Returns (total, unavailable_count, 'top offender domains' text)."""
    total = len(states)
    bad = [s for s in states if s.get("state") == "unavailable"]
    domains = Counter(s["entity_id"].split(".", 1)[0] for s in bad if "entity_id" in s)
    top = ", ".join(f"{d} ({n})" for d, n in domains.most_common(3))
    return total, len(bad), top


class HomeAssistantCollector(Collector):
    id = "ha"

    def __init__(self, cfg, db):
        super().__init__(cfg, db)
        self.interval = cfg.poll.fast
        self.hcfg = cfg.home_assistant
        self._http = httpx.AsyncClient(
            base_url=self.hcfg.url.rstrip("/"),
            headers={"Authorization": f"Bearer {self.hcfg.token}"},
            timeout=20,
        )
        self._poll_n = 0

    async def aclose(self) -> None:
        await self._http.aclose()

    # -- remediation executor backends -----------------------------------------

    async def call_service(self, domain: str, service: str, data: dict) -> None:
        r = await self._http.post(f"/api/services/{domain}/{service}", json=data)
        r.raise_for_status()

    async def error_log_tail(self, lines: int = 60) -> str:
        r = await self._http.get("/api/error_log")
        r.raise_for_status()
        return "\n".join(r.text.splitlines()[-lines:])

    async def list_config_entries(self) -> list[dict]:
        r = await self._http.get("/api/config/config_entries/entry")
        r.raise_for_status()
        return r.json()

    async def reload_config_entry(self, entry_id: str) -> None:
        r = await self._http.post(
            f"/api/config/config_entries/entry/{entry_id}/reload", timeout=60
        )
        r.raise_for_status()

    async def restart_core(self) -> str:
        r = await self._http.post("/api/services/homeassistant/restart", json={},
                                  timeout=60)
        r.raise_for_status()
        return "Home Assistant Core restart requested"

    async def restart_addon(self, slug: str) -> str:
        # Prefer the hassio.addon_restart service — the same mechanism HA
        # automations use, and friendlier to tokens than the raw /api/hassio
        # Supervisor proxy (which newer HA versions restrict).
        r = await self._http.post(
            "/api/services/hassio/addon_restart", json={"addon": slug}, timeout=90
        )
        if r.status_code in (400, 404, 405):  # hassio services unavailable: old proxy
            r = await self._http.post(f"/api/hassio/addons/{slug}/restart", timeout=90)
        if r.status_code in (401, 403):
            raise RuntimeError(
                f"Home Assistant rejected the add-on restart (HTTP {r.status_code}). "
                "The HA_TOKEN user must be an Administrator — check HA → Settings → "
                "People → Users → (token's user) → 'Administrator' toggle."
            )
        r.raise_for_status()
        return f"add-on {slug} restart requested"

    def _handle_integrations(self, out: CollectorOutput, entries: list[dict]) -> None:
        bad = failed_entries(entries)
        out.samples.append(Sample("ha.integrations_failed", len(bad)))
        if not bad:
            out.checks.append(CheckResult(
                "ha.integrations", OK, f"{len(entries)} integrations loaded",
                severity="warn", meta={"name": "HA integrations"},
            ))
            return
        detail = "; ".join(
            f"{e.get('title') or e.get('domain', '?')} [{e.get('state')}]"
            + (f": {e['reason']}" if e.get("reason") else "")
            for e in bad[:5]
        )
        out.checks.append(CheckResult(
            "ha.integrations", FAIL,
            f"{len(bad)} integration(s) failed to set up — {detail}",
            severity="warn",
            meta={
                "name": "HA integrations",
                "remediation": {
                    "kind": "ha_reload_entries", "name": "HA integrations",
                    "entries": [
                        {"id": e["entry_id"],
                         "title": e.get("title") or e.get("domain", "?")}
                        for e in bad[:5] if e.get("entry_id")
                    ],
                },
                "remediation_fallbacks": [
                    {"kind": "ha_restart_core", "name": "Home Assistant core"},
                ],
            },
        ))

    def _down_meta(self) -> dict:
        meta = {"name": "Home Assistant"}
        if self.hcfg.container_name:
            meta["remediation"] = {
                "kind": "ha_restart", "name": self.hcfg.container_name,
            }
        return meta

    async def collect(self) -> CollectorOutput:
        out = CollectorOutput()
        self._poll_n += 1

        t0 = time.perf_counter()
        try:
            r = await self._http.get("/api/")
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            msg = f"HTTP {exc.response.status_code}"
            if exc.response.status_code == 401:
                msg += " — long-lived token rejected (check HA_TOKEN)"
            out.checks.append(CheckResult("ha.api", FAIL, msg, meta=self._down_meta()))
            return out
        except Exception as exc:  # noqa: BLE001
            out.checks.append(CheckResult(
                "ha.api", FAIL, f"unreachable: {exc}", meta=self._down_meta()
            ))
            return out

        latency_ms = (time.perf_counter() - t0) * 1000
        out.samples.append(Sample("ha.api_latency_ms", latency_ms))
        out.checks.append(CheckResult(
            "ha.api", OK, f"API up, {latency_ms:.0f} ms", meta={"name": "Home Assistant"}
        ))

        # Full state scan is heavier — every 4th poll
        if self._poll_n % 4 != 1:
            return out
        try:
            r = await self._http.get("/api/states")
            r.raise_for_status()
            states = r.json()
        except Exception as exc:  # noqa: BLE001
            log.debug("ha states failed: %s", exc)
            return out

        total, unavailable, top = summarize_unavailable(states)
        # Entity ids reveal which integration died — kept for the AI analyst.
        sample = [s["entity_id"] for s in states
                  if s.get("state") == "unavailable" and "entity_id" in s][:30]
        self.db.kv_set_json("ha.unavailable_sample", sample)
        out.samples.append(Sample("ha.entities_total", total))
        out.samples.append(Sample("ha.entities_unavailable", unavailable))
        pct = unavailable / total * 100 if total else 0
        if pct > self.hcfg.unavailable_warn_pct:
            out.checks.append(CheckResult(
                "ha.entities", WARN,
                f"{unavailable}/{total} entities unavailable ({pct:.0f}%) — top: {top}. "
                "An integration or device hub may be down.",
                severity="warn", meta={"name": "HA entities"},
            ))
        else:
            out.checks.append(CheckResult(
                "ha.entities", OK, f"{unavailable}/{total} unavailable", severity="warn",
                meta={"name": "HA entities"},
            ))

        updates = sum(
            1 for s in states
            if s.get("entity_id", "").startswith("update.") and s.get("state") == "on"
        )
        out.samples.append(Sample("ha.updates_available", updates))

        # Failed integrations: the precise cause behind entity blackouts, with
        # a reload->restart-core remediation ladder attached.
        try:
            entries = await self.list_config_entries()
            self._handle_integrations(out, entries)
        except Exception as exc:  # noqa: BLE001 — older HA / non-admin token
            log.debug("config entries unavailable: %s", exc)

        try:
            r = await self._http.get("/api/config")
            r.raise_for_status()
            version = r.json().get("version", "")
            prev = self.db.kv_get("ha.version")
            if version and prev and version != prev:
                out.events.append(Event(
                    f"ha.version.{version}", "Home Assistant updated",
                    f"Core {prev} → {version}", severity="info",
                ))
            if version:
                self.db.kv_set("ha.version", version)
        except Exception as exc:  # noqa: BLE001
            log.debug("ha config failed: %s", exc)
        return out
