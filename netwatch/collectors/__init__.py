"""Collector registry: builds the set of enabled collectors from config."""
from __future__ import annotations

from ..config import Config
from ..db import Database


def build_collectors(cfg: Config, db: Database) -> dict:
    from .adguard import AdguardCollector
    from .docker_ import DockerCollector
    from .homeassistant import HomeAssistantCollector
    from .truenas import TruenasCollector
    from .unifi import UnifiCollector
    from .wan import WanCollector

    collectors = {}
    if cfg.wan.enabled:
        collectors["wan"] = WanCollector(cfg, db)
    if cfg.docker.enabled:
        collectors["docker"] = DockerCollector(cfg, db)
    if cfg.adguard.enabled:
        collectors["adguard"] = AdguardCollector(cfg, db)
    if cfg.home_assistant.enabled:
        collectors["ha"] = HomeAssistantCollector(cfg, db)
    if cfg.unifi.enabled:
        collectors["unifi"] = UnifiCollector(cfg, db)
    if cfg.truenas.enabled:
        collectors["truenas"] = TruenasCollector(cfg, db)
    return collectors
