"""Base collector class and small shared helpers."""
from __future__ import annotations

import re

from ..config import Config
from ..db import Database
from ..models import CollectorOutput


class Collector:
    id: str = "base"
    interval: int = 60

    def __init__(self, cfg: Config, db: Database):
        self.cfg = cfg
        self.db = db

    async def collect(self) -> CollectorOutput:
        raise NotImplementedError

    async def aclose(self) -> None:
        pass


def slug(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9_-]+", "-", name.strip()).strip("-")
    return s or "unnamed"
