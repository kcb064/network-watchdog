"""Entrypoint: wire config → db → collectors → engine → web, then serve."""
from __future__ import annotations

import argparse
import asyncio
import logging
import shutil
import sys
from pathlib import Path

from .collectors import build_collectors
from .config import load_config
from .db import Database
from .notify import Notifier
from .remediate import Remediator


def setup_logging(level: str) -> None:
    # Windows consoles may default to a legacy codepage that can't print
    # the dashes/emoji used in messages.
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                pass
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def ensure_config_file(path: Path) -> None:
    """Drop a reference copy of the example next to where config.yaml would go.

    config.yaml itself is optional — most deployments configure everything via
    environment variables. Users who want advanced tuning copy the example.
    """
    example = Path(__file__).parent.parent / "config.example.yaml"
    if not example.exists():
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(example, path.parent / "config.example.yaml")
    except OSError as exc:
        logging.getLogger("netwatch").debug("could not seed config example: %s", exc)


async def doctor(cfg, db: Database) -> int:
    """Try every enabled collector once and report — validates URLs/credentials."""
    collectors = build_collectors(cfg, db)
    if not collectors:
        print("No collectors enabled. Edit config.yaml and enable some services.")
        return 1
    print(f"Testing {len(collectors)} collector(s)...\n")
    failures = 0
    for cid, col in collectors.items():
        try:
            out = await asyncio.wait_for(col.collect(), timeout=30)
            bad = [c for c in out.checks if c.status != "ok"]
            print(f"[{cid}] OK — {len(out.checks)} checks, {len(out.samples)} metrics")
            for c in bad:
                print(f"    ⚠ {c.key}: {c.message}")
                failures += 1
        except Exception as exc:  # noqa: BLE001
            print(f"[{cid}] FAILED — {type(exc).__name__}: {exc}")
            failures += 1
        finally:
            await col.aclose()
    print(f"\n{'All good!' if failures == 0 else f'{failures} problem(s) found.'}")
    if cfg.ntfy.enabled and not cfg.ntfy.topic:
        print("Note: ntfy is enabled but no topic is set — notifications will be log-only.")
    return 0 if failures == 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(prog="netwatch", description="Network Watchdog")
    parser.add_argument("--config", default="config.yaml", help="path to config.yaml")
    parser.add_argument("--data", default="data", help="data directory (SQLite)")
    parser.add_argument("--doctor", action="store_true",
                        help="test connectivity to all enabled services and exit")
    args = parser.parse_args()

    config_path = Path(args.config)
    ensure_config_file(config_path)
    cfg = load_config(config_path)
    setup_logging(cfg.server.log_level)
    log = logging.getLogger("netwatch")

    db = Database(Path(args.data) / "netwatch.db")

    if args.doctor:
        sys.exit(asyncio.run(doctor(cfg, db)))

    from .ai import Analyst
    from .engine import Engine
    from .web import create_app

    notifier = Notifier(db, cfg)
    collectors = build_collectors(cfg, db)
    remediator = Remediator(db, cfg, collectors, notifier)
    analyst = Analyst(db, cfg, notifier, collectors)
    remediator.analyst = analyst
    engine = Engine(db, cfg, notifier, remediator, collectors, analyst=analyst)
    app = create_app(engine)
    if analyst.enabled:
        log.info("AI incident analysis enabled (model %s)", cfg.ai.model)

    if not collectors:
        log.warning("no collectors enabled — dashboard will be empty until you edit config.yaml")
    if cfg.remediation.mode == "off":
        log.info("remediation mode: off (suggest-only)")

    import uvicorn

    log.info("Network Watchdog starting on port %d", cfg.server.port)
    uvicorn.run(app, host="0.0.0.0", port=cfg.server.port, log_level="warning")


if __name__ == "__main__":
    main()
