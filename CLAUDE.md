# Network Watchdog — dev notes

Homelab health monitor (FastAPI + SQLite, single Docker container) for Kevin's
TrueNAS SCALE NAS. Monitors UniFi, Home Assistant, AdGuard, Docker, WAN, NAS;
notifies via ntfy; tiered auto-remediation with approval buttons.

## Commands (Windows dev box)

```powershell
.\.venv\Scripts\python.exe -m pytest tests -q          # run tests
.\.venv\Scripts\python.exe -m netwatch --config config.example.yaml --data data-dev
.\.venv\Scripts\python.exe -m netwatch --doctor ...    # connectivity check
```

Dashboard: http://127.0.0.1:8787 (WAN checks work on Windows; Docker collector
needs the Linux socket, fails gracefully here).

## Architecture map

- `netwatch/engine.py` — pure state machine (`apply_result`: hysteresis 3-open/
  2-close, flap detection, escalation) + `Engine` orchestrator (asyncio loops:
  per-collector poll, sweeper, predictions, prune, heartbeat).
- `netwatch/collectors/*` — each returns `CollectorOutput(samples, checks,
  events)`. Checks carry `meta.remediation` dicts that the remediator matches.
  Service-down must be a CheckResult FAIL (not an exception); exceptions become
  `watchdog.collector.<id>` warn checks.
- `netwatch/remediate.py` — `SPECS` registry. Tiers: auto/approve/off; global
  modes tiered/approve_all/off. Approval = single-use token, ntfy http-action
  buttons POST to `/api/actions/{id}/approve`.
- `netwatch/predict.py` — pure math (`linear_fit`, `fill_eta_days`,
  `latency_anomaly`) + `_manage()` which owns prediction-kind incidents.
- `netwatch/notify.py` — ntfy JSON publish via persistent SQLite queue with
  backoff (survives WAN outages). Disabled topic ⇒ log-only.
- Check keys are namespaced (`wan.ping`, `docker.container.<name>`,
  `truenas.pool.<name>`); the dashboard groups by first segment (see
  `web.py GROUPS`).

## Conventions / gotchas

- Tests cover the pure logic; collectors are tested via their parse/classify
  helpers only (no network mocking).
- `config.example.yaml` is copied into the image and seeded to /config on
  first run. Don't put `${...}` patterns in YAML comments — the env
  interpolator runs over the whole file.
- DB schema changes: SCHEMA in db.py uses CREATE IF NOT EXISTS only; for
  existing deployments add ALTER-based migration or bump a schema version.
- deps in requirements.txt are range-pinned; pydantic comes via fastapi.
