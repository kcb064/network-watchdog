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
  buttons POST to `/api/actions/{id}/approve`. `lifeline=True` specs
  (DNS/WAN/UniFi fixes) auto-retry with doubling backoff instead of
  downgrading to approval on cooldown — approvals are undeliverable when the
  notification path itself is what broke. Checks may carry
  `meta.remediation_fallbacks` (list): consider() walks the ladder, advancing
  when a rung's attempt budget is spent. Specs with a `reverter` are
  mitigations (e.g. unifi.dns_failover): no fix-verification, undone by the
  sweeper via revert_orphans() when their incident closes. Matchers take
  (ctx, rem), not the whole check.
- `netwatch/predict.py` — pure math (`linear_fit`, `fill_eta_days`,
  `latency_anomaly`) + `_manage()` which owns prediction-kind incidents.
- `netwatch/notify.py` — ntfy JSON publish via persistent SQLite queue with
  backoff (survives WAN outages). Disabled topic ⇒ log-only.
- `netwatch/ai.py` — opt-in Claude incident analyst (ANTHROPIC_API_KEY).
  Read-only: bundles incident + checks + actions + metrics + container/HA
  logs, calls the Messages API (anthropic SDK, adaptive thinking), stores
  result in incidents.analysis + ntfy push. Triggers: critical open,
  fix_failed, fix_unresolved (capped/spaced), manual via
  POST /api/incidents/{id}/analyze (uncapped). Logs are untrusted input —
  the system prompt hardens against instruction-following; output is
  display-only, never executed.
- Check keys are namespaced (`wan.ping`, `docker.container.<name>`,
  `truenas.pool.<name>`); the dashboard groups by first segment (see
  `web.py GROUPS`).

## Conventions / gotchas

- Tests cover the pure logic; collectors are tested via their parse/classify
  helpers only (no network mocking).
- Config is env-first: `apply_env_overrides` in config.py maps plain env vars
  (UNIFI_URL, HA_TOKEN, …) onto the config and auto-enables a service when any
  of its vars is set; `<X>_ENABLED` is the explicit override and env always
  beats YAML. config.yaml is optional advanced tuning; the container seeds
  only a `config.example.yaml` reference copy into /config. Kevin deploys by
  pasting docker-compose.yml into Dockge + filling its .env panel (no clone).
  Don't put `${...}` patterns in YAML comments — the env interpolator runs
  over the whole file.
- DB schema changes: SCHEMA in db.py uses CREATE IF NOT EXISTS only; for
  existing deployments add ALTER-based migration or bump a schema version.
- deps in requirements.txt are range-pinned; pydantic comes via fastapi.
- CI (.github/workflows/ci.yml): pytest on push/PR; pushes to main publish
  multi-arch (amd64/arm64) image to ghcr.io/kcb064/network-watchdog with
  :latest + :sha-* tags (v* tags add semver). Repo + image are PUBLIC (MIT).
  Kevin's NAS deploys the GHCR image via Dockge, not a local build.
- Release flow: bump `netwatch/__init__.py` __version__, add CHANGELOG.md
  entry, push, then `gh release create vX.Y.Z` — the tag's CI run publishes
  the `:X.Y.Z` image tag.
