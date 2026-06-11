# 🐕 Network Watchdog

[![CI](https://github.com/kcb064/network-watchdog/actions/workflows/ci.yml/badge.svg)](https://github.com/kcb064/network-watchdog/actions/workflows/ci.yml)
[![Image](https://img.shields.io/badge/ghcr.io-kcb064%2Fnetwork--watchdog-blue)](https://github.com/kcb064/network-watchdog/pkgs/container/network-watchdog)

Self-hosted homelab health monitor for a TrueNAS SCALE + Dockge setup. Watches
**UniFi, Home Assistant, AdGuard Home, Docker containers, internet/WAN quality,
and the NAS itself**, detects problems as they happen, **predicts** ones that
haven't happened yet, pushes alerts via **ntfy**, and **fixes what it safely
can** — with approval buttons for anything risky.

Single container. SQLite storage. No agents on other machines — everything is
monitored over the APIs you already have.

## What it does

| Capability | How |
|---|---|
| Detect outages | Polls every service (default 30 s) with hysteresis: 3 consecutive failures open an incident, 2 successes close it — no alerts from a single dropped packet |
| Root-cause grouping | If the WAN is down, DNS/HTTP failures are attributed to it instead of spamming you with 5 alerts |
| Flap suppression | A service bouncing up/down gets one "flapping" alert, then up/down alerts are muted until it stabilizes — automatic fixes keep running and are always announced |
| Predict disk full | Linear trend on pool usage → "Pool tank full in ~12 days" before it happens |
| Predict memory leaks | Containers with steadily climbing RAM are flagged with their exhaustion ETA |
| Predict ISP degradation | Recent ping latency vs. 7-day baseline (z-score) |
| Auto-fix (tiered) | Crashed/unhealthy containers restarted automatically; risky fixes (reboot an AP, restart HA) send an **Approve/Deny button in the ntfy notification** |
| Verify fixes | If a fix doesn't resolve the incident within 10 min, you're told it didn't work |
| Audit log | Every action — auto or approved — is recorded and shown on the dashboard |
| Survive outages | Notifications queue in SQLite and retry with backoff, so you still get the story after the WAN comes back |
| Dead man's switch | Optional healthchecks.io heartbeat — the one failure (NAS death) it can't report itself |

Per-service checks:

- **UniFi** — controller reachability, gateway WAN status, internet health (latency/throughput from the gateway's view), every AP/switch (offline, hung with maxed CPU/RAM → offers reboot), client count, pending firmware updates
- **Home Assistant** — API up + latency, unavailable-entity spikes ("top offender: zwave (12)"), pending updates, version-change events; optional container-restart remediation
- **AdGuard Home** — reachability, protection accidentally left disabled (auto re-enables after a grace period), slow DNS processing, query/block stats
- **Docker** — every container: crashed (non-zero exit), unhealthy healthcheck, restart loops (those always require approval — a restart rarely fixes a crash loop), per-container CPU/RAM
- **TrueNAS** — pool health (DEGRADED/FAULTED = critical), capacity warnings, every TrueNAS alert (SMART failures, scrub errors) pushed individually, disk temps, host CPU/RAM, reboot detection
- **WAN** — ICMP ping loss/latency to 1.1.1.1 + 8.8.8.8, DNS via *your AdGuard and a public resolver separately* (so you know which broke), HTTP fetch

## Quick start (Dockge — nothing to clone)

1. In Dockge: **+ Compose**, name it `network-watchdog`, and paste
   [docker-compose.yml](https://raw.githubusercontent.com/kcb064/network-watchdog/main/docker-compose.yml).

2. In the **.env** panel, paste
   [.env.example](https://raw.githubusercontent.com/kcb064/network-watchdog/main/.env.example)
   and uncomment/fill the services you run. **Setting a service's variables
   turns its monitoring on** — no other configuration needed. WAN + Docker
   monitoring are on by default.

3. **Deploy** (pulls the prebuilt multi-arch image
   `ghcr.io/kcb064/network-watchdog:latest`), then open
   `http://<nas-ip>:8787` and subscribe to your topic in the
   [ntfy app](https://ntfy.sh/app).

### Environment variables

| Variables | Enables |
|---|---|
| `NTFY_TOPIC` (+ `NTFY_SERVER`, `NTFY_TOKEN`) | Push notifications |
| `PUBLIC_URL` | Approve/Deny buttons inside notifications |
| `UNIFI_URL`, `UNIFI_USERNAME`, `UNIFI_PASSWORD` | UniFi monitoring |
| `HA_URL`, `HA_TOKEN` (+ `HA_CONTAINER`) | Home Assistant monitoring (+ restart remediation) |
| `ADGUARD_URL`, `ADGUARD_USERNAME`, `ADGUARD_PASSWORD` | AdGuard monitoring + protection re-enable |
| `TRUENAS_URL`, `TRUENAS_API_KEY` | Pool health, alerts, capacity predictions |
| `WATCHDOG_PASSWORD` | Dashboard basic auth (user `admin`) |
| `HEARTBEAT_URL` | Dead man's switch (healthchecks.io) |
| `REMEDIATION_MODE` | `tiered` (default) / `approve_all` / `off` |
| `ADGUARD_HA_ADDON` | AdGuard runs as an HA add-on → auto-restart it when it dies (slug, e.g. `a0d7b954_adguard`) |
| `ADGUARD_FAILOVER_DNS` | AdGuard stays dead → switch UniFi DHCP DNS to this resolver, revert on recovery (e.g. `1.1.1.1`) |
| `ANTHROPIC_API_KEY` (+ `AI_MODEL`, `AI_CONTEXT`) | AI incident analysis — Claude-written root-cause diagnosis on incidents and failed fixes; `AI_CONTEXT` = facts about your lab it can't infer |
| `WAN_POWER_CYCLE_ENTITY` | HA smart plug on the modem → power-cycle when internet is hard-down |
| `REMEDIATION_OVERRIDES` | Per-action tiers, e.g. `unifi.poe_cycle=auto,wan.power_cycle=auto` |
| `WAN_ENABLED`, `DOCKER_ENABLED`, `UNIFI_ENABLED`, `HA_ENABLED`, `ADGUARD_ENABLED`, `TRUENAS_ENABLED` | Explicit on/off overrides |

Fine-grained tuning (thresholds, poll intervals, per-action remediation
tiers, container exclude lists) lives in an optional YAML file: the container
drops `config.example.yaml` into the stack's `./config` folder — copy it to
`config/config.yaml`, edit, redeploy. Environment variables always win over
YAML.

### Credentials to create

| Service | What to make | Where |
|---|---|---|
| UniFi | **Local** admin (not ui.com SSO), "Restrict to local access only" | UniFi OS → Admins & Users |
| Home Assistant | Long-lived access token | Profile → Security → Long-lived tokens |
| AdGuard Home | Your existing UI username/password | — |
| TrueNAS | API key | UI → user icon → API Keys |
| ntfy | Just pick a long random topic name | — |

### Validate your credentials

After deploying, open the container's terminal in Dockge (`>_` on the
container) and run:

```bash
python -m netwatch --config /config/config.yaml --data /tmp --doctor
```

`--doctor` tries every enabled service once and tells you exactly which
credential or URL is wrong. (The dashboard's Watchdog card shows the same
collector errors live.)

### Updating

Every push to `main` publishes a fresh `:latest` image via GitHub Actions —
just hit **Update** on the stack in Dockge (or
`docker compose pull && docker compose up -d`). Pin a `sha-<commit>` tag (or
`vX.Y.Z` once releases are tagged) instead of `:latest` if you want updates
only when you choose.

## Remediation model

```
mode: tiered            # in config.yaml
```

| Action | Default tier | Notes |
|---|---|---|
| `docker.restart_container` | **auto** | crashed or unhealthy containers; max once per 30 min per container, never for restart-loops |
| `adguard.enable_protection` | **auto** | only after the grace period (default 30 min) |
| `adguard.restart_ha_addon` | **auto** | AdGuard-as-HA-add-on stopped answering (needs `ADGUARD_HA_ADDON`) |
| `ha.restart_container` | approve | needs `home_assistant.container_name` set |
| `unifi.restart_device` | approve | offered when a device is hung (CPU/RAM maxed) |
| `unifi.poe_cycle` | approve | AP went offline → power-cycle its PoE port on the upstream switch (uplink learned while the AP was online) |
| `wan.power_cycle` | approve | internet hard-down → power-cycle the modem via an HA smart plug (needs `WAN_POWER_CYCLE_ENTITY`); always turns power back on, with retries |
| `unifi.dns_failover` | **auto** | fallback rung behind the AdGuard restarts: switches UniFi DHCP DNS to `ADGUARD_FAILOVER_DNS`, **auto-reverts when AdGuard recovers**. Clients pick up the change as DHCP leases renew |

Fixes can form **fallback chains**: when a rung's attempt budget is spent, the
next rung takes over while the earlier one keeps retrying on its backoff
schedule. The AdGuard ladder is *restart add-on → DNS failover*, so a dead
AdGuard costs you ad-blocking, not internet.

Want connectivity problems to fix themselves without waiting for your tap?
Flip the risky-but-effective ones to auto:

```
REMEDIATION_OVERRIDES=unifi.restart_device=auto,unifi.poe_cycle=auto,wan.power_cycle=auto
```

**Repeat handling** distinguishes two classes of fixes:

- **Lifeline fixes** (`adguard.restart_ha_addon`, `wan.power_cycle`,
  `unifi.poe_cycle`, `unifi.restart_device`) restore the connectivity that
  notifications themselves need — so they never wait on an approval that
  can't be delivered mid-outage. They auto-retry with doubling backoff
  (30 min → 1 h → …), up to `max_auto_attempts` (default 3) per 6 h, and only
  then fall back to an approval request (queued, delivered when possible).
- **Everything else** (e.g. container restarts) downgrades to an approval
  after one auto attempt per 30 min — a fix that isn't sticking should get a
  human look before it loops.

- Switch to `approve_all` (everything asks) or `off` (suggest-only) globally,
  or override per action in `remediation.overrides`.
- `never_touch` protects containers (default: `dockge`, `network-watchdog`).
- Approval links are single-use tokens that expire after 60 min.
- Every fix is verified: still broken 10 min later → escalation alert.

## AI incident analysis (optional)

Set `ANTHROPIC_API_KEY` (from [console.anthropic.com](https://console.anthropic.com))
and every critical incident, failed fix, and fix-that-didn't-help gets a short
Claude-written diagnosis — probable cause, evidence, next steps — pushed via
ntfy and shown under the incident on the dashboard. The analyst sees what an
SRE would: current check states, remediation history, metric summaries, and
the failing container's logs (or HA's error log).

- **Read-only by design.** The AI explains and suggests; it never executes
  anything. The rules engine remains the only acting layer.
- **Cost-bounded.** Automatic analyses are capped (default 20/day, 30-min
  per-incident spacing); each costs a few cents with the default
  `claude-opus-4-8` (set `AI_MODEL=claude-haiku-4-5` to make it ~5× cheaper).
  The dashboard's 🧠 button analyzes on demand, uncapped.
- **Injection-aware.** Logs fed to the model are marked untrusted, and model
  output is only ever displayed — never executed.
- **Knows your layout.** The bundle includes a topology section derived from
  your configured URLs (which services share a host, which are separate
  machines) plus a sample of unavailable HA entities when relevant. Add
  `AI_CONTEXT` with anything it can't infer ("HA runs on a mini-PC, Zigbee
  dongle on the HA box") — one sentence here noticeably sharpens diagnoses.
- Needs WAN (it's a cloud API): during a full internet outage, analysis is
  unavailable while local rules keep acting.

## Security notes

- The Docker socket grants root-equivalent control of the host. If you want a
  read-only watchdog: mount the socket `:ro` and set the docker/HA remediation
  overrides to `off`.
- The dashboard is unauthenticated by default (LAN tool). Set
  `WATCHDOG_PASSWORD` in `.env` to enable basic auth (user `admin`). Don't
  port-forward it to the internet; use a VPN (WireGuard/Tailscale).
- Anyone who knows your ntfy topic on ntfy.sh can read your alerts — treat the
  topic like a password, or self-host ntfy (compose file includes a commented
  block; that also keeps push working during WAN outages).
- Prefer IP addresses over hostnames in `config.yaml` so monitoring keeps
  working when DNS itself is the problem.

## The one thing it can't see

If the NAS dies, the watchdog dies with it. Set `server.heartbeat_url` to a
free [healthchecks.io](https://healthchecks.io) check URL — the watchdog pings
it every minute, and healthchecks.io alerts you when the pings stop.

## Development

```bash
python -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest tests        # 52 tests, pure-logic core
.venv/bin/python -m netwatch --config config.example.yaml --data data
```

CI (`.github/workflows/ci.yml`) runs the tests on every push/PR and publishes
the multi-arch image to GHCR on pushes to `main` and `v*` tags.

Architecture:

```
netwatch/
  engine.py       state machine (hysteresis, flap, escalation) + scheduling
  collectors/     wan, docker_, adguard, homeassistant, unifi, truenas
  predict.py      disk-fill ETA, memory-leak ETA, latency anomaly (pure math)
  remediate.py    action registry, tier policy, approval tokens, audit
  notify.py       ntfy JSON publish + persistent retry queue
  web.py          FastAPI dashboard + JSON API + approval endpoints
  db.py           SQLite (WAL): samples, check_states, incidents, actions, queue
```

## Roadmap ideas

- Generic ping/TCP/HTTP checks for arbitrary LAN devices
- TLS certificate expiry countdowns
- Daily/weekly digest notification
- Claude-powered incident summaries ("what probably happened and why")
