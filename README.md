# 🐕 Network Watchdog

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
| Flap suppression | A service bouncing up/down gets one "flapping" alert, then silence until it stabilizes |
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

## Quick start (Dockge on TrueNAS SCALE)

1. Clone into your Dockge stacks directory:

   ```bash
   cd /mnt/<pool>/dockge/stacks
   git clone https://github.com/kcb064/network-watchdog.git
   cd network-watchdog
   ```

   (Updates later: `git pull`, then rebuild/redeploy the stack in Dockge.)

2. Create your env file and config:

   ```bash
   cp .env.example .env        # fill in credentials (see below)
   mkdir -p config
   cp config.example.yaml config/config.yaml   # enable your services
   ```

   (If you skip the config copy, the container seeds it on first start —
   edit and redeploy.)

3. In Dockge: the stack appears → **Deploy**. It builds the image locally.

4. Open the dashboard: `http://<nas-ip>:8787`

5. Subscribe to your topic in the [ntfy app](https://ntfy.sh/app)
   (use the same topic string as `NTFY_TOPIC` in `.env`).

### Credentials to create

| Service | What to make | Where |
|---|---|---|
| UniFi | **Local** admin (not ui.com SSO), "Restrict to local access only" | UniFi OS → Admins & Users |
| Home Assistant | Long-lived access token | Profile → Security → Long-lived tokens |
| AdGuard Home | Your existing UI username/password | — |
| TrueNAS | API key | UI → user icon → API Keys |
| ntfy | Just pick a long random topic name | — |

Set `server.public_url` in `config/config.yaml` to `http://<nas-ip>:8787` so the
Approve/Deny buttons in notifications work from your phone (on LAN/VPN).

### Validate before deploying

```bash
docker compose run --rm watchdog python -m netwatch --config /config/config.yaml --data /data --doctor
```

`--doctor` tries every enabled service once and tells you exactly which
credential or URL is wrong.

## Remediation model

```
mode: tiered            # in config.yaml
```

| Action | Default tier | Notes |
|---|---|---|
| `docker.restart_container` | **auto** | crashed or unhealthy containers; max once per 30 min per container, never for restart-loops |
| `adguard.enable_protection` | **auto** | only after the grace period (default 30 min) |
| `ha.restart_container` | approve | needs `home_assistant.container_name` set |
| `unifi.restart_device` | approve | offered when a device is hung (CPU/RAM maxed) |

- Switch to `approve_all` (everything asks) or `off` (suggest-only) globally,
  or override per action in `remediation.overrides`.
- `never_touch` protects containers (default: `dockge`, `network-watchdog`).
- Approval links are single-use tokens that expire after 60 min.
- Every fix is verified: still broken 10 min later → escalation alert.

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
