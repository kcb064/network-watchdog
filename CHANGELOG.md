# Changelog

## v0.2.0 — 2026-06-10

First tagged release. Everything below was built and battle-tested against a
live TrueNAS SCALE + Dockge + UniFi + Home Assistant + AdGuard homelab.

### Deploy & config
- Paste-to-deploy: a single `docker-compose.yml` configured entirely through
  environment variables — setting a service's vars enables its monitoring;
  `<X>_ENABLED` overrides; env always beats the optional `config.yaml`.
- Multi-arch images (amd64/arm64) published to
  `ghcr.io/kcb064/network-watchdog` on every push to `main` (`:latest`,
  `:sha-*`) and on version tags (`:X.Y.Z`).

### Monitoring & prediction
- Collectors: UniFi (controller, WAN/www subsystems, per-device health with
  uplink learning), Home Assistant (API, unavailable-entity spikes, failed
  integrations by name), AdGuard Home (API, protection state, DNS latency),
  Docker (crashes, health, restart loops, per-container stats, image-change
  tracking), TrueNAS (pools, alerts, SMART via alerts, host CPU/RAM), WAN
  (ICMP-with-TCP-fallback ping, split DNS probes, HTTP).
- Engine: 3-open/2-close hysteresis, flap detection that mutes alerts but not
  auto-fixes, root-cause attribution, still-open reminders, stale-check
  cleanup.
- Predictions: pool days-until-full, container memory-leak ETAs (with restart
  offers), WAN latency degradation vs 7-day baseline.

### Remediation
- Tiered autonomy (auto / approve / off; global modes) with single-use
  approval tokens delivered as ntfy action buttons and a dashboard panel.
- Lifeline semantics: connectivity-restoring fixes retry with doubling
  backoff instead of degrading to approvals that can't be delivered
  mid-outage.
- Fallback ladders (`remediation_fallbacks`): rungs advance when a rung is
  exhausted, blocked, or proven unhelpful. Shipped ladders:
  - AdGuard add-on restart → UniFi DHCP DNS failover (auto-reverts on
    recovery)
  - HA failed-integration reload → HA Core restart
  - container restart / PoE port cycle / UniFi device reboot / modem
    power-cycle via HA smart plug
- Fix verification ("didn't help" escalation), revertible mitigations,
  failed attempts re-enter consideration instead of parking incidents.

### AI incident analyst (opt-in)
- `ANTHROPIC_API_KEY` enables Claude-written diagnoses (probable cause /
  evidence / next steps) on critical opens, failed fixes, and unresolved
  fixes, plus an uncapped manual button per incident.
- Bundles include derived host topology, unavailable-entity samples,
  remediation history, metric summaries, container logs / HA error log
  (marked untrusted), and image-change notes. Read-only by design;
  capped and spaced automatic spend.

### Observability
- Dark-mode dashboard: status cards with sparklines, incidents, predictions,
  approvals, remediation audit log, AI analyses.
- ntfy notifications with persistent retry queue (survives WAN outages),
  recovery notices, flap notices; optional healthchecks.io dead man's switch.

## v0.1.0 — 2026-06-10 (untagged)

Initial scaffold: collectors, state-machine engine, SQLite storage, ntfy
notifications, tiered remediation registry, predictions, dashboard.
