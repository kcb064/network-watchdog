"""Configuration loading: YAML file with ${ENV_VAR} interpolation for secrets."""
from __future__ import annotations

import logging
import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

log = logging.getLogger("netwatch.config")

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class _Base(BaseModel):
    model_config = ConfigDict(extra="ignore")


class PollConfig(_Base):
    fast: int = 30      # availability checks (seconds)
    medium: int = 120   # stats / metrics
    slow: int = 3600    # predictions, slow scans


class StateConfig(_Base):
    open_after: int = 3          # consecutive bad polls before an incident opens
    close_after: int = 2         # consecutive ok polls before it closes
    flap_window_minutes: int = 60
    flap_threshold: int = 6      # state changes within window => flapping
    flap_calm_minutes: int = 30
    remind_hours: float = 6.0    # re-notify still-open critical incidents (0 = off)


class NtfyConfig(_Base):
    enabled: bool = True
    server: str = "https://ntfy.sh"
    topic: str = ""
    token: str = ""              # ntfy access token (Bearer), optional
    username: str = ""           # or basic auth, optional
    password: str = ""
    notify_recoveries: bool = True
    startup_message: bool = True
    max_queue_age_hours: float = 6.0  # drop undeliverable notifications after this


class UnifiConfig(_Base):
    enabled: bool = False
    url: str = "https://192.168.1.1"   # UDM/UDR or controller URL
    username: str = ""
    password: str = ""
    site: str = "default"
    verify_ssl: bool = False
    device_offline_severity: str = "warn"


class HomeAssistantConfig(_Base):
    enabled: bool = False
    url: str = "http://homeassistant.local:8123"
    token: str = ""                 # long-lived access token
    container_name: str = ""        # if HA runs in Docker on this NAS, enables restart remediation
    unavailable_warn_pct: float = 10.0  # warn if > this % of entities are unavailable/unknown


class AdguardConfig(_Base):
    enabled: bool = False
    url: str = "http://192.168.1.5:3000"
    username: str = ""
    password: str = ""
    # 0 = re-enable protection immediately when found disabled; -1 = never auto;
    # N>0 = auto re-enable after N minutes disabled (gives you room to test things)
    auto_reenable_after_minutes: int = 30
    avg_processing_warn_ms: float = 300.0
    # If AdGuard runs as a Home Assistant add-on, its slug (e.g.
    # "a0d7b954_adguard") lets the watchdog restart it via HA when it dies.
    ha_addon: str = ""
    # Last-resort DNS failover: when AdGuard stays dead after the restart
    # attempts are exhausted, UniFi networks whose DHCP DNS points at AdGuard
    # are switched to this resolver — and switched back once AdGuard recovers.
    # Empty = feature off. Requires UniFi monitoring.
    failover_dns: str = ""


class TruenasConfig(_Base):
    enabled: bool = False
    url: str = "https://192.168.1.2"
    api_key: str = ""
    verify_ssl: bool = False
    pool_capacity_warn_pct: float = 85.0
    host_metrics: bool = True   # CPU/RAM/load via /proc (works because we run on the NAS)


class WanConfig(_Base):
    enabled: bool = True
    ping_targets: list[str] = Field(default_factory=lambda: ["1.1.1.1", "8.8.8.8"])
    ping_count: int = 5
    method: str = "auto"        # auto | icmp | tcp  (tcp needs no privileges)
    dns_test_domain: str = "example.com"
    dns_servers: list[str] = Field(default_factory=list)  # e.g. AdGuard IP + a public resolver
    http_targets: list[str] = Field(
        default_factory=lambda: ["https://www.gstatic.com/generate_204"]
    )
    loss_warn_pct: float = 10.0
    loss_fail_pct: float = 60.0
    # HA switch/outlet entity powering the modem (e.g. "switch.modem_plug").
    # When the internet is hard-down, the watchdog can power-cycle it via HA.
    power_cycle_entity: str = ""
    power_cycle_off_seconds: int = 15


class DockerConfig(_Base):
    enabled: bool = True
    socket: str = "/var/run/docker.sock"
    stats: bool = True                      # per-container CPU/mem (heavier)
    exclude: list[str] = Field(default_factory=list)  # name patterns to ignore (fnmatch)
    restart_loop_count: int = 3             # restarts within window => loop
    restart_loop_window_minutes: int = 15


class RemediationConfig(_Base):
    # tiered: per-action default tiers apply (safe ones auto-run)
    # approve_all: every action needs approval
    # off: never act, only suggest
    mode: str = "tiered"
    overrides: dict[str, str] = Field(default_factory=dict)  # action id -> auto|approve|off
    never_touch: list[str] = Field(default_factory=lambda: ["dockge", "network-watchdog"])
    auto_cooldown_minutes: int = 30   # min gap between auto runs of same action+target
    # Lifeline (connectivity-restoring) fixes retry automatically with doubling
    # backoff up to this many attempts per 6 h before asking for approval —
    # an approval request can't reach you while DNS/WAN itself is down.
    max_auto_attempts: int = 3
    approval_ttl_minutes: int = 60
    verify_minutes: int = 10          # escalate if incident still open this long after a fix


class PredictionsConfig(_Base):
    enabled: bool = True
    disk_warn_days: float = 14.0
    disk_min_points: int = 12
    mem_leak_window_hours: float = 24.0
    mem_leak_min_r2: float = 0.6
    latency_z_threshold: float = 3.0


class AIConfig(_Base):
    """Claude-powered incident analysis. Off unless an API key is set."""

    enabled: bool = True
    api_key: str = ""                  # ANTHROPIC_API_KEY
    model: str = "claude-opus-4-8"     # AI_MODEL to override (e.g. claude-haiku-4-5)
    max_per_day: int = 20              # cap on automatic analyses (manual is uncapped)
    min_gap_minutes: int = 30          # per-incident spacing for automatic analyses


class ServerConfig(_Base):
    port: int = 8787
    public_url: str = ""     # e.g. http://192.168.1.2:8787 — needed for ntfy action buttons
    password: str = ""       # optional HTTP basic auth (user: admin)
    heartbeat_url: str = ""  # optional healthchecks.io-style dead man's switch
    retention_days: int = 30
    log_level: str = "INFO"


class Config(_Base):
    server: ServerConfig = Field(default_factory=ServerConfig)
    poll: PollConfig = Field(default_factory=PollConfig)
    state: StateConfig = Field(default_factory=StateConfig)
    ntfy: NtfyConfig = Field(default_factory=NtfyConfig)
    unifi: UnifiConfig = Field(default_factory=UnifiConfig)
    home_assistant: HomeAssistantConfig = Field(default_factory=HomeAssistantConfig)
    adguard: AdguardConfig = Field(default_factory=AdguardConfig)
    truenas: TruenasConfig = Field(default_factory=TruenasConfig)
    wan: WanConfig = Field(default_factory=WanConfig)
    docker: DockerConfig = Field(default_factory=DockerConfig)
    remediation: RemediationConfig = Field(default_factory=RemediationConfig)
    predictions: PredictionsConfig = Field(default_factory=PredictionsConfig)
    ai: AIConfig = Field(default_factory=AIConfig)

    missing_env: set[str] = Field(default_factory=set, exclude=True)


def interpolate_env(text: str) -> tuple[str, set[str]]:
    """Replace ${VAR} with the environment value; collect names that are unset."""
    missing: set[str] = set()

    def sub(m: re.Match) -> str:
        name = m.group(1)
        val = os.environ.get(name)
        if val is None:
            missing.add(name)
            return ""
        return val

    return _ENV_RE.sub(sub, text), missing


def _bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


# env var -> (config section attr on Config, field). Setting any var of a
# service enables that service unless an explicit <X>_ENABLED says otherwise.
_SERVICE_ENV = {
    "unifi": {"UNIFI_URL": "url", "UNIFI_USERNAME": "username",
              "UNIFI_PASSWORD": "password", "UNIFI_SITE": "site"},
    "home_assistant": {"HA_URL": "url", "HA_TOKEN": "token",
                       "HA_CONTAINER": "container_name"},
    "adguard": {"ADGUARD_URL": "url", "ADGUARD_USERNAME": "username",
                "ADGUARD_PASSWORD": "password", "ADGUARD_HA_ADDON": "ha_addon",
                "ADGUARD_FAILOVER_DNS": "failover_dns"},
    "truenas": {"TRUENAS_URL": "url", "TRUENAS_API_KEY": "api_key"},
}
_ENABLED_ENV = {
    "unifi": "UNIFI_ENABLED", "home_assistant": "HA_ENABLED",
    "adguard": "ADGUARD_ENABLED", "truenas": "TRUENAS_ENABLED",
    "wan": "WAN_ENABLED", "docker": "DOCKER_ENABLED", "ai": "AI_ENABLED",
}
_SIMPLE_ENV = {
    "NTFY_SERVER": ("ntfy", "server"), "NTFY_TOPIC": ("ntfy", "topic"),
    "NTFY_TOKEN": ("ntfy", "token"),
    "PUBLIC_URL": ("server", "public_url"),
    "WATCHDOG_PASSWORD": ("server", "password"),
    "HEARTBEAT_URL": ("server", "heartbeat_url"),
    "REMEDIATION_MODE": ("remediation", "mode"),
    "WAN_POWER_CYCLE_ENTITY": ("wan", "power_cycle_entity"),
    "ANTHROPIC_API_KEY": ("ai", "api_key"),
    "AI_MODEL": ("ai", "model"),
}


def apply_env_overrides(cfg: Config) -> None:
    """Compose-only deployment mode: configure everything with plain env vars.

    Env vars always win over config.yaml. A service is auto-enabled when any
    of its env vars is set (non-empty); <X>_ENABLED=true/false is explicit.
    """
    for env_name, (section_name, attr) in _SIMPLE_ENV.items():
        val = os.environ.get(env_name)
        if val:
            setattr(getattr(cfg, section_name), attr, val)

    for section_name, mapping in _SERVICE_ENV.items():
        section = getattr(cfg, section_name)
        touched = False
        for env_name, attr in mapping.items():
            val = os.environ.get(env_name)
            if val:
                setattr(section, attr, val)
                touched = True
        if touched:
            section.enabled = True

    for section_name, env_name in _ENABLED_ENV.items():
        val = os.environ.get(env_name)
        if val:
            getattr(cfg, section_name).enabled = _bool(val)

    # Per-action tier overrides without YAML, e.g.
    # REMEDIATION_OVERRIDES=unifi.poe_cycle=auto,docker.restart_container=approve
    overrides = os.environ.get("REMEDIATION_OVERRIDES", "")
    for pair in overrides.split(","):
        if "=" not in pair:
            continue
        action, tier = (p.strip() for p in pair.split("=", 1))
        if action and tier.lower() in ("auto", "approve", "off"):
            cfg.remediation.overrides[action] = tier.lower()


def load_config(path: str | Path | None) -> Config:
    data: dict = {}
    missing: set[str] = set()
    if path and Path(path).exists():
        raw = Path(path).read_text(encoding="utf-8")
        raw, missing = interpolate_env(raw)
        data = yaml.safe_load(raw) or {}
    elif path:
        log.info("No config file at %s — using defaults + environment variables", path)

    cfg = Config(**data)
    cfg.missing_env = missing
    for name in sorted(missing):
        log.warning("Environment variable %s referenced in config but not set", name)
    apply_env_overrides(cfg)
    return cfg
