"""Config loading: env interpolation, defaults, missing-env tracking."""
from netwatch.config import interpolate_env, load_config


def test_interpolate_env(monkeypatch):
    monkeypatch.setenv("MY_SECRET", "hunter2")
    monkeypatch.delenv("MISSING_ONE", raising=False)
    text, missing = interpolate_env("a: ${MY_SECRET}\nb: ${MISSING_ONE}")
    assert "hunter2" in text
    assert "b: " in text
    assert missing == {"MISSING_ONE"}


def test_load_defaults_without_file(tmp_path):
    cfg = load_config(tmp_path / "nope.yaml")
    assert cfg.server.port == 8787
    assert cfg.wan.enabled is True
    assert cfg.unifi.enabled is False
    assert cfg.remediation.mode == "tiered"
    assert cfg.state.open_after == 3


def test_load_yaml_with_env(tmp_path, monkeypatch):
    monkeypatch.setenv("T_PASS", "secret!")
    p = tmp_path / "config.yaml"
    p.write_text(
        """
server:
  port: 9999
adguard:
  enabled: true
  password: "${T_PASS}"
  auto_reenable_after_minutes: -1
remediation:
  mode: approve_all
  overrides:
    docker.restart_container: "off"
""",
        encoding="utf-8",
    )
    cfg = load_config(p)
    assert cfg.server.port == 9999
    assert cfg.adguard.password == "secret!"
    assert cfg.adguard.auto_reenable_after_minutes == -1
    assert cfg.remediation.overrides["docker.restart_container"] == "off"
    assert cfg.missing_env == set()


def test_unknown_keys_ignored(tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text("server:\n  port: 1234\n  bogus_key: hi\nwhatever: 1\n", encoding="utf-8")
    cfg = load_config(p)
    assert cfg.server.port == 1234


def test_env_vars_enable_service_without_yaml(tmp_path, monkeypatch):
    monkeypatch.setenv("HA_URL", "http://10.0.0.5:8123")
    monkeypatch.setenv("HA_TOKEN", "tok")
    monkeypatch.delenv("UNIFI_URL", raising=False)
    cfg = load_config(tmp_path / "absent.yaml")
    assert cfg.home_assistant.enabled is True
    assert cfg.home_assistant.url == "http://10.0.0.5:8123"
    assert cfg.home_assistant.token == "tok"
    assert cfg.unifi.enabled is False


def test_explicit_enabled_flag_wins(tmp_path, monkeypatch):
    monkeypatch.setenv("ADGUARD_URL", "http://10.0.0.6:3000")
    monkeypatch.setenv("ADGUARD_ENABLED", "false")
    monkeypatch.setenv("WAN_ENABLED", "false")
    cfg = load_config(tmp_path / "absent.yaml")
    assert cfg.adguard.enabled is False
    assert cfg.adguard.url == "http://10.0.0.6:3000"  # value still applied
    assert cfg.wan.enabled is False


def test_env_overrides_beat_yaml(tmp_path, monkeypatch):
    p = tmp_path / "config.yaml"
    p.write_text(
        "unifi:\n  enabled: false\n  url: https://old.local\n"
        "remediation:\n  mode: approve_all\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("UNIFI_URL", "https://192.168.9.1")
    monkeypatch.setenv("REMEDIATION_MODE", "off")
    monkeypatch.setenv("PUBLIC_URL", "http://nas:8787")
    cfg = load_config(p)
    assert cfg.unifi.enabled is True
    assert cfg.unifi.url == "https://192.168.9.1"
    assert cfg.remediation.mode == "off"
    assert cfg.server.public_url == "http://nas:8787"
