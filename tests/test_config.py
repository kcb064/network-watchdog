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
