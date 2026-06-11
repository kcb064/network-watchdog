"""Parsing/classification helpers in collectors (no network needed)."""
from netwatch.collectors.adguard import normalize_processing_ms
from netwatch.collectors.base import slug
from netwatch.collectors.docker_ import classify_container, container_name
from netwatch.collectors.homeassistant import failed_entries, summarize_unavailable
from netwatch.collectors.truenas import alert_severity, classify_pool, ws_url
from netwatch.collectors.unifi import extract_uplink, map_subsystem
from netwatch.models import FAIL, OK, WARN


def test_container_name():
    assert container_name({"Names": ["/plex"]}) == "plex"
    assert container_name({}) == "unknown"


def test_classify_running_healthy():
    info = {"Id": "x", "Names": ["/plex"], "State": "running", "Status": "Up 3 hours (healthy)"}
    status, sev, msg, rem = classify_container(info, None)
    assert status == OK and not rem


def test_classify_unhealthy_offers_restart():
    info = {"Id": "x", "Names": ["/plex"], "State": "running",
            "Status": "Up 3 hours (unhealthy)"}
    status, sev, msg, rem = classify_container(info, None)
    assert status == FAIL
    assert rem["kind"] == "restart_container" and rem["reason"] == "unhealthy"


def test_classify_crashed_vs_stopped():
    info = {"Id": "x", "Names": ["/app"], "State": "exited", "Status": "Exited (1) 5m ago"}
    inspect = {"State": {"ExitCode": 1}}
    status, _, msg, rem = classify_container(info, inspect)
    assert status == FAIL and rem["reason"] == "crashed"

    inspect_ok = {"State": {"ExitCode": 0}}
    status, _, msg, rem = classify_container(
        {"Id": "x", "Names": ["/job"], "State": "exited", "Status": "Exited (0)"}, inspect_ok
    )
    assert status == OK and not rem


def test_classify_restart_loop():
    info = {"Id": "x", "Names": ["/bad"], "State": "restarting",
            "Status": "Restarting (1) 2 seconds ago"}
    status, _, msg, rem = classify_container(info, None)
    assert status == FAIL and rem.get("restart_loop") is True


def test_adguard_unit_normalization():
    assert normalize_processing_ms(0.014) == 14.0   # seconds -> ms
    assert normalize_processing_ms(23.5) == 23.5    # already ms


def test_truenas_pool_classification():
    ok_pool = {"name": "tank", "status": "ONLINE", "healthy": True,
               "size": 1000, "allocated": 400}
    assert classify_pool(ok_pool, 85)[0] == OK

    full = dict(ok_pool, allocated=900)
    status, sev, msg = classify_pool(full, 85)
    assert status == WARN and "90%" in msg

    degraded = dict(ok_pool, status="DEGRADED", healthy=False)
    status, sev, msg = classify_pool(degraded, 85)
    assert status == FAIL and sev == "critical"

    faulted = dict(ok_pool, status="FAULTED")
    assert classify_pool(faulted, 85)[1] == "critical"


def test_truenas_ws_url():
    assert ws_url("https://192.168.1.250") == "wss://192.168.1.250/api/current"
    assert ws_url("http://truenas.local/") == "ws://truenas.local/api/current"


def test_truenas_alert_severity():
    assert alert_severity("CRITICAL") == "critical"
    assert alert_severity("WARNING") == "warn"
    assert alert_severity("info") == "warn"


def test_unifi_subsystem_mapping():
    assert map_subsystem("ok") == (OK, "critical")
    assert map_subsystem("warning") == (WARN, "warn")
    assert map_subsystem("error") == (FAIL, "critical")
    assert map_subsystem("unknown") == (OK, "critical")  # unused subsystem: silent


def test_ha_unavailable_summary():
    states = [
        {"entity_id": "light.kitchen", "state": "on"},
        {"entity_id": "sensor.temp", "state": "unavailable"},
        {"entity_id": "sensor.hum", "state": "unavailable"},
        {"entity_id": "switch.fan", "state": "unknown"},  # unknown is often legit
    ]
    total, unavailable, top = summarize_unavailable(states)
    assert total == 4 and unavailable == 2
    assert "sensor (2)" in top


def test_slug():
    assert slug("Living Room AP") == "Living-Room-AP"
    assert slug("  ") == "unnamed"


def test_failed_entries():
    entries = [
        {"entry_id": "a", "state": "loaded", "title": "Fine"},
        {"entry_id": "b", "state": "setup_error", "title": "Plex", "reason": "auth"},
        {"entry_id": "c", "state": "setup_retry", "title": "UniFi"},
        {"entry_id": "d", "state": "setup_error", "title": "Off",
         "disabled_by": "user"},
        {"entry_id": "e", "state": "not_loaded", "title": "Lazy"},
    ]
    bad = failed_entries(entries)
    assert [e["entry_id"] for e in bad] == ["b", "c"]


def test_extract_uplink():
    dev = {"uplink": {"type": "wire", "uplink_mac": "aa:bb:cc",
                      "uplink_remote_port": "8"}}
    assert extract_uplink(dev) == {"switch_mac": "aa:bb:cc", "port_idx": 8}
    assert extract_uplink({"uplink": {"type": "wireless"}}) is None  # mesh AP
    assert extract_uplink({}) is None


def test_select_dns_networks():
    from netwatch.collectors.unifi import select_dns_networks
    nets = [
        {"_id": "n1", "name": "LAN", "dhcpd_dns_1": "192.168.1.28", "dhcpd_dns_2": ""},
        {"_id": "n2", "name": "IoT", "dhcpd_dns_1": "9.9.9.9"},
        {"_id": "n3", "name": "Guest", "dhcpd_dns_2": "192.168.1.28"},
    ]
    saved = select_dns_networks(nets, "192.168.1.28")
    assert set(saved) == {"n1", "n3"}
    assert saved["n1"]["dhcpd_dns_1"] == "192.168.1.28"
    assert saved["n3"]["name"] == "Guest"
