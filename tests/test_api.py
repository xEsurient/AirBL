"""HTTP API tests (FastAPI TestClient, startup events not run)."""

import pytest
from fastapi.testclient import TestClient

from airbl.config import GluetunProfileConfig, WireGuardProfileConfig, config_manager
from airbl.web import tasks
from airbl.web.routes import api
from airbl.web.state import state


@pytest.fixture
def client(fresh_config, monkeypatch):
    from airbl.web.app import create_app

    async def no_api():
        raise RuntimeError("network disabled in tests")

    monkeypatch.setattr(api, "get_airvpn_status", no_api)
    return TestClient(create_app())  # no `with`: startup (DB, AirVPN API) never runs


def post_settings(client, payload):
    return client.post("/api/settings", json=payload)


# --- POST /api/settings: validation ------------------------------------------

@pytest.mark.parametrize("payload", [
    {"scan_interval_minutes": 30, "preferred_mtu": None},
    {"scan_interval_minutes": 30, "preferred_mtu": "abc"},
    {"scan_interval_minutes": 30, "performance_threshold_download": "nan"},
    {"scan_interval_minutes": 30, "speedtest_enabled": "maybe"},
    {"scan_interval_minutes": 30, "scan_mode": "hourly"},
    {"scan_interval_minutes": 30, "preferred_port": 1234},
    {"scan_interval_minutes": 30, "discovery_duration_days": 4},
    {"scan_interval_minutes": 30, "enabled_countries": "CH"},
    {"scan_interval_minutes": 30, "scan_schedule_days": ["Mon", "Funday"]},
    {"scan_interval_minutes": 30, "auto_scan_enabled": None},
    {"scan_interval_minutes": 30, "gluetun_control_port": True},
])
def test_settings_bad_value_400_and_nothing_changed(client, fresh_config, payload):
    before = fresh_config.model_dump()
    r = post_settings(client, payload)
    assert r.status_code == 400
    assert "error" in r.json()
    assert config_manager.config.model_dump() == before
    assert config_manager.config.scan.scan_interval_minutes == 120


def test_settings_non_object_and_bad_json(client):
    assert post_settings(client, [1, 2]).status_code == 400
    r = client.post("/api/settings", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 400


def test_settings_valid_payload_applied(client, fresh_config, broadcasts):
    r = post_settings(client, {
        "scan_interval_minutes": "45",
        "scan_mode": "schedule",
        "scan_schedule_days": ["sunday", "Mon", "mon"],
        "auto_scan_enabled": "off",
        "speedtest_enabled": 0,
        "preferred_port": "47107",
        "preferred_entry_ip": "AUTO",
        "performance_threshold_download": 75.5,
        "deviation_download_weight": 0.3,
        "signal_good_threshold": 40,
        "signal_medium_threshold": 60,
        "gluetun_control_host": "",
        "post_server_wait": 180,
    })
    assert r.status_code == 200, r.text
    assert r.json()["warnings"] == []
    cfg = config_manager.config
    assert cfg.scan.scan_interval_minutes == 45
    assert cfg.scan.scan_mode == "schedule"
    assert cfg.scan.scan_schedule_days == ["Mon", "Sun"]  # deduped, canonical order
    assert cfg.scan.auto_scan_enabled is False
    assert cfg.scan.speedtest_enabled is False
    assert cfg.scan.preferred_port == 47107
    assert cfg.scan.preferred_entry_ip == "AUTO"
    assert cfg.performance.threshold_download == 75.5
    assert (cfg.scoring.deviation_download_weight, cfg.scoring.deviation_upload_weight) == (0.3, 0.7)
    # medium must stay below good
    assert cfg.scoring.signal_good_threshold == 40
    assert cfg.scoring.signal_medium_threshold == 39
    assert cfg.gluetun.control_server_host == "127.0.0.1"
    assert cfg.scan.post_server_wait == 180
    assert "settings_changed" in broadcasts.types()


def test_settings_interval_clamped(client):
    post_settings(client, {"scan_interval_minutes": 1})
    assert config_manager.config.scan.scan_interval_minutes == 5
    post_settings(client, {"scan_interval_minutes": 99999})
    assert config_manager.config.scan.scan_interval_minutes == 1440


def test_settings_gluetun_watchdog_interval(client, fresh_config):
    assert client.get("/api/settings").json()["gluetun_watchdog_interval"] == 60
    post_settings(client, {"gluetun_watchdog_interval": 0})
    assert config_manager.config.gluetun.watchdog_interval_seconds == 0
    post_settings(client, {"gluetun_watchdog_interval": 99999})
    assert config_manager.config.gluetun.watchdog_interval_seconds == 3600


def test_settings_save_failure_returns_500(client, monkeypatch):
    monkeypatch.setattr(config_manager, "save", lambda: False)
    r = post_settings(client, {"scan_interval_minutes": 60})
    assert r.status_code == 500


@pytest.mark.parametrize("value,expected", [("7:05", "07:05"), (" 23:59 ", "23:59"), ("00:00", "00:00")])
def test_schedule_time_valid(client, value, expected):
    assert post_settings(client, {"scan_schedule_time": value}).status_code == 200
    assert config_manager.config.scan.scan_schedule_time == expected


@pytest.mark.parametrize("value", ["24:00", "12:60", "noon", "", None, "1:5", "12:00:00"])
def test_schedule_time_invalid(client, value):
    assert post_settings(client, {"scan_schedule_time": value}).status_code == 400
    assert config_manager.config.scan.scan_schedule_time == "20:00"


@pytest.mark.parametrize("value,expected", [(9000, 1500), (100, 1280), ("1400", 1400), (1320.9, 1320)])
def test_preferred_mtu_clamp(client, value, expected):
    assert post_settings(client, {"preferred_mtu": value}).status_code == 200
    assert config_manager.config.scan.preferred_mtu == expected


def test_speedtest_test_count(client):
    # Unset: GET falls back to discovery_test_count (legacy)
    config_manager.config.scan.discovery_test_count = 4
    assert client.get("/api/settings").json()["speedtest_test_count"] == 4
    assert post_settings(client, {"speedtest_test_count": 2}).status_code == 200
    assert config_manager.config.scan.speedtest_test_count == 2
    assert client.get("/api/settings").json()["speedtest_test_count"] == 2
    assert tasks._speedtest_count() == 2
    post_settings(client, {"speedtest_test_count": 50})
    assert config_manager.config.scan.speedtest_test_count == 10
    post_settings(client, {"speedtest_test_count": 0})
    assert config_manager.config.scan.speedtest_test_count == 1


def test_excluded_countries_normalised(client):
    r = post_settings(client, {"excluded_countries": ["de", " ch ", "XYZ", "DE", ""]})
    assert r.status_code == 200
    assert config_manager.config.regions.excluded_countries == ["CH", "DE"]
    assert post_settings(client, {"excluded_countries": None}).status_code == 200
    assert config_manager.config.regions.excluded_countries == []


def test_invalid_gluetun_profiles_warn_and_keep_previous(client, fresh_config):
    before = [p.model_dump() for p in fresh_config.gluetun.profiles]
    r = post_settings(client, {"scan_interval_minutes": 60,
                               "gluetun_profiles": [{"name": "ok"}, {"min_download_mbps": "fast"}]})
    assert r.status_code == 200
    warns = r.json()["warnings"]
    assert len(warns) == 1 and "Gluetun" in warns[0] and warns[0].startswith("1 ")
    assert [p.model_dump() for p in config_manager.config.gluetun.profiles] == before
    assert config_manager.config.scan.scan_interval_minutes == 60  # rest still applied


def test_gluetun_profiles_not_a_list_warns(client):
    r = post_settings(client, {"gluetun_profiles": "nope"})
    assert r.status_code == 200 and len(r.json()["warnings"]) == 1


def test_valid_gluetun_profiles_replace(client, monkeypatch):
    called = []

    async def fake_gen():
        called.append(1)

    import airbl.gluetun as gl
    monkeypatch.setattr(gl, "generate_gluetun_servers_json", fake_gen)
    r = post_settings(client, {"gluetun_profiles": [
        {"name": "A", "enabled": False, "min_download_mbps": "80", "allowed_countries": ["CH"]}]})
    assert r.status_code == 200 and r.json()["warnings"] == []
    profs = config_manager.config.gluetun.profiles
    assert len(profs) == 1 and profs[0].name == "A" and profs[0].min_download_mbps == 80.0
    assert called == []  # no enabled profile -> no generation
    # Empty list = user removed all profiles
    assert post_settings(client, {"gluetun_profiles": []}).status_code == 200
    assert config_manager.config.gluetun.profiles == []


def test_invalid_wg_profiles_warn_and_keep_previous(client, fresh_config):
    before = [p.model_dump() for p in fresh_config.wireguard.profiles]
    r = post_settings(client, {"wg_profiles": [{"name": "x", "port": "not-a-port"}, "junk"]})
    assert r.status_code == 200
    warns = r.json()["warnings"]
    assert len(warns) == 1 and "WireGuard" in warns[0] and warns[0].startswith("2 ")
    assert [p.model_dump() for p in config_manager.config.wireguard.profiles] == before


def test_valid_wg_profiles_replace(client):
    r = post_settings(client, {"wg_profiles": [{"name": "Mine", "port": 51820, "entry_ip": "ENTRY1"}]})
    assert r.status_code == 200 and r.json()["warnings"] == []
    (p,) = config_manager.config.wireguard.profiles
    assert (p.name, p.port, p.entry_ip) == ("Mine", 51820, "ENTRY1")


# --- Discovery toggle ------------------------------------------------------------

def test_discovery_toggle_off_to_on_resets_and_starts(client, fresh_config):
    fresh_config.scan.discovery_results = {"1637_E3": {"tests": 5}}
    fresh_config.scan.discovery_scan_count = 7
    state.port_discovery_results = {"1637_E3": {"tests": 5}}
    r = post_settings(client, {"port_discovery_enabled": True})
    assert r.status_code == 200
    scan = config_manager.config.scan
    assert scan.port_discovery_enabled is True
    assert scan.discovery_started_at is not None
    assert scan.discovery_results == {} and scan.discovery_scan_count == 0
    assert state.port_discovery_results == {}


def test_discovery_toggle_on_to_on_keeps_period(client, fresh_config):
    fresh_config.scan.port_discovery_enabled = True
    fresh_config.scan.discovery_started_at = "2026-10-01T00:00:00+00:00"
    fresh_config.scan.discovery_results = {"1637_E3": {"tests": 5}}
    assert post_settings(client, {"port_discovery_enabled": True}).status_code == 200
    assert config_manager.config.scan.discovery_started_at == "2026-10-01T00:00:00+00:00"
    assert config_manager.config.scan.discovery_results == {"1637_E3": {"tests": 5}}


def test_discovery_toggle_on_to_off_clears_start(client, fresh_config):
    fresh_config.scan.port_discovery_enabled = True
    fresh_config.scan.discovery_started_at = "2026-10-01T00:00:00+00:00"
    fresh_config.scan.discovery_results = {"1637_E3": {"tests": 5}}
    assert post_settings(client, {"port_discovery_enabled": False}).status_code == 200
    scan = config_manager.config.scan
    assert scan.port_discovery_enabled is False
    assert scan.discovery_started_at is None
    assert scan.discovery_results == {"1637_E3": {"tests": 5}}  # results kept for display


def test_discovery_restart_refused_while_scanning(client, fresh_config):
    fresh_config.scan.discovery_results = {"1637_E3": {"tests": 5}}
    state.is_scanning = True
    r = client.post("/api/discovery/restart")
    assert r.status_code == 409
    assert config_manager.config.scan.discovery_results == {"1637_E3": {"tests": 5}}


def test_discovery_restart_ok(client, fresh_config):
    fresh_config.scan.discovery_results = {"1637_E3": {"tests": 5}}
    r = client.post("/api/discovery/restart")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["started_at"]
    assert config_manager.config.scan.discovery_results == {}
    assert config_manager.config.scan.port_discovery_enabled is True


# --- GET /api/settings -------------------------------------------------------------

def test_get_settings_hides_api_key(client):
    r = post_settings(client, {"gluetun_api_key": "  s3cr3t-key  "})
    assert r.status_code == 200
    assert config_manager.config.gluetun.api_key == "s3cr3t-key"
    body = client.get("/api/settings")
    assert body.status_code == 200
    data = body.json()
    assert data["gluetun_api_key_set"] is True
    assert "s3cr3t-key" not in body.text
    assert not any("api_key" == k for k in data)
    # Empty key in a later save keeps the stored one; explicit clear removes it
    post_settings(client, {"gluetun_api_key": ""})
    assert config_manager.config.gluetun.api_key == "s3cr3t-key"
    post_settings(client, {"gluetun_api_key_clear": True})
    assert config_manager.config.gluetun.api_key == ""
    assert client.get("/api/settings").json()["gluetun_api_key_set"] is False


# --- servers / misc ------------------------------------------------------------------

def test_enable_server(client, fresh_config):
    fresh_config.performance.disabled_servers = ["Toliman", "Ran"]
    fresh_config.performance.history = {"Toliman": [{"download": 1}], "Ran": [{"download": 2}]}
    state.server_performance_history = {"TOLIMAN": [{"download": 1}], "Ran": [{"download": 2}]}
    r = client.post("/api/servers/toliman/enable")
    assert r.status_code == 200
    assert r.json()["disabled_servers"] == ["Ran"]
    assert config_manager.config.performance.disabled_servers == ["Ran"]
    assert "Toliman" not in config_manager.config.performance.history
    assert "TOLIMAN" not in state.server_performance_history
    assert "Ran" in state.server_performance_history


def test_enable_unknown_server_is_noop(client, fresh_config):
    fresh_config.performance.disabled_servers = ["Ran"]
    r = client.post("/api/servers/Nobody/enable")
    assert r.status_code == 200 and r.json()["disabled_servers"] == ["Ran"]


@pytest.mark.parametrize("port", ["abc", 70000, 0, -5, True])
def test_gluetun_test_bad_port(client, monkeypatch, port):
    import airbl.gluetun as gl

    async def boom(cfg):
        raise AssertionError("must not contact Gluetun")

    monkeypatch.setattr(gl, "get_gluetun_status", boom)
    r = client.post("/api/gluetun/test", json={"host": "127.0.0.1", "port": port})
    assert r.status_code == 400
    assert r.json()["ok"] is False


def test_gluetun_test_uses_form_values(client, monkeypatch, fresh_config):
    import airbl.gluetun as gl
    fresh_config.gluetun.api_key = "saved"
    seen = {}

    async def fake_status(cfg):
        seen.update(host=cfg.control_server_host, port=cfg.control_server_port, key=cfg.api_key)
        return {"connected": True, "error": None}

    monkeypatch.setattr(gl, "get_gluetun_status", fake_status)
    r = client.post("/api/gluetun/test", json={"host": "gluetun", "port": "8001", "api_key": "typed"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert seen == {"host": "gluetun", "port": 8001, "key": "typed"}
    assert config_manager.config.gluetun.control_server_port == 8000  # not saved
    # Empty key: the saved one is used for the saved address only
    client.post("/api/gluetun/test", json={"api_key": ""})
    assert seen["key"] == "saved"
    assert client.post("/api/gluetun/test", json=[1]).status_code == 400


def test_gluetun_test_never_sends_saved_key_elsewhere(client, monkeypatch, fresh_config):
    import airbl.gluetun as gl
    fresh_config.gluetun.api_key = "saved"
    seen = []

    async def fake_status(cfg):
        seen.append(cfg.api_key)
        return {"connected": False, "error": "Gluetun rejected the API key (401)."}

    monkeypatch.setattr(gl, "get_gluetun_status", fake_status)
    for body in ({"host": "attacker.example"}, {"port": 9999}, {"host": "http://10.0.0.9:8000"}):
        r = client.post("/api/gluetun/test", json=body)
        assert "only sent to the saved address" in r.json()["error"]
    assert seen == ["", "", ""]


@pytest.mark.parametrize("host", ["http://user:pw@evil", "ftp://gluetun", "http://gluetun/v1/x",
                                  "gluetun/../x", "a b", "evil@host"])
def test_gluetun_control_host_rejected(client, monkeypatch, host):
    import airbl.gluetun as gl

    async def boom(cfg):
        raise AssertionError("must not contact Gluetun")

    monkeypatch.setattr(gl, "get_gluetun_status", boom)
    assert client.post("/api/gluetun/test", json={"host": host}).status_code == 400
    assert post_settings(client, {"gluetun_control_host": host}).status_code == 400


@pytest.mark.parametrize("host", ["192.168.1.20", "gluetun", "fd00::5", "[fd00::5]", "http://gluetun:8000/"])
def test_gluetun_control_host_accepted(client, host):
    assert post_settings(client, {"gluetun_control_host": host}).status_code == 200


@pytest.mark.parametrize("path", ["/app/data/airbl-settings.json", "/app/gluetun/../data/x.json",
                                  "servers.json", "/app/gluetun", "/etc/passwd"])
def test_gluetun_profile_path_outside_mount_rejected(client, fresh_config, path):
    before = [p.model_dump() for p in fresh_config.gluetun.profiles]
    r = post_settings(client, {"gluetun_profiles": [{"name": "X", "output_path": path}]})
    assert r.status_code == 400 and "/app/gluetun" in r.json()["error"] and "'X'" in r.json()["error"]
    assert [p.model_dump() for p in config_manager.config.gluetun.profiles] == before


def test_gluetun_profile_bools_parsed(client):
    r = post_settings(client, {"gluetun_profiles": [
        {"name": "A", "enabled": "false", "require_clean": "false", "output_path": "/app/gluetun/servers/airvpn.json"}]})
    assert r.status_code == 200
    (p,) = config_manager.config.gluetun.profiles
    assert p.enabled is False and p.require_clean is False  # bool("false") was True
    r = post_settings(client, {"gluetun_profiles": [{"name": "B", "min_download_mbps": "nan"}]})
    assert r.status_code == 200 and len(r.json()["warnings"]) == 1  # NaN: invalid, previous kept
    assert [p.name for p in config_manager.config.gluetun.profiles] == ["A"]


@pytest.mark.parametrize("field", [{"output_dir": "/app/data"}, {"output_dir": "/app/wireguard/../conf"},
                                   {"output_dir": "wireguard"}])
def test_wg_profile_dir_outside_mount_rejected(client, fresh_config, field):
    before = [p.model_dump() for p in fresh_config.wireguard.profiles]
    r = post_settings(client, {"wg_profiles": [{"name": "W", **field}]})
    assert r.status_code == 400 and "'W'" in r.json()["error"] and "/app/wireguard" in r.json()["error"]
    assert [p.model_dump() for p in config_manager.config.wireguard.profiles] == before


@pytest.mark.parametrize("field", [{"mode": "everything"}, {"entry_ip": "ENTRY2"}, {"ip_protocol": "IPX"},
                                   {"ip_layer_exit": "v5"}, {"enabled": "maybe"}])
def test_wg_profile_bad_values_warn_and_keep_previous(client, fresh_config, field):
    before = [p.model_dump() for p in fresh_config.wireguard.profiles]
    r = post_settings(client, {"wg_profiles": [{"name": "W", **field}]})
    assert r.status_code == 200 and len(r.json()["warnings"]) == 1
    assert [p.model_dump() for p in config_manager.config.wireguard.profiles] == before


def test_wg_profile_numbers_clamped_and_subdir_ok(client):
    r = post_settings(client, {"wg_profiles": [{"name": "W", "output_dir": "/app/wireguard/home",
                                                "mtu": 9000, "keepalive": -1, "port": 70000}]})
    assert r.status_code == 200
    (p,) = config_manager.config.wireguard.profiles
    assert (p.output_dir, p.mtu, p.keepalive, p.port) == ("/app/wireguard/home", 1500, 0, 65535)


# --- Cross-site writes ---------------------------------------------------------------

def test_cross_site_post_blocked(client, fresh_config):
    r = client.post("/api/settings", json={"scan_interval_minutes": 30},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert config_manager.config.scan.scan_interval_minutes == 120
    # Form-style request without a JSON body, opaque origin
    assert client.post("/api/scan/stop", headers={"Origin": "null"}).status_code == 403


def test_same_origin_and_scripted_posts_allowed(client, monkeypatch):
    ok = {"scan_interval_minutes": 30}
    assert client.post("/api/settings", json=ok, headers={"Origin": "http://testserver"}).status_code == 200
    assert client.post("/api/settings", json=ok).status_code == 200  # curl/scripts: no Origin
    # Behind a reverse proxy that rewrites Host
    r = client.post("/api/settings", json=ok, headers={"Origin": "https://airbl.home", "X-Forwarded-Host": "airbl.home"})
    assert r.status_code == 200
    monkeypatch.setenv("AIRBL_ALLOWED_ORIGINS", "https://dash.example")
    assert client.post("/api/settings", json=ok, headers={"Origin": "https://dash.example"}).status_code == 200
    # Reads are never blocked
    assert client.get("/api/status", headers={"Origin": "http://evil.example"}).status_code == 200


def test_gluetun_check_endpoint(client, monkeypatch):
    import airbl.gluetun as gl
    seen = []

    async def fake_check(force=False):
        seen.append(force)
        return {"applied": False, "reason": "current server still clean", "current": "Fuyue"}

    monkeypatch.setattr(gl, "gluetun_watchdog_check", fake_check)
    for path in ("/api/gluetun/check", "/api/gluetun/apply"):
        assert client.post(path).json()["current"] == "Fuyue"
    assert seen == [True, True]


def test_status_network_owner(client, monkeypatch):
    data = client.get("/api/status").json()
    assert "network_owner" in data and data["network_owner"] is None
    assert data["is_scanning"] is False and data["has_results"] is False

    class Locked:
        def locked(self):
            return True

    monkeypatch.setattr(tasks, "_network_lock", Locked())
    monkeypatch.setattr(tasks, "_network_owner", "speedtest Toliman")
    assert client.get("/api/status").json()["network_owner"] == "speedtest Toliman"


def test_status_next_scan_at_has_utc_offset(client, monkeypatch):
    # Browsers read an offset-less ISO time as *their* local time, so the countdown
    # was wrong (often "Now") whenever the browser's zone differed from the server's.
    from datetime import datetime, timedelta
    monkeypatch.setattr(state, "next_scan_at", datetime.now() + timedelta(hours=1))
    value = client.get("/api/status").json()["next_scan_at"]
    parsed = datetime.fromisoformat(value)
    assert parsed.tzinfo is not None, value
    assert abs((parsed - datetime.now().astimezone()).total_seconds() - 3600) < 5


def test_speedtest_refused_while_scanning(client, monkeypatch, fake_server, make_summary):
    called = []

    async def fake_task(*a, **k):
        called.append(a)

    monkeypatch.setattr(api, "run_speedtest_task", fake_task)
    state.current_scan = make_summary([fake_server("Toliman")])
    state.is_scanning = True
    r = client.post("/api/speedtest/Toliman")
    assert r.status_code == 200 and "error" in r.json()
    assert called == []
    # Not scanning: queued with the server object
    state.is_scanning = False
    r = client.post("/api/speedtest/Toliman")
    assert r.json()["status"].startswith("Speedtest queued")
    assert len(called) == 1 and called[0][0].server_name == "Toliman"
    assert "error" in client.post("/api/speedtest/Nobody").json()


def test_baseline_refused_while_scanning(client, monkeypatch):
    called = []

    async def fake_baseline():
        called.append(1)

    monkeypatch.setattr(tasks, "run_baseline_speedtest", fake_baseline)
    state.is_scanning = True
    r = client.post("/api/baseline-speedtest")
    assert "error" in r.json() and called == []
    state.is_scanning = False
    r = client.post("/api/baseline-speedtest")
    assert r.json()["status"] == "started" and called == [1]


# --- metrics ---------------------------------------------------------------------------

def test_metrics_country_stats_no_double_counting(client, fresh_config, fake_server, make_summary):
    servers = [
        fake_server("Toliman", "clean"),
        fake_server("Achernar", "blocked"),
        fake_server("Hamal", "unknown"),
        fake_server("Bunda", "blocked"),     # disabled
        fake_server("Castor", "clean"),      # disabled
        fake_server("Ran", "clean", country_code="DE", location="Frankfurt"),
        fake_server("Taurus", "unknown", country_code="DE", location="Frankfurt"),
    ]
    fresh_config.performance.disabled_servers = ["bunda", "CASTOR"]
    state.current_scan = make_summary(servers)
    data = client.get("/api/metrics").json()
    stats = {c["country_code"]: c for c in data["country_stats"]}
    assert set(stats) == {"CH", "DE"}
    ch = stats["CH"]
    assert {k: ch[k] for k in ("clean", "blocked", "disabled", "unknown")} == \
        {"clean": 1, "blocked": 1, "disabled": 2, "unknown": 1}
    assert ch["country_name"] == "Switzerland"
    de = stats["DE"]
    assert (de["clean"], de["blocked"], de["disabled"], de["unknown"]) == (1, 0, 0, 1)
    total = sum(c["clean"] + c["blocked"] + c["disabled"] + c["unknown"] for c in data["country_stats"])
    assert total == len(servers)
    assert data["current_stats"]["total_servers"] == 7
    assert data["current_stats"]["disabled_servers"] == 2


def test_metrics_db_fallback(client, fresh_config):
    state.servers_by_country = {"Toliman": "CH", "Ran": "CH", "Hamal": "CH", "Old": "CH", "Gone": "CH"}
    state.all_countries = {"CH": "Switzerland"}
    fresh_config.performance.disabled_servers = ["Gone"]
    state._last_scan_servers = [
        {"server_name": "Toliman", "reputation": "clean", "is_blocked": 0},
        {"server_name": "Ran", "reputation": "blocked", "is_blocked": 1},
        {"server_name": "Hamal", "reputation": "unknown", "is_blocked": 0},
        {"server_name": "Old", "reputation": None, "is_blocked": 0},     # legacy row = clean
        {"server_name": "Gone", "reputation": "blocked", "is_blocked": 1},
    ]
    state._last_scan_entry_pings = [
        {"server_name": "Toliman", "entry_type": "ENTRY1", "latency_ms": 10.0, "is_alive": 1},
        {"server_name": "Toliman", "entry_type": "ENTRY3", "latency_ms": 20.0, "is_alive": 1},
    ]
    data = client.get("/api/metrics").json()
    (ch,) = data["country_stats"]
    assert (ch["clean"], ch["blocked"], ch["disabled"], ch["unknown"]) == (2, 1, 1, 1)
    assert ch["clean"] + ch["blocked"] + ch["disabled"] + ch["unknown"] == 5
    assert data["ping_by_country"][0]["avg_entry1"] == 10.0


def test_metrics_counts_unscanned_disabled_servers(client, fresh_config, fake_server, make_summary):
    # Scans skip disabled servers, so they must still show up in the per-country counts
    state.current_scan = make_summary([fake_server("Toliman", "clean")])
    state.servers_by_country = {"Hamal": "CH", "Cujam": "DE"}
    state.all_countries = {"CH": "Switzerland", "DE": "Germany"}
    fresh_config.performance.disabled_servers = ["Hamal", "Cujam"]
    stats = {c["country_code"]: c for c in client.get("/api/metrics").json()["country_stats"]}
    assert (stats["CH"]["clean"], stats["CH"]["disabled"]) == (1, 1)
    assert stats["DE"] == {"country_code": "DE", "country_name": "Germany",
                           "clean": 0, "blocked": 0, "disabled": 1, "unknown": 0}


def test_disabled_servers_details(client, fresh_config):
    perf = fresh_config.performance
    perf.disabled_servers = ["Hamal", "Ghost"]
    perf.threshold_download, perf.threshold_upload, perf.check_count = 130.0, 120.0, 2
    state.servers_by_country = {"Hamal": "CH"}
    state.server_to_city_api = {"Hamal": "Zurich"}
    state.all_countries = {"CH": "Switzerland"}
    state.server_performance_history = {"Hamal": [
        {"download": 99.0, "upload": 99.0, "timestamp": "2026-10-01T05:00:00"},
        {"download": 4.0, "upload": 3.0, "timestamp": "2026-10-07T05:00:00"},
        {"download": 6.0, "upload": 5.0, "timestamp": "2026-10-08T05:00:00"},
    ]}
    data = client.get("/api/servers/disabled").json()
    assert (data["threshold_download"], data["threshold_upload"], data["check_count"]) == (130.0, 120.0, 2)
    ghost, hamal = data["servers"]
    assert hamal["country_code"] == "CH" and hamal["city"] == "Zurich" and hamal["country_name"] == "Switzerland"
    assert [r["download"] for r in hamal["recent"]] == [4.0, 6.0]  # last check_count results
    assert (hamal["avg_download_mbps"], hamal["avg_upload_mbps"]) == (5.0, 4.0)
    assert hamal["last_tested"] == "2026-10-08T05:00:00"
    assert ghost["country_code"] == "??" and ghost["recent"] == [] and ghost["avg_download_mbps"] is None


async def test_metrics_wireguard_stats(client, tmp_path):
    from airbl.database import DatabaseManager
    db = DatabaseManager(tmp_path / "wg.db")
    await db.init()
    try:
        for dl, ul, ping, port, entry, ok in [
            (100, 50, 20, 1637, "Entry 3", True), (200, 70, 1800000.0, 1637, "Entry 3", True),
            (0, 0, 0, 1637, "Entry 1", False), (300, 90, 40, 47107, "Entry 1", True),
        ]:
            await db.add_speedtest_result({"download_mbps": dl, "upload_mbps": ul, "ping_ms": ping,
                                           "vpn_port": port, "vpn_entry": entry,
                                           **({} if ok else {"error": "failed"})})
        state.db = db
        # Discovery results are kept apart from speedtest history; older ones hold averages only
        state.port_discovery_results = {"47107_E3": {"port": 47107, "entry": 3, "tests": 2,
                                                     "success_tests": 2, "download_mbps": 100.0,
                                                     "upload_mbps": 10.0, "ping_ms": 30.0}}
        data = client.get("/api/metrics").json()
    finally:
        await db.close()
    ports = {p["key"]: p for p in data["wg_port_stats"]}
    assert [p["key"] for p in data["wg_port_stats"]] == ["1637", "47107"]
    p1637 = ports["1637"]
    assert (p1637["tests"], p1637["success_tests"], p1637["success_rate"]) == (3, 2, 0.67)
    assert (p1637["download_mbps"], p1637["upload_mbps"]) == (150.0, 60.0)
    assert p1637["ping_ms"] == 20.0  # placeholder 1,800,000 ms ping left out
    p47107 = ports["47107"]
    assert p47107["tests"] == 3 and p47107["download_mbps"] == round((300 + 200) / 3, 1)
    entries = {e["key"]: e for e in data["wg_entry_stats"]}
    assert set(entries) == {"Entry 1", "Entry 3"}
    assert entries["Entry 1"]["tests"] == 2 and entries["Entry 1"]["download_mbps"] == 300.0
    assert entries["Entry 3"]["tests"] == 4


def test_metrics_empty(client):
    data = client.get("/api/metrics").json()
    assert data["country_stats"] == [] and data["current_stats"]["total_servers"] == 0


def test_results_and_export(client, fake_server, make_summary):
    assert "error" in client.get("/api/results").json()
    state.current_scan = make_summary([fake_server("Toliman"), fake_server("Ran", "blocked"),
                                       fake_server("Hamal", "unknown")])
    r = client.get("/api/export/gluetun")
    assert r.status_code == 200 and r.text == "SERVER_NAMES=Toliman"
    res = client.get("/api/results").json()
    assert res["clean_servers_count"] == 1 and res["blocked_servers_count"] == 1
    assert res["unknown_servers_count"] == 1
    servers = client.get("/api/servers", params={"status": "unknown"}).json()["countries"]
    assert [s["server_name"] for s in servers[0]["servers"]] == ["Hamal"]


def test_preferred_port_with_no_available_ports_is_400(fresh_config):
    from airbl.web.app import create_app
    fresh_config.scan.available_ports = []
    client = TestClient(create_app(), raise_server_exceptions=False)
    r = client.post("/api/settings", json={"preferred_port": 1637})
    assert r.status_code == 400


def test_pages_use_versioned_assets_and_revalidate(client):
    from airbl.web.routes.pages import templates
    version = templates.env.globals["asset_version"]
    html = client.get("/").text
    assert f"/static/js/app.js?v={version}" in html and f"/static/css/style.css?v={version}" in html
    assert client.get("/").headers.get("cache-control") == "no-cache"
    assert client.get(f"/static/js/app.js?v={version}").headers.get("cache-control") == "no-cache"
    assert "cache-control" not in client.get("/api/status").headers


def test_baseline_survives_restart(fresh_config):
    from airbl.config import settings
    baseline = {"download_mbps": 800.0, "upload_mbps": 810.0, "ping_ms": 2.0}
    state.save_baseline(baseline)
    assert (settings.cache_dir / "baseline.json").exists()
    state.baseline_speedtest = None
    state._load_baseline()
    assert state.baseline_speedtest == baseline
    (settings.cache_dir / "baseline.json").unlink()


# --- Settings side effects ---------------------------------------------------------

def test_unblocking_in_settings_drops_history(client, fresh_config):
    # Old below-threshold history made _should_skip_server skip the server forever
    fresh_config.performance.disabled_servers = ["Hamal", "Cujam", "Achernar"]
    bad = [{"download": 5, "upload": 5}] * 3
    state.server_performance_history = {"Hamal": list(bad), "Cujam": list(bad), "Achernar": list(bad)}
    fresh_config.performance.history = {"Hamal": list(bad)}
    assert post_settings(client, {"disabled_servers": ["Cujam", "Achernar"]}).status_code == 200
    assert "Hamal" not in state.server_performance_history and "Hamal" not in fresh_config.performance.history
    assert tasks._should_skip_server("Hamal") is False
    # Enabling via enabled_servers takes it off the list too
    assert post_settings(client, {"enabled_servers": ["cujam"]}).status_code == 200
    assert "Cujam" not in state.server_performance_history
    assert "Achernar" in state.server_performance_history  # still disabled: kept


def test_only_schedule_changes_reschedule(client, monkeypatch):
    import asyncio
    event = asyncio.Event()
    monkeypatch.setattr(state, "settings_updated_event", event)
    assert post_settings(client, {"performance_threshold_download": 99}).status_code == 200
    assert not event.is_set()  # a Gluetun/threshold edit no longer pushes the next scan back
    assert post_settings(client, {"scan_interval_minutes": 60}).status_code == 200
    assert event.is_set()


def test_discovery_cannot_restart_during_scan(client, fresh_config):
    fresh_config.scan.port_discovery_enabled = False
    state.is_scanning = True
    try:
        r = post_settings(client, {"port_discovery_enabled": True})
        assert r.status_code == 409 and fresh_config.scan.port_discovery_enabled is False
        # Turning it off, or other settings, still work during a scan
        assert post_settings(client, {"port_discovery_enabled": False}).status_code == 200
    finally:
        state.is_scanning = False


def test_schedule_mode_needs_a_day(client, fresh_config):
    # The scheduler treats an empty list as "every day"
    r = post_settings(client, {"scan_mode": "schedule", "scan_schedule_days": []})
    assert r.status_code == 400 and "at least one day" in r.json()["error"]
    assert fresh_config.scan.scan_mode == "interval"
    # In interval mode the day list doesn't matter
    assert post_settings(client, {"scan_mode": "interval", "scan_schedule_days": []}).status_code == 200


def test_servers_max_load_accepts_decimals(client):
    assert client.get("/api/servers?max_load=50.5").status_code == 200


def test_default_profiles_round_trip_unchanged(client, fresh_config):
    # What the settings page loads must save back as-is (a missing choice such as
    # PING_PRIORITY made every save drop back to "previous profiles kept")
    from airbl.config import AirBLConfig
    defaults = AirBLConfig()
    fresh_config.gluetun.profiles = defaults.gluetun.profiles
    fresh_config.wireguard.profiles = defaults.wireguard.profiles
    cur = client.get("/api/settings").json()
    r = post_settings(client, {"gluetun_profiles": cur["gluetun_profiles"], "wg_profiles": cur["wg_profiles"]})
    assert r.status_code == 200 and r.json()["warnings"] == []
    assert client.get("/api/settings").json()["gluetun_profiles"] == cur["gluetun_profiles"]
    assert client.get("/api/settings").json()["wg_profiles"] == cur["wg_profiles"]
