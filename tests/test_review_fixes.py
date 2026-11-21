"""Fixes from the 2026-11-21 project review: DNS rebinding, host network, scheduler, auto-disable
baseline guard, watchdog while the VPN is busy, DroneBL sinkhole, private settings files."""

import os
import stat

import pytest
from fastapi.testclient import TestClient

from airbl import dronebl, gluetun
from airbl.dronebl import DroneBLResult
from airbl.web import app as app_mod
from airbl.web import tasks
from airbl.web.state import state


@pytest.fixture
def client(fresh_config, monkeypatch):
    from airbl.web.routes import api

    async def no_api():
        raise RuntimeError("network disabled in tests")
    monkeypatch.setattr(api, "get_airvpn_status", no_api)
    return TestClient(app_mod.create_app())


@pytest.mark.parametrize("host,ok", [
    ("192.168.1.10:5665", True), ("[::1]:5665", True), ("localhost:5665", True), ("peach:5665", True),
    ("airbl.local", True), ("pi.home.arpa:5665", True), ("box.lan", True), ("", True),
    ("evil.example:5665", False), ("rebind.attacker.com", False), ("192.168.1.10.nip.io", False),
])
def test_host_allowed(host, ok, monkeypatch):
    monkeypatch.delenv("AIRBL_ALLOWED_HOSTS", raising=False)
    assert app_mod._host_allowed(host) is ok


def test_allowed_hosts_env(monkeypatch):
    monkeypatch.setenv("AIRBL_ALLOWED_HOSTS", "airbl.example.com, other.org")
    assert app_mod._host_allowed("airbl.example.com:443") and app_mod._host_allowed("other.org")
    assert not app_mod._host_allowed("evil.example")


def test_rebinding_blocked_on_http_and_ws(client):
    r = client.get("/api/settings", headers={"host": "evil.example:5665"})
    assert r.status_code == 403 and "AIRBL_ALLOWED_HOSTS" in r.json()["error"]
    assert client.get("/api/ranking/speed", headers={"host": "192.168.1.10:5665"}).status_code == 200
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"host": "evil.example"}) as ws:
            ws.receive_text()
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws", headers={"origin": "http://evil.example"}) as ws:
            ws.receive_text()


def test_settings_file_private(tmp_path):
    from airbl.config import SettingsManager, Settings
    s = Settings(config_dir=tmp_path / "conf", cache_dir=tmp_path / "data")
    m = SettingsManager(s)
    m.load()
    m.config.scan.scan_interval_minutes = 30
    assert m.save()
    m.config.scan.scan_interval_minutes = 40
    assert m.save()
    for p in (m.user_settings_path, m.user_settings_path.with_name(m.user_settings_path.name + ".bak")):
        assert stat.S_IMODE(os.stat(p).st_mode) == 0o600, p


async def test_auto_disable_ignores_results_when_baseline_is_low(fresh_config, broadcasts, monkeypatch):
    perf = fresh_config.performance
    perf.threshold_download, perf.threshold_upload, perf.check_count = 100, 50, 2
    monkeypatch.setattr(state, "server_performance_history", {})
    monkeypatch.setattr(state, "baseline_speedtest", {"download_mbps": 80, "upload_mbps": 300})
    for _ in range(3):
        await tasks._check_and_disable_underperforming_server("Toliman", {"download_mbps": 10, "upload_mbps": 5})
    assert perf.disabled_servers == [] and state.server_performance_history == {}
    monkeypatch.setattr(state, "baseline_speedtest", {"download_mbps": 500, "upload_mbps": 300})
    for _ in range(2):
        await tasks._check_and_disable_underperforming_server("Toliman", {"download_mbps": 10, "upload_mbps": 5})
    assert perf.disabled_servers == ["Toliman"]


async def test_watchdog_steps_aside_while_vpn_busy(fresh_config, monkeypatch):
    fresh_config.gluetun.force_update_enabled = True
    monkeypatch.setattr(state, "is_scanning", False)
    import asyncio
    monkeypatch.setattr(tasks, "_network_lock", asyncio.Lock())
    async with tasks.network_job("speedtest Hamal"):
        r = await gluetun.gluetun_watchdog_check()
    assert r == {"applied": False, "reason": "VPN busy (speedtest Hamal)"}


async def test_sinkhole_resolver_detected(monkeypatch):
    async def everything_listed(ip, timeout=None):
        return DroneBLResult(ip=ip, is_listed=True, listing_code=3)
    monkeypatch.setattr(dronebl, "check_dronebl", everything_listed)
    monkeypatch.setattr(dronebl, "_canary_checked_at", None)
    err = await dronebl.dnsbl_resolver_error()
    assert err and "sinkhole" in err

    async def honest(ip, timeout=None):
        return DroneBLResult(ip=ip, is_listed=ip == "127.0.0.2")
    monkeypatch.setattr(dronebl, "check_dronebl", honest)
    monkeypatch.setattr(dronebl, "_canary_checked_at", None)
    assert await dronebl.dnsbl_resolver_error() is None


def test_manual_speedtest_not_queued_twice(client, fake_server, make_summary, monkeypatch):
    from airbl.web.routes import api
    state.current_scan = make_summary([fake_server("Hamal")])
    monkeypatch.setattr(state, "is_scanning", False)
    monkeypatch.setattr(api, "_queued_speedtests", {"Hamal"})
    r = client.post("/api/speedtest/Hamal").json()
    assert "already queued" in r["error"]


async def test_vpn_refused_in_host_network(monkeypatch, tmp_path):
    from airbl.hummingbird import WireGuardController
    monkeypatch.setattr(os, "listdir", lambda p: ["lo", "eth0", "wlan0", "docker0"])
    monkeypatch.delenv("AIRBL_ALLOW_HOST_NETWORK", raising=False)
    assert "host network" in WireGuardController.host_network_reason()
    called = []

    async def must_not_run(*a, **k):
        called.append(a)
        return 0, "", ""
    ctl = WireGuardController(use_sudo=False)
    monkeypatch.setattr(ctl, "_run", must_not_run, raising=False)
    r = await ctl.connect(tmp_path / "x.conf")
    assert not r.success and "Refusing" in r.error and called == []
    monkeypatch.setattr(os, "listdir", lambda p: ["lo", "eth0", "wg0", "tunl0"])
    assert WireGuardController.host_network_reason() is None


def test_scheduler_wait_is_capped():
    import inspect
    src = inspect.getsource(app_mod)
    assert "timeout=min(sleep_duration, SCHEDULER_MAX_WAIT)" in src and app_mod.SCHEDULER_MAX_WAIT <= 300


# --- retest of auto-disabled servers ---------------------------------------------------------------

from datetime import datetime, timedelta, timezone  # noqa: E402


def _ago(days):
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def test_retest_after_days(fresh_config, monkeypatch):
    perf = fresh_config.performance
    perf.retest_after_days = 7
    perf.disabled_servers = ["Old", "Recent", "ByHand"]
    perf.seedbox_disabled_servers = ["ListedOld"]
    perf.disabled_at = {"Old": _ago(8), "Recent": _ago(2), "ListedOld": _ago(30)}
    monkeypatch.setattr(state, "server_performance_history", {"Old": [{"download": 1, "upload": 1}]})
    monkeypatch.setattr(state, "seedbox_history", {})
    back = tasks.retest_disabled_servers()
    assert sorted(back) == ["ListedOld", "Old"]
    assert perf.disabled_servers == ["Recent", "ByHand"] and perf.seedbox_disabled_servers == []
    assert sorted(perf.probation) == ["ListedOld", "Old"] and "Old" not in state.server_performance_history
    assert "Old" not in perf.disabled_at
    perf.retest_after_days = 0
    perf.disabled_at["Recent"] = _ago(100)
    assert tasks.retest_disabled_servers() == []  # 0 = never


def test_retest_legacy_entries_use_last_result(fresh_config, monkeypatch):
    perf = fresh_config.performance
    perf.retest_after_days, perf.check_count = 7, 2
    perf.threshold_download, perf.threshold_upload = 100, 50
    perf.disabled_servers = ["Slow", "Manual"]
    old = (datetime.now() - timedelta(days=10)).isoformat()
    monkeypatch.setattr(state, "server_performance_history", {
        "Slow": [{"download": 10, "upload": 5, "timestamp": old}] * 2,
        "Manual": [{"download": 500, "upload": 500, "timestamp": old}] * 2,  # was fine: disabled by hand
    })
    assert tasks.retest_disabled_servers() == ["Slow"] and perf.disabled_servers == ["Manual"]


async def test_probation_one_strike(fresh_config, broadcasts, monkeypatch):
    perf = fresh_config.performance
    perf.threshold_download, perf.threshold_upload, perf.check_count = 100, 50, 3
    perf.probation = ["Fail", "Pass"]
    monkeypatch.setattr(state, "server_performance_history", {})
    monkeypatch.setattr(state, "baseline_speedtest", None)
    await tasks._check_and_disable_underperforming_server("Fail", {"download_mbps": 10, "upload_mbps": 5})
    assert perf.disabled_servers == ["Fail"] and "Fail" in perf.disabled_at and "Fail" not in perf.probation
    await tasks._check_and_disable_underperforming_server("Pass", {"download_mbps": 300, "upload_mbps": 100})
    assert "Pass" not in perf.probation and "Pass" not in perf.disabled_servers
    # Normal servers still need check_count results
    await tasks._check_and_disable_underperforming_server("Normal", {"download_mbps": 10, "upload_mbps": 5})
    assert "Normal" not in perf.disabled_servers


def test_disabled_list_shows_retest_date_and_reenable_clears(client, fresh_config):
    perf = fresh_config.performance
    perf.retest_after_days = 7
    perf.disabled_servers = ["Old"]
    perf.disabled_at = {"Old": _ago(1)}
    perf.probation = ["Old"]
    row = client.get("/api/servers/disabled").json()["servers"][0]
    assert row["retest_at"] and row["disabled_at"]
    client.post("/api/servers/Old/enable")
    assert perf.disabled_at == {} and perf.probation == []
    r = client.post("/api/settings", json={"performance_retest_after_days": 400})
    assert r.status_code == 200 and perf.retest_after_days == 365


# --- optional login token ------------------------------------------------------------------------------

def test_no_token_no_login(client, monkeypatch):
    monkeypatch.delenv("AIRBL_AUTH_TOKEN", raising=False)
    assert client.get("/api/ranking/speed").status_code == 200


def test_login_token(client, monkeypatch):
    import base64
    monkeypatch.setenv("AIRBL_AUTH_TOKEN", "correct-horse-battery-staple")
    r = client.get("/api/settings")
    assert r.status_code == 401 and r.headers["www-authenticate"].startswith("Basic")
    assert client.get("/healthz").json() == {"ok": True}  # Docker healthcheck stays open
    assert client.get("/api/settings", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/settings", headers={"Authorization": "Bearer correct-horse-battery-staple"}).status_code == 200
    assert client.get("/api/settings", headers={"X-AirBL-Token": "correct-horse-battery-staple"}).status_code == 200
    basic = base64.b64encode(b"anyone:correct-horse-battery-staple").decode()
    r = client.get("/", headers={"Authorization": f"Basic {basic}"})
    assert r.status_code == 200 and app_mod.AUTH_COOKIE in r.cookies
    cookie = r.cookies[app_mod.AUTH_COOKIE]
    assert "correct-horse" not in cookie
    client.cookies.set(app_mod.AUTH_COOKIE, cookie)
    assert client.get("/api/settings").status_code == 200  # cookie session
    client.cookies.clear()
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws") as ws:
            ws.receive_text()


def test_websocket_accepts_session_cookie(client, monkeypatch):
    monkeypatch.setenv("AIRBL_AUTH_TOKEN", "correct-horse-battery-staple")
    client.cookies.set(app_mod.AUTH_COOKIE, app_mod._session_value("correct-horse-battery-staple"))
    with client.websocket_connect("/ws") as ws:  # accepted (would raise WebSocketDisconnect otherwise)
        ws.send_text("ping")
    client.cookies.clear()


# --- database compaction (VACUUM) ---------------------------------------------------------------

async def test_vacuum_after_prune_shrinks_file(tmp_path, monkeypatch):
    from airbl import database
    db = database.DatabaseManager(tmp_path / "v.db")
    await db.init()
    old = (datetime.now() - timedelta(days=400)).isoformat()
    for i in range(3000):
        await db._conn.execute(
            "INSERT INTO entry_ping_history (scan_id, server_name, entry_type, ip, latency_ms, is_alive, timestamp) "
            "VALUES (1, ?, 'ENTRY1', '192.0.2.1', 10.0, 1, ?)", (f"S{i}" + "x" * 200, old))
    await db._conn.commit()
    await db._conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    before = os.path.getsize(db.db_path)
    await db._conn.execute("DELETE FROM meta")  # never compacted yet
    await db.prune(180)
    after = os.path.getsize(db.db_path)
    assert after < before / 3, (before, after)
    assert await db._meta("last_vacuum")
    # Within the interval: not again
    assert await db.vacuum_if_due() is False
    await db.close()


async def test_vacuum_skips_when_little_to_gain_or_no_space(tmp_path, monkeypatch):
    from airbl import database
    db = database.DatabaseManager(tmp_path / "w.db")
    await db.init()
    await db._conn.execute("DELETE FROM meta")
    assert await db.vacuum_if_due() is False  # nothing free: only the WAL trim, time recorded
    assert await db._meta("last_vacuum")
    fake_shutil = type("S", (), {"disk_usage": staticmethod(lambda p: type("U", (), {"free": 0})())})
    monkeypatch.setattr(database, "shutil", fake_shutil)  # only the DB module's view
    assert await db.vacuum_if_due(force=True) is False  # no room for the temporary copy
    await db.close()


# --- Gluetun without a public IP: judge its server list ---------------------------------------------

def _gluetun_client(monkeypatch, settings_body, publicip=""):
    import httpx

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass

        async def get(self, url):
            if url.endswith("/v1/vpn/status"):
                return httpx.Response(200, json={"status": "running"})
            if url.endswith("/v1/publicip/ip"):
                return httpx.Response(200, json={"public_ip": publicip})
            if url.endswith("/v1/vpn/settings"):
                return httpx.Response(200, json=settings_body) if settings_body is not None else httpx.Response(403)
            return httpx.Response(404)
    monkeypatch.setattr(httpx, "AsyncClient", C)


async def test_status_without_public_ip_uses_selection(fresh_config, monkeypatch):
    _gluetun_client(monkeypatch, {"provider": {"name": "airvpn", "server_selection": {
        "names": ["Mirzam", "Taiyangshou"], "countries": [], "cities": []}}})
    st = await gluetun.get_gluetun_status(fresh_config.gluetun)
    assert st["connected"] and st["ip"] is None and st["selected_names"] == ["Mirzam", "Taiyangshou"]
    assert "PUBLICIP" in st["note"]
    # Selecting by country (or the route not allowed): no inference, as before
    _gluetun_client(monkeypatch, {"provider": {"server_selection": {"names": ["Mirzam"], "countries": ["NL"]}}})
    st = await gluetun.get_gluetun_status(fresh_config.gluetun)
    assert not st["connected"] and st["selected_names"] is None
    _gluetun_client(monkeypatch, None)
    assert (await gluetun.get_gluetun_status(fresh_config.gluetun))["selected_names"] is None
    # With a public IP nothing changes
    _gluetun_client(monkeypatch, {"provider": {"server_selection": {"names": ["Mirzam"]}}}, publicip="192.0.2.9")
    st = await gluetun.get_gluetun_status(fresh_config.gluetun)
    assert st["ip"] == "192.0.2.9" and st["selected_names"] is None


@pytest.fixture
def judged(fresh_config, fake_server, make_summary, monkeypatch):
    servers = [fake_server("Mirzam"), fake_server("Taiyangshou", latency_ms=30), fake_server("Fuyue", latency_ms=50),
               fake_server("Hamal", reputation="blocked")]
    state.current_scan = make_summary(servers)
    pushed = []

    async def fake_set(cfg, names):
        pushed.append(names)
        return {"applied": True, "names": names}
    monkeypatch.setattr(gluetun, "set_gluetun_server_names", fake_set)
    return fresh_config.gluetun, [(s, []) for s in servers], pushed


async def test_clean_only_stays_when_whole_selection_clean(judged):
    g, cand, pushed = judged
    g.force_update_mode = "CLEAN_ONLY"
    st = {"ip": None, "vpn_status": "running", "selected_names": ["Mirzam", "Taiyangshou"], "error": None}
    r = await gluetun.update_gluetun_server_selection(cand, status=st, quiet=True)
    assert r["reason"] == "current server still clean" and pushed == []
    st["selected_names"] = ["Mirzam", "Hamal"]  # one of them is now listed: it may be on that one
    await gluetun.update_gluetun_server_selection(cand, status=st, quiet=True)
    assert pushed == [["Fuyue", "Mirzam", "Taiyangshou"]]  # full list: Gluetun keeps its fallback
    st["selected_names"] = ["Gone"]  # not in the scan: unknown -> replace
    await gluetun.update_gluetun_server_selection(cand, status=st, quiet=True)
    assert len(pushed) == 2


async def test_top_n_with_selection(judged):
    g, cand, pushed = judged
    g.force_update_mode = "NOT_BEST"
    st = {"ip": None, "vpn_status": "running", "selected_names": ["Mirzam"], "error": None}
    r = await gluetun.update_gluetun_server_selection(cand, status=st, quiet=True)
    assert r["reason"] == "current server within target set"
    st["selected_names"] = ["Mirzam", "Fuyue"]  # might be on Fuyue, which isn't the best
    await gluetun.update_gluetun_server_selection(cand, status=st, quiet=True)
    assert pushed == [["Mirzam"]]


async def test_watchdog_runs_without_public_ip(judged, monkeypatch):
    g, cand, pushed = judged
    g.force_update_enabled, g.force_update_mode = True, "CLEAN_ONLY"
    monkeypatch.setattr(state, "is_scanning", False)

    async def status(cfg):
        return {"ip": None, "server_name": None, "vpn_status": "running", "error": None,
                "selected_names": ["Mirzam", "Hamal"]}
    monkeypatch.setattr(gluetun, "get_gluetun_status", status)
    monkeypatch.setitem(gluetun._ctl_state, "primary", gluetun._CtlState())
    r = await gluetun.gluetun_watchdog_check()
    assert r["applied"] and r["current"] == "one of Mirzam, Hamal" and pushed



async def test_full_list_when_gluetun_reports_ip(judged):
    g, cand, pushed = judged
    g.force_update_mode = "CLEAN_ONLY"
    st = {"ip": "198.51.100.200", "vpn_status": "running", "server_name": None, "error": None}  # unknown/listed IP
    await gluetun.update_gluetun_server_selection(cand, status=st, quiet=True)
    assert pushed == [["Fuyue", "Mirzam", "Taiyangshou"]]  # Gluetun reports its IP: keep its fallback list


async def test_single_server_selection_is_shown(fresh_config, monkeypatch, fake_server, make_summary):
    state.current_scan = make_summary([fake_server("Mirzam", country_code="NL", location="Alblasserdam")])
    _gluetun_client(monkeypatch, {"provider": {"server_selection": {"names": ["Mirzam"]}}})
    st = await gluetun.get_gluetun_status(fresh_config.gluetun)
    assert st["connected"] and st["server_name"] == "Mirzam" and st["country"] == "NL"
    assert st["ip"] is None and "only this server" in st["note"]
    _gluetun_client(monkeypatch, {"provider": {"server_selection": {"names": ["Mirzam", "Fuyue"]}}})
    st = await gluetun.get_gluetun_status(fresh_config.gluetun)
    assert st["server_name"] is None and st["selected_names"] == ["Mirzam", "Fuyue"]



async def test_follow_up_after_switch_logs_result(fresh_config, monkeypatch, caplog):
    import asyncio
    import logging
    import httpx
    monkeypatch.setattr(gluetun, "SWITCH_FOLLOW_UP_SECONDS", 0)
    monkeypatch.setitem(gluetun._ctl_state, "primary", gluetun._CtlState())

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def put(self, url, json): return httpx.Response(200, text="settings updated")
    monkeypatch.setattr(httpx, "AsyncClient", C)

    async def status(cfg):
        return {"ip": "198.51.100.5", "server_name": "Mirzam", "vpn_status": "running", "error": None}
    monkeypatch.setattr(gluetun, "get_gluetun_status", status)
    with caplog.at_level(logging.INFO, logger="airbl.gluetun"):
        r = await gluetun.set_gluetun_server_names(fresh_config.gluetun, ["Mirzam", "Fuyue"])
        assert r["applied"]
        for _ in range(5):
            await asyncio.sleep(0)
    assert "after the switch Gluetun is on Mirzam (public IP 198.51.100.5)" in caplog.text
