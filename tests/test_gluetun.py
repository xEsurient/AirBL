"""Gluetun servers.json export and control-server API (httpx mocked)."""

import json
import types

import httpx
import pytest

from airbl import gluetun
from airbl.config import GluetunConfig, GluetunProfileConfig
from airbl.pinger import PingResult
from airbl.web.state import state


def _ping(ip, ms=10.0, alive=True):
    return PingResult(ip=ip, is_alive=alive, avg_rtt_ms=ms if alive else None)


def _profile(tmp_path, name="servers.json", **kw):
    params = dict(name="P", enabled=True, output_path=tmp_path / name, endpoint_strategy="ALL",
                  min_download_mbps=0, min_upload_mbps=0, require_clean=True)
    params.update(kw)
    return GluetunProfileConfig(**params)


@pytest.fixture
def servers(fake_server):
    def mk(name, rep="clean", cc="CH", city="Zurich", dl=200, ul=200, e1=20.0, e3=10.0, latency=20.0, ip=None):
        kw = {}
        if ip:
            kw["ip"] = ip
        return fake_server(
            name=name, reputation=rep, country_code=cc, location=city, latency_ms=latency,
            speedtest={"download_mbps": dl, "upload_mbps": ul} if dl is not None else None,
            entry1_ping=_ping(f"198.51.100.{len(name)}", e1) if e1 is not None else None,
            entry3_ping=_ping(f"203.0.113.{len(name)}", e3) if e3 is not None else None,
            **kw,
        )
    return mk


# --- _write_servers_json ---------------------------------------------------------------

def test_write_servers_json_format(tmp_path, servers):
    p = _profile(tmp_path)
    s = servers("AirVPN Toliman")
    assert gluetun._write_servers_json(p, [(s, ["203.0.113.1"])])
    data = json.loads((tmp_path / "servers.json").read_text())
    assert data["version"] == 1
    prov = data["airvpn"]
    assert prov["version"] == 1 and prov["preferred"] is True and isinstance(prov["timestamp"], int)
    [e] = prov["servers"]
    assert e == {
        "vpn": "wireguard", "country": "Switzerland", "region": "Europe", "city": "Zurich",
        "server_name": "Toliman", "hostname": "ch.vpn.airdns.org", "wgpubkey": gluetun.WG_PUBKEY,
        "ips": ["203.0.113.1"],
    }
    assert not list(tmp_path.glob("*.tmp"))


def test_write_provider_only_format_for_airvpn_json(tmp_path, servers):
    p = _profile(tmp_path, name="servers/airvpn.json")
    assert gluetun._write_servers_json(p, [(servers("Toliman"), ["203.0.113.1"])])
    data = json.loads((tmp_path / "servers" / "airvpn.json").read_text())
    assert "airvpn" not in data
    assert data["version"] == 1 and data["preferred"] is True
    assert data["servers"][0]["server_name"] == "Toliman"


def test_empty_result_keeps_previous_file(tmp_path):
    p = _profile(tmp_path)
    (tmp_path / "servers.json").write_text("previous")
    assert gluetun._write_servers_json(p, []) is False
    assert (tmp_path / "servers.json").read_text() == "previous"


def test_unknown_region_and_own_pubkey(tmp_path, servers):
    s = servers("Foo", cc="ZZ")
    s.wg_pubkey = "own-key"
    gluetun._write_servers_json(_profile(tmp_path), [(s, ["1.2.3.4"])])
    e = json.loads((tmp_path / "servers.json").read_text())["airvpn"]["servers"][0]
    assert e["region"] == "Unknown" and e["wgpubkey"] == "own-key"


# --- _filter_profile_servers ------------------------------------------------------------

def _names(res):
    return [s.server_name for s, _ in res]


def test_filter_require_clean(tmp_path, servers):
    lst = [servers("A"), servers("B", rep="blocked"), servers("C", rep="unknown")]
    assert _names(gluetun._filter_profile_servers(_profile(tmp_path), lst)) == ["A"]
    assert _names(gluetun._filter_profile_servers(_profile(tmp_path, require_clean=False), lst)) == ["A", "B", "C"]


def test_filter_thresholds(tmp_path, servers):
    lst = [servers("Fast", dl=150, ul=130), servers("SlowUp", dl=500, ul=100), servers("NoTest", dl=None)]
    p = _profile(tmp_path, min_download_mbps=120, min_upload_mbps=120)
    assert _names(gluetun._filter_profile_servers(p, lst)) == ["Fast"]
    # Zero thresholds accept servers without a speedtest
    assert _names(gluetun._filter_profile_servers(_profile(tmp_path), lst)) == ["Fast", "SlowUp", "NoTest"]
    # Exactly at the threshold passes
    assert _names(gluetun._filter_profile_servers(
        _profile(tmp_path, min_download_mbps=150, min_upload_mbps=130), lst)) == ["Fast"]


def test_filter_locations(tmp_path, servers):
    lst = [servers("A", cc="CH", city="Zurich"), servers("B", cc="DE", city="Frankfurt"),
           servers("C", cc="ch", city="Geneva")]
    assert _names(gluetun._filter_profile_servers(_profile(tmp_path, allowed_countries=["ch"]), lst)) == ["A", "C"]
    assert _names(gluetun._filter_profile_servers(_profile(tmp_path, allowed_cities=["ZURICH", "frankfurt"]), lst)) == ["A", "B"]


@pytest.mark.parametrize("strategy,e1,e3,expected", [
    ("ALL", 20.0, 10.0, ["198.51.100.1", "203.0.113.1"]),
    ("ENTRY1", 20.0, 10.0, ["198.51.100.1"]),
    ("ENTRY3", 20.0, 10.0, ["203.0.113.1"]),
    ("PING_PRIORITY", 20.0, 10.0, ["203.0.113.1"]),
    ("PING_PRIORITY", 5.0, 10.0, ["198.51.100.1"]),
    ("ALL", None, 10.0, ["203.0.113.1"]),
    ("ENTRY1", None, 10.0, None),
])
def test_filter_strategies(tmp_path, servers, strategy, e1, e3, expected):
    s = servers("X", e1=e1, e3=e3)
    res = gluetun._filter_profile_servers(_profile(tmp_path, endpoint_strategy=strategy), [s])
    if expected is None:
        assert res == []
    else:
        assert res[0][1] == expected


def test_filter_dead_entry_skipped(tmp_path, servers):
    s = servers("X")
    s.entry1_ping = _ping("198.51.100.1", alive=False)
    s.entry3_ping = _ping("203.0.113.1", alive=False)
    assert gluetun._filter_profile_servers(_profile(tmp_path), [s]) == []


# --- update_gluetun_server_selection -----------------------------------------------------

@pytest.fixture
def control(monkeypatch, fresh_config):
    calls = {"status": 0, "set": []}
    status = {"value": {"ip": None, "error": None}}

    async def fake_status(cfg):
        calls["status"] += 1
        return status["value"]

    async def fake_set(cfg, names):
        calls["set"].append(names)
        return {"applied": True, "names": names}

    monkeypatch.setattr(gluetun, "get_gluetun_status", fake_status)
    monkeypatch.setattr(gluetun, "set_gluetun_server_names", fake_set)
    return fresh_config.gluetun, status, calls


@pytest.fixture
def ranked(servers):
    # Scores fall with latency: S1 best ... S5 worst; plus a blocked one
    lst = [servers(f"S{i}", latency=10.0 * i, ip=f"192.0.2.{i}") for i in range(1, 6)]
    lst.append(servers("Bad", rep="blocked", ip="192.0.2.66"))
    return [(s, ["x"]) for s in lst]


async def test_not_top4_stays_when_in_top4(control, ranked):
    cfg, status, calls = control
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": "192.0.2.4", "error": None}
    r = await gluetun.update_gluetun_server_selection(ranked)
    assert r["applied"] is False and calls["set"] == []


async def test_not_top4_switches_from_5th(control, ranked):
    cfg, status, calls = control
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": "192.0.2.5", "error": None}
    await gluetun.update_gluetun_server_selection(ranked)
    assert calls["set"] == [["S1", "S2", "S3", "S4"]]


async def test_not_best(control, ranked):
    cfg, status, calls = control
    cfg.force_update_mode = "NOT_BEST"
    status["value"] = {"ip": "192.0.2.2", "error": None}
    await gluetun.update_gluetun_server_selection(ranked)
    assert calls["set"] == [["S1"]]
    status["value"] = {"ip": "192.0.2.1", "error": None}
    r = await gluetun.update_gluetun_server_selection(ranked)
    assert r["applied"] is False and len(calls["set"]) == 1


async def test_always_skips_status_and_excludes_blocked(control, ranked):
    cfg, status, calls = control
    cfg.force_update_mode = "ALWAYS"
    await gluetun.update_gluetun_server_selection(ranked)
    assert calls["status"] == 0
    assert calls["set"] == [["S1", "S2", "S3", "S4", "S5"]]


async def test_clean_only(control, ranked, make_summary):
    cfg, status, calls = control
    cfg.force_update_mode = "CLEAN_ONLY"
    state.current_scan = make_summary([s for s, _ in ranked])
    status["value"] = {"ip": "192.0.2.5", "error": None}  # worst but clean -> stay
    r = await gluetun.update_gluetun_server_selection(ranked)
    assert r == {"applied": False, "reason": "current server still clean"}
    status["value"] = {"ip": "192.0.2.66", "error": None}  # blocked -> move to all clean
    await gluetun.update_gluetun_server_selection(ranked)
    assert calls["set"] == [["S1", "S2", "S3", "S4", "S5"]]
    status["value"] = {"ip": "8.8.8.8", "error": None}  # unknown server -> move
    await gluetun.update_gluetun_server_selection(ranked)
    assert len(calls["set"]) == 2


async def test_status_error_does_not_change(control, ranked):
    cfg, status, calls = control
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": None, "error": "Gluetun rejected the API key (401)."}
    r = await gluetun.update_gluetun_server_selection(ranked)
    assert r["applied"] is False and "401" in r["reason"] and calls["set"] == []


async def test_no_clean_servers(control, servers):
    cfg, status, calls = control
    cfg.force_update_mode = "ALWAYS"
    r = await gluetun.update_gluetun_server_selection([(servers("Bad", rep="blocked"), ["x"])])
    assert r["applied"] is False and calls["set"] == []


async def test_unknown_public_ip_yet_pushes(control, ranked):
    cfg, status, calls = control
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": None, "error": None}
    await gluetun.update_gluetun_server_selection(ranked)
    assert calls["set"] == [["S1", "S2", "S3", "S4"]]


async def test_name_match_when_exit_ip_unknown(control, ranked):
    # A rebuilt scan keeps one exit IP per server; the resolved name must still count
    cfg, status, calls = control
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": "198.18.0.9", "server_name": "S2", "error": None}
    r = await gluetun.update_gluetun_server_selection(ranked)
    assert r["applied"] is False and calls["set"] == []


# --- watchdog ------------------------------------------------------------------------------

@pytest.fixture
def watchdog(control, ranked, monkeypatch):
    cfg, status, calls = control
    cfg.force_update_enabled = True
    monkeypatch.setattr(gluetun, "_last_push_at", None)
    monkeypatch.setattr(gluetun, "_watchdog_error", None)
    monkeypatch.setattr(gluetun, "_control_profile", lambda c: object())

    async def servers_():
        return [s for s, _ in ranked]

    monkeypatch.setattr(gluetun, "_get_servers_for_gluetun_generation", servers_)
    monkeypatch.setattr(gluetun, "_filter_profile_servers", lambda p, s: ranked)
    status["value"] = {"ip": "192.0.2.1", "vpn_status": "running", "error": None}
    return cfg, status, calls


async def test_watchdog_stays_within_targets(watchdog):
    cfg, status, calls = watchdog
    for mode in ("NOT_TOP4", "NOT_BEST", "CLEAN_ONLY", "ALWAYS"):
        cfg.force_update_mode = mode
        r = await gluetun.gluetun_watchdog_check()
        assert r["applied"] is False, mode
    assert calls["set"] == []  # ALWAYS doesn't re-push every minute


async def test_watchdog_switches_when_outside(watchdog, make_summary, ranked):
    cfg, status, calls = watchdog
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": "192.0.2.5", "vpn_status": "running", "error": None}  # 5th
    r = await gluetun.gluetun_watchdog_check()
    assert r["applied"] is True and calls["set"] == [["S1", "S2", "S3", "S4"]]


async def test_watchdog_clean_only_unknown_server(watchdog, make_summary, ranked):
    # Gluetun with its full built-in list may land on a server AirBL never scanned
    cfg, status, calls = watchdog
    cfg.force_update_mode = "CLEAN_ONLY"
    state.current_scan = make_summary([s for s, _ in ranked])
    status["value"] = {"ip": "198.18.0.1", "vpn_status": "running", "error": None}
    await gluetun.gluetun_watchdog_check()
    assert calls["set"] == [["S1", "S2", "S3", "S4", "S5"]]


async def test_watchdog_cooldown_and_skips(watchdog, monkeypatch):
    cfg, status, calls = watchdog
    cfg.force_update_mode = "NOT_BEST"
    status["value"] = {"ip": "192.0.2.3", "vpn_status": "running", "error": None}
    monkeypatch.setattr(gluetun, "_last_push_at", gluetun.time.monotonic())
    assert (await gluetun.gluetun_watchdog_check())["reason"] == "cooldown after a switch"
    monkeypatch.setattr(gluetun, "_last_push_at", None)
    state.is_scanning = True
    assert (await gluetun.gluetun_watchdog_check())["reason"] == "scan running"
    state.is_scanning = False
    status["value"] = {"ip": None, "vpn_status": "stopped", "error": None}
    assert (await gluetun.gluetun_watchdog_check())["reason"] == "Gluetun not connected yet"
    cfg.force_update_mode = "DISABLED"
    assert (await gluetun.gluetun_watchdog_check())["reason"] == "control disabled"
    assert calls["set"] == []


async def test_check_now_forces(watchdog, monkeypatch):
    # Check Now skips the cooldown and works with automatic control off, but not in DISABLED mode
    cfg, status, calls = watchdog
    cfg.force_update_mode = "NOT_BEST"
    cfg.force_update_enabled = False
    monkeypatch.setattr(gluetun, "_last_push_at", gluetun.time.monotonic())
    status["value"] = {"ip": "192.0.2.3", "server_name": "S3", "vpn_status": "running", "error": None}
    r = await gluetun.gluetun_watchdog_check(force=True)
    assert r["applied"] is True and r["current"] == "S3" and r["mode"] == "NOT_BEST"
    assert calls["set"] == [["S1"]]
    status["value"] = {"ip": "192.0.2.1", "server_name": "S1", "vpn_status": "running", "error": None}
    r = await gluetun.gluetun_watchdog_check(force=True)
    assert r == {"applied": False, "reason": "current server within target set", "current": "S1", "mode": "NOT_BEST"}
    cfg.force_update_mode = "DISABLED"
    assert (await gluetun.gluetun_watchdog_check(force=True))["reason"] == "control disabled"
    assert (await gluetun.gluetun_watchdog_check())["reason"] == "control disabled"
    assert len(calls["set"]) == 1


async def test_no_profile_uses_all_clean_servers(control, servers, make_summary, monkeypatch, fresh_config):
    # Profiles only write files; Gluetun control works with none enabled
    cfg, status, calls = control
    cfg.profiles = []
    cfg.force_update_enabled, cfg.force_update_mode = True, "CLEAN_ONLY"
    monkeypatch.setattr(gluetun, "_last_push_at", None)
    fresh_config.performance.disabled_servers = ["Slow"]
    scan = [servers("Good", ip="192.0.2.1"), servers("Slow", ip="192.0.2.2"),
            servers("Bad", rep="blocked", ip="192.0.2.3")]
    state.current_scan = make_summary(scan)
    status["value"] = {"ip": "192.0.2.3", "vpn_status": "running", "error": None}
    r = await gluetun.gluetun_watchdog_check(force=True)
    assert r["applied"] is True and calls["set"] == [["Good"]]
    await gluetun.generate_gluetun_servers_json()  # after a scan
    assert calls["set"] == [["Good"], ["Good"]]
    cfg.force_update_enabled = False
    await gluetun.generate_gluetun_servers_json()  # control off, no profiles: nothing
    assert len(calls["set"]) == 2


async def test_watchdog_logs_errors_once(watchdog, caplog):
    cfg, status, calls = watchdog
    cfg.force_update_mode = "NOT_TOP4"
    status["value"] = {"ip": None, "error": "Could not reach Gluetun"}
    with caplog.at_level("WARNING", logger="airbl.gluetun"):
        for _ in range(3):
            await gluetun.gluetun_watchdog_check()
    assert sum("Could not reach Gluetun" in r.message for r in caplog.records) == 1
    assert calls["set"] == []


async def test_watchdog_no_cooldown_after_fresh_boot(watchdog, monkeypatch):
    # monotonic() counts from boot: a few seconds after a reboot (or on a fresh CI VM)
    # there has been no push yet, so no cooldown
    cfg, status, calls = watchdog
    cfg.force_update_mode = "NOT_TOP4"
    # only the module's clock, not asyncio's
    monkeypatch.setattr(gluetun, "time", types.SimpleNamespace(monotonic=lambda: 30.0, time=gluetun.time.time))
    status["value"] = {"ip": "192.0.2.5", "vpn_status": "running", "error": None}
    r = await gluetun.gluetun_watchdog_check()
    assert r["applied"] is True and calls["set"] == [["S1", "S2", "S3", "S4"]]


async def test_set_names_starts_cooldown(http, monkeypatch):
    box, _ = http
    monkeypatch.setattr(gluetun, "_last_push_at", None)
    box["fn"] = lambda r: httpx.Response(400, text="bad")
    await gluetun.set_gluetun_server_names(GluetunConfig(), ["A"])
    assert gluetun.time.monotonic() - gluetun._last_push_at < 5  # failed attempts count too


# --- HTTP layer (httpx.MockTransport) ---------------------------------------------------

@pytest.fixture
def http(monkeypatch):
    handler_box = {}
    requests = []
    real = httpx.AsyncClient

    def factory(*a, **kw):
        def handler(request):
            requests.append(request)
            return handler_box["fn"](request)
        kw["transport"] = httpx.MockTransport(handler)
        return real(*a, **kw)

    monkeypatch.setattr(httpx, "AsyncClient", factory)
    return handler_box, requests


async def test_set_names_payload_and_api_key(http):
    box, reqs = http
    box["fn"] = lambda r: httpx.Response(200, text="settings updated\n")
    cfg = GluetunConfig(api_key="secret-test-key", control_server_host="10.0.0.5", control_server_port=8001)
    r = await gluetun.set_gluetun_server_names(cfg, ["Achernar", "Toliman"])
    assert r == {"applied": True, "names": ["Achernar", "Toliman"], "outcome": "settings updated"}
    [req] = reqs
    assert req.method == "PUT" and str(req.url) == "http://10.0.0.5:8001/v1/vpn/settings"
    assert req.headers["X-API-Key"] == "secret-test-key"
    assert json.loads(req.content) == {"provider": {"server_selection": {
        "names": ["Achernar", "Toliman"], "countries": [], "regions": [], "cities": [], "hostnames": []}}}


async def test_set_names_without_key_sends_no_header(http):
    box, reqs = http
    box["fn"] = lambda r: httpx.Response(200, text="ok")
    await gluetun.set_gluetun_server_names(GluetunConfig(), ["A"])
    assert "X-API-Key" not in reqs[0].headers


async def test_set_names_401(http):
    box, _ = http
    box["fn"] = lambda r: httpx.Response(401, text="unauthorized")
    r = await gluetun.set_gluetun_server_names(GluetunConfig(api_key="k"), ["A"])
    assert r["applied"] is False and "API key" in r["reason"] and "401" in r["reason"]


async def test_set_names_unreachable(http):
    box, _ = http

    def boom(r):
        raise httpx.ConnectError("refused", request=r)

    box["fn"] = boom
    r = await gluetun.set_gluetun_server_names(GluetunConfig(), ["A"])
    assert r["applied"] is False and "Could not reach" in r["reason"]


@pytest.mark.parametrize("host,expected", [
    ("127.0.0.1", "http://127.0.0.1:8000"),
    ("::1", "http://[::1]:8000"),
    ("https://gluetun.local/", "https://gluetun.local"),
    (" gluetun ", "http://gluetun:8000"),
])
def test_base_url(host, expected):
    assert gluetun._base_url(GluetunConfig(control_server_host=host)) == expected


async def test_status_parses_json_without_content_type(http, make_summary, servers):
    box, reqs = http
    state.current_scan = make_summary([servers("AirVPN Toliman", ip="203.0.113.5")])

    def handler(r):
        if r.url.path == "/v1/vpn/status":
            return httpx.Response(200, json={"status": "running"})
        return httpx.Response(200, content=b'{"public_ip":"203.0.113.5","country":"Switzerland"}',
                              headers={"content-type": "text/plain; charset=utf-8"})

    box["fn"] = handler
    r = await gluetun.get_gluetun_status(GluetunConfig(api_key="k"))
    assert r["error"] is None and r["ip"] == "203.0.113.5" and r["connected"] is True
    assert r["server_name"] == "Toliman" and r["country"] == "CH" and r["city"] == "Zurich"
    assert all(q.headers["X-API-Key"] == "k" for q in reqs)


async def test_status_plain_text_ip(http):
    box, _ = http
    box["fn"] = lambda r: (httpx.Response(200, json={"status": "running"}) if r.url.path == "/v1/vpn/status"
                           else httpx.Response(200, text="203.0.113.9\n"))
    r = await gluetun.get_gluetun_status(GluetunConfig())
    assert r["ip"] == "203.0.113.9" and r["server_name"] is None


async def test_status_401_clear_error(http):
    box, _ = http
    box["fn"] = lambda r: httpx.Response(401, text="")
    r = await gluetun.get_gluetun_status(GluetunConfig(api_key="wrong"))
    assert r["ip"] is None
    assert r["error"].startswith("Gluetun rejected the API key (401)")


async def test_status_403_and_other(http):
    box, _ = http
    box["fn"] = lambda r: httpx.Response(403)
    assert "403" in (await gluetun.get_gluetun_status(GluetunConfig()))["error"]
    box["fn"] = lambda r: httpx.Response(500, text="oops")
    assert (await gluetun.get_gluetun_status(GluetunConfig()))["error"] == "Gluetun returned HTTP 500: oops"


async def test_status_unreachable(http):
    box, _ = http

    def boom(r):
        raise httpx.ConnectTimeout("t", request=r)

    box["fn"] = boom
    r = await gluetun.get_gluetun_status(GluetunConfig())
    assert "Could not reach" in r["error"]


# --- end-to-end generation ------------------------------------------------------------------

async def test_generate_writes_each_enabled_profile(tmp_path, fresh_config, servers, make_summary):
    a = servers("Toliman", dl=200, ul=200)
    b = servers("Slow", dl=50, ul=50)
    state.current_scan = make_summary([a, b])
    fresh_config.gluetun.profiles = [
        _profile(tmp_path, name="servers/airvpn.json", min_download_mbps=120, min_upload_mbps=120),
        _profile(tmp_path, name="servers.json"),
        _profile(tmp_path, name="disabled.json", enabled=False),
    ]
    await gluetun.generate_gluetun_servers_json()
    new = json.loads((tmp_path / "servers" / "airvpn.json").read_text())
    old = json.loads((tmp_path / "servers.json").read_text())
    assert [e["server_name"] for e in new["servers"]] == ["Toliman"]
    assert sorted(e["server_name"] for e in old["airvpn"]["servers"]) == ["Slow", "Toliman"]
    assert not (tmp_path / "disabled.json").exists()


async def test_status_falls_back_to_scan_history(http, make_summary, servers, monkeypatch):
    # A disabled server is no longer scanned, but Gluetun may still be on it
    box, _ = http
    state.current_scan = make_summary([servers("AirVPN Toliman", ip="203.0.113.5")])

    class FakeDB:
        async def find_server_by_exit_ip(self, ip):
            return "Hamal" if ip == "203.0.113.43" else None

    monkeypatch.setattr(state, "db", FakeDB())
    monkeypatch.setitem(state.servers_by_country, "Hamal", "CH")
    monkeypatch.setitem(state.server_to_city_api, "Hamal", "Zurich")
    box["fn"] = lambda r: (httpx.Response(200, json={"status": "running"}) if r.url.path == "/v1/vpn/status"
                           else httpx.Response(200, json={"public_ip": "203.0.113.43"}))
    r = await gluetun.get_gluetun_status(GluetunConfig())
    assert r["server_name"] == "Hamal" and r["country"] == "CH" and r["city"] == "Zurich"


async def test_set_names_400_nameless_list_hint(http):
    box, _ = http
    box["fn"] = lambda r: httpx.Response(400, text=(
        "provider settings: server selection: for VPN service provider airvpn: the server name specified "
        "is not valid: one or more values is set but there is no possible value available"))
    r = await gluetun.set_gluetun_server_names(GluetunConfig(), ["A"])
    assert r["applied"] is False and "servers/airvpn.json" in r["reason"]


async def test_set_names_400_stale_list_hint(http):
    box, _ = http
    box["fn"] = lambda r: httpx.Response(400, text=(
        "provider settings: server selection: for VPN service provider airvpn: the server name specified "
        "is not valid: value is not one of the possible choices: none of Toliman is one of the choices "
        "available Fuyue, Mirzam"))
    r = await gluetun.set_gluetun_server_names(GluetunConfig(), ["Toliman"])
    assert r["applied"] is False and "Restart Gluetun" in r["reason"]


@pytest.mark.parametrize("body", ["<html>not gluetun</html>", "[1, 2]", "null"])
async def test_status_unexpected_reply_is_an_error_not_a_crash(http, body):
    box, _ = http
    box["fn"] = lambda r: httpx.Response(200, text=body)
    r = await gluetun.get_gluetun_status(GluetunConfig())
    assert r["error"] and "Unexpected reply" in r["error"] and r["connected"] is False
