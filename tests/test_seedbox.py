"""Seedbox ranking: speed_score ignores reputation, opt-in blocked speedtest queue."""

import json
from pathlib import Path

import pytest

from airbl.scanner import speedtest_score
from airbl.web import tasks
from airbl.web.state import state


# --- speed_score ---------------------------------------------------------------

def test_speedtest_score_variants():
    assert speedtest_score(None) is None
    assert speedtest_score({}) is None
    assert speedtest_score({"error": "boom", "deviation_score": 90}) is None  # failed: never ranked
    assert speedtest_score({"deviation_score": 135.5}) == 135.5  # no upper cap
    assert speedtest_score({"score": 7.2}) == pytest.approx(72.0)
    assert speedtest_score({"download_mbps": 10}) == 0.0
    assert speedtest_score({"deviation_score": -5}) == 0.0


def test_speed_score_ignores_reputation_but_score_does_not(fake_server):
    blocked = fake_server("Hamal", reputation="blocked", speedtest={"deviation_score": 140})
    clean = fake_server("Toliman", speedtest={"deviation_score": 140})
    assert blocked.score == 0.0 and blocked.speed_score == 140
    assert clean.score == 100.0 and clean.speed_score == 140  # clean score stays capped
    assert fake_server("Untested", reputation="blocked").speed_score is None
    d = blocked.to_dict()
    assert d["speed_score"] == 140 and d["score"] == 0.0
    assert fake_server("X").to_dict()["speed_score"] is None


# --- blocked speedtest queue ---------------------------------------------------

def _with_conf(server, tmp_path):
    server.config_file = Path(tmp_path) / f"{server.server_name}.conf"
    return server


def test_blocked_queue_off_by_default(fake_server, fresh_config, tmp_path):
    servers = [_with_conf(fake_server("B", reputation="blocked"), tmp_path)]
    assert fresh_config.scan.speedtest_blocked_top_n == 0
    assert tasks._blocked_speedtest_queue(servers, 0) == []


def test_blocked_queue_top_n_by_ping(fake_server, fresh_config, tmp_path, monkeypatch):
    servers = [
        _with_conf(fake_server("Slow", reputation="blocked", latency_ms=90), tmp_path),
        _with_conf(fake_server("Fast", reputation="blocked", latency_ms=10), tmp_path),
        _with_conf(fake_server("Mid", reputation="blocked", latency_ms=40), tmp_path),
        _with_conf(fake_server("Clean", latency_ms=1), tmp_path),            # clean: not in this queue
        _with_conf(fake_server("Unk", reputation="unknown", latency_ms=1), tmp_path),  # unknown: yes
        fake_server("NoConf", reputation="blocked", latency_ms=1),            # no config file
    ]
    q = tasks._blocked_speedtest_queue(servers, 2)
    assert [s.server_name for s in q] == ["Unk", "Fast"]  # not verified clean = seedbox queue
    q = tasks._blocked_speedtest_queue(servers, 3)
    assert [s.server_name for s in q] == ["Unk", "Fast", "Mid"]


def test_blocked_queue_skips_disabled_and_city_filter(fake_server, fresh_config, tmp_path, monkeypatch):
    fresh_config.performance.disabled_servers = ["Fast"]
    servers = [
        _with_conf(fake_server("Fast", reputation="blocked", latency_ms=10), tmp_path),
        _with_conf(fake_server("Zur", reputation="blocked", latency_ms=20), tmp_path),
        _with_conf(fake_server("Gen", reputation="blocked", latency_ms=15, location="Geneva"), tmp_path),
    ]
    fresh_config.cities = {"CH": ["Zurich"]}
    monkeypatch.setattr(tasks, "get_scannable_configs", lambda configs: [
        type("C", (), {"file_path": s.config_file, "city": s.location})() for s in servers])
    monkeypatch.setattr(state, "server_configs", lambda: [])
    q = tasks._blocked_speedtest_queue(servers, 5)
    assert [s.server_name for s in q] == ["Zur"]


async def test_batch_runs_blocked_after_clean(monkeypatch, fake_server, fresh_config, tmp_path,
                                              make_summary, broadcasts):
    fresh_config.scan.speedtest_blocked_top_n = 1
    fresh_config.scan.post_server_wait = 0
    servers = [
        _with_conf(fake_server("B1", reputation="blocked", latency_ms=5), tmp_path),
        _with_conf(fake_server("B2", reputation="blocked", latency_ms=50), tmp_path),
        _with_conf(fake_server("C1", country_code="DE"), tmp_path),
        _with_conf(fake_server("C2"), tmp_path),
    ]
    monkeypatch.setattr(state, "current_scan", make_summary(servers))
    monkeypatch.setattr(state, "scan_cancelled", False)
    monkeypatch.setattr(state, "is_paused", False)
    ran, discovery_got = [], []

    async def fake_single(server, index, total, *a, **k):
        ran.append((server.server_name, index, total))

    async def fake_discovery(clean, controller):
        discovery_got.append([s.server_name for s in clean])

    async def no_wait(*a, **k):
        return None

    async def no_resolve(server):
        return None

    monkeypatch.setattr(tasks, "_run_single_server_speedtest", fake_single)
    monkeypatch.setattr(tasks, "_run_discovery_phase", fake_discovery)
    monkeypatch.setattr(tasks, "_resolve_server_config", no_resolve)
    monkeypatch.setattr(tasks, "_smart_wait", no_wait)
    async def teardown(coro):
        await coro

    monkeypatch.setattr(tasks, "_finish_teardown", teardown)
    monkeypatch.setattr(tasks, "WireGuardController", lambda **k: type("W", (), {"disconnect": no_wait})())
    await tasks._run_batch_speedtests()
    names = [r[0] for r in ran]
    assert set(names[:2]) == {"C1", "C2"} and names[2:] == ["B1"]
    assert all(r[2] == 3 for r in ran) and [r[1] for r in ran] == [1, 2, 3]
    assert discovery_got and sorted(discovery_got[0]) == ["C1", "C2"]  # blocked never in discovery


def test_settings_api_blocked_top_n(fresh_config):
    from airbl.web.routes.api import _parse_settings, _BadSetting
    p, _ = _parse_settings({"speedtest_blocked_top_n": 99}, fresh_config)
    assert p["speedtest_blocked_top_n"] == 50
    with pytest.raises(_BadSetting):
        _parse_settings({"speedtest_blocked_top_n": "x"}, fresh_config)


# --- secondary control target ---------------------------------------------------

from airbl import gluetun  # noqa: E402
from airbl.config import ControlTargetConfig  # noqa: E402


@pytest.fixture
def seed_ctl(monkeypatch, fresh_config):
    calls = {"status": 0, "set": []}
    status = {"value": {"ip": None, "error": None}}

    async def fake_status(cfg):
        calls["status"] += 1
        return status["value"]

    async def fake_set(cfg, names):
        calls["set"].append((gluetun._target_key(cfg), names))
        st = gluetun._ctl_state[gluetun._target_key(cfg)]
        st.last_push_at = st.last_switch_at = gluetun.time.monotonic()
        return {"applied": True, "names": names}

    async def no_companion(cfg):
        return None

    monkeypatch.setattr(gluetun, "get_gluetun_status", fake_status)
    monkeypatch.setattr(gluetun, "set_gluetun_server_names", fake_set)
    monkeypatch.setattr(gluetun, "get_companion_status", no_companion)
    for key in ("primary", "secondary"):
        monkeypatch.setitem(gluetun._ctl_state, key, gluetun._CtlState())
    sec = fresh_config.gluetun.secondary
    sec.enabled = True
    sec.control_server_host = "192.0.2.50"
    sec.min_dwell_minutes = 0
    return sec, status, calls


@pytest.fixture
def mixed(fake_server):
    """Clean servers with modest speed, blocked ones faster; one blocked without a speedtest."""
    def mk(name, rep, dev, ip, up=100):
        st = {"deviation_score": dev, "download_mbps": dev, "upload_mbps": up} if dev is not None else None
        return fake_server(name, reputation=rep, speedtest=st, ip=ip)
    lst = [mk("C1", "clean", 80, "192.0.2.1"), mk("C2", "clean", 60, "192.0.2.2"),
           mk("B1", "blocked", 150, "192.0.2.11"), mk("B2", "blocked", 120, "192.0.2.12"),
           mk("B3", "blocked", None, "192.0.2.13"), mk("B4", "blocked", 120, "192.0.2.14", up=300)]
    dead = fake_server("B5", reputation="blocked", speedtest={"error": "Failed to connect"}, ip="192.0.2.15")
    return [(s, []) for s in lst + [dead]]


async def test_secondary_ranks_by_speed_including_blocked(seed_ctl, mixed):
    sec, status, calls = seed_ctl
    sec.force_update_mode = "ALLOWED"
    await gluetun.update_gluetun_server_selection(mixed, target=sec)
    # Rank order kept (not sorted); B4 beats B2 on upload at equal speed; B3 untested -> never
    assert calls["set"] == [("secondary", ["B1", "B4", "B2", "C1", "C2"])]


async def test_secondary_without_blocked(seed_ctl, mixed):
    sec, status, calls = seed_ctl
    sec.force_update_mode = "ALLOWED"
    sec.allow_blocked = False
    await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert calls["set"] == [("secondary", ["C1", "C2"])]


async def test_primary_still_clean_only_with_blocked_speedtests(seed_ctl, mixed, fresh_config):
    _, status, calls = seed_ctl
    fresh_config.gluetun.force_update_mode = "ALWAYS"
    await gluetun.update_gluetun_server_selection(mixed)
    assert calls["set"] == [("primary", ["C1", "C2"])]


async def test_secondary_top_n_and_dwell(seed_ctl, mixed):
    sec, status, calls = seed_ctl
    sec.force_update_mode = "NOT_TOPN"
    sec.top_n = 2
    status["value"] = {"ip": "192.0.2.12", "error": None}  # B2: 3rd
    await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert calls["set"] == [("secondary", ["B1", "B4"])]
    # Now on C1 (4th) right after a push: still an allowed candidate -> dwell holds it
    sec.min_dwell_minutes = 30
    status["value"] = {"ip": "192.0.2.1", "error": None}
    r = await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert r["reason"] == "minimum dwell" and len(calls["set"]) == 1
    # Forced (Check Now) ignores the dwell
    await gluetun.update_gluetun_server_selection(mixed, target=sec, force=True)
    assert len(calls["set"]) == 2
    # Untested (B3): unknown is not slower -> stay, dwell or not
    status["value"] = {"ip": "192.0.2.13", "error": None}
    r = await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert r["reason"] == "current server not re-tested yet" and len(calls["set"]) == 2
    # Its test failed (B5): that is evidence -> switch despite the dwell
    status["value"] = {"ip": "192.0.2.15", "error": None}
    await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert len(calls["set"]) == 3


async def test_secondary_clean_profile_does_not_hide_blocked(seed_ctl, mixed, fresh_config, tmp_path):
    sec, _, _ = seed_ctl
    prof = fresh_config.gluetun.profiles[0]
    prof.enabled = True
    prof.min_download_mbps = prof.min_upload_mbps = 0
    sec.control_profile = prof.name
    for s, _ in mixed:
        s.entry3_ping = s.exit_ping
    names = {s.server_name for s, _ in gluetun._control_candidates(sec, [s for s, _ in mixed])}
    assert {"B1", "B2"} <= names
    # Primary with the same profile: clean only
    names = {s.server_name for s, _ in gluetun._control_candidates(fresh_config.gluetun, [s for s, _ in mixed])}
    assert names == {"C1", "C2"}


async def test_secondary_without_profile_uses_all(seed_ctl, mixed, fresh_config):
    sec, _, _ = seed_ctl
    fresh_config.gluetun.profiles[0].enabled = True  # primary would use it; secondary names none
    assert gluetun._control_profile(sec) is None
    assert len(gluetun._control_candidates(sec, [s for s, _ in mixed])) == len(mixed)


async def test_watchdog_state_is_per_target(seed_ctl, mixed, monkeypatch, fresh_config):
    sec, status, calls = seed_ctl
    fresh_config.gluetun.force_update_enabled = True
    fresh_config.gluetun.force_update_mode = "NOT_BEST"
    sec.force_update_mode = "NOT_BEST"
    monkeypatch.setattr(state, "is_scanning", False)

    async def srv():
        return [s for s, _ in mixed]

    monkeypatch.setattr(gluetun, "_get_servers_for_gluetun_generation", srv)
    status["value"] = {"ip": "192.0.2.2", "error": None, "vpn_status": "running"}
    await gluetun.gluetun_watchdog_check(target="secondary")
    assert calls["set"] == [("secondary", ["B1"])]
    # The secondary's push starts only its own cooldown
    assert gluetun._ctl_state["primary"].last_push_at is None
    r = await gluetun.gluetun_watchdog_check(target="secondary")
    assert r["reason"] == "cooldown after a switch"
    await gluetun.gluetun_watchdog_check(target="primary")
    assert calls["set"][-1] == ("primary", ["C1"])
    sec.enabled = False
    assert (await gluetun.gluetun_watchdog_check(target="secondary"))["reason"] == "control disabled"


async def test_generate_pushes_each_target(seed_ctl, mixed, monkeypatch, fresh_config):
    sec, status, calls = seed_ctl
    sec.force_update_mode = "ALLOWED"
    fresh_config.gluetun.force_update_enabled = True
    fresh_config.gluetun.force_update_mode = "ALWAYS"
    for p in fresh_config.gluetun.profiles:
        p.enabled = False

    async def srv():
        return [s for s, _ in mixed]

    monkeypatch.setattr(gluetun, "_get_servers_for_gluetun_generation", srv)
    await gluetun.generate_gluetun_servers_json()
    assert [c[0] for c in calls["set"]] == ["primary", "secondary"]


def test_settings_api_secondary(fresh_config):
    from airbl.web.routes.api import _parse_settings, _BadSetting
    sec = fresh_config.gluetun.secondary
    sec.control_server_host, sec.api_key = "192.168.1.20", "keep"
    p, w = _parse_settings({"gluetun_secondary": {
        "enabled": True, "control_server_host": "192.168.1.20", "control_server_port": "8000",
        "force_update_mode": "NOT_BEST", "top_n": 99, "rank_by": "speed", "min_dwell_minutes": 10,
    }}, fresh_config)
    t = p["gluetun_secondary"]
    assert isinstance(t, ControlTargetConfig) and w == []
    assert (t.enabled, t.top_n, t.api_key, t.force_update_mode) == (True, 20, "keep", "NOT_BEST")
    # New address without a new key: the saved key is dropped, with a warning
    p, w = _parse_settings({"gluetun_secondary": {"control_server_port": 8001}}, fresh_config)
    assert p["gluetun_secondary"].api_key == "" and "removed" in w[0]
    p, w = _parse_settings({"gluetun_secondary": {"control_server_port": 8001, "api_key": "new"}}, fresh_config)
    assert p["gluetun_secondary"].api_key == "new" and w == []
    p, _ = _parse_settings({"gluetun_secondary": {"api_key_clear": True}}, fresh_config)
    assert p["gluetun_secondary"].api_key == ""
    for bad, why in (({"force_update_mode": "CLEAN_ONLY"}, "must be one of"),
                     ({"force_update_mode": "ALWAYS"}, "must be one of"),
                     ({"enabled": True, "control_server_host": ""}, "enter the host"),
                     ({"rank_by": "score"}, "allow_blocked"),
                     ({"control_server_host": "bad host!"}, "second target: host")):
        with pytest.raises(_BadSetting, match=why):
            _parse_settings({"gluetun_secondary": bad}, fresh_config)
    with pytest.raises(_BadSetting):
        _parse_settings({"gluetun_secondary": "nope"}, fresh_config)
    p, _ = _parse_settings({"gluetun_secondary": {"rank_by": "score", "allow_blocked": False}}, fresh_config)
    assert p["gluetun_secondary"].rank_by == "score"


def test_secondary_cannot_point_at_primary(fresh_config):
    from airbl.web.routes.api import _parse_settings, _BadSetting
    g = fresh_config.gluetun
    g.force_update_enabled, g.control_server_host, g.control_server_port = True, "127.0.0.1", 8000
    for host in ("127.0.0.1", "localhost", "http://127.0.0.1:8000"):
        with pytest.raises(_BadSetting, match="same control server"):
            _parse_settings({"gluetun_secondary": {"enabled": True, "control_server_host": host,
                                                   "control_server_port": 8000}}, fresh_config)
    # Different port, or the primary's control off: fine
    _parse_settings({"gluetun_secondary": {"enabled": True, "control_server_host": "127.0.0.1",
                                           "control_server_port": 8001}}, fresh_config)
    _parse_settings({"gluetun_force_update": False, "gluetun_secondary": {
        "enabled": True, "control_server_host": "127.0.0.1", "control_server_port": 8000}}, fresh_config)
    # Moving the primary onto the secondary's address is caught too
    g.secondary = ControlTargetConfig(enabled=True, control_server_host="192.168.1.20")
    with pytest.raises(_BadSetting, match="same control server"):
        _parse_settings({"gluetun_control_host": "192.168.1.20"}, fresh_config)


def test_settings_get_never_returns_secondary_key(client, fresh_config):
    fresh_config.gluetun.secondary.api_key = "s3cret"
    body = client.get("/api/settings").json()
    assert body["gluetun_secondary"]["api_key_set"] is True
    assert "s3cret" not in json.dumps(body)


def test_speed_ranking_endpoint(client, fake_server, make_summary):
    state.current_scan = make_summary([
        fake_server("C1", speedtest={"deviation_score": 80, "upload_mbps": 50}),
        fake_server("B1", reputation="blocked", speedtest={"deviation_score": 150, "upload_mbps": 90}),
        fake_server("B2", reputation="blocked", speedtest={"error": "x"}),
        fake_server("U1", reputation="unknown", speedtest={"deviation_score": 200}),
        fake_server("N1"),
    ])
    rows = client.get("/api/ranking/speed").json()["servers"]
    assert [r["server_name"] for r in rows] == ["U1", "B1", "C1"]  # reputation ignored (unknown too)
    assert [r["reputation"] for r in rows] == ["unknown", "blocked", "clean"]
    rows = client.get("/api/ranking/speed?include_blocked=false").json()["servers"]
    assert [r["server_name"] for r in rows] == ["C1"]


@pytest.fixture
def client(fresh_config, monkeypatch):
    from fastapi.testclient import TestClient
    from airbl.web.app import create_app
    from airbl.web.routes import api

    async def no_api():
        raise RuntimeError("network disabled in tests")

    monkeypatch.setattr(api, "get_airvpn_status", no_api)
    return TestClient(create_app())


async def test_db_fallback_keeps_blocked_and_speed(fresh_config, tmp_path, monkeypatch):
    """Before a fresh scan exists, the control targets rebuild servers from the DB."""
    from airbl.database import DatabaseManager
    db = DatabaseManager(tmp_path / "f.db")
    await db.init()
    sid = await db.add_scan_result({})
    await db.add_server_scan_result(sid, {"server_name": "Hamal", "reputation": "blocked", "is_blocked": True})
    await db.add_server_scan_result(sid, {"server_name": "Toliman", "reputation": "clean"})
    await db.add_server_scan_result(sid, {"server_name": "Old", "is_blocked": True})  # pre-reputation row
    await db.update_scan_result(sid, {})
    await db.add_speedtest_result({"download_mbps": 300.0, "upload_mbps": 150.0, "ping_ms": 9.0,
                                   "vpn_server_name": "Hamal"}, scan_id=sid)
    await db.add_speedtest_result({"download_mbps": 50.0, "upload_mbps": 10.0, "ping_ms": 30.0,
                                   "vpn_server_name": "Toliman"}, scan_id=sid)
    monkeypatch.setattr(state, "current_scan", None)
    monkeypatch.setattr(state, "db", db)
    try:
        servers = {s.server_name: s for s in await gluetun._get_servers_for_gluetun_generation()}
    finally:
        await db.close()
    assert servers["Hamal"].is_blocked and not servers["Hamal"].is_clean
    assert servers["Old"].is_blocked and not servers["Toliman"].is_blocked
    # Stored rows have no score column: it must be derived, or every server would rank 0
    assert servers["Hamal"].speed_score > servers["Toliman"].speed_score > 0
    assert servers["Old"].speed_score is None
    ranked = gluetun._rank(fresh_config.gluetun.secondary, [(s, []) for s in servers.values()])
    assert [s.server_name for s in ranked] == ["Hamal", "Toliman"]


# --- review fixes (2026-11-21) -----------------------------------------------------------------

def test_failed_speedtest_never_ranked(seed_ctl, fake_server, make_summary, client):
    ok = fake_server("A", reputation="blocked", speedtest={"deviation_score": 90, "upload_mbps": 50})
    failed = fake_server("B", reputation="blocked", speedtest={"error": "Failed to connect"})
    assert failed.speed_score is None and failed.score == 0.0
    assert [s.server_name for s in gluetun._rank("secondary", [(ok, []), (failed, [])])] == ["A"]
    state.current_scan = make_summary([ok, failed])
    assert [r["server_name"] for r in client.get("/api/ranking/speed").json()["servers"]] == ["A"]


def test_mixed_score_scales_rank_by_upload(seed_ctl, fake_server):
    live = fake_server("Live", reputation="blocked",
                       speedtest={"deviation_score": 95, "upload_mbps": 80, "download_mbps": 300})
    legacy = fake_server("Old", reputation="blocked", speedtest={"score": 9.9, "upload_mbps": 200, "download_mbps": 250})
    # 95 vs 99 on different scales would put Old first by accident; with a mix, Mbps decide
    assert [s.server_name for s in gluetun._rank("secondary", [(live, []), (legacy, [])])] == ["Old", "Live"]
    legacy.speedtest_result["upload_mbps"] = 10
    assert [s.server_name for s in gluetun._rank("secondary", [(live, []), (legacy, [])])] == ["Live", "Old"]


async def test_allowed_mode_dwell_and_reorder(seed_ctl, mixed):
    sec, status, calls = seed_ctl
    sec.force_update_mode = "ALLOWED"
    sec.min_dwell_minutes = 30
    status["value"] = {"ip": "192.0.2.2", "error": None}  # on C2, last allowed
    r = await gluetun.update_gluetun_server_selection(mixed, target=sec)  # end-of-scan (not quiet)
    assert r["reason"] == "current server within target set" and calls["set"] == []
    assert calls["status"] == 1  # the secondary always checks first, unlike the primary's ALWAYS
    status["value"] = {"ip": "192.0.2.15", "error": None}  # B5: its speedtest failed
    await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert calls["set"] == [("secondary", ["B1", "B4", "B2", "C1", "C2"])]


async def test_primary_always_still_pushes_without_status(seed_ctl, mixed, fresh_config):
    _, status, calls = seed_ctl
    fresh_config.gluetun.force_update_mode = "ALWAYS"
    await gluetun.update_gluetun_server_selection(mixed)
    assert calls["status"] == 0 and calls["set"] == [("primary", ["C1", "C2"])]


async def test_primary_hand_edited_not_topn_does_not_crash(seed_ctl, mixed, fresh_config):
    _, status, calls = seed_ctl
    fresh_config.gluetun.force_update_mode = "NOT_TOPN"
    status["value"] = {"ip": "192.0.2.99", "error": None}
    await gluetun.update_gluetun_server_selection(mixed)
    assert calls["set"] == [("primary", ["C1", "C2"])]  # top 4 of the clean ones


async def test_failed_push_does_not_start_dwell(seed_ctl, mixed, monkeypatch):
    sec, status, calls = seed_ctl
    sec.min_dwell_minutes = 30
    sec.force_update_mode = "NOT_BEST"

    async def rejected(cfg, names):
        gluetun._ctl_state["secondary"].last_push_at = gluetun.time.monotonic()
        return {"applied": False, "reason": "HTTP 400"}
    monkeypatch.setattr(gluetun, "set_gluetun_server_names", rejected)
    status["value"] = {"ip": "192.0.2.12", "error": None}  # B2, allowed but not best
    await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert gluetun._ctl_state["secondary"].last_switch_at is None


async def test_real_set_names_sets_switch_time_only_on_success(monkeypatch, fresh_config):
    import httpx
    sec = ControlTargetConfig(enabled=True, control_server_host="192.0.2.50")
    monkeypatch.setitem(gluetun._ctl_state, "secondary", gluetun._CtlState())
    responses = iter([httpx.Response(400, text="bad"), httpx.Response(200, text="settings updated")])

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def put(self, url, json): return next(responses)
    monkeypatch.setattr(httpx, "AsyncClient", C)
    await gluetun.set_gluetun_server_names(sec, ["A"])
    st = gluetun._ctl_state["secondary"]
    assert st.last_push_at is not None and st.last_switch_at is None
    await gluetun.set_gluetun_server_names(sec, ["A"])
    assert st.last_switch_at is not None


async def test_dwell_seeded_from_companion_after_restart(seed_ctl, mixed, monkeypatch):
    sec, status, calls = seed_ctl
    sec.min_dwell_minutes = 30
    sec.force_update_mode = "NOT_BEST"

    async def companion(cfg):
        return {"last_switch_at": gluetun.time.time() - 300}  # switched 5 min ago
    monkeypatch.setattr(gluetun, "get_companion_status", companion)
    status["value"] = {"ip": "192.0.2.12", "error": None}
    r = await gluetun.update_gluetun_server_selection(mixed, target=sec)
    assert r["reason"] == "minimum dwell" and calls["set"] == []
    assert gluetun._ctl_state["secondary"].dwell_seeded


async def test_secondary_profile_not_enabled(seed_ctl, mixed, fresh_config, monkeypatch):
    sec, status, calls = seed_ctl
    sec.control_profile = "Gone"

    async def srv():
        return [s for s, _ in mixed]
    monkeypatch.setattr(gluetun, "_get_servers_for_gluetun_generation", srv)
    r = await gluetun.push_target("secondary")
    assert r == {"applied": False, "reason": "profile 'Gone' is not enabled"} and calls["set"] == []
    monkeypatch.setattr(state, "is_scanning", False)
    status["value"] = {"ip": "192.0.2.1", "error": None, "vpn_status": "running"}
    r = await gluetun.gluetun_watchdog_check(target="secondary")
    assert "not enabled" in r["reason"]


async def test_secondary_disabled_without_host(fresh_config):
    sec = fresh_config.gluetun.secondary
    sec.enabled = True
    assert not gluetun._view("secondary").enabled  # no host: treated as off
    assert [v.key for v in gluetun.control_targets()] == []


async def test_save_secondary_pushes_only_secondary(client, fresh_config, monkeypatch):
    from airbl.web.routes import api
    pushed, generated = [], []

    async def fake_push(key):
        pushed.append(key)

    async def fake_generate():
        generated.append(1)
    monkeypatch.setattr(gluetun, "push_target", fake_push)
    monkeypatch.setattr(gluetun, "generate_gluetun_servers_json", fake_generate)
    fresh_config.gluetun.force_update_enabled = True
    fresh_config.gluetun.force_update_mode = "ALWAYS"
    r = client.post("/api/settings", json={"gluetun_secondary": {"enabled": True, "control_server_host": "192.0.2.50"}})
    assert r.status_code == 200, r.text
    for t in list(api._background_tasks):
        await t
    assert pushed == ["secondary"] and generated == []


async def test_watchdog_loops_are_independent(fresh_config, monkeypatch):
    import asyncio
    seen = []

    async def check(force=False, target="primary"):
        seen.append(target)
        if target == "secondary":
            await asyncio.sleep(3600)  # a hung second target
    monkeypatch.setattr(gluetun, "gluetun_watchdog_check", check)
    fresh_config.gluetun.watchdog_interval_seconds = 5
    fresh_config.gluetun.secondary = ControlTargetConfig(enabled=True, control_server_host="192.0.2.50",
                                                         watchdog_interval_seconds=5)

    async def fake_sleep(t):
        await asyncio.sleep(0)
    tasks_ = [asyncio.create_task(gluetun.watchdog_loop(k, sleep=fake_sleep)) for k in ("primary", "secondary")]
    for _ in range(50):
        await asyncio.sleep(0)
    for t in tasks_:
        t.cancel()
    await asyncio.gather(*tasks_, return_exceptions=True)
    assert seen.count("secondary") == 1 and seen.count("primary") > 3  # primary keeps going


async def test_target_lock_serialises_pushes(seed_ctl, mixed, monkeypatch):
    import asyncio
    sec, status, calls = seed_ctl
    sec.force_update_mode = "NOT_BEST"
    inside = []

    async def slow_status(cfg):
        inside.append(1)
        assert len(inside) == 1, "two pushes for one target ran at once"
        await asyncio.sleep(0.01)
        inside.pop()
        return {"ip": "192.0.2.12", "error": None}
    monkeypatch.setattr(gluetun, "get_gluetun_status", slow_status)
    await asyncio.gather(*(gluetun.update_gluetun_server_selection(mixed, target=sec) for _ in range(3)))
    assert len(calls["set"]) == 3


async def test_companion_status_is_filtered(monkeypatch):
    import httpx
    body = {"server": "Hamal", "public_ip": "<script>", "tunnel_up": True, "handshake_age_s": 3.5,
            "last_switch_at": 1700000000, "evil": {"x": 1}, "last_error": "e" * 500,
            "qbit": {"connection_status": "connected", "warnings": list("abcdefg"), "nested": {"a": 1},
                     "reannounce_pending": 5}}

    class C:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): pass
        async def get(self, url): return httpx.Response(200, json=body)
    monkeypatch.setattr(httpx, "AsyncClient", C)
    out = await gluetun.get_companion_status(ControlTargetConfig(control_server_host="192.0.2.50"))
    assert "evil" not in out and len(out["last_error"]) == 200
    assert out["qbit"] == {"connection_status": "connected", "warnings": list("abcde"), "reannounce_pending": 5}


async def test_current_secondary_server_always_requeued(fake_server, fresh_config, tmp_path):
    servers = [_with_conf(fake_server(f"B{i}", reputation="blocked", latency_ms=10 + i), tmp_path) for i in range(5)]
    q = tasks._blocked_speedtest_queue(servers, 2, must_include="B4")
    assert [s.server_name for s in q] == ["B0", "B1", "B4"]
    assert [s.server_name for s in tasks._blocked_speedtest_queue(servers, 2, must_include="AirVPN B1")] == ["B0", "B1"]


def test_blocked_result_carried_over_one_scan(fake_server, make_summary):
    old = make_summary([fake_server("B", reputation="blocked", speedtest={"deviation_score": 120}),
                        fake_server("F", reputation="blocked", speedtest={"error": "x"}),
                        fake_server("C", speedtest={"deviation_score": 80})])
    new = make_summary([fake_server("B", reputation="blocked"), fake_server("F", reputation="blocked"),
                        fake_server("C")])
    tasks._carry_over_blocked_results(old, new)
    by = {s.server_name: s for s in new.servers}
    assert by["B"].speedtest_result == {"deviation_score": 120, "stale": True}
    assert by["F"].speedtest_result is None and by["C"].speedtest_result is None  # failed / clean
    newer = make_summary([fake_server("B", reputation="blocked")])
    tasks._carry_over_blocked_results(new, newer)
    assert newer.servers[0].speedtest_result is None  # at most one scan old


async def test_seedbox_thresholds_use_own_list(fresh_config, broadcasts, monkeypatch):
    perf = fresh_config.performance
    perf.check_count = 2
    bad = {"download_mbps": 10, "upload_mbps": 5}
    monkeypatch.setattr(state, "seedbox_history", {})
    monkeypatch.setattr(state, "server_performance_history", {})
    # Off by default: nothing recorded, nothing disabled
    for _ in range(3):
        await tasks._check_and_disable_underperforming_server("Hamal", bad, blocked=True)
    assert state.seedbox_history == {} and perf.seedbox_disabled_servers == []
    perf.seedbox_threshold_download, perf.seedbox_threshold_upload = 50, 20
    for _ in range(2):
        await tasks._check_and_disable_underperforming_server("Hamal", bad, blocked=True)
    assert perf.seedbox_disabled_servers == ["Hamal"] and perf.disabled_servers == []
    assert state.server_performance_history == {} and len(state.seedbox_history["Hamal"]) == 2
    assert tasks._should_skip_server("Hamal", blocked=True) and not tasks._should_skip_server("Hamal")


def test_seedbox_disabled_list_api(client, fresh_config, monkeypatch):
    perf = fresh_config.performance
    perf.seedbox_disabled_servers = ["Hamal"]
    perf.disabled_servers = ["Toliman"]
    monkeypatch.setattr(state, "seedbox_history", {"Hamal": [{"download": 1, "upload": 1}]})
    body = client.get("/api/servers/disabled?list=seedbox").json()
    assert body["list"] == "seedbox" and [s["name"] for s in body["servers"]] == ["Hamal"]
    assert [s["name"] for s in client.get("/api/servers/disabled").json()["servers"]] == ["Toliman"]
    r = client.post("/api/servers/Hamal/enable?list=seedbox").json()
    assert r["disabled_servers"] == [] and perf.disabled_servers == ["Toliman"]
    assert "Hamal" not in state.seedbox_history


async def test_cancel_during_blocked_queue(monkeypatch, fake_server, fresh_config, tmp_path, make_summary, broadcasts):
    fresh_config.scan.speedtest_blocked_top_n = 3
    servers = [_with_conf(fake_server(f"B{i}", reputation="blocked", latency_ms=i), tmp_path) for i in range(3)]
    monkeypatch.setattr(state, "current_scan", make_summary(servers))
    monkeypatch.setattr(state, "scan_cancelled", False)
    monkeypatch.setattr(state, "is_paused", False)
    ran = []

    async def fake_single(server, *a, **k):
        ran.append(server.server_name)
        state.scan_cancelled = True  # Stop pressed during the first blocked test

    async def nothing(*a, **k):
        return None

    async def teardown(coro):
        await coro
    monkeypatch.setattr(tasks, "_run_single_server_speedtest", fake_single)
    monkeypatch.setattr(tasks, "_resolve_server_config", nothing)
    monkeypatch.setattr(tasks, "_smart_wait", nothing)
    monkeypatch.setattr(tasks, "_secondary_current_server", nothing)
    monkeypatch.setattr(tasks, "_finish_teardown", teardown)
    monkeypatch.setattr(tasks, "WireGuardController", lambda **k: type("W", (), {"disconnect": nothing})())
    await tasks._run_batch_speedtests()
    assert ran == ["B0"]


async def test_deviation_score_survives_db_restore_and_fallback(fresh_config, tmp_path, monkeypatch):
    from airbl.database import DatabaseManager
    db = DatabaseManager(tmp_path / "d.db")
    await db.init()
    sid = await db.add_scan_result({})
    await db.add_server_scan_result(sid, {"server_name": "Hamal", "reputation": "blocked", "is_blocked": True,
                                          "exit_ping": {"ip": "192.0.2.5", "latency_ms": 10}})
    await db.add_server_scan_result(sid, {"server_name": "Old", "reputation": "blocked", "is_blocked": True})
    await db.update_scan_result(sid, {})
    await db.add_speedtest_result({"download_mbps": 300.0, "upload_mbps": 150.0, "ping_ms": 9.0,
                                   "vpn_server_name": "Hamal", "deviation_score": 131.5}, scan_id=sid)
    await db.add_speedtest_result({"download_mbps": 200.0, "upload_mbps": 90.0, "ping_ms": 9.0,
                                   "vpn_server_name": "Old"}, scan_id=sid)  # pre-baseline / old row
    rows = await db.get_speedtest_history(limit=10)
    assert {r["vpn_server_name"]: r["deviation_score"] for r in rows} == {"Hamal": 131.5, "Old": None}
    monkeypatch.setattr(state, "db", db)
    monkeypatch.setattr(state, "config_dir", tmp_path)
    state._last_scan_servers = await db.get_last_scan_servers()
    state._last_scan_entry_pings = []
    restored = {s.server_name: s for s in (await state._restore_last_scan()).servers}
    assert restored["Hamal"].speed_score == 131.5  # same scale as a live result
    assert "deviation_score" not in restored["Old"].speedtest_result
    monkeypatch.setattr(state, "current_scan", None)
    fb = {s.server_name: s for s in await gluetun._get_servers_for_gluetun_generation()}
    assert fb["Hamal"].speed_score == 131.5 and "deviation_score" not in fb["Old"].speedtest_result
    await db.close()


# --- second review round (2026-11-21) ------------------------------------------------------------

def test_same_control_address_aliases():
    from airbl.web.routes.api import _same_control_address as same
    for a in ("127.0.0.1", "localhost", "http://localhost:8000", "http://[::1]:8000", "0.0.0.0", "::1"):
        assert same(a, 8000, "127.0.0.1", 8000), a
    assert not same("http://localhost:8001", 8000, "127.0.0.1", 8000)  # URL port wins
    assert not same("192.168.1.20", 8000, "127.0.0.1", 8000) and not same("", 8000, "127.0.0.1", 8000)


def test_primary_key_dropped_on_address_change(fresh_config):
    from airbl.web.routes.api import _parse_settings
    g = fresh_config.gluetun
    g.control_server_host, g.control_server_port, g.api_key = "192.168.1.5", 8000, "k"
    p, w = _parse_settings({"gluetun_control_host": "192.168.1.5", "gluetun_control_port": 8000}, fresh_config)
    assert "gluetun_api_key" not in p and w == []
    p, w = _parse_settings({"gluetun_control_host": "192.168.1.6"}, fresh_config)
    assert p["gluetun_api_key"] == "" and "removed" in w[0]
    p, w = _parse_settings({"gluetun_control_host": "192.168.1.6", "gluetun_api_key": "new"}, fresh_config)
    assert p["gluetun_api_key"] == "new"


def test_wg_profile_keys_validated(fresh_config):
    from airbl.web.routes.api import _parse_settings
    import base64
    good = base64.b64encode(b"\x05" * 32).decode()
    p, w = _parse_settings({"wg_profiles": [{"name": "A", "private_key": good, "public_key": ""}]}, fresh_config)
    assert p["wg_profiles"][0].private_key == good
    for bad in (good[:-1] + "\nPostUp = id", "x", good + "A"):
        p, w = _parse_settings({"wg_profiles": [{"name": "A", "private_key": bad}]}, fresh_config)
        assert "wg_profiles" not in p and "invalid" in w[0]  # whole list rejected, previous kept


def _ui_save(client, **extra):
    """What the Settings page sends: the profiles are always included."""
    from airbl.config import config_manager
    body = {"gluetun_profiles": [p.model_dump(mode="json") for p in config_manager.config.gluetun.profiles]}
    body.update(extra)
    return client.post("/api/settings", json=body)


async def test_ui_saves_push_only_what_changed(client, fresh_config, monkeypatch):
    from airbl.web.routes import api
    pushed, generated = [], []

    async def fake_push(key):
        pushed.append(key)

    async def fake_generate():
        generated.append(1)
    monkeypatch.setattr(gluetun, "push_target", fake_push)
    monkeypatch.setattr(gluetun, "generate_gluetun_servers_json", fake_generate)
    monkeypatch.setattr(state, "is_scanning", False)
    g = fresh_config.gluetun
    g.force_update_enabled, g.force_update_mode = True, "ALWAYS"

    async def drain():
        for t in list(api._background_tasks):
            await t
    assert _ui_save(client, scan_interval_minutes=60).status_code == 200  # unrelated
    await drain()
    assert generated == [] and pushed == []
    assert _ui_save(client, gluetun_secondary={"enabled": True, "control_server_host": "192.0.2.50"}).status_code == 200
    await drain()
    assert generated == [] and pushed == ["secondary"]  # main Gluetun untouched
    assert _ui_save(client, gluetun_force_update_mode="NOT_BEST").status_code == 200
    await drain()
    assert generated == [1]
    monkeypatch.setattr(state, "is_scanning", True)
    assert _ui_save(client, gluetun_force_update_mode="NOT_TOP4").status_code == 200
    await drain()
    assert generated == [1]  # mid-scan: applied when the scan ends


async def test_secondary_stays_on_untested_unknown_current(seed_ctl, fake_server):
    sec, status, calls = seed_ctl
    sec.min_dwell_minutes = 0
    sec.force_update_mode = "NOT_BEST"
    fast = fake_server("Fast", reputation="blocked", speedtest={"deviation_score": 150}, ip="192.0.2.30")
    unk = fake_server("Unk", reputation="unknown", ip="192.0.2.31")  # lookup failed, not re-tested
    status["value"] = {"ip": "192.0.2.31", "error": None}
    r = await gluetun.update_gluetun_server_selection([(fast, []), (unk, [])], target=sec)
    assert r["reason"] == "current server not re-tested yet" and calls["set"] == []
    unk.speedtest_result = {"deviation_score": 90}  # unknown reputation still ranks by speed
    assert [s.server_name for s in gluetun._rank(sec, [(fast, []), (unk, [])])] == ["Fast", "Unk"]
    sec.allow_blocked = False
    sec.rank_by = "score"
    assert gluetun._rank(sec, [(fast, []), (unk, [])]) == []  # clean only


async def test_seedbox_disabled_excluded_with_profile(seed_ctl, mixed, fresh_config):
    sec, _, _ = seed_ctl
    prof = fresh_config.gluetun.profiles[0]
    prof.enabled, prof.min_download_mbps, prof.min_upload_mbps = True, 0, 0
    sec.control_profile = prof.name
    fresh_config.performance.seedbox_disabled_servers = ["B1"]
    for s, _ in mixed:
        s.entry3_ping = s.exit_ping
    names = {s.server_name for s, _ in gluetun._control_candidates(sec, [s for s, _ in mixed])}
    assert "B1" not in names and "B2" in names


def test_carry_over_skips_seedbox_disabled(fake_server, make_summary, fresh_config):
    fresh_config.performance.seedbox_disabled_servers = ["B"]
    old = make_summary([fake_server("B", reputation="blocked", speedtest={"deviation_score": 120}),
                        fake_server("U", reputation="unknown", speedtest={"deviation_score": 90})])
    new = make_summary([fake_server("B", reputation="blocked"), fake_server("U", reputation="unknown")])
    tasks._carry_over_blocked_results(old, new)
    assert new.servers[0].speedtest_result is None and new.servers[1].speedtest_result["stale"]


async def test_dwell_seed_retried_until_companion_answers(seed_ctl, mixed, monkeypatch):
    sec, status, calls = seed_ctl
    sec.min_dwell_minutes = 30
    sec.force_update_mode = "NOT_BEST"
    answers = iter([None, {"last_switch_at": gluetun.time.time() - 60}])

    async def companion(cfg):
        return next(answers)
    monkeypatch.setattr(gluetun, "get_companion_status", companion)
    status["value"] = {"ip": "192.0.2.12", "error": None}
    st = gluetun._ctl_state["secondary"]
    await gluetun._seed_dwell_from_companion(gluetun._view(sec), st)
    assert not st.dwell_seeded and st.last_switch_at is None
    await gluetun._seed_dwell_from_companion(gluetun._view(sec), st)
    assert st.dwell_seeded and st.last_switch_at is not None


async def test_fallback_newest_failed_not_speed_ranked(fresh_config, tmp_path, monkeypatch):
    from airbl.database import DatabaseManager
    db = DatabaseManager(tmp_path / "n.db")
    await db.init()
    sid = await db.add_scan_result({})
    await db.add_server_scan_result(sid, {"server_name": "Hamal", "reputation": "blocked", "is_blocked": True})
    await db.update_scan_result(sid, {})
    await db.add_speedtest_result({"download_mbps": 300.0, "upload_mbps": 150.0, "ping_ms": 9.0,
                                   "vpn_server_name": "Hamal", "timestamp": "2026-11-01T00:00:00"}, scan_id=sid)
    await db.add_speedtest_result({"error": "Failed to connect", "vpn_server_name": "Hamal",
                                   "timestamp": "2026-11-02T00:00:00"}, scan_id=sid)
    monkeypatch.setattr(state, "current_scan", None)
    monkeypatch.setattr(state, "db", db)
    try:
        hamal = (await gluetun._get_servers_for_gluetun_generation())[0]
    finally:
        await db.close()
    assert hamal.speedtest_result["download_mbps"] == 300.0  # the primary's thresholds: unchanged
    assert hamal.speed_score is None  # the speed ranking: newest test failed


def test_status_endpoint_returns_target_name(client, fresh_config, monkeypatch):
    sec = fresh_config.gluetun.secondary
    sec.name = "Mac"
    assert client.get("/api/gluetun/status?target=secondary").json() == {
        "connected": False, "enabled": False, "target": "secondary", "name": "Mac"}
    sec.enabled, sec.control_server_host = True, "192.0.2.50"

    async def fake_status(cfg):
        return {"connected": True, "ip": "198.51.100.5", "server_name": "Hamal", "error": None}

    async def no_companion(cfg):
        return None
    monkeypatch.setattr(gluetun, "get_gluetun_status", fake_status)
    monkeypatch.setattr(gluetun, "get_companion_status", no_companion)
    body = client.get("/api/gluetun/status?target=secondary").json()
    assert body["name"] == "Mac" and body["server_name"] == "Hamal" and body["enabled"]
