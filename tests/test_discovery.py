"""Port/entry discovery with a fake WireGuard controller and fake Ookla speedtests."""

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace as NS

import pytest

import airbl.confgen as confgen
from airbl.config import config_manager
from airbl.pinger import PingResult
from airbl.speedtest import SpeedTestResult
from airbl.web import tasks
from airbl.web.state import state

_real_sleep = asyncio.sleep
EXIT = "203.0.113.9"


@pytest.fixture(autouse=True)
def setup(monkeypatch, fresh_config):
    async def fast(t, *a, **k):
        await _real_sleep(0)

    async def no_wait(*a, **k):
        pass

    monkeypatch.setattr(asyncio, "sleep", fast)
    monkeypatch.setattr(tasks, "_smart_wait", no_wait)
    monkeypatch.setattr(tasks, "DISCOVERY_STABILIZE", 0)
    monkeypatch.setattr(tasks, "_network_lock", asyncio.Lock())
    monkeypatch.setattr(confgen, "get_client_identity",
                        lambda: confgen.ClientIdentity(private_key="A" * 43 + "=", address="10.128.0.2/32"))
    cfg = fresh_config.scan
    cfg.post_server_wait = 0
    cfg.discovery_test_count = 3
    cfg.discovery_duration_days = 3
    cfg.preferred_entry_ip = "ENTRY3"
    return fresh_config


class Ctrl:
    """51820/Entry1 never connects; everything else connects with exit IP EXIT."""

    def __init__(self):
        self.connects = []
        self.current = None

    async def connect(self, path):
        self.connects.append(path.name)
        self.current = path.name
        if "51820-E1" in path.name:
            return NS(success=False, error="no handshake", public_ip=None)
        return NS(success=True, public_ip=EXIT, error=None)

    async def disconnect(self, *a):
        self.current = None


class Ookla:
    """Deterministic speeds per combo; 1637 test #2 fails, 51820/E3 test #3 leaks outside the VPN."""

    def __init__(self, ctrl):
        self.ctrl = ctrl
        self.calls = 0
        self.per_connect = {}

    async def __call__(self, cc, secure=True):
        self.calls += 1
        name = self.ctrl.current
        n = self.per_connect[name] = self.per_connect.get(name, 0) + 1
        n = (n - 1) % 3 + 1
        dl = 400.0 if "-47107-" in name else 300.0 if "-1637-" in name else 200.0
        ping = 30.0 if "-E3" in name else 45.0
        if "-1637-" in name and n == 2:
            return SpeedTestResult(download_mbps=0, upload_mbps=0, ping_ms=0, error="Speedtest timed out")
        if "-51820-E3" in name and n == 3:
            return SpeedTestResult(download_mbps=900, upload_mbps=900, ping_ms=2, external_ip="198.51.100.1")
        return SpeedTestResult(download_mbps=dl, upload_mbps=dl / 5, ping_ms=ping, external_ip=EXIT)


def srv(fake_server, name, latency):
    s = fake_server(name, latency_ms=latency, wg_pubkey="S" * 43 + "=")
    s.entry1_ping = PingResult(ip="192.0.2.1", is_alive=True, avg_rtt_ms=20)
    s.entry3_ping = PingResult(ip="192.0.2.3", is_alive=True, avg_rtt_ms=20)
    return s


@pytest.fixture
def servers(fake_server):
    # Score order (lower latency = higher score): Toliman > Achernar > Hamal > Extra
    return [srv(fake_server, "Toliman", 10), srv(fake_server, "Achernar", 40),
            srv(fake_server, "Hamal", 80), srv(fake_server, "Extra", 150)]


@pytest.fixture
def rig(monkeypatch):
    ctrl = Ctrl()
    ookla = Ookla(ctrl)
    monkeypatch.setattr(tasks, "run_speedtest_for_country", ookla)
    return ctrl, ookla


async def _run_scans(servers, ctrl, n):
    tasks.reset_discovery(start=True)
    for _ in range(n):
        await tasks._run_discovery_phase(servers, ctrl)


async def test_discovery_four_scans(servers, rig, broadcasts):
    ctrl, ookla = rig
    cfg = config_manager.config.scan
    await _run_scans(servers, ctrl, 4)
    res = state.port_discovery_results
    assert sorted(res) == ["1637_E1", "1637_E3", "47107_E1", "47107_E3", "51820_E1", "51820_E3"]

    # Rotation through the top 3 by score; the 4th server is never used
    used = [h["server"] for h in res["47107_E3"]["history"][::3]]
    assert used == ["Toliman", "Achernar", "Hamal", "Toliman"]
    assert cfg.discovery_scan_count == 4

    # Failing combo: one failed attempt per scan (connect + one retry), never N tests
    fail = res["51820_E1"]
    assert fail["tests"] == 4 and fail["success_tests"] == 0 and fail["download_mbps"] == 0.0
    assert all("Connect failed" in h["error"] for h in fail["history"])
    assert len(ctrl.connects) == 4 * (5 + 2)
    assert ookla.calls == 4 * 5 * 3

    # Success-only averages: failed (0) and leaked (900) runs excluded
    assert res["1637_E3"]["tests"] == 12 and res["1637_E3"]["success_tests"] == 8
    assert res["1637_E3"]["download_mbps"] == 300.0 and res["1637_E3"]["success_rate"] == 0.67
    assert res["51820_E3"]["success_tests"] == 8 and res["51820_E3"]["download_mbps"] == 200.0
    assert any("outside the VPN" in h.get("error", "") for h in res["51820_E3"]["history"])
    for k in ("47107_E1", "47107_E3"):
        assert res[k]["success_tests"] == 12 and res[k]["download_mbps"] == 400.0
    assert res["47107_E3"]["ping_ms"] == 30.0 and res["47107_E1"]["ping_ms"] == 45.0

    # Relative scores: only combos with successes, best = 47107/E3
    assert "relative_score" not in res["51820_E1"]
    best = max((k for k in res if "relative_score" in res[k]), key=lambda k: res[k]["relative_score"])
    assert best == "47107_E3"
    assert res["47107_E3"]["rel_n"] == 4

    # Persisted copy is independent of the live dict
    assert cfg.discovery_results == res and cfg.discovery_results is not res
    assert {"discovery_started", "discovery_combo_complete", "discovery_scan_complete"} <= set(broadcasts.types())

    # Period expired -> next scan finalizes instead of testing
    cfg.discovery_started_at = (datetime.now(timezone.utc) - timedelta(days=4)).isoformat()
    calls_before = ookla.calls
    await tasks._run_discovery_phase(servers, ctrl)
    assert ookla.calls == calls_before
    assert cfg.discovery_outcome == "47107/ENTRY3"
    assert (cfg.preferred_port, cfg.preferred_entry_ip) == (47107, "ENTRY3")
    assert (cfg.discovery_auto_port, cfg.discovery_auto_entry) == (47107, "ENTRY3")
    assert cfg.port_discovery_enabled is False
    assert cfg.discovery_started_at is None and cfg.discovery_finished_at
    assert "discovery_finalized" in broadcasts.types()


async def test_history_capped(servers, rig):
    ctrl, _ = rig
    config_manager.config.scan.discovery_test_count = 10
    await _run_scans(servers, ctrl, 4)
    r = state.port_discovery_results["47107_E3"]
    assert r["tests"] == 40 and len(r["history"]) == tasks.DISCOVERY_HISTORY_CAP


async def test_entry_filter(servers, rig):
    ctrl, _ = rig
    config_manager.config.scan.discovery_entry_filter = "ENTRY1"
    await _run_scans(servers, ctrl, 1)
    assert sorted(state.port_discovery_results) == ["1637_E1", "47107_E1", "51820_E1"]


async def test_disabled_discovery_does_nothing(servers, rig):
    ctrl, ookla = rig
    config_manager.config.scan.port_discovery_enabled = False
    await tasks._run_discovery_phase(servers, ctrl)
    assert ctrl.connects == [] and state.port_discovery_results == {}


async def test_missing_start_time_starts_period(servers, rig):
    ctrl, _ = rig
    cfg = config_manager.config.scan
    cfg.port_discovery_enabled = True
    cfg.discovery_started_at = None
    await tasks._run_discovery_phase(servers, ctrl)
    assert cfg.discovery_started_at is not None
    assert len(state.port_discovery_results) == 6


async def test_no_identity_aborts(servers, rig, monkeypatch):
    ctrl, _ = rig

    def no_keys():
        raise ValueError("No WireGuard keys available")

    monkeypatch.setattr(confgen, "get_client_identity", no_keys)
    await _run_scans(servers, ctrl, 1)
    assert ctrl.connects == []


async def test_cancel_stops_discovery(servers, rig):
    ctrl, ookla = rig
    tasks.reset_discovery(start=True)
    state.scan_cancelled = True
    await tasks._run_discovery_phase(servers, ctrl)
    assert ctrl.connects == [] and ookla.calls == 0


async def test_generated_configs_use_tmp_confgen_dir(servers, rig, tmp_path):
    ctrl, _ = rig
    await _run_scans(servers, ctrl, 1)
    out = sorted(p.name for p in (tmp_path / "confgen").glob("*.conf"))
    assert len(out) == 6 and all(n.startswith("CH-Zurich_Toliman-") for n in out)
    text = (tmp_path / "confgen" / "CH-Zurich_Toliman-47107-E3.conf").read_text()
    assert "Endpoint = 192.0.2.3:47107" in text and "MTU = 1320" in text


# --- finalize ----------------------------------------------------------------------------

def _rec(port, entry, ok, tests, dl=300.0, rel=None):
    r = {"port": port, "entry": entry, "tests": tests, "success_tests": ok,
         "dl_sum": dl * ok, "ul_sum": dl / 5 * ok, "ping_sum": 30.0 * ok}
    if rel is not None:
        r.update(rel_dl_sum=rel, rel_ul_sum=rel, rel_ping_sum=rel, rel_n=1)
    return r


async def test_finalize_keeps_auto_entry():
    cfg = config_manager.config.scan
    tasks.reset_discovery(start=True)
    state.port_discovery_results = {"47107_E1": _rec(47107, 1, 5, 5, rel=1.2),
                                    "1637_E3": _rec(1637, 3, 5, 5, rel=0.8)}
    cfg.preferred_entry_ip = "AUTO"
    await tasks._finalize_discovery()
    assert cfg.preferred_port == 47107 and cfg.preferred_entry_ip == "AUTO"
    assert cfg.discovery_auto_entry == "ENTRY1" and cfg.discovery_outcome == "47107/ENTRY1"


async def test_finalize_weighs_success_rate():
    cfg = config_manager.config.scan
    tasks.reset_discovery(start=True)
    state.port_discovery_results = {"47107_E3": _rec(47107, 3, 3, 12, rel=1.2),   # 1.2 * 0.25
                                    "1637_E3": _rec(1637, 3, 10, 10, rel=0.9)}    # 0.9 * 1.0
    await tasks._finalize_discovery()
    assert cfg.discovery_outcome == "1637/ENTRY3"


async def test_finalize_inconclusive_keeps_settings():
    cfg = config_manager.config.scan
    tasks.reset_discovery(start=True)
    cfg.preferred_port, cfg.preferred_entry_ip = 51820, "ENTRY1"
    state.port_discovery_results = {"1637_E3": _rec(1637, 3, 2, 4)}  # below DISCOVERY_MIN_SUCCESS
    await tasks._finalize_discovery()
    assert (cfg.preferred_port, cfg.preferred_entry_ip) == (51820, "ENTRY1")
    assert cfg.discovery_outcome.startswith("inconclusive")
    assert cfg.discovery_auto_port is None and cfg.discovery_auto_entry is None
    assert cfg.port_discovery_enabled is False and cfg.discovery_started_at is None
    assert cfg.discovery_finished_at


async def test_finalize_ignores_combos_outside_current_filter():
    cfg = config_manager.config.scan
    tasks.reset_discovery(start=True)
    cfg.available_ports = [1637, 51820]
    cfg.discovery_entry_filter = "ENTRY3"
    state.port_discovery_results = {"47107_E3": _rec(47107, 3, 9, 9, rel=2.0),   # port no longer offered
                                    "1637_E1": _rec(1637, 1, 9, 9, rel=1.5),     # entry filtered out
                                    "51820_E3": _rec(51820, 3, 9, 9, rel=1.0)}
    await tasks._finalize_discovery()
    assert cfg.discovery_outcome == "51820/ENTRY3"


def test_legacy_record_conversion():
    legacy = {"port": 47107, "entry": 3, "download_mbps": 150.0, "upload_mbps": 30.0, "ping_ms": 15.0,
              "tests": 4, "success_tests": 2}
    r = tasks._combo_record(legacy, 47107, 3)
    tasks._refresh_combo_stats(r)
    # Old averages counted failures as 0: sum over 4 tests == sum over the 2 successes
    assert (r["download_mbps"], r["upload_mbps"], r["ping_ms"]) == (300.0, 60.0, 30.0)
    assert r["success_rate"] == 0.5 and r["history"] == []
    assert legacy.get("dl_sum") is None  # input not mutated


def test_reset_discovery():
    cfg = config_manager.config.scan
    cfg.discovery_results = {"x": {}}
    cfg.discovery_scan_count = 3
    state.port_discovery_results = {"x": {}}
    tasks.reset_discovery(start=False)
    assert cfg.discovery_started_at is None and cfg.discovery_results == {} and cfg.discovery_scan_count == 0
    assert state.port_discovery_results == {}
    tasks.reset_discovery(start=True)
    started = tasks._parse_ts(cfg.discovery_started_at)
    assert started.tzinfo is not None and cfg.port_discovery_enabled is True


def test_parse_ts_naive_is_local():
    aware = tasks._parse_ts("2026-10-04T12:00:00")
    assert aware.tzinfo is not None


# --- _resolve_server_config -----------------------------------------------------------------

async def test_resolve_entry_fallback_keeps_port(servers):
    cfg = config_manager.config.scan
    cfg.preferred_port, cfg.preferred_entry_ip = 47107, "ENTRY1"
    s = servers[0]
    s.entry1_ping.is_alive = False
    p = await tasks._resolve_server_config(s)
    assert p.name == "CH-Zurich_Toliman-47107-E3.conf"
    assert "Endpoint = 192.0.2.3:47107" in p.read_text()


async def test_resolve_none_when_both_entries_dead(servers):
    s = servers[0]
    s.entry1_ping.is_alive = False
    s.entry3_ping = None
    assert await tasks._resolve_server_config(s) is None


async def test_resolve_none_when_config_already_matches(servers, tmp_path):
    s = servers[0]
    s.config_file = tmp_path / "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf"
    assert await tasks._resolve_server_config(s) is None  # default 1637/ENTRY3


async def test_resolve_none_without_pubkey(servers):
    config_manager.config.scan.preferred_port = 51820
    s = servers[0]
    s.wg_pubkey = ""
    assert await tasks._resolve_server_config(s) is None


async def test_resolve_auto_uses_db_best_entry(servers):
    config_manager.config.scan.preferred_entry_ip = "AUTO"

    class DB:
        async def get_best_entry_for_server(self, name):
            return "ENTRY1"

    state.db = DB()
    p = await tasks._resolve_server_config(servers[0])
    assert p.name == "CH-Zurich_Toliman-1637-E1.conf"


# --- pause -----------------------------------------------------------------------------------

async def test_pause_holds_discovery(servers, rig):
    ctrl, ookla = rig
    tasks.reset_discovery(start=True)
    state.is_paused = True
    t = asyncio.create_task(tasks._run_discovery_phase(servers, ctrl))
    for _ in range(30):
        await _real_sleep(0.001)
    assert ookla.calls == 0 and ctrl.connects == [] and not t.done()
    state.is_paused = False
    await asyncio.wait_for(t, 5)
    assert ookla.calls == 15
