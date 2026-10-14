"""Background task logic in airbl.web.tasks (VPN, speedtest and scanner fully mocked)."""

import asyncio
from datetime import datetime, timedelta
from types import SimpleNamespace as NS

import pytest

import airbl.scanner as scanner_mod
import airbl.speedtest as speedtest_mod
from airbl.config import config_manager
from airbl.database import DatabaseManager
from airbl.scanner import ScanSummary, ScanUpdate
from airbl.speedtest import SpeedTestResult
from airbl.web import tasks
from airbl.web.state import state

_real_sleep = asyncio.sleep


@pytest.fixture(autouse=True)
def fresh_lock(monkeypatch):
    # A module-level asyncio.Lock binds to the first loop that contends it; each test has its own loop
    monkeypatch.setattr(tasks, "_network_lock", asyncio.Lock())
    monkeypatch.setattr(tasks, "_network_owner", None)


@pytest.fixture
def fast_sleep(monkeypatch):
    slept = []

    async def fake(t, *a, **k):
        slept.append(t)
        await _real_sleep(0)

    monkeypatch.setattr(asyncio, "sleep", fake)
    return slept


# --- network_job lock ------------------------------------------------------------

async def test_network_job_serializes_and_broadcasts_waiting(broadcasts):
    order = []
    a_in = asyncio.Event()
    release_a = asyncio.Event()

    async def job_a():
        async with tasks.network_job("scan"):
            order.append("a-start")
            assert tasks.network_owner() == "scan"
            a_in.set()
            await release_a.wait()
            order.append("a-end")

    async def job_b():
        await a_in.wait()
        async with tasks.network_job("speedtest X"):
            order.append("b-start")
            assert tasks.network_owner() == "speedtest X"

    ta, tb = asyncio.create_task(job_a()), asyncio.create_task(job_b())
    await a_in.wait()
    for _ in range(5):
        await _real_sleep(0)
    assert order == ["a-start"]  # b is blocked
    release_a.set()
    await asyncio.wait_for(asyncio.gather(ta, tb), 2)
    assert order == ["a-start", "a-end", "b-start"]
    assert broadcasts.of("network_job_waiting") == [{"job": "speedtest X", "owner": "scan"}]
    assert tasks.network_owner() is None


async def test_network_job_releases_on_error():
    with pytest.raises(RuntimeError):
        async with tasks.network_job("x"):
            raise RuntimeError("boom")
    assert tasks.network_owner() is None and not tasks._network_lock.locked()


async def test_nested_baseline_inside_scan_lock_no_deadlock(monkeypatch, broadcasts):
    async def fake_run_speedtest(timeout=120):
        return SpeedTestResult(download_mbps=800, upload_mbps=700, ping_ms=5, server_name="Ookla")

    monkeypatch.setattr(speedtest_mod, "run_speedtest", fake_run_speedtest)

    async def scan_like():
        async with tasks.network_job("scan"):
            await tasks._run_baseline_speedtest()

    await asyncio.wait_for(scan_like(), 2)
    assert state.baseline_speedtest["download_mbps"] == 800
    assert "baseline_speedtest_complete" in broadcasts.types()


async def test_baseline_retries_once(monkeypatch, fast_sleep, broadcasts):
    results = [SpeedTestResult(download_mbps=0, upload_mbps=0, ping_ms=0, error="licence"),
               SpeedTestResult(download_mbps=500, upload_mbps=400, ping_ms=7)]

    async def fake_run_speedtest(timeout=120):
        return results.pop(0)

    monkeypatch.setattr(speedtest_mod, "run_speedtest", fake_run_speedtest)
    await tasks.run_baseline_speedtest()
    assert results == []
    assert state.baseline_speedtest["upload_mbps"] == 400


async def test_baseline_both_fail_reports_error(monkeypatch, fast_sleep, broadcasts):
    async def fake_run_speedtest(timeout=120):
        return SpeedTestResult(download_mbps=0, upload_mbps=0, ping_ms=0, error="down")

    monkeypatch.setattr(speedtest_mod, "run_speedtest", fake_run_speedtest)
    await tasks.run_baseline_speedtest()
    assert state.baseline_speedtest is None
    assert broadcasts.of("baseline_speedtest_error") == [{"error": "down"}]


# --- small helpers ---------------------------------------------------------------

def _res(dl=100.0, ul=50.0, ping=10.0, ext="203.0.113.9", error=None, **kw):
    return SpeedTestResult(download_mbps=dl, upload_mbps=ul, ping_ms=ping, external_ip=ext, error=error, **kw)


def test_reject_if_not_via_vpn():
    leaked = tasks._reject_if_not_via_vpn(_res(ext="198.51.100.1"), "203.0.113.9")
    assert not leaked.is_success and "outside the VPN" in leaked.error
    ok = tasks._reject_if_not_via_vpn(_res(), "203.0.113.9")
    assert ok.is_success and ok.error is None
    # Unknown egress or unknown Ookla IP: can't judge, keep
    assert tasks._reject_if_not_via_vpn(_res(ext="198.51.100.1"), None).is_success
    assert tasks._reject_if_not_via_vpn(_res(ext=None), "203.0.113.9").is_success
    # An already failed result keeps its own error
    failed = tasks._reject_if_not_via_vpn(_res(ext="198.51.100.1", error="timeout"), "203.0.113.9")
    assert failed.error == "timeout"


def test_average_speedtest_results():
    t = datetime(2026, 10, 4, 12, 0)
    rs = [_res(100, 10, 20, server_location="Bern", server_country="Switzerland", server_name="A"),
          _res(200, 30, 40, server_location="Zurich", server_country="Switzerland", server_name="B",
               server_id=7, client_ip="10.0.0.2", tested_at=t)]
    avg = tasks._average_speedtest_results(rs, "Toliman")
    assert (avg.download_mbps, avg.upload_mbps, avg.ping_ms) == (150, 20, 30)
    assert avg.server_location == "Zurich" and avg.server_country == "Switzerland"
    assert avg.external_ip == "203.0.113.9" and avg.server_name == "B" and avg.server_id == 7
    assert avg.client_ip == "10.0.0.2" and avg.tested_at == t
    assert avg.is_success


def test_average_speedtest_results_empty():
    avg = tasks._average_speedtest_results([], "Toliman")
    assert not avg.is_success and avg.error
    assert avg.server_name == "Toliman"


async def test_check_and_disable_underperforming(fresh_config, broadcasts):
    fresh_config.performance.check_count = 3
    state.server_performance_history = {}
    bad = SpeedTestResult(download_mbps=5, upload_mbps=50, ping_ms=10).to_dict()
    assert "error" in bad and bad["error"] is None  # to_dict always has the key
    for i in range(2):
        await tasks._check_and_disable_underperforming_server("Toliman", bad)
    assert len(state.server_performance_history["Toliman"]) == 2
    assert config_manager.config.performance.disabled_servers == []
    await tasks._check_and_disable_underperforming_server("Toliman", bad)
    assert config_manager.config.performance.disabled_servers == ["Toliman"]
    assert "Toliman" in config_manager.config.performance.history
    assert broadcasts.of("server_disabled") == [{"server": "Toliman", "reason": "underperformance"}]


async def test_check_underperforming_ignores_failures_and_good_runs(fresh_config):
    fresh_config.performance.check_count = 2
    state.server_performance_history = {}
    await tasks._check_and_disable_underperforming_server("Ran", {"error": "timeout", "download_mbps": 0})
    await tasks._check_and_disable_underperforming_server("Ran", None)
    assert "Ran" not in state.server_performance_history
    good = SpeedTestResult(download_mbps=500, upload_mbps=100, ping_ms=10).to_dict()
    bad = SpeedTestResult(download_mbps=500, upload_mbps=1, ping_ms=10).to_dict()  # upload below
    for r in (bad, good, bad):
        await tasks._check_and_disable_underperforming_server("Ran", r)
    assert config_manager.config.performance.disabled_servers == []
    await tasks._check_and_disable_underperforming_server("Ran", bad)
    assert config_manager.config.performance.disabled_servers == ["Ran"]
    # History capped at check_count * 2
    assert len(state.server_performance_history["Ran"]) == 4


# --- calculate_next_scan_time ----------------------------------------------------------

def test_next_scan_interval(fresh_config):
    fresh_config.scan.scan_mode = "interval"
    fresh_config.scan.scan_interval_minutes = 90
    last = datetime(2026, 10, 4, 10, 0)
    assert tasks.calculate_next_scan_time(fresh_config.scan, last) == last + timedelta(minutes=90)
    before = datetime.now()
    nxt = tasks.calculate_next_scan_time(fresh_config.scan)
    assert before + timedelta(minutes=90) <= nxt <= datetime.now() + timedelta(minutes=90)


@pytest.mark.parametrize("days,weekdays", [(["Wed"], {2}), (["Sat", "Sun"], {5, 6}), ([], set(range(7)))])
def test_next_scan_schedule(fresh_config, days, weekdays):
    fresh_config.scan.scan_mode = "schedule"
    fresh_config.scan.scan_schedule_time = "06:30"
    fresh_config.scan.scan_schedule_days = days
    now = datetime.now()
    nxt = tasks.calculate_next_scan_time(fresh_config.scan)
    assert nxt > now and nxt - now <= timedelta(days=7)
    assert (nxt.hour, nxt.minute, nxt.second) == (6, 30, 0)
    assert nxt.weekday() in weekdays


@pytest.mark.parametrize("bad", ["25:99", "noon", "", "7"])
def test_next_scan_invalid_time_falls_back(fresh_config, bad):
    fresh_config.scan.scan_mode = "schedule"
    fresh_config.scan.scan_schedule_time = bad
    fresh_config.scan.scan_schedule_days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
    nxt = tasks.calculate_next_scan_time(fresh_config.scan)
    assert (nxt.hour, nxt.minute) == (20, 0)
    assert nxt > datetime.now()


# --- run_speedtest_task ---------------------------------------------------------------------

class _Ctrl:
    def __init__(self):
        self.disconnects = 0

    async def connect(self, path):
        return NS(success=True, public_ip="203.0.113.9", error=None)

    async def disconnect(self, *a):
        self.disconnects += 1


@pytest.mark.parametrize("outcome", ["ok", "error", "raise"])
async def test_run_speedtest_task_always_reports_done(monkeypatch, fake_server, broadcasts, outcome, fresh_config):
    server = fake_server("Toliman")

    async def fake_single(srv, *a, **k):
        if outcome == "raise":
            raise RuntimeError("crash")
        if outcome == "error":
            return "Failed to connect: no handshake"
        srv.speedtest_result = {"download_mbps": 321.0, "upload_mbps": 99.0, "ping_ms": 12.0}
        return None

    async def no_override(srv):
        return None

    monkeypatch.setattr(tasks, "_run_single_server_speedtest", fake_single)
    monkeypatch.setattr(tasks, "_resolve_server_config", no_override)
    state.scan_progress = {"phase": "idle", "current": 0, "total": 0, "server": "", "country": "", "next": ""}
    ctrl = _Ctrl()
    if outcome == "raise":
        with pytest.raises(RuntimeError):
            await tasks.run_speedtest_task(server, controller=ctrl)
    else:
        await tasks.run_speedtest_task(server, controller=ctrl)
    (done,) = broadcasts.of("speedtest_manual_done")
    assert done["server"] == "Toliman"
    if outcome == "ok":
        assert done["ok"] is True and done["error"] is None and done["download_mbps"] == 321.0
    elif outcome == "error":
        assert done["ok"] is False and "handshake" in done["error"] and done["download_mbps"] is None
    else:
        assert done["ok"] is False and "crashed" in done["error"]
    assert state.scan_progress["phase"] == "idle"
    assert tasks.network_owner() is None


async def test_run_single_server_speedtest_end_to_end(monkeypatch, fake_server, fresh_config, fast_sleep,
                                                       broadcasts, make_summary, tmp_path):
    """Real _run_single_server_speedtest with a fake controller and fake Ookla: one leaked run excluded."""
    fresh_config.scan.speedtest_test_count = 3
    conf = tmp_path / "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf"
    conf.write_text("")
    server = fake_server("Toliman", config_file=conf)
    state.current_scan = make_summary([server])
    state.baseline_speedtest = {"download_mbps": 400.0, "upload_mbps": 100.0}
    state.server_performance_history = {}
    runs = [_res(200, 50), _res(900, 900, ext="198.51.100.1"), _res(300, 70)]

    async def fake_ookla(cc, secure=True):
        return runs.pop(0)

    async def no_override(srv):
        return None

    monkeypatch.setattr(tasks, "run_speedtest_for_country", fake_ookla)
    monkeypatch.setattr(tasks, "_resolve_server_config", no_override)
    ctrl = _Ctrl()
    await tasks.run_speedtest_task(server, controller=ctrl)
    st = server.speedtest_result
    assert st["download_mbps"] == 250 and st["upload_mbps"] == 60
    assert st["vpn_port"] == 1637 and st["vpn_entry"] == "Entry 3"
    # 0.4 * 62.5% + 0.6 * 60%
    assert st["deviation_score"] == pytest.approx(61.0)
    assert broadcasts.of("speedtest_manual_done")[0]["ok"] is True
    assert ctrl.disconnects >= 1


# --- run_scan_task ------------------------------------------------------------------------

def _fake_scanner_cls(updates_factory, created):
    class FakeScanner:
        def __init__(self, **kw):
            created.append(kw)

        async def scan_iter(self):
            for u in updates_factory():
                yield u
    return FakeScanner


def _updates(servers, cancel_after=None):
    def factory():
        summary = ScanSummary(countries_scanned=["CH"])
        for i, s in enumerate(servers, 1):
            summary.servers.append(s)
            yield ScanUpdate(summary=summary, server=s, total_expected=len(servers))
            if cancel_after is not None and i >= cancel_after:
                state.scan_cancelled = True
    return factory


@pytest.fixture
async def temp_db(tmp_path):
    db = DatabaseManager(tmp_path / "scan.db")
    await db.init()
    yield db
    await db.close()


@pytest.fixture
def gen_calls(monkeypatch):
    calls = []

    async def fake_gluetun():
        calls.append("gluetun")

    async def fake_wg():
        calls.append("wg")

    import airbl.wireguard_gen as wg_gen
    monkeypatch.setattr(tasks, "generate_gluetun_servers_json", fake_gluetun)
    monkeypatch.setattr(wg_gen, "generate_wireguard_configs", fake_wg)
    return calls


async def test_scan_without_speedtests_still_generates_outputs(monkeypatch, fake_server, fresh_config,
                                                              broadcasts, temp_db, gen_calls):
    fresh_config.scan.speedtest_enabled = False
    fresh_config.regions.excluded_countries = ["SE"]
    fresh_config.performance.disabled_servers = ["Bad"]
    servers = [fake_server("Toliman"), fake_server("Ran", "blocked"), fake_server("Hamal", "unknown")]
    created = []
    monkeypatch.setattr(tasks, "EnhancedScanner", _fake_scanner_cls(_updates(servers), created))

    async def must_not_run(*a, **k):
        raise AssertionError("speedtests disabled")

    monkeypatch.setattr(tasks, "_run_batch_speedtests", must_not_run)
    monkeypatch.setattr(tasks, "_run_baseline_speedtest", must_not_run)
    state.db = temp_db
    state.ban_history = {}
    state.scan_history = []

    await asyncio.wait_for(tasks.run_scan_task(), 5)

    assert created[0]["country_exclude"] == {"SE"} and created[0]["server_exclude"] == {"Bad"}
    assert gen_calls == ["gluetun", "wg"]
    assert state.current_scan is not None and state.current_scan.total_servers == 3
    assert state.live_scan is None and state.is_scanning is False
    assert state.ban_history == {"Ran": 1}
    assert "scan_complete" in broadcasts.types()
    last = await temp_db.get_last_complete_scan()
    assert last["total_servers"] == 3 and last["clean_servers"] == 1 and last["blocked_servers"] == 1
    rows = await temp_db.get_last_scan_servers()
    assert {r["server_name"]: r["reputation"] for r in rows} == {"Toliman": "clean", "Ran": "blocked",
                                                                 "Hamal": "unknown"}
    assert state.scan_progress["phase"] == "idle" and state.next_scan_at > datetime.now()


async def test_scan_with_speedtests_runs_baseline_inside_lock(monkeypatch, fake_server, fresh_config,
                                                             gen_calls, broadcasts):
    fresh_config.scan.speedtest_enabled = True
    servers = [fake_server("Toliman")]
    monkeypatch.setattr(tasks, "EnhancedScanner", _fake_scanner_cls(_updates(servers), []))
    order = []

    async def fake_run_speedtest(timeout=120):
        order.append(("baseline", tasks.network_owner()))
        return SpeedTestResult(download_mbps=800, upload_mbps=700, ping_ms=5)

    async def fake_batch():
        order.append(("batch", tasks.network_owner()))

    monkeypatch.setattr(speedtest_mod, "run_speedtest", fake_run_speedtest)
    monkeypatch.setattr(tasks, "_run_batch_speedtests", fake_batch)
    await asyncio.wait_for(tasks.run_scan_task(), 5)  # would hang on a re-entrant lock
    assert order == [("baseline", "scan"), ("batch", "scan")]
    assert gen_calls == ["gluetun", "wg"]
    assert state.baseline_speedtest["download_mbps"] == 800


async def test_scan_cancel_keeps_previous_results(monkeypatch, fake_server, fresh_config, make_summary,
                                                  temp_db, gen_calls, broadcasts):
    previous = make_summary([fake_server("Old")])
    state.current_scan = previous
    state.db = temp_db
    servers = [fake_server("Toliman"), fake_server("Ran"), fake_server("Hamal")]
    monkeypatch.setattr(tasks, "EnhancedScanner", _fake_scanner_cls(_updates(servers, cancel_after=1), []))
    await asyncio.wait_for(tasks.run_scan_task(), 5)
    assert state.current_scan is previous
    assert state.live_scan is None and state.is_scanning is False and state.scan_cancelled is False
    assert gen_calls == []
    assert "scan_complete" not in broadcasts.types()
    assert await temp_db.get_last_complete_scan() is None
    async with temp_db._conn.execute("SELECT status FROM scan_history") as cur:
        assert [r["status"] for r in await cur.fetchall()] == ["cancelled"]


async def test_scan_with_no_results_marked_failed(monkeypatch, fresh_config, temp_db, gen_calls, make_summary,
                                                  fake_server):
    previous = make_summary([fake_server("Old")])
    state.current_scan = previous
    state.db = temp_db
    monkeypatch.setattr(tasks, "EnhancedScanner", _fake_scanner_cls(lambda: iter(()), []))
    await asyncio.wait_for(tasks.run_scan_task(), 5)
    assert state.current_scan is previous and gen_calls == []
    async with temp_db._conn.execute("SELECT status FROM scan_history") as cur:
        assert [r["status"] for r in await cur.fetchall()] == ["failed"]


async def test_scan_task_cancelled_externally(monkeypatch, fresh_config, fake_server, make_summary, broadcasts,
                                              gen_calls):
    previous = make_summary([fake_server("Old")])
    state.current_scan = previous
    started = asyncio.Event()

    class SlowScanner:
        def __init__(self, **kw):
            pass

        async def scan_iter(self):
            summary = ScanSummary()
            summary.servers.append(fake_server("Toliman"))
            yield ScanUpdate(summary=summary, server=summary.servers[0])
            started.set()
            await asyncio.Event().wait()  # hang until cancelled
            yield  # pragma: no cover

    monkeypatch.setattr(tasks, "EnhancedScanner", SlowScanner)
    state.is_scanning = True
    task = asyncio.create_task(tasks.run_scan_task())
    state.scan_task = task
    await asyncio.wait_for(started.wait(), 2)
    task.cancel()
    await asyncio.wait_for(asyncio.gather(task, return_exceptions=True), 2)
    assert state.current_scan is previous
    assert "scan_cancelled" in broadcasts.types()
    assert state.is_scanning is False and state.scan_task is None
    assert tasks.network_owner() is None


async def test_scan_with_only_region_config_reports_error(monkeypatch, fresh_config, tmp_path, temp_db,
                                                          gen_calls, broadcasts, make_summary, fake_server):
    """Region config without keys: error toast naming the file, not an empty 'complete' scan."""
    (tmp_path / "AirVPN_Europe_UDP-1637-Entry3.conf").write_text(
        "[Peer]\nEndpoint = europe3.vpn.airdns.org:1637\n")
    previous = make_summary([fake_server("Old")])
    state.current_scan = previous
    state.db = temp_db
    monkeypatch.setattr(state, "config_dir", tmp_path)

    async def no_api():
        raise RuntimeError("network disabled in tests")

    monkeypatch.setattr(scanner_mod, "get_airvpn_status", no_api)
    await asyncio.wait_for(tasks.run_scan_task(), 5)
    errors = broadcasts.of("scan_error")
    assert errors and "AirVPN_Europe_UDP-1637-Entry3.conf" in errors[0]["error"]
    assert "scan_complete" not in broadcasts.types()
    assert state.current_scan is previous and state.is_scanning is False
    assert gen_calls == []
    async with temp_db._conn.execute("SELECT status FROM scan_history") as cur:
        assert [r["status"] for r in await cur.fetchall()] == ["failed"]
