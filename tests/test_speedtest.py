"""Ookla speedtest wrapper: error extraction, country mapping, retries, blacklisting."""

import json

import pytest

from airbl import speedtest as st
from airbl.speedtest import (
    SpeedTestResult,
    _get_country_code_from_name,
    _ookla_error,
    list_speedtest_servers,
    run_speedtest,
    run_speedtest_for_country,
)

BANNER = (b"==============================================================================\n\n"
          b"You may only use this Speedtest software and information generated\nfrom it for personal, "
          b"non-commercial use...\n\nLicense acceptance recorded. Continuing.\n\n")


def _log(msg, level="error"):
    return json.dumps({"type": "log", "timestamp": "2026-10-04T00:00:00Z", "message": msg, "level": level}).encode()


# --- _ookla_error ------------------------------------------------------------------

def test_ookla_error_prefers_json_log_on_stdout():
    out = _log("Configuration - Couldn't resolve host name (HostNotFoundException)") + b"\n" + \
        _log("Cannot retrieve configuration document (0)") + b"\nnot json\n"
    msg = _ookla_error(out, BANNER)
    assert msg == "Configuration - Couldn't resolve host name (HostNotFoundException); " \
                  "Cannot retrieve configuration document (0)"


def test_ookla_error_banner_only():
    assert _ookla_error(b"", BANNER) == "Speedtest failed (no error output)"


def test_ookla_error_banner_then_real_error():
    assert _ookla_error(b"", BANNER + b"[error] No servers defined (NoServersException)\n") == \
        "[error] No servers defined (NoServersException)"


def test_ookla_error_plain_stderr():
    assert _ookla_error(None, b"[error] Cannot open socket: Timeout occurred in connect.\n") == \
        "[error] Cannot open socket: Timeout occurred in connect."


def test_ookla_error_ignores_non_log_json():
    out = json.dumps({"type": "result", "message": "x"}).encode()
    assert _ookla_error(out, b"boom") == "boom"


# --- country mapping ------------------------------------------------------------------

@pytest.mark.parametrize("name,code", [
    ("Estonia", "EE"), ("Chile", "CL"), ("Switzerland", "CH"), ("Spain", "ES"),
    ("  united kingdom ", "GB"), ("The Netherlands", "NL"), ("Atlantis", None), ("", None), (None, None),
])
def test_country_codes(name, code):
    assert _get_country_code_from_name(name) == code


def test_result_to_dict():
    r = SpeedTestResult(download_mbps=100.123, upload_mbps=20, ping_ms=12.34, server_country="EE",
                        external_ip="203.0.113.7", client_ip="203.0.113.7")
    d = r.to_dict()
    assert d["server_country"] == "EE"
    assert d["download_mbps"] == 100.12 and d["ping_ms"] == 12.3
    assert d["error"] is None and d["score"] == round(r.score, 2)
    json.dumps(d)


def test_result_to_dict_has_external_ip():
    d = SpeedTestResult(download_mbps=1, upload_mbps=1, ping_ms=1, external_ip="203.0.113.7").to_dict()
    assert d["external_ip"] == "203.0.113.7"


def test_is_success_and_score():
    assert not SpeedTestResult(0, 10, 5).is_success
    assert not SpeedTestResult(10, 10, 5, error="x").is_success
    assert SpeedTestResult(0, 10, 5).score == 0.0
    assert SpeedTestResult(1000, 500, 0).score == pytest.approx(10.0)


# --- subprocess fakes --------------------------------------------------------------

class FakeProc:
    def __init__(self, rc=0, out=b"", err=b""):
        self.returncode = None
        self._rc, self._out, self._err = rc, out, err
        self.pid = 1

    async def communicate(self):
        self.returncode = self._rc
        return self._out, self._err

    def kill(self):
        pass

    async def wait(self):
        return self._rc


@pytest.fixture
def fake_exec(monkeypatch):
    queue = []
    calls = []

    async def fake(*cmd, **kw):
        calls.append(list(cmd))
        item = queue.pop(0)
        if isinstance(item, BaseException):
            raise item
        return item

    async def no_sleep(*a, **kw):
        return None

    monkeypatch.setattr(st.asyncio, "create_subprocess_exec", fake)
    monkeypatch.setattr(st.asyncio, "sleep", no_sleep)
    return queue, calls


SERVER_LIST = json.dumps({"type": "serverList", "servers": [
    {"id": 3, "name": "Far", "location": "Tallinn", "country": "Estonia", "host": "x"},
    {"id": 1, "name": "Near", "location": "Santiago", "country": "Chile", "host": "y"},
    {"id": 2, "name": "Mid", "location": "Nowhere", "country": "Atlantis", "host": "z"},
    {"name": "no id"},
]}).encode()


async def test_list_servers_retry_after_failure_succeeds(fake_exec):
    queue, calls = fake_exec
    queue.extend([
        FakeProc(rc=1, out=_log("Temporary failure in name resolution")),
        FakeProc(rc=0, out=SERVER_LIST),
    ])
    servers = await list_speedtest_servers()
    assert len(calls) == 2
    assert [s.server_id for s in servers] == [3, 1, 2]  # CLI order kept
    assert [s.country_code for s in servers] == ["EE", "CL", None]
    assert "-L" in calls[0]


async def test_list_servers_non_transient_error_raises(fake_exec):
    queue, calls = fake_exec
    queue.append(FakeProc(rc=1, out=_log("Invalid license")))
    with pytest.raises(Exception, match="Invalid license"):
        await list_speedtest_servers()
    assert len(calls) == 1


async def test_list_servers_missing_binary(fake_exec):
    queue, _ = fake_exec
    queue.append(FileNotFoundError())
    with pytest.raises(Exception, match="not installed"):
        await list_speedtest_servers()


async def test_run_speedtest_parses_result(fake_exec):
    queue, calls = fake_exec
    data = {"type": "result", "ping": {"latency": 12.5}, "download": {"bandwidth": 12_500_000},
            "upload": {"bandwidth": 2_500_000}, "isp": "AirVPN",
            "interface": {"internalIp": "10.0.0.2", "externalIp": "203.0.113.7"},
            "server": {"id": 42, "name": "Elisa", "location": "Tallinn", "country": "Estonia"}}
    queue.append(FakeProc(out=json.dumps(data).encode()))
    r = await run_speedtest(server_id=42)
    assert r.is_success and r.download_mbps == pytest.approx(100.0) and r.upload_mbps == pytest.approx(20.0)
    assert r.server_country == "EE" and r.external_ip == "203.0.113.7" and r.client_ip == "203.0.113.7"
    assert r.server_location == "Tallinn, Estonia"
    assert calls[0][-2:] == ["-s", "42"]


async def test_run_speedtest_no_servers_maps_to_not_available(fake_exec):
    queue, _ = fake_exec
    queue.append(FakeProc(rc=2, out=_log("No servers found (NoServersException)"), err=BANNER))
    r = await run_speedtest(server_id=7)
    assert r.error == "Server 7 not available"


async def test_run_speedtest_failure_message_is_readable(fake_exec):
    queue, _ = fake_exec
    queue.append(FakeProc(rc=2, out=_log("Cannot open socket: Timeout occurred in connect."), err=BANNER))
    r = await run_speedtest(server_id=7)
    assert r.error == "Cannot open socket: Timeout occurred in connect."


# --- blacklisting ------------------------------------------------------------------

@pytest.fixture
def clean_blacklist():
    st.clear_server_blacklist()
    yield st._server_blacklist
    st.clear_server_blacklist()


def _patch_run(monkeypatch, results):
    async def fake_servers(cc, max_servers=3, secure=True):
        return [101, 102, 103][:max_servers]

    seq = list(results)
    tried = []

    async def fake_run(server_id=None, secure=True, timeout=180):
        tried.append(server_id)
        return seq.pop(0)

    monkeypatch.setattr(st, "get_speedtest_servers_for_country", fake_servers)
    monkeypatch.setattr(st, "run_speedtest", fake_run)
    return tried


def _fail(msg):
    return SpeedTestResult(0, 0, 0, error=msg)


async def test_server_side_error_blacklists(monkeypatch, fresh_config, clean_blacklist):
    tried = _patch_run(monkeypatch, [_fail("Server 101 not available"), SpeedTestResult(100, 50, 10)])
    r = await run_speedtest_for_country("DE")
    assert r.is_success and tried == [101, 102]
    assert 101 in clean_blacklist and 102 not in clean_blacklist


@pytest.mark.parametrize("msg", [
    "Speedtest timed out after 180s",
    "Speedtest completed with 0.00 Mbps for both download and upload",
    "Download test failed (0.00 Mbps), upload succeeded (5.00 Mbps)",
    "Cannot open socket: Network unreachable",
])
async def test_tunnel_side_errors_do_not_blacklist(monkeypatch, fresh_config, clean_blacklist, msg):
    _patch_run(monkeypatch, [_fail(msg), _fail(msg), _fail(msg)])
    r = await run_speedtest_for_country("DE")
    assert not r.is_success
    assert clean_blacklist == {}


async def test_blacklisted_server_filtered_after_threshold(fresh_config, clean_blacklist):
    fresh_config.speedtest_blacklist.max_failures = 2
    st._blacklist_server(5)
    assert not st._is_server_blacklisted(5)
    st._blacklist_server(5)
    assert st._is_server_blacklisted(5)


async def test_success_clears_blacklist_entry(monkeypatch, fresh_config, clean_blacklist):
    st._blacklist_server(101)
    _patch_run(monkeypatch, [SpeedTestResult(100, 50, 10)])
    await run_speedtest_for_country("DE")
    assert 101 not in clean_blacklist


async def test_unknown_country_falls_back_to_auto(monkeypatch):
    seen = []

    async def fake_run(server_id=None, secure=True, timeout=180):
        seen.append(server_id)
        return SpeedTestResult(10, 10, 10)

    monkeypatch.setattr(st, "run_speedtest", fake_run)
    await run_speedtest_for_country(None)
    assert seen == [None]


def test_ookla_error_falls_back_to_raw_stdout():
    from airbl.speedtest import _ookla_error
    msg = _ookla_error(b'{"type":"result","error":"Cannot open socket"}\n', b"")
    assert "Cannot open socket" in msg
