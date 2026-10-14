"""Ping parsing and ICMP/TCP combination (no real network)."""

import asyncio

import pytest

from airbl import pinger
from airbl.pinger import PingResult, parse_ping_output, ping_ip, tcp_ping

LINUX_OK = """PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.
64 bytes from 192.0.2.1: icmp_seq=1 ttl=57 time=10.1 ms
64 bytes from 192.0.2.1: icmp_seq=2 ttl=57 time=12.0 ms
64 bytes from 192.0.2.1: icmp_seq=3 ttl=57 time=11.2 ms

--- 192.0.2.1 ping statistics ---
3 packets transmitted, 3 received, 0% packet loss, time 2003ms
rtt min/avg/max/mdev = 10.123/11.456/12.012/0.734 ms
"""

LINUX_PARTIAL_UNREACHABLE = """PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.
From 10.0.0.1 icmp_seq=1 Destination Host Unreachable
64 bytes from 192.0.2.1: icmp_seq=2 ttl=57 time=20.5 ms
64 bytes from 192.0.2.1: icmp_seq=3 ttl=57 time=21.5 ms

--- 192.0.2.1 ping statistics ---
3 packets transmitted, 2 received, +1 errors, 33.3333% packet loss, time 2002ms
rtt min/avg/max/mdev = 20.500/21.000/21.500/0.500 ms
"""

LINUX_DEAD = """PING 192.0.2.1 (192.0.2.1) 56(84) bytes of data.
From 10.0.0.1 icmp_seq=1 Destination Host Unreachable

--- 192.0.2.1 ping statistics ---
3 packets transmitted, 0 received, +3 errors, 100% packet loss, time 2030ms
"""

MACOS_OK = """PING 192.0.2.1 (192.0.2.1): 56 data bytes
64 bytes from 192.0.2.1: icmp_seq=0 ttl=57 time=15.123 ms

--- 192.0.2.1 ping statistics ---
3 packets transmitted, 3 packets received, 0.0% packet loss
round-trip min/avg/max/stddev = 14.100/15.456/16.789/1.234 ms
"""

WINDOWS_OK = """Pinging 192.0.2.1 with 32 bytes of data:
Reply from 192.0.2.1: bytes=32 time=10ms TTL=117
Reply from 192.0.2.1: bytes=32 time=12ms TTL=117
Reply from 192.0.2.1: bytes=32 time=11ms TTL=117

Ping statistics for 192.0.2.1:
    Packets: Sent = 3, Received = 3, Lost = 0 (0% loss),
Approximate round trip times in milli-seconds:
    Minimum = 10ms, Maximum = 12ms, Average = 11ms
"""


def test_parse_linux():
    r = parse_ping_output("192.0.2.1", LINUX_OK, 3)
    assert r.is_alive and r.packets_received == 3 and r.packet_loss == 0
    assert (r.min_rtt_ms, r.avg_rtt_ms, r.max_rtt_ms) == (10.123, 11.456, 12.012)


def test_parse_partial_loss_with_unreachable_is_alive():
    r = parse_ping_output("192.0.2.1", LINUX_PARTIAL_UNREACHABLE, 3)
    assert r.is_alive and r.packets_received == 2
    assert r.packet_loss == pytest.approx(33.3333)
    assert r.avg_rtt_ms == 21.0


def test_parse_dead():
    r = parse_ping_output("192.0.2.1", LINUX_DEAD, 3)
    assert not r.is_alive and r.packets_received == 0 and r.packet_loss == 100.0 and r.avg_rtt_ms is None


def test_parse_macos():
    r = parse_ping_output("192.0.2.1", MACOS_OK, 3)
    assert r.is_alive and r.packets_received == 3 and r.packet_loss == 0.0
    assert r.avg_rtt_ms == 15.456


def test_parse_windows_liveness():
    r = parse_ping_output("192.0.2.1", WINDOWS_OK, 3)
    assert r.is_alive and r.packets_received == 3 and r.packet_loss == 0.0


def test_parse_windows_rtt():
    assert parse_ping_output("192.0.2.1", WINDOWS_OK, 3).avg_rtt_ms == 11.0


def test_parse_garbage():
    r = parse_ping_output("192.0.2.1", "ping: unknown host", 3)
    assert not r.is_alive


# --- ping_ip combining ICMP + TCP -------------------------------------------------

def _patch_probes(monkeypatch, icmp, tcp):
    async def fake_icmp(ip, count, timeout):
        return icmp

    async def fake_tcp(ip, count=1, timeout=2.0, port=443):
        return tcp

    monkeypatch.setattr(pinger, "_icmp_ping", fake_icmp)
    monkeypatch.setattr(pinger, "tcp_ping", fake_tcp)


async def test_ping_ip_picks_lowest(monkeypatch):
    _patch_probes(monkeypatch, PingResult(ip="x", is_alive=True, avg_rtt_ms=30.0),
                  PingResult(ip="x", is_alive=True, avg_rtt_ms=12.0))
    r = await ping_ip("x", count=1, timeout=1)
    assert r.method == "tcp" and r.avg_rtt_ms == 12.0
    assert r.icmp_avg_ms == 30.0 and r.tcp_avg_ms == 12.0


async def test_ping_ip_icmp_only(monkeypatch):
    _patch_probes(monkeypatch, PingResult(ip="x", is_alive=True, avg_rtt_ms=30.0),
                  PingResult(ip="x", is_alive=False, error="No TCP reply on port 443"))
    r = await ping_ip("x", count=1, timeout=1)
    assert r.is_alive and r.method == "icmp" and r.tcp_avg_ms is None and r.icmp_avg_ms == 30.0


async def test_ping_ip_prefers_measured_rtt(monkeypatch):
    _patch_probes(monkeypatch, PingResult(ip="x", is_alive=True, avg_rtt_ms=None),
                  PingResult(ip="x", is_alive=True, avg_rtt_ms=50.0))
    r = await ping_ip("x", count=1, timeout=1)
    assert r.method == "tcp" and r.avg_rtt_ms == 50.0


async def test_ping_ip_neither(monkeypatch):
    _patch_probes(monkeypatch, PingResult(ip="x", is_alive=False, error="Ping timeout"),
                  PingResult(ip="x", is_alive=False, error="No TCP reply on port 443"))
    r = await ping_ip("x", count=1, timeout=1)
    assert not r.is_alive and "Ping timeout" in r.error and "No TCP reply" in r.error


# --- tcp_ping refusals -------------------------------------------------------------

async def test_fast_connection_refused_not_counted(monkeypatch):
    async def refuse(host, port):
        raise ConnectionRefusedError()

    monkeypatch.setattr(pinger.asyncio, "open_connection", refuse)
    r = await tcp_ping("192.0.2.1", count=3, timeout=1)
    assert not r.is_alive
    assert "3 instant refusal" in r.error


async def test_slow_connection_refused_counts_as_alive(monkeypatch):
    async def refuse_late(host, port):
        await asyncio.sleep(0.005)
        raise ConnectionRefusedError()

    monkeypatch.setattr(pinger.asyncio, "open_connection", refuse_late)
    r = await tcp_ping("192.0.2.1", count=2, timeout=1)
    assert r.is_alive and r.packets_received == 2 and r.avg_rtt_ms >= pinger.MIN_REFUSED_RTT_MS


async def test_tcp_connect_success(monkeypatch):
    class W:
        def close(self):
            pass

        async def wait_closed(self):
            pass

    async def ok(host, port):
        return object(), W()

    monkeypatch.setattr(pinger.asyncio, "open_connection", ok)
    r = await tcp_ping("192.0.2.1", count=2, timeout=1)
    assert r.is_alive and r.packet_loss == 0.0


# --- ICMP command line -------------------------------------------------------------

class _Proc:
    returncode = 0

    def __init__(self, out=b""):
        self.out = out

    async def communicate(self):
        return self.out, b""


@pytest.mark.parametrize("system,timeout,flag,value", [
    ("Linux", 0.5, "-W", "1"),
    ("Linux", 2.2, "-W", "3"),
    ("Linux", 2.0, "-W", "2"),
    ("Darwin", 0.5, "-t", "1"),
    ("Windows", 0.5, "-w", "500"),
])
async def test_icmp_wait_is_ceiled(monkeypatch, system, timeout, flag, value):
    captured = {}

    async def fake_exec(*cmd, **kw):
        captured["cmd"] = list(cmd)
        return _Proc(LINUX_OK.encode())

    monkeypatch.setattr(pinger.platform, "system", lambda: system)
    monkeypatch.setattr(pinger.asyncio, "create_subprocess_exec", fake_exec)
    r = await pinger._icmp_ping("192.0.2.1", 3, timeout)
    cmd = captured["cmd"]
    assert cmd[cmd.index(flag) + 1] == value
    assert r.is_alive


async def test_icmp_missing_binary(monkeypatch):
    async def fake_exec(*cmd, **kw):
        raise FileNotFoundError("ping")

    monkeypatch.setattr(pinger.asyncio, "create_subprocess_exec", fake_exec)
    r = await pinger._icmp_ping("192.0.2.1", 1, 1)
    assert not r.is_alive and r.error
