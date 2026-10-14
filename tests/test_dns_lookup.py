"""Exit-IP lookups via dig, with a fake subprocess."""

import asyncio

import pytest

from airbl import dns_lookup
from airbl.dns_lookup import DNSLookupError, lookup_exit_ips, lookup_server_exit_ips


class FakeProc:
    def __init__(self, stdout=b"", stderr=b"", rc=0, hang=False):
        self._out, self._err, self._rc, self.hang = stdout, stderr, rc, hang
        self.returncode = None
        self.killed = False

    async def communicate(self):
        if self.hang:
            await asyncio.sleep(10)
        self.returncode = self._rc
        return self._out, self._err

    def kill(self):
        self.killed = True

    async def wait(self):
        self.returncode = -9
        return -9


@pytest.fixture
def fake_dig(monkeypatch):
    """Map (rdtype, server) -> FakeProc or exception; records commands."""
    calls = []
    table = {}

    async def fake_exec(*cmd, **kw):
        calls.append(list(cmd))
        rdtype, server = cmd[1], cmd[3].lstrip("@")
        item = table.get((rdtype, server), table.get(rdtype, FakeProc()))
        if isinstance(item, BaseException):
            raise item
        return item() if callable(item) else item

    monkeypatch.setattr(dns_lookup.asyncio, "create_subprocess_exec", fake_exec)
    return table, calls


async def test_parses_a_and_aaaa(fake_dig):
    table, calls = fake_dig
    table["A"] = lambda: FakeProc(b"some.cname.example.\n192.0.2.10\n;; comment\nnot-an-ip\n192.0.2.11\n")
    table["AAAA"] = lambda: FakeProc(b"2001:db8::1\n2001:0db8:0000::0001\n")
    ips, err = await lookup_exit_ips("Toliman")
    assert err is None
    assert ips == {"192.0.2.10", "192.0.2.11", "2001:db8::1"}
    assert {c[1] for c in calls} == {"A", "AAAA"}
    assert all(c[2] == "toliman_exit.airservers.org" for c in calls)
    assert {c[3] for c in calls} == {"@dns1.airvpn.org", "@dns2.airvpn.org"}
    assert len(calls) == 4


async def test_no_records_is_not_an_error(fake_dig):
    ips, err = await lookup_exit_ips("Nobody")
    assert ips == set() and err is None


async def test_partial_failure_still_answers(fake_dig):
    table, _ = fake_dig
    table[("A", "dns1.airvpn.org")] = lambda: FakeProc(b";; connection timed out; no servers could be reached\n", rc=9)
    table[("A", "dns2.airvpn.org")] = lambda: FakeProc(b"192.0.2.10\n")
    ips, err = await lookup_exit_ips("Toliman")
    assert ips == {"192.0.2.10"} and err is None


async def test_missing_dig_error(fake_dig):
    table, _ = fake_dig
    table["A"] = FileNotFoundError("dig")
    table["AAAA"] = FileNotFoundError("dig")
    ips, err = await lookup_exit_ips("Toliman")
    assert ips == set()
    assert err == "dig command not found (install bind-utils or dnsutils)"


async def test_timeout_error_and_kill(fake_dig, monkeypatch):
    monkeypatch.setattr(dns_lookup, "DIG_TIMEOUT_SECONDS", 0.01)
    table, _ = fake_dig
    procs = []

    def hanging():
        p = FakeProc(hang=True)
        procs.append(p)
        return p

    table["A"] = hanging
    table["AAAA"] = hanging
    ips, err = await lookup_exit_ips("Toliman")
    assert ips == set()
    assert "timed out" in err and "not found" not in err
    assert len(procs) == 4 and all(p.killed for p in procs)


async def test_nonzero_exit_error(fake_dig):
    table, _ = fake_dig
    table["A"] = lambda: FakeProc(b";; connection timed out; no servers could be reached\n", rc=9)
    table["AAAA"] = lambda: FakeProc(b"", b"some resolver error\n", rc=10)
    ips, err = await lookup_exit_ips("Toliman")
    assert ips == set()
    assert "dig exit 9: ;; connection timed out" in err
    assert "dig exit 10: some resolver error" in err


async def test_lookup_server_exit_ips_raises(fake_dig):
    table, _ = fake_dig
    table["A"] = FileNotFoundError()
    table["AAAA"] = FileNotFoundError()
    with pytest.raises(DNSLookupError):
        await lookup_server_exit_ips("Toliman")
