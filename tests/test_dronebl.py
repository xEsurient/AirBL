"""DroneBL DNSBL lookups with a fake resolver."""

import dns.exception
import dns.resolver
import pytest

from airbl import dronebl
from airbl.dronebl import build_dnsbl_query, check_dronebl, check_dronebl_batch, reverse_ip


def test_reverse_ipv4():
    assert reverse_ip("192.168.1.100") == "100.1.168.192"


def test_reverse_ipv6_nibbles():
    r = reverse_ip("2001:db8::1")
    parts = r.split(".")
    assert len(parts) == 32
    assert parts[0] == "1" and parts[-4:] == ["1", "0", "0", "2"]


def test_reverse_invalid():
    with pytest.raises(ValueError):
        reverse_ip("not-an-ip")


def test_build_query():
    assert build_dnsbl_query("1.2.3.4", "dnsbl.example") == "4.3.2.1.dnsbl.example"


class FakeResolver:
    """Stands in for dns.asyncresolver.Resolver; behaviour set per test."""
    behaviour = None
    instances: list = []

    def __init__(self, configure=True):
        self.configure = configure
        self.nameservers = []
        self.queries = []
        FakeResolver.instances.append(self)

    async def resolve(self, qname, rdtype):
        self.queries.append((qname, rdtype))
        b = FakeResolver.behaviour
        if callable(b):
            b = b()
        if isinstance(b, BaseException):
            raise b
        return b


@pytest.fixture
def resolver(monkeypatch):
    FakeResolver.instances = []
    FakeResolver.behaviour = None
    monkeypatch.setattr(dronebl.dns.asyncresolver, "Resolver", FakeResolver)
    monkeypatch.setattr(dronebl, "_NAMESERVERS", [])
    monkeypatch.setattr(dronebl, "RETRY_BACKOFF_SECONDS", 0)
    return FakeResolver


async def test_listed(resolver):
    resolver.behaviour = ["127.0.0.19"]
    r = await check_dronebl("1.2.3.4")
    assert r.is_listed and r.listing_code == 19 and r.listing_reason == "Abused VPN Service"
    assert r.is_verified and r.error is None
    assert resolver.instances[0].queries == [("4.3.2.1.dnsbl.dronebl.org", "A")]


async def test_nxdomain_is_verified_clean(resolver):
    resolver.behaviour = dns.resolver.NXDOMAIN()
    r = await check_dronebl("1.2.3.4")
    assert not r.is_listed and r.is_verified and r.status_color == "green"


async def test_noanswer_is_clean(resolver):
    resolver.behaviour = dns.resolver.NoAnswer()
    r = await check_dronebl("1.2.3.4")
    assert not r.is_listed and r.is_verified


async def test_timeout_is_unverified(resolver):
    resolver.behaviour = dns.exception.Timeout()
    r = await check_dronebl("1.2.3.4")
    assert not r.is_listed and not r.is_verified and r.error == "DNS timeout"
    assert r.status_color == "yellow"


async def test_non_127_answer_is_error(resolver):
    resolver.behaviour = ["10.0.0.1"]
    r = await check_dronebl("1.2.3.4")
    assert not r.is_listed and not r.is_verified
    assert "Unexpected DNSBL answer" in r.error and "10.0.0.1" in r.error


async def test_other_exception_is_error(resolver):
    resolver.behaviour = dns.resolver.NoNameservers()
    r = await check_dronebl("1.2.3.4")
    assert not r.is_verified


async def test_dns_servers_used(resolver, monkeypatch):
    monkeypatch.setattr(dronebl, "_NAMESERVERS", ["9.9.9.9"])
    resolver.behaviour = dns.resolver.NXDOMAIN()
    await check_dronebl("1.2.3.4")
    inst = resolver.instances[0]
    assert inst.configure is False and inst.nameservers == ["9.9.9.9"]


async def test_system_resolver_when_no_dns_servers(resolver):
    resolver.behaviour = dns.resolver.NXDOMAIN()
    await check_dronebl("1.2.3.4")
    assert resolver.instances[0].configure is True


async def test_batch_retries_once_after_error(resolver):
    seq = [dns.exception.Timeout(), dns.resolver.NXDOMAIN()]
    resolver.behaviour = lambda: seq.pop(0)
    [r] = await check_dronebl_batch(["1.2.3.4"], concurrency=1)
    assert r.is_verified and not r.is_listed
    assert seq == []


async def test_batch_retry_only_once(resolver):
    calls = []

    def always_timeout():
        calls.append(1)
        return dns.exception.Timeout()

    resolver.behaviour = always_timeout
    [r] = await check_dronebl_batch(["1.2.3.4"], concurrency=1)
    assert not r.is_verified and len(calls) == 2


async def test_batch_no_retry_on_success(resolver):
    calls = []

    def listed():
        calls.append(1)
        return ["127.0.0.3"]

    resolver.behaviour = listed
    progress = []
    res = await check_dronebl_batch(["1.2.3.4", "5.6.7.8"], concurrency=2,
                                    progress_callback=lambda a, b: progress.append((a, b)))
    assert [r.listing_code for r in res] == [3, 3] and len(calls) == 2
    assert progress[-1] == (2, 2)
