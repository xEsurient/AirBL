"""
DNS Lookup Module for AirVPN Server Exit IPs.

Uses dig commands to query AirVPN DNS servers for server exit IPs.
"""

import asyncio
import ipaddress
import logging
from typing import Optional, Set, Tuple

logger = logging.getLogger("airbl.dns_lookup")

DNS_SERVERS = ["dns1.airvpn.org", "dns2.airvpn.org"]
DIG_TIMEOUT_SECONDS = 10.0  # Whole dig run; dig itself gets +time=3 +tries=2


class DNSLookupError(Exception):
    """Every exit-IP query failed (dig missing, timeout, resolver error)."""


async def _dig(query_name: str, rdtype: str, dns_server: str) -> Set[str]:
    """Run one dig query; return valid IPs, raise DNSLookupError on failure."""
    cmd = ["dig", rdtype, query_name, f"@{dns_server}", "+short", "+time=3", "+tries=2"]
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        raise DNSLookupError("dig command not found (install bind-utils or dnsutils)")

    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=DIG_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        raise DNSLookupError(f"dig timed out after {DIG_TIMEOUT_SECONDS:.0f}s")
    finally:
        # Kill and reap on timeout or cancellation so no dig child is left behind
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            await process.wait()

    if process.returncode != 0:
        # dig +short prints errors like ";; connection timed out" on stdout
        msg = (stderr.decode("utf-8", "ignore") or stdout.decode("utf-8", "ignore")).strip()
        raise DNSLookupError(f"dig exit {process.returncode}: {msg.splitlines()[-1] if msg else 'no output'}")

    ips = set()
    for line in stdout.decode("utf-8", "ignore").splitlines():
        line = line.strip()
        if not line or line.startswith(";"):
            continue
        try:
            # +short also prints CNAME targets; keep only real addresses
            ips.add(str(ipaddress.ip_address(line)))
        except ValueError:
            continue
    return ips


async def lookup_exit_ips(server_name: str) -> Tuple[Set[str], Optional[str]]:
    """
    Lookup exit IPs (IPv4 and IPv6) for a server.

    Queries A and AAAA (not ANY: RFC 8482 resolvers refuse or minimise it) for
    SERVERNAME_exit.airservers.org at dns1/dns2.airvpn.org.

    Returns:
        (ips, error): error is None when at least one query got an answer
        (possibly empty = no records); otherwise a reason why every query failed.
    """
    query_name = f"{server_name.lower()}_exit.airservers.org"
    jobs = [(srv, rd) for srv in DNS_SERVERS for rd in ("A", "AAAA")]
    results = await asyncio.gather(
        *[_dig(query_name, rd, srv) for srv, rd in jobs],
        return_exceptions=True,
    )

    all_ips: Set[str] = set()
    errors = []
    answered = False
    for (srv, rd), res in zip(jobs, results):
        if isinstance(res, BaseException):
            if isinstance(res, asyncio.CancelledError):
                raise res
            errors.append(str(res))
            logger.warning(f"DNS query failed for {query_name} {rd} @{srv}: {res}")
        else:
            answered = True
            all_ips.update(res)

    if not answered:
        return set(), "; ".join(sorted(set(errors)))  # usually one shared reason
    return all_ips, None


async def lookup_server_exit_ips(server_name: str) -> Set[str]:
    """
    Lookup exit IPs for a server.

    Returns the set of IPs; raises DNSLookupError if every query failed.
    """
    ips, error = await lookup_exit_ips(server_name)
    if error:
        raise DNSLookupError(error)
    return ips
