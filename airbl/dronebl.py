"""
DroneBL DNS-based Blocklist Lookup Module.

Uses DNS queries to check if IPs are listed in DroneBL.
Based on: https://github.com/antipatico/zeek-dronebl-dnsbl

How DNSBL works:
1. Reverse the IP octets: 1.2.3.4 → 4.3.2.1
2. Append the DNSBL host: 4.3.2.1.dnsbl.dronebl.org
3. Perform DNS A record lookup
4. If it resolves to 127.0.0.X, the IP is listed (X = listing type)
"""

import asyncio
import ipaddress
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

import dns.resolver
import dns.asyncresolver
from tenacity import retry, stop_after_attempt, wait_exponential

from .config import settings, get_dronebl_reason


@dataclass
class DroneBLResult:
    """Result of a DroneBL lookup."""
    ip: str
    is_listed: bool
    listing_code: Optional[int] = None
    listing_reason: Optional[str] = None
    lookup_time_ms: float = 0.0
    checked_at: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None
    
    @property
    def status_color(self) -> str:
        """Return color for terminal display."""
        if self.error:
            return "yellow"
        return "red" if self.is_listed else "green"
    
    @property
    def status_emoji(self) -> str:
        """Return status emoji."""
        if self.error:
            return "⚠️"
        return "🚫" if self.is_listed else "✅"


def reverse_ip(ip: str) -> str:
    """
    Reverse IP octets for DNSBL query.
    
    Example: 192.168.1.100 → 100.1.168.192
    """
    try:
        addr = ipaddress.ip_address(ip)
        if isinstance(addr, ipaddress.IPv4Address):
            octets = ip.split(".")
            return ".".join(reversed(octets))
        else:
            # IPv6 - expand and reverse nibbles
            expanded = addr.exploded.replace(":", "")
            return ".".join(reversed(expanded))
    except ValueError as e:
        raise ValueError(f"Invalid IP address: {ip}") from e


def build_dnsbl_query(ip: str, dnsbl_host: str = None) -> str:
    """
    Build the DNSBL query hostname.
    
    Example: 192.168.1.100 + dnsbl.dronebl.org → 100.1.168.192.dnsbl.dronebl.org
    """
    if dnsbl_host is None:
        dnsbl_host = settings.dronebl_dnsbl_host
    
    reversed_ip = reverse_ip(ip)
    return f"{reversed_ip}.{dnsbl_host}"


async def check_dronebl(ip: str, timeout: float = None) -> DroneBLResult:
    """
    Check if an IP is listed in DroneBL.
    
    Args:
        ip: IP address to check
        timeout: DNS query timeout in seconds
        
    Returns:
        DroneBLResult with listing status
    """
    if timeout is None:
        timeout = settings.dronebl_lookup_timeout
    
    start_time = asyncio.get_event_loop().time()
    
    try:
        query = build_dnsbl_query(ip)
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = timeout
        resolver.lifetime = timeout
        
        try:
            answers = await resolver.resolve(query, "A")
            
            # Parse the response
            for rdata in answers:
                response_ip = str(rdata)
                # DroneBL returns 127.0.0.X where X is the listing code
                if response_ip.startswith("127.0.0."):
                    code = int(response_ip.split(".")[-1])
                    elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
                    
                    return DroneBLResult(
                        ip=ip,
                        is_listed=True,
                        listing_code=code,
                        listing_reason=get_dronebl_reason(code),
                        lookup_time_ms=elapsed,
                    )
            
            # Got a response but not in expected format
            elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
            return DroneBLResult(
                ip=ip,
                is_listed=False,
                lookup_time_ms=elapsed,
            )
            
        except dns.resolver.NXDOMAIN:
            # NXDOMAIN means IP is NOT listed (this is the good case)
            elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
            return DroneBLResult(
                ip=ip,
                is_listed=False,
                lookup_time_ms=elapsed,
            )
        except dns.resolver.NoAnswer:
            # No A record means not listed
            elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
            return DroneBLResult(
                ip=ip,
                is_listed=False,
                lookup_time_ms=elapsed,
            )
            
    except dns.exception.Timeout:
        elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
        return DroneBLResult(
            ip=ip,
            is_listed=False,
            lookup_time_ms=elapsed,
            error="DNS timeout",
        )
    except Exception as e:
        elapsed = (asyncio.get_event_loop().time() - start_time) * 1000
        return DroneBLResult(
            ip=ip,
            is_listed=False,
            lookup_time_ms=elapsed,
            error=str(e),
        )


async def check_dronebl_batch(
    ips: list[str],
    concurrency: int = None,
    progress_callback=None,
) -> list[DroneBLResult]:
    """
    Check multiple IPs against DroneBL with rate limiting.
    
    Args:
        ips: List of IP addresses to check
        concurrency: Max concurrent DNS queries
        progress_callback: Optional callback(checked_count, total_count)
        
    Returns:
        List of DroneBLResult objects
    """
    if concurrency is None:
        concurrency = settings.scan_concurrency
    
    semaphore = asyncio.Semaphore(concurrency)
    results = []
    checked = 0
    total = len(ips)
    
    async def check_with_semaphore(ip: str) -> DroneBLResult:
        nonlocal checked
        async with semaphore:
            result = await check_dronebl(ip)
            checked += 1
            if progress_callback:
                progress_callback(checked, total)
            return result
    
    tasks = [check_with_semaphore(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    
    return results


# Synchronous wrapper for simple usage
def check_dronebl_sync(ip: str) -> DroneBLResult:
    """Synchronous wrapper for check_dronebl."""
    return asyncio.run(check_dronebl(ip))

