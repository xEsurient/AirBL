"""
Ping Checker Module.

Cross-platform ping implementation using icmplib.
On macOS, privileged ICMP requires root, so we use UDP-based ping as fallback.
"""

import asyncio
import subprocess
import platform
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime

from .config import settings


@dataclass
class PingResult:
    """Result of a ping test."""
    ip: str
    is_alive: bool
    min_rtt_ms: Optional[float] = None
    avg_rtt_ms: Optional[float] = None
    max_rtt_ms: Optional[float] = None
    packet_loss: float = 100.0  # Percentage
    packets_sent: int = 0
    packets_received: int = 0
    tested_at: datetime = field(default_factory=datetime.now)
    error: Optional[str] = None
    
    @property
    def status_color(self) -> str:
        """Return color for terminal display."""
        if not self.is_alive:
            return "red"
        if self.avg_rtt_ms is not None:
            if self.avg_rtt_ms < 50:
                return "green"
            elif self.avg_rtt_ms < 150:
                return "yellow"
        return "red"
    
    @property
    def latency_display(self) -> str:
        """Format latency for display."""
        if not self.is_alive:
            return "N/A"
        if self.avg_rtt_ms is not None:
            return f"{self.avg_rtt_ms:.1f}ms"
        return "N/A"


async def ping_ip(
    ip: str,
    count: int = None,
    timeout: float = None,
) -> PingResult:
    """
    Ping an IP address using system ping command.
    
    Uses subprocess to call system ping, which works without root on macOS.
    
    Args:
        ip: IP address to ping
        count: Number of ping packets
        timeout: Timeout per packet in seconds
        
    Returns:
        PingResult with latency statistics
    """
    if count is None:
        count = settings.ping_count
    if timeout is None:
        timeout = settings.ping_timeout
    
    system = platform.system().lower()
    
    # Build ping command based on OS
    if system == "darwin":  # macOS
        cmd = ["ping", "-c", str(count), "-t", str(int(timeout)), ip]
    elif system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    else:  # Linux
        cmd = ["ping", "-c", str(count), "-W", str(int(timeout)), ip]
    
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout * count + 5,  # Extra buffer
        )
        
        output = stdout.decode("utf-8", errors="ignore")
        
        # Parse ping output
        return parse_ping_output(ip, output, count)
        
    except asyncio.TimeoutError:
        return PingResult(
            ip=ip,
            is_alive=False,
            packets_sent=count,
            error="Ping timeout",
        )
    except Exception as e:
        return PingResult(
            ip=ip,
            is_alive=False,
            packets_sent=count,
            error=str(e),
        )


def parse_ping_output(ip: str, output: str, count: int) -> PingResult:
    """
    Parse ping command output to extract statistics.
    
    Handles macOS, Linux, and Windows output formats.
    """
    lines = output.lower().strip().split("\n")
    
    # Check if host is unreachable
    if any("unreachable" in line or "100% packet loss" in line or "100.0% packet loss" in line for line in lines):
        return PingResult(
            ip=ip,
            is_alive=False,
            packets_sent=count,
            packets_received=0,
            packet_loss=100.0,
        )
    
    # Try to find RTT statistics line
    # macOS/Linux: "round-trip min/avg/max/stddev = 10.123/15.456/20.789/1.234 ms"
    # or "rtt min/avg/max/mdev = 10.123/15.456/20.789/1.234 ms"
    min_rtt = avg_rtt = max_rtt = None
    packets_received = 0
    packet_loss = 100.0
    
    for line in lines:
        # Parse packet statistics
        if "packets transmitted" in line or "received" in line:
            import re
            # macOS/Linux: "3 packets transmitted, 3 received, 0% packet loss"
            # or "3 packets transmitted, 3 packets received, 0.0% packet loss"
            match = re.search(r"(\d+)\s+(?:packets\s+)?received", line)
            if match:
                packets_received = int(match.group(1))
            
            match = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet\s+)?loss", line)
            if match:
                packet_loss = float(match.group(1))
        
        # Parse RTT statistics
        if "min/avg/max" in line or "rtt" in line:
            import re
            # Extract numbers from patterns like "10.123/15.456/20.789"
            match = re.search(r"(\d+\.?\d*)/(\d+\.?\d*)/(\d+\.?\d*)", line)
            if match:
                min_rtt = float(match.group(1))
                avg_rtt = float(match.group(2))
                max_rtt = float(match.group(3))
    
    is_alive = packets_received > 0
    
    return PingResult(
        ip=ip,
        is_alive=is_alive,
        min_rtt_ms=min_rtt,
        avg_rtt_ms=avg_rtt,
        max_rtt_ms=max_rtt,
        packet_loss=packet_loss,
        packets_sent=count,
        packets_received=packets_received,
    )


async def ping_batch(
    ips: list[str],
    concurrency: int = None,
    progress_callback=None,
) -> list[PingResult]:
    """
    Ping multiple IPs concurrently.
    
    Args:
        ips: List of IP addresses to ping
        concurrency: Max concurrent pings
        progress_callback: Optional callback(checked_count, total_count)
        
    Returns:
        List of PingResult objects
    """
    if concurrency is None:
        concurrency = min(settings.scan_concurrency, 20)  # Limit concurrent pings
    
    semaphore = asyncio.Semaphore(concurrency)
    checked = 0
    total = len(ips)
    
    async def ping_with_semaphore(ip: str) -> PingResult:
        nonlocal checked
        async with semaphore:
            result = await ping_ip(ip)
            checked += 1
            if progress_callback:
                progress_callback(checked, total)
            return result
    
    tasks = [ping_with_semaphore(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    
    return results


# Quick connectivity check using TCP connect
async def tcp_check(ip: str, port: int = 443, timeout: float = 2.0) -> bool:
    """
    Quick TCP connectivity check.
    
    Useful for fast scanning before doing full ping tests.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def tcp_check_batch(
    ips: list[str],
    port: int = 443,
    concurrency: int = 100,
) -> dict[str, bool]:
    """
    Quick TCP connectivity check for multiple IPs.
    
    Args:
        ips: List of IP addresses to check
        port: Port to check (default 443)
        concurrency: Max concurrent checks
    
    Returns:
        Dict mapping IP to connectivity status
    """
    semaphore = asyncio.Semaphore(concurrency)
    
    async def check_with_semaphore(ip: str) -> tuple[str, bool]:
        async with semaphore:
            result = await tcp_check(ip, port)
            return ip, result
    
    tasks = [check_with_semaphore(ip) for ip in ips]
    results = await asyncio.gather(*tasks)
    return dict(results)

