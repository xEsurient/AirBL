"""
Ping Checker Module.

Cross-platform ping: system ICMP ping and a TCP connect probe run together,
since servers may block either protocol. The lower average wins.
"""

import asyncio
import math
import platform
import re
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
    method: Optional[str] = None          # "icmp" or "tcp": which probe avg_rtt_ms came from
    icmp_avg_ms: Optional[float] = None   # Per-protocol averages (None = no reply)
    tcp_avg_ms: Optional[float] = None
    
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


# A refusal faster than this is almost certainly a local or middlebox REJECT,
# not a round trip to the remote host.
MIN_REFUSED_RTT_MS = 1.0


async def tcp_ping(ip: str, count: int = 1, timeout: float = 2.0, port: int = 443) -> PingResult:
    import time
    latencies = []
    fast_refusals = 0
    for _ in range(count):
        start = time.perf_counter()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            latencies.append((time.perf_counter() - start) * 1000.0)
            writer.close()
            await writer.wait_closed()
        except ConnectionRefusedError:
            # RST from a closed port is still a full round trip to the host.
            rtt = (time.perf_counter() - start) * 1000.0
            if rtt >= MIN_REFUSED_RTT_MS:
                latencies.append(rtt)
            else:
                fast_refusals += 1
        except Exception:
            pass
    
    if not latencies:
        error = f"No TCP reply on port {port}"
        if fast_refusals:
            error += f" ({fast_refusals} instant refusal(s) ignored: likely local/middlebox reject)"
        return PingResult(ip=ip, is_alive=False, packets_sent=count, packets_received=0, packet_loss=100.0,
                          error=error)
    
    return PingResult(
        ip=ip,
        is_alive=True,
        min_rtt_ms=min(latencies),
        avg_rtt_ms=sum(latencies)/len(latencies),
        max_rtt_ms=max(latencies),
        packet_loss=(count - len(latencies)) / count * 100.0,
        packets_sent=count,
        packets_received=len(latencies)
    )

async def _icmp_ping(ip: str, count: int, timeout: float) -> PingResult:
    """ICMP ping via the system ping command (works without root on macOS)."""
    system = platform.system().lower()
    
    # Whole seconds, at least 1: int(0.5) would be 0 (= wait forever / invalid)
    wait_s = str(max(1, math.ceil(timeout)))
    
    # Build ping command based on OS
    if system == "darwin":  # macOS
        cmd = ["ping", "-c", str(count), "-t", wait_s, ip]
    elif system == "windows":
        cmd = ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), ip]
    else:  # Linux
        cmd = ["ping", "-c", str(count), "-W", wait_s, ip]
    
    process = None
    error = None
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
        return parse_ping_output(ip, output, count)
        
    except asyncio.TimeoutError:
        error = "Ping timeout"
    except Exception as e:
        error = str(e)
    finally:
        # Also runs on CancelledError, so the ping child is never orphaned
        if process and process.returncode is None:
            try:
                process.kill()
            except (OSError, ProcessLookupError):
                pass
            try:
                await process.wait()
            except Exception:
                pass
    return PingResult(ip=ip, is_alive=False, packets_sent=count, error=error)


async def ping_ip(
    ip: str,
    count: int = None,
    timeout: float = None,
) -> PingResult:
    """
    Ping an IP with both ICMP and TCP (port 443) at the same time.
    
    Hosts may block either protocol, so the IP counts as alive if either replies,
    and avg_rtt_ms is the lower of the two averages (method says which one).
    
    Args:
        ip: IP address to ping
        count: Number of probes per protocol
        timeout: Timeout per probe in seconds
        
    Returns:
        PingResult with latency statistics of the faster protocol
    """
    if count is None:
        count = settings.ping_count
    if timeout is None:
        timeout = settings.ping_timeout
    
    icmp, tcp = await asyncio.gather(
        _icmp_ping(ip, count, timeout),
        tcp_ping(ip, count, timeout),
    )
    icmp.method, tcp.method = "icmp", "tcp"
    
    replied = [r for r in (icmp, tcp) if r.is_alive]
    if not replied:
        icmp.error = "; ".join(e for e in (icmp.error, tcp.error) if e) or "No ICMP or TCP reply"
        best = icmp
    else:
        # Prefer a result with a measured RTT, then the lowest average.
        best = min(replied, key=lambda r: r.avg_rtt_ms if r.avg_rtt_ms is not None else float("inf"))
    
    best.icmp_avg_ms = icmp.avg_rtt_ms if icmp.is_alive else None
    best.tcp_avg_ms = tcp.avg_rtt_ms if tcp.is_alive else None
    return best


def parse_ping_output(ip: str, output: str, count: int) -> PingResult:
    """
    Parse ping command output to extract statistics.
    
    Handles macOS, Linux, and Windows output formats.
    """
    lines = output.lower().strip().split("\n")
    
    # Alive is decided by the received count below, not by "unreachable" lines:
    # one ICMP unreachable among real replies doesn't make the host dead.
    # Try to find RTT statistics line
    # macOS/Linux: "round-trip min/avg/max/stddev = 10.123/15.456/20.789/1.234 ms"
    # or "rtt min/avg/max/mdev = 10.123/15.456/20.789/1.234 ms"
    min_rtt = avg_rtt = max_rtt = None
    packets_received = 0
    packet_loss = 100.0
    
    for line in lines:
        # Parse packet statistics
        if "packets transmitted" in line or "received" in line:
            # macOS/Linux: "3 packets transmitted, 3 received, 0% packet loss"
            # or "3 packets transmitted, 3 packets received, 0.0% packet loss"
            match = re.search(r"(\d+)\s+(?:packets\s+)?received", line) or re.search(r"received\s*=\s*(\d+)", line)
            if match:
                packets_received = int(match.group(1))
            
            match = re.search(r"(\d+(?:\.\d+)?)\s*%\s*(?:packet\s+)?loss", line)
            if match:
                packet_loss = float(match.group(1))
        
        # Windows: "Minimum = 10ms, Maximum = 20ms, Average = 15ms"
        win = re.search(r"minimum\s*=\s*(\d+)ms.*maximum\s*=\s*(\d+)ms.*average\s*=\s*(\d+)ms", line)
        if win:
            min_rtt, max_rtt, avg_rtt = float(win.group(1)), float(win.group(2)), float(win.group(3))
        
        # Parse RTT statistics
        if "min/avg/max" in line or "rtt" in line:
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

