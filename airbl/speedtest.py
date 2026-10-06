"""
Speedtest Module with Country-Specific Server Pinning.

Uses Ookla speedtest CLI to find nearest servers dynamically,
with failover support for consistent results.
"""

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List

from .config import config_manager

logger = logging.getLogger("airbl.speedtest")

# Server blacklist: server_id -> (failure_count, blacklisted_until)
_server_blacklist: Dict[int, tuple[int, datetime]] = {}


@dataclass
class SpeedTestServer:
    """Represents a speedtest server from --list output."""
    server_id: int
    name: str
    location: str
    country: str
    country_code: Optional[str]  # None when the country name is unknown
    distance_km: Optional[float] = None


@dataclass
class SpeedTestResult:
    """Result of a speed test."""
    download_mbps: float
    upload_mbps: float
    ping_ms: float
    server_id: Optional[int] = None
    server_name: Optional[str] = None
    server_location: Optional[str] = None
    server_country: Optional[str] = None
    client_ip: Optional[str] = None
    external_ip: Optional[str] = None  # Ookla's view of our public IP (VPN egress check)
    client_isp: Optional[str] = None
    tested_at: datetime = field(default_factory=datetime.now)
    duration_seconds: float = 0.0
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        """Check if speedtest was successful.
        
        Success requires:
        - No error set
        - Download speed > 0 (upload can be 0 for download-only tests)
        """
        if self.error is not None:
            return False
        # Require download > 0 for success (upload-only results are considered partial failures)
        return self.download_mbps > 0
    
    @property
    def score(self) -> float:
        """
        Calculate overall score for ranking.
        Higher is better. Weights: download=0.5, upload=0.3, ping=0.2
        """
        if not self.is_success:
            return 0.0
        
        # Normalize: download/upload in Mbps (higher=better), ping in ms (lower=better)
        download_score = min(self.download_mbps / 100, 10)  # Cap at 1000 Mbps
        upload_score = min(self.upload_mbps / 50, 10)       # Cap at 500 Mbps
        ping_score = max(0, 10 - (self.ping_ms / 10))       # 100ms = 0, 0ms = 10
        
        return (download_score * 0.5) + (upload_score * 0.3) + (ping_score * 0.2)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "download_mbps": round(self.download_mbps, 2),
            "upload_mbps": round(self.upload_mbps, 2),
            "ping_ms": round(self.ping_ms, 1),
            "server_id": self.server_id,
            "server_name": self.server_name,
            "server_location": self.server_location,
            "server_country": self.server_country,
            "external_ip": self.external_ip,
            "client_ip": self.client_ip,
            "tested_at": self.tested_at.isoformat() if self.tested_at else None,
            "score": round(self.score, 2),
            "error": self.error,
        }


# Country names as Ookla reports them (plus common variants) -> ISO 3166-1 alpha-2.
# Guessing from the first two letters picks the wrong country (Estonia -> "ES",
# Chile -> "CH"), so unknown names map to None instead.
_COUNTRY_NAME_TO_CODE = {
    "albania": "AL", "algeria": "DZ", "argentina": "AR", "armenia": "AM", "australia": "AU",
    "austria": "AT", "azerbaijan": "AZ", "bahrain": "BH", "bangladesh": "BD", "belarus": "BY",
    "belgium": "BE", "bolivia": "BO", "bosnia and herzegovina": "BA", "brazil": "BR",
    "bulgaria": "BG", "cambodia": "KH", "canada": "CA", "chile": "CL", "china": "CN",
    "colombia": "CO", "costa rica": "CR", "croatia": "HR", "cyprus": "CY",
    "czech republic": "CZ", "czechia": "CZ", "denmark": "DK", "dominican republic": "DO",
    "ecuador": "EC", "egypt": "EG", "estonia": "EE", "finland": "FI", "france": "FR",
    "georgia": "GE", "germany": "DE", "greece": "GR", "guatemala": "GT", "hong kong": "HK",
    "hong kong sar": "HK", "hungary": "HU", "iceland": "IS", "india": "IN", "indonesia": "ID",
    "iraq": "IQ", "ireland": "IE", "isle of man": "IM", "israel": "IL", "italy": "IT",
    "japan": "JP", "jordan": "JO", "kazakhstan": "KZ", "kenya": "KE", "kosovo": "XK",
    "kuwait": "KW", "latvia": "LV", "lebanon": "LB", "liechtenstein": "LI", "lithuania": "LT",
    "luxembourg": "LU", "macau": "MO", "macao": "MO", "malaysia": "MY", "malta": "MT",
    "mexico": "MX", "moldova": "MD", "republic of moldova": "MD", "monaco": "MC",
    "mongolia": "MN", "montenegro": "ME", "morocco": "MA", "netherlands": "NL",
    "the netherlands": "NL", "new zealand": "NZ", "nigeria": "NG", "north macedonia": "MK",
    "macedonia": "MK", "norway": "NO", "oman": "OM", "pakistan": "PK", "panama": "PA",
    "paraguay": "PY", "peru": "PE", "philippines": "PH", "poland": "PL", "portugal": "PT",
    "puerto rico": "PR", "qatar": "QA", "romania": "RO", "russia": "RU",
    "russian federation": "RU", "saudi arabia": "SA", "serbia": "RS", "singapore": "SG",
    "slovakia": "SK", "slovenia": "SI", "south africa": "ZA", "south korea": "KR",
    "korea": "KR", "republic of korea": "KR", "korea, republic of": "KR", "spain": "ES",
    "sri lanka": "LK", "sweden": "SE", "switzerland": "CH", "taiwan": "TW", "thailand": "TH",
    "tunisia": "TN", "turkey": "TR", "turkiye": "TR", "türkiye": "TR", "ukraine": "UA",
    "united arab emirates": "AE", "uae": "AE", "united kingdom": "GB", "uk": "GB",
    "great britain": "GB", "england": "GB", "scotland": "GB", "wales": "GB",
    "northern ireland": "GB", "united states": "US", "united states of america": "US",
    "usa": "US", "us": "US", "uruguay": "UY", "uzbekistan": "UZ", "venezuela": "VE",
    "vietnam": "VN", "viet nam": "VN",
}


def _get_country_code_from_name(country_name: Optional[str]) -> Optional[str]:
    """ISO code for a country name as Ookla reports it, or None when unknown."""
    code = _COUNTRY_NAME_TO_CODE.get((country_name or "").lower().strip())
    if code is None and country_name:
        logger.debug(f"Unknown speedtest country name: {country_name!r}")
    return code


async def list_speedtest_servers(secure: bool = True, max_retries: int = 3) -> List[SpeedTestServer]:
    """
    Get list of available speedtest servers using official Ookla CLI.
    
    Args:
        secure: Use HTTPS for server list retrieval (ignored for Ookla CLI)
        max_retries: Maximum number of retry attempts for DNS/network failures
        
    Returns:
        List of SpeedTestServer objects in the CLI's order (Ookla lists the
        servers nearest to the current public IP first; -L has no distance field)
    """
    import shutil
    speedtest_bin = shutil.which("speedtest") or "speedtest"
    cmd = [speedtest_bin, "-L", "-f", "json", "--accept-license", "--accept-gdpr"]
    
    stdout = None
    for attempt in range(max_retries):
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            out, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30,
            )
            
            if process.returncode != 0:
                error_msg = _ookla_error(out, stderr)
                raise Exception(f"Failed to list servers: {error_msg}")
            
            stdout = out
            break  # success: earlier failures no longer matter
            
        except asyncio.CancelledError:
            await _kill_process(process)
            raise
        except asyncio.TimeoutError:
            await _kill_process(process)  # don't leave the CLI running
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                logger.warning(f"Timeout listing servers, retrying in {wait_time}s (attempt {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            raise Exception("Timeout while listing speedtest servers")
        except FileNotFoundError:
            raise Exception("speedtest binary not installed in PATH.")
        except Exception as e:
            error_str = str(e).lower()
            # Check for DNS/network errors that might be transient
            transient = any(keyword in error_str for keyword in
                            ["name resolution", "dns", "temporary failure", "network", "connection"])
            if transient and attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff
                logger.warning(f"DNS/network error listing servers: {e}, retrying in {wait_time}s (attempt {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            # Non-retryable error or out of retries
            raise
    
    if stdout is None:  # max_retries < 1
        raise Exception("Failed to list speedtest servers")
    
    # Parse the output
    try:
        data = json.loads(stdout.decode())
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse speedtest JSON output: {e}")
        logger.debug(f"Raw stdout: {stdout.decode()[:500]}")
        raise Exception(f"Failed to parse server list JSON: {e}")
    
    servers = []
    
    server_list = data.get("servers", [])
    
    for s in server_list:
        server_id = s.get("id")
        name = s.get("name", "")
        location = s.get("location", "")
        country = s.get("country", "")
        distance = s.get("distance")
        
        # Extract country code from country name
        country_code = _get_country_code_from_name(country)
        
        if server_id is not None:
            servers.append(SpeedTestServer(
                server_id=server_id,
                name=name,
                location=location,
                country=country,
                country_code=country_code,
                distance_km=distance,
            ))
    
    # Keep the CLI's order: it is already nearest-first, and -L has no distance to sort by
    return servers


def _is_server_blacklisted(server_id: int) -> bool:
    """Check if a server is currently blacklisted.
    
    A server is considered blacklisted if:
    1. It has reached or exceeded the max failure count threshold
    2. The blacklist period has not expired
    """
    if server_id not in _server_blacklist:
        return False
    
    failure_count, blacklisted_until = _server_blacklist[server_id]
    
    # Check if blacklist has expired
    if datetime.now() > blacklisted_until:
        # Remove expired entry
        del _server_blacklist[server_id]
        return False
    
    # Only consider blacklisted if failure count meets threshold
    return failure_count >= config_manager.config.speedtest_blacklist.max_failures


def _blacklist_server(server_id: int):
    """Add a server to the blacklist or increment failure count."""
    now = datetime.now()
    blacklisted_until = now + timedelta(days=config_manager.config.speedtest_blacklist.duration_days)
    
    if server_id in _server_blacklist:
        failure_count, _ = _server_blacklist[server_id]
        failure_count += 1
    else:
        failure_count = 1
    
    _server_blacklist[server_id] = (failure_count, blacklisted_until)
    logger.debug(f"Server {server_id} blacklisted (failures: {failure_count}) until {blacklisted_until}")


def _clear_expired_blacklist():
    """Remove expired entries from blacklist."""
    now = datetime.now()
    expired = [
        server_id for server_id, (_, blacklisted_until) in _server_blacklist.items()
        if now > blacklisted_until
    ]
    for server_id in expired:
        del _server_blacklist[server_id]


async def get_speedtest_servers_for_country(
    country_code: Optional[str],
    max_servers: int = 3,
    secure: bool = True,
) -> List[int]:
    """
    Get list of speedtest server IDs for a country, nearest first.
    
    Lists servers fresh every time (no cache): Ookla's list depends on the current
    public IP, which changes with every VPN server. Filters out blacklisted servers.
    
    Args:
        country_code: ISO country code (e.g., "DE", "US"); None/unknown -> []
        max_servers: Maximum number of servers to return (for failover)
        secure: Use HTTPS
        
    Returns:
        List of server IDs, closest first (excluding blacklisted servers)
    """
    if not country_code:
        return []
    country_code = country_code.upper()
    
    # Clear expired blacklist entries
    _clear_expired_blacklist()
    
    try:
        all_servers = await list_speedtest_servers(secure=secure)
        
        return [
            s.server_id for s in all_servers
            if s.country_code == country_code and not _is_server_blacklisted(s.server_id)
        ][:max_servers]
        
    except Exception as e:
        # If listing fails, return empty list (will fall back to manual selection)
        logger.warning(f"Failed to list servers for {country_code}: {e}")
        return []


async def run_speedtest(
    server_id: Optional[int] = None,
    secure: bool = True,
    timeout: int = 180,
) -> SpeedTestResult:
    """
    Run official Ookla speedtest CLI and return results.
    
    Args:
        server_id: Specific speedtest server ID to use
        secure: Ignored (Ookla CLI defaults to HTTPS)
        timeout: Maximum test duration in seconds
        
    Returns:
        SpeedTestResult with download/upload/ping
    """
    start_time = datetime.now()
    
    # Get full path to speedtest
    import shutil
    import os
    speedtest_bin = shutil.which("speedtest") or "speedtest"
    
    cmd = [speedtest_bin, "-f", "json", "--accept-license", "--accept-gdpr"]
    if server_id:
        cmd.extend(["-s", str(server_id)])
    
    # Prepare environment - preserve PATH for venv
    env = os.environ.copy()
    
    logger.debug(f"Starting speedtest: server_id={server_id}, timeout={timeout}s")
    logger.debug(f"Command: {' '.join(cmd)}")
    
    process = None
    try:
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        
        stdout, stderr = await asyncio.wait_for(
            process.communicate(),
            timeout=timeout,
        )
        
        duration = (datetime.now() - start_time).total_seconds()
        
        if process.returncode != 0:
            error_msg = _ookla_error(stdout, stderr)
            logger.error(f"Speedtest failed (returncode={process.returncode}): {error_msg}")
            # Check for common Ookla CLI errors
            if "Configuration error" in error_msg or "No servers found" in error_msg:
                error_msg = f"Server {server_id} not available"
            return SpeedTestResult(
                download_mbps=0,
                upload_mbps=0,
                ping_ms=0,
                duration_seconds=duration,
                error=error_msg or "Speedtest failed",
            )
        
        data = json.loads(stdout.decode())
        
        # Bandwidth is returned in bytes/s. Convert to Mbps.
        download_mbps = (data.get("download", {}).get("bandwidth", 0) * 8) / 1_000_000
        upload_mbps = (data.get("upload", {}).get("bandwidth", 0) * 8) / 1_000_000
        ping_ms = data.get("ping", {}).get("latency", 0.0)
        
        # Impossible pings guard
        if ping_ms > 10000:
            return SpeedTestResult(
                download_mbps=download_mbps,
                upload_mbps=upload_mbps,
                ping_ms=0,
                duration_seconds=duration,
                error=f"Speedtest latency test failed (impossible ping: {ping_ms}ms)",
            )
            
        server_info = data.get("server", {})
        client_info = data.get("interface", {})
        isp_info = data.get("isp", "")
        
        server_country_name = server_info.get("country", "")
        
        result = SpeedTestResult(
            download_mbps=download_mbps,
            upload_mbps=upload_mbps,
            ping_ms=ping_ms,
            server_id=server_info.get("id"),
            server_name=server_info.get("name"),
            server_location=f"{server_info.get('location')}, {server_country_name}",
            server_country=_get_country_code_from_name(server_country_name),
            client_ip=client_info.get("externalIp") or client_info.get("internalIp"),
            external_ip=client_info.get("externalIp"),
            client_isp=isp_info,
            duration_seconds=duration,
        )
        
        # Validate results and set appropriate error messages
        if download_mbps == 0 and upload_mbps > 0:
            result.error = f"Download test failed (0.00 Mbps), upload succeeded ({upload_mbps:.2f} Mbps)"
            logger.warning(f"Speedtest partial failure: {result.error}")
        elif download_mbps == 0 and upload_mbps == 0:
            result.error = "Speedtest completed with 0.00 Mbps for both download and upload"
            logger.warning(f"Speedtest complete failure: {result.error}")
        elif download_mbps > 0:
            # Success - no error
            logger.info(f"Speedtest completed: {result.download_mbps:.2f} Mbps down, {result.upload_mbps:.2f} Mbps up, {result.ping_ms:.1f}ms ping (server: {result.server_name}, {result.server_location})")
        
        logger.debug(f"Speedtest details: client_ip={result.client_ip}, client_isp={result.client_isp}, duration={duration:.2f}s")
        
        return result
        
    except asyncio.CancelledError:
        # Job cancelled: never leave the CLI running past VPN teardown
        await _kill_process(process)
        raise
    except asyncio.TimeoutError:
        await _kill_process(process)  # a surviving CLI would keep measuring over the direct line
        duration = (datetime.now() - start_time).total_seconds()
        logger.error(f"Speedtest timed out after {timeout}s")
        return SpeedTestResult(
            download_mbps=0,
            upload_mbps=0,
            ping_ms=0,
            duration_seconds=duration,
            error=f"Speedtest timed out after {timeout}s",
        )
    except FileNotFoundError:
        logger.error("speedtest binary not found in PATH")
        return SpeedTestResult(
            download_mbps=0,
            upload_mbps=0,
            ping_ms=0,
            error="speedtest binary not installed.",
        )
    except json.JSONDecodeError as e:
        logger.error(f"Failed to parse speedtest JSON output: {e}")
        logger.debug(f"Raw stdout: {stdout.decode()[:500] if 'stdout' in locals() else 'N/A'}")
        return SpeedTestResult(
            download_mbps=0,
            upload_mbps=0,
            ping_ms=0,
            error=f"Failed to parse speedtest output: {e}",
        )
    except Exception as e:
        logger.exception(f"Unexpected error during speedtest: {e}")
        return SpeedTestResult(
            download_mbps=0,
            upload_mbps=0,
            ping_ms=0,
            error=str(e),
        )


def _ookla_error(stdout: bytes, stderr: bytes) -> str:
    """Readable error from a failed Ookla run.

    With -f json the CLI reports errors as JSON log lines on stdout; stderr only
    holds the licence banner on a fresh install, which hid the real cause.
    """
    messages = []
    for line in (stdout or b"").decode(errors="ignore").splitlines():
        try:
            entry = json.loads(line)
        except ValueError:
            continue
        if isinstance(entry, dict) and entry.get("type") == "log" and entry.get("message"):
            messages.append(str(entry["message"]).strip())
    if messages:
        return "; ".join(messages)
    text = (stderr or b"").decode(errors="ignore")
    if "License acceptance recorded" in text or "=====" in text:
        text = text.split("Continuing.")[-1] if "Continuing." in text else ""
    if text.strip():
        return text.strip()
    # Nothing recognisable: show what the CLI did print, so failures can be diagnosed
    raw = " ".join((stdout or b"").decode(errors="ignore").split())
    return f"Speedtest failed: {raw[:300]}" if raw else "Speedtest failed (no error output)"


async def _kill_process(process) -> None:
    """Kill and reap a subprocess if it is still running."""
    if process is None or process.returncode is not None:
        return
    try:
        process.kill()
    except ProcessLookupError:
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=5)
    except asyncio.TimeoutError:
        logger.warning(f"Speedtest process {process.pid} did not exit after kill")


async def run_speedtest_for_country(
    country_code: Optional[str],
    secure: bool = True,
    timeout: int = 180,
    max_retries: int = 2,
) -> SpeedTestResult:
    """
    Run speedtest using the nearest server for a specific country.
    
    Uses --list to find the nearest server dynamically, with failover.
    
    Args:
        country_code: ISO country code
        secure: Use HTTPS
        timeout: Test timeout
        max_retries: Maximum number of servers to try (failover)
        
    Returns:
        SpeedTestResult
    """
    country_code = (country_code or "").upper() or None
    
    logger.debug(f"Getting speedtest servers for country: {country_code}")
    # Servers for this country, nearest first (listed via the current VPN exit)
    server_ids = await get_speedtest_servers_for_country(
        country_code,
        max_servers=max_retries + 1,  # Get one extra for failover
        secure=secure,
    )
    
    if not server_ids:
        logger.warning(f"No servers found for {country_code}, falling back to auto-select")
        # Fallback: try without server pinning (let Ookla CLI choose)
        return await run_speedtest(server_id=None, secure=secure, timeout=timeout)
    
    logger.info(f"Found {len(server_ids)} servers for {country_code}, trying up to {max_retries + 1}")
    
    # Try each server in order (failover)
    last_error = None
    last_result = None
    for i, server_id in enumerate(server_ids[:max_retries + 1]):
        logger.debug(f"Attempting speedtest {i+1}/{min(len(server_ids), max_retries + 1)} with server {server_id}")
        result = await run_speedtest(server_id=server_id, secure=secure, timeout=timeout)
        last_result = result
        
        if result.is_success:
            logger.info(f"Speedtest succeeded on attempt {i+1} with server {server_id}")
            # Clear blacklist on success (server is working again)
            if server_id in _server_blacklist:
                del _server_blacklist[server_id]
            return result
        
        # Ensure error is set for logging
        error_msg = result.error or "Unknown error"
        
        # Only Ookla's own "server not available" (No servers / Configuration error)
        # blames the server. Timeouts, 0 Mbps and network errors are usually our tunnel,
        # so they must not blacklist a working Ookla server for days.
        if result.error and "not available" in result.error.lower():
            last_error = result.error
            logger.warning(f"Server {server_id} not available: {result.error}, trying next server")
            _blacklist_server(server_id)
            # Try next server
            continue
        elif result.error and ("Download test failed" in result.error or 
                              "0.00 Mbps" in result.error):
            # 0.00 download is a partial failure - try next server
            last_error = result.error
            logger.warning(f"Server {server_id} returned 0.00 Mbps download: {result.error}, trying next server")
            continue
        else:
            # Other error (timeout, network, etc.) - try next server if available, otherwise return
            last_error = error_msg
            logger.warning(f"Speedtest failed with server {server_id}: {error_msg}")
            if i < len(server_ids) - 1:
                continue
            else:
                # Last server, return the error
                logger.error(f"Speedtest failed with non-recoverable error: {error_msg}")
                return result
    
    # All servers failed - return last error with proper error message
    final_error = last_error or (last_result.error if last_result else "All servers failed")
    if not final_error or final_error == "None":
        final_error = "All servers failed - no specific error available"
    
    logger.error(f"All {len(server_ids)} servers failed for {country_code}. Last error: {final_error}")
    return SpeedTestResult(
        download_mbps=0,
        upload_mbps=0,
        ping_ms=0,
        error=f"All {len(server_ids)} servers failed. Last error: {final_error}",
    )


def clear_server_blacklist():
    """Clear the server blacklist (useful for testing or manual reset)."""
    _server_blacklist.clear()
    logger.info("Server blacklist cleared")


# Synchronous wrapper
def run_speedtest_sync(server_id: Optional[int] = None, secure: bool = True) -> SpeedTestResult:
    """Synchronous wrapper for run_speedtest."""
    return asyncio.run(run_speedtest(server_id=server_id, secure=secure))
