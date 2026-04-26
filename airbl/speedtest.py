"""
Speedtest Module with Country-Specific Server Pinning.

Uses speedtest-cli --list to find nearest servers dynamically,
with failover support for consistent results.
"""

import asyncio
import json
import logging
import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional, Dict, List

from .config import settings, config_manager

logger = logging.getLogger("airbl.speedtest")

# Cache for country -> server IDs (with failover list)
_country_server_cache: Dict[str, List[int]] = {}

# Server blacklist: server_id -> (failure_count, blacklisted_until)
_server_blacklist: Dict[int, tuple[int, datetime]] = {}


@dataclass
class SpeedTestServer:
    """Represents a speedtest server from --list output."""
    server_id: int
    name: str
    location: str
    country: str
    country_code: str
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
            "client_ip": self.client_ip,
            "tested_at": self.tested_at.isoformat() if self.tested_at else None,
            "score": round(self.score, 2),
            "error": self.error,
        }


def _get_country_code_from_name(country_name: str) -> str:
    """Simple mapping from country name to ISO code."""
    # Common country name mappings
    country_map = {
        "germany": "DE",
        "united states": "US",
        "usa": "US",
        "united kingdom": "GB",
        "uk": "GB",
        "france": "FR",
        "italy": "IT",
        "spain": "ES",
        "netherlands": "NL",
        "belgium": "BE",
        "switzerland": "CH",
        "austria": "AT",
        "sweden": "SE",
        "norway": "NO",
        "denmark": "DK",
        "finland": "FI",
        "poland": "PL",
        "portugal": "PT",
        "greece": "GR",
        "czech republic": "CZ",
        "czechia": "CZ",
        "romania": "RO",
        "hungary": "HU",
        "ireland": "IE",
        "canada": "CA",
        "australia": "AU",
        "japan": "JP",
        "south korea": "KR",
        "singapore": "SG",
        "hong kong": "HK",
        "brazil": "BR",
        "mexico": "MX",
        "india": "IN",
        "thailand": "TH",
        "malaysia": "MY",
        "indonesia": "ID",
        "philippines": "PH",
        "vietnam": "VN",
        "taiwan": "TW",
        "new zealand": "NZ",
        "south africa": "ZA",
        "turkey": "TR",
        "israel": "IL",
        "uae": "AE",
        "united arab emirates": "AE",
        "luxembourg": "LU",
        "latvia": "LV",
        "lithuania": "LT",
        "slovakia": "SK",
        "slovenia": "SI",
        "croatia": "HR",
        "serbia": "RS",
        "ukraine": "UA",
        "bulgaria": "BG",
    }
    
    country_lower = country_name.lower().strip()
    return country_map.get(country_lower, country_name[:2].upper() if len(country_name) >= 2 else "XX")


async def list_speedtest_servers(secure: bool = True, max_retries: int = 3) -> List[SpeedTestServer]:
    """
    Get list of available speedtest servers using --list.
    
    Args:
        secure: Use HTTPS for server list retrieval
        max_retries: Maximum number of retry attempts for DNS/network failures
        
    Returns:
        List of SpeedTestServer objects sorted by distance
    """
    cmd = ["speedtest-cli", "--list"]
    if secure:
        cmd.append("--secure")
    
    last_exception = None
    for attempt in range(max_retries):
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=30,
            )
            
            if process.returncode != 0:
                error_msg = stderr.decode().strip()
                raise Exception(f"Failed to list servers: {error_msg}")
            
            # Success - break out of retry loop
            break
            
        except asyncio.TimeoutError:
            last_exception = Exception("Timeout while listing speedtest servers")
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
                logger.warning(f"Timeout listing servers, retrying in {wait_time}s (attempt {attempt+1}/{max_retries})")
                await asyncio.sleep(wait_time)
                continue
            raise last_exception
        except FileNotFoundError:
            raise Exception("speedtest-cli not installed. Run: pip install speedtest-cli")
        except Exception as e:
            error_str = str(e).lower()
            # Check for DNS/network errors that might be transient
            if any(keyword in error_str for keyword in ["name resolution", "dns", "temporary failure", "network", "connection"]):
                last_exception = e
                if attempt < max_retries - 1:
                    wait_time = 2 ** attempt  # Exponential backoff
                    logger.warning(f"DNS/network error listing servers: {e}, retrying in {wait_time}s (attempt {attempt+1}/{max_retries})")
                    await asyncio.sleep(wait_time)
                    continue
            # Non-retryable error or out of retries
            raise
    
    # If we get here, we had success on last attempt
    if last_exception:
        raise last_exception
    
    # Parse the output
    output = stdout.decode("utf-8", errors="ignore")
    servers = []
    
    # Parse output format: "12345) Server Name (Location, Country) [distance] km"
    # Example: "4018) Vodafone GmbH (Frankfurt, Germany) [12.34] km"
    pattern = re.compile(
        r'(\d+)\)\s+(.+?)\s+\(([^,]+),\s+([^)]+)\)\s+(?:\[([\d.]+)\s*km\])?',
        re.IGNORECASE
    )
    
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("Retrieving") or line.startswith("Selecting"):
            continue
        
        match = pattern.match(line)
        if match:
            server_id = int(match.group(1))
            name = match.group(2).strip()
            location = match.group(3).strip()
            country = match.group(4).strip()
            distance_str = match.group(5)
            distance = float(distance_str) if distance_str else None
            
            # Extract country code from country name
            country_code = _get_country_code_from_name(country)
            
            servers.append(SpeedTestServer(
                server_id=server_id,
                name=name,
                location=location,
                country=country,
                country_code=country_code,
                distance_km=distance,
            ))
    
    # Sort by distance (closest first), then by server ID
    servers.sort(key=lambda s: (s.distance_km or float('inf'), s.server_id))
    
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
    country_code: str,
    max_servers: int = 3,
    secure: bool = True,
    use_cache: bool = True,
) -> List[int]:
    """
    Get list of speedtest server IDs for a country, sorted by distance.
    
    Uses --list to find nearest servers dynamically, with caching.
    Filters out blacklisted servers.
    
    Args:
        country_code: ISO country code (e.g., "DE", "US")
        max_servers: Maximum number of servers to return (for failover)
        secure: Use HTTPS
        use_cache: Use cached results if available
        
    Returns:
        List of server IDs, closest first (excluding blacklisted servers)
    """
    country_code = country_code.upper()
    
    # Clear expired blacklist entries
    _clear_expired_blacklist()
    
    # Check cache first
    if use_cache and country_code in _country_server_cache:
        cached = _country_server_cache[country_code]
        # Filter out blacklisted servers
        filtered = [sid for sid in cached if not _is_server_blacklisted(sid)]
        return filtered[:max_servers]
    
    try:
        # Get all servers
        all_servers = await list_speedtest_servers(secure=secure)
        
        # Filter by country code
        country_servers = [
            s for s in all_servers
            if s.country_code.upper() == country_code
        ]
        
        if not country_servers:
            # Fallback: try to find by country name similarity
            # This is a simple fallback - could be improved
            return []
        
        # Extract server IDs, sorted by distance, excluding blacklisted
        server_ids = [
            s.server_id for s in country_servers
            if not _is_server_blacklisted(s.server_id)
        ][:max_servers]
        
        # Cache the results (including blacklisted for future reference)
        _country_server_cache[country_code] = [s.server_id for s in country_servers[:max_servers * 2]]
        
        return server_ids
        
    except Exception as e:
        # If listing fails, return empty list (will fall back to manual selection)
        logger.warning(f"Failed to list servers for {country_code}: {e}")
        return []


async def run_speedtest(
    server_id: Optional[int] = None,
    secure: bool = True,
    timeout: int = 180,
    namespace = None,
) -> SpeedTestResult:
    """
    Run speedtest-cli and return results.
    
    Args:
        server_id: Specific speedtest server ID to use
        secure: Use HTTPS for test (recommended)
        timeout: Maximum test duration in seconds
        namespace: Optional NetworkNamespace to run inside
        
    Returns:
        SpeedTestResult with download/upload/ping
    """
    start_time = datetime.now()
    
    # Get full path to speedtest-cli (in case we're in a venv)
    import shutil
    import os
    speedtest_bin = shutil.which("speedtest-cli") or "speedtest-cli"
    
    cmd = [speedtest_bin, "--json"]
    if secure:
        cmd.append("--secure")
    if server_id:
        cmd.extend(["--server", str(server_id)])
    
    # Prepare environment - preserve PATH for venv
    env = os.environ.copy()
    
    # Wrap in namespace if provided
    original_cmd = list(cmd)
    if namespace and getattr(namespace, 'exists', False):
        # We need to run speedtest-cli inside the namespace using ip netns exec
        
        # Check if running as root or sudo is available
        import shutil
        is_root = os.geteuid() == 0
        sudo_path = shutil.which("sudo")
        
        ns_cmd = ["ip", "netns", "exec", namespace.name]
        
        if not is_root and sudo_path:
            # Use sudo if not root
            cmd = [sudo_path, "-E"] + ns_cmd + cmd
        else:
            # If root or no sudo, try running directly
            cmd = ns_cmd + cmd
    
    logger.debug(f"Starting speedtest: server_id={server_id}, secure={secure}, timeout={timeout}s")
    logger.debug(f"Command: {' '.join(cmd)}")
    
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
            error_msg = stderr.decode().strip()
            logger.error(f"Speedtest failed (returncode={process.returncode}): {error_msg}")
            # Check for "No matched servers" error
            if "No matched servers" in error_msg or "ERROR: No matched servers" in error_msg:
                error_msg = f"Server {server_id} not available"
            return SpeedTestResult(
                download_mbps=0,
                upload_mbps=0,
                ping_ms=0,
                duration_seconds=duration,
                error=error_msg or "Speedtest failed",
            )
        
        data = json.loads(stdout.decode())
        
        download_mbps = data["download"] / 1_000_000  # bits to Mbps
        upload_mbps = data["upload"] / 1_000_000
        ping_ms = data["ping"]
        
        result = SpeedTestResult(
            download_mbps=download_mbps,
            upload_mbps=upload_mbps,
            ping_ms=ping_ms,
            server_id=data["server"]["id"],
            server_name=data["server"]["sponsor"],
            server_location=f"{data['server']['name']}, {data['server']['country']}",
            server_country=data["server"]["cc"],
            client_ip=data["client"]["ip"],
            client_isp=data["client"]["isp"],
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
        
    except asyncio.TimeoutError:
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
        logger.error("speedtest-cli not found in PATH")
        return SpeedTestResult(
            download_mbps=0,
            upload_mbps=0,
            ping_ms=0,
            error="speedtest-cli not installed. Run: pip install speedtest-cli",
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


async def run_speedtest_for_country(
    country_code: str,
    secure: bool = True,
    timeout: int = 180,
    max_retries: int = 2,
    namespace = None,
) -> SpeedTestResult:
    """
    Run speedtest using the nearest server for a specific country.
    
    Uses --list to find the nearest server dynamically, with failover.
    
    Args:
        country_code: ISO country code
        secure: Use HTTPS
        timeout: Test timeout
        max_retries: Maximum number of servers to try (failover)
        namespace: Optional namespace
        
    Returns:
        SpeedTestResult
    """
    country_code = country_code.upper()
    
    logger.debug(f"Getting speedtest servers for country: {country_code}")
    # Get list of servers for this country (sorted by distance)
    # Disable cache when running through VPN to ensure we get servers available from VPN exit IP
    server_ids = await get_speedtest_servers_for_country(
        country_code,
        max_servers=max_retries + 1,  # Get one extra for failover
        secure=secure,
        use_cache=False,  # Don't use cache when running through VPN
    )
    
    if not server_ids:
        logger.warning(f"No servers found for {country_code}, falling back to auto-select")
        # Fallback: try without server pinning (let speedtest-cli choose)
        return await run_speedtest(server_id=None, secure=secure, timeout=timeout, namespace=namespace)
    
    logger.info(f"Found {len(server_ids)} servers for {country_code}, trying up to {max_retries + 1}")
    
    # Try each server in order (failover)
    last_error = None
    last_result = None
    for i, server_id in enumerate(server_ids[:max_retries + 1]):
        logger.debug(f"Attempting speedtest {i+1}/{min(len(server_ids), max_retries + 1)} with server {server_id}")
        result = await run_speedtest(server_id=server_id, secure=secure, timeout=timeout, namespace=namespace)
        last_result = result
        
        if result.is_success:
            logger.info(f"Speedtest succeeded on attempt {i+1} with server {server_id}")
            # Clear blacklist on success (server is working again)
            if server_id in _server_blacklist:
                del _server_blacklist[server_id]
            return result
        
        # Ensure error is set for logging
        error_msg = result.error or "Unknown error"
        
        # Check if it's a "server not available" error
        if result.error and ("not available" in result.error.lower() or 
                           "No matched servers" in result.error):
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
            _blacklist_server(server_id)
            continue
        else:
            # Other error (timeout, network, etc.) - try next server if available, otherwise return
            last_error = error_msg
            logger.warning(f"Speedtest failed with server {server_id}: {error_msg}")
            if i < len(server_ids) - 1:
                # Try next server
                _blacklist_server(server_id)
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


def clear_server_cache():
    """Clear the server ID cache (useful for testing or refresh)."""
    global _country_server_cache
    _country_server_cache.clear()


def clear_server_blacklist():
    """Clear the server blacklist (useful for testing or manual reset)."""
    global _server_blacklist
    _server_blacklist.clear()
    logger.info("Server blacklist cleared")


def get_available_countries() -> list[str]:
    """Get list of countries with configured speedtest servers."""
    # This is now dynamic, but we keep it for backward compatibility
    return list(_country_server_cache.keys())


# Synchronous wrapper
def run_speedtest_sync(server_id: Optional[int] = None, secure: bool = True) -> SpeedTestResult:
    """Synchronous wrapper for run_speedtest."""
    return asyncio.run(run_speedtest(server_id=server_id, secure=secure))
