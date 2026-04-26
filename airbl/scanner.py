"""
Enhanced Scanner Module.

Workflow:
1. Parse .conf files to get endpoint IPs
2. Fetch API to get additional server info
3. For each server, lookup exit IPs using DNS (dig commands)
4. Ping all discovered IPs
5. Check responsive IPs against DroneBL
6. Only scan countries present in conf directory
7. Apply US Europe-friendly filter
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
import ipaddress
from pathlib import Path

from .config import settings

logger = logging.getLogger("airbl.scanner")
from .airvpn import AirVPNServer, AirVPNStatus, get_airvpn_status
from .dronebl import DroneBLResult, check_dronebl_batch
from .pinger import PingResult, ping_batch
from .dns_lookup import lookup_server_exit_ips
from .wireguard import (
    WireGuardConfig,
    scan_config_directory,
    get_unique_countries,
    get_scannable_configs,
    US_ALLOWED_LOCATIONS,
)


@dataclass
class ScannedIP:
    """Complete scan result for a single IP."""
    ip: str
    server_name: str
    country_code: str
    country_name: str
    location: str
    is_from_config: bool = False  # True if IP was from .conf file
    is_from_api: bool = False     # True if IP was from API
    is_from_dns: bool = False      # True if IP was from DNS lookup
    dronebl: Optional[DroneBLResult] = None
    ping: Optional[PingResult] = None
    is_responsive: bool = False
    
    @property
    def is_blocked(self) -> bool:
        """Check if IP is blocked by DroneBL."""
        return self.dronebl is not None and self.dronebl.is_listed
    
    @property
    def status(self) -> str:
        """Get overall status string."""
        if self.is_blocked:
            return "BLOCKED"
        if not self.is_responsive:
            return "OFFLINE"
        return "OK"
    
    @property
    def status_color(self) -> str:
        """Get color for status display."""
        if self.is_blocked:
            return "red"
        if not self.is_responsive:
            return "dim"
        return "green"
    
    @property
    def latency_ms(self) -> Optional[float]:
        """Get ping latency if available."""
        if self.ping and self.ping.avg_rtt_ms:
            return self.ping.avg_rtt_ms
        return None
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON."""
        return {
            "ip": self.ip,
            "server_name": self.server_name,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "location": self.location,
            "is_from_config": self.is_from_config,
            "is_blocked": self.is_blocked,
            "is_responsive": self.is_responsive,
            "status": self.status,
            "latency_ms": self.latency_ms,
            "dronebl_reason": self.dronebl.listing_reason if self.dronebl and self.dronebl.is_listed else None,
        }


@dataclass
class ServerScanResult:
    """Complete scan result for an AirVPN server."""
    server_name: str
    country_code: str
    country_name: str
    location: str
    load_percent: int
    users: int
    bandwidth_current: int
    bandwidth_max: int
    config_file: Optional[Path] = None
    wg_pubkey: str = ""
    scanned_ips: list[ScannedIP] = field(default_factory=list)
    scanned_at: datetime = field(default_factory=datetime.now)
    speedtest_result: Optional[dict] = None  # Will hold SpeedTestResult.to_dict()
    exit_ping: Optional[PingResult] = None  # Exit IP ping (DNS)
    entry1_ping: Optional[PingResult] = None  # Entry 1 Ping
    entry3_ping: Optional[PingResult] = None  # Entry 3 Ping
    
    @property
    def total_ips_scanned(self) -> int:
        return len(self.scanned_ips)
    
    @property
    def blocked_ips(self) -> list[ScannedIP]:
        return [ip for ip in self.scanned_ips if ip.is_blocked]
    
    @property
    def blocked_count(self) -> int:
        return len(self.blocked_ips)
    
    @property
    def responsive_ips(self) -> list[ScannedIP]:
        return [ip for ip in self.scanned_ips if ip.is_responsive]
    
    @property
    def responsive_count(self) -> int:
        return len(self.responsive_ips)
    
    @property
    def clean_responsive_ips(self) -> list[ScannedIP]:
        """Get responsive IPs that are NOT blocked."""
        return [ip for ip in self.scanned_ips if ip.is_responsive and not ip.is_blocked]
    
    @property
    def is_clean(self) -> bool:
        """True if server has NO blocked IPs."""
        return self.blocked_count == 0
    
    @property
    def best_ip(self) -> Optional[ScannedIP]:
        """Get the best IP (lowest latency, not blocked)."""
        clean = self.clean_responsive_ips
        if not clean:
            return None
        with_latency = [ip for ip in clean if ip.latency_ms is not None]
        if with_latency:
            return min(with_latency, key=lambda x: x.latency_ms)
        return clean[0]
    
    @property
    def block_percentage(self) -> float:
        """Percentage of responsive IPs that are blocked."""
        if self.responsive_count == 0:
            return 0.0
        return (self.blocked_count / self.responsive_count) * 100
    
    @property
    def score(self) -> float:
        """
        Calculate overall server score for ranking.
        Considers: speedtest results, ping, load, blocked status.
        """
        if not self.is_clean:
            return 0.0
        
        score = 100.0
        
        # Speedtest score (if available)
        # Prefer deviation_score if available (compares to baseline), otherwise use regular score
        if self.speedtest_result:
            if self.speedtest_result.get("deviation_score") is not None:
                # deviation_score is percentage of baseline speed retained
                # e.g., 100 = same as baseline, 50 = half speed, 150 = 50% faster
                # Cap at 100 for display, so 80% of baseline = 80, 120% = 100
                deviation = self.speedtest_result["deviation_score"]
                score = max(0, min(100, deviation))  # Cap at 0-100
            elif self.speedtest_result.get("score"):
                score = self.speedtest_result["score"] * 10  # Scale up
        else:
            # Fallback to ping/load based scoring
            best = self.best_ip
            if best and best.latency_ms:
                # Lower latency = higher score
                ping_score = max(0, 50 - (best.latency_ms / 4))  # 200ms = 0, 0ms = 50
                score = ping_score
            elif self.entry1_ping or self.entry3_ping:
                pings = [p.avg_rtt_ms for p in (self.entry1_ping, self.entry3_ping) if p and p.avg_rtt_ms]
                if pings:
                    best_ping = min(pings)
                    ping_score = max(0, 50 - (best_ping / 4))
                    score = ping_score
                else:
                    # Entry pings exist but none are reachable
                    score = 1
            else:
                # No ping data at all
                score = 1
            
            # Load penalty
            load_penalty = self.load_percent / 5  # 100% load = -20 points
            score -= load_penalty
        
        # Block penalty
        if self.blocked_count > 0:
            score -= self.blocked_count * 5
        
        return max(0, score)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON."""
        return {
            "server_name": self.server_name,
            "country_code": self.country_code,
            "country_name": self.country_name,
            "location": self.location,
            "load_percent": self.load_percent,
            "users": self.users,
            "bandwidth_current": self.bandwidth_current,
            "bandwidth_max": self.bandwidth_max,
            "config_file": str(self.config_file) if self.config_file else None,
            "total_ips_scanned": self.total_ips_scanned,
            "responsive_count": self.responsive_count,
            "blocked_count": self.blocked_count,
            "is_clean": self.is_clean,
            "best_ip": self.best_ip.to_dict() if self.best_ip else None,
            "score": round(self.score, 2),
            "speedtest": self.speedtest_result,
            "scanned_at": self.scanned_at.isoformat(),
            "exit_ping": {
                "ip": self.exit_ping.ip,
                "latency_ms": round(self.exit_ping.avg_rtt_ms, 1) if self.exit_ping and self.exit_ping.avg_rtt_ms else None,
                "is_alive": self.exit_ping.is_alive if self.exit_ping else False,
            } if self.exit_ping else None,
            "entry1_ping": {
                "ip": self.entry1_ping.ip,
                "latency_ms": round(self.entry1_ping.avg_rtt_ms, 1) if self.entry1_ping and self.entry1_ping.avg_rtt_ms else None,
                "is_alive": self.entry1_ping.is_alive if self.entry1_ping else False,
            } if self.entry1_ping else None,
            "entry3_ping": {
                "ip": self.entry3_ping.ip,
                "latency_ms": round(self.entry3_ping.avg_rtt_ms, 1) if self.entry3_ping and self.entry3_ping.avg_rtt_ms else None,
                "is_alive": self.entry3_ping.is_alive if self.entry3_ping else False,
            } if self.entry3_ping else None,
        }


@dataclass
class ScanSummary:
    """Summary of a complete scan across all servers."""
    servers: list[ServerScanResult] = field(default_factory=list)
    countries_scanned: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=datetime.now)
    completed_at: Optional[datetime] = None
    next_scan_at: Optional[datetime] = None
    scan_interval_minutes: int = 120
    
    @property
    def total_servers(self) -> int:
        return len(self.servers)
    
    @property
    def clean_servers(self) -> list[ServerScanResult]:
        return [s for s in self.servers if s.is_clean]
    
    @property
    def clean_servers_count(self) -> int:
        return len(self.clean_servers)
    
    @property
    def blocked_servers(self) -> list[ServerScanResult]:
        return [s for s in self.servers if not s.is_clean]
    
    @property
    def blocked_servers_count(self) -> int:
        return len(self.blocked_servers)
    
    @property
    def total_ips_scanned(self) -> int:
        return sum(s.total_ips_scanned for s in self.servers)
    
    @property
    def total_blocked(self) -> int:
        return sum(s.blocked_count for s in self.servers)
    
    @property
    def total_responsive(self) -> int:
        return sum(s.responsive_count for s in self.servers)
    
    def servers_by_country(self) -> dict[str, list[ServerScanResult]]:
        """Group servers by country, sorted by score."""
        by_country = {}
        for server in self.servers:
            if server.country_code not in by_country:
                by_country[server.country_code] = []
            by_country[server.country_code].append(server)
        
        # Sort each country's servers by score
        for country in by_country:
            by_country[country].sort(key=lambda s: s.score, reverse=True)
        
        return by_country
    
    def best_server_per_country(self) -> dict[str, ServerScanResult]:
        """Get the best clean server for each country."""
        best = {}
        for country, servers in self.servers_by_country().items():
            clean = [s for s in servers if s.is_clean]
            if clean:
                best[country] = clean[0]  # Already sorted by score
        return best
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON."""
        return {
            "total_servers": self.total_servers,
            "clean_servers_count": len(self.clean_servers),
            "blocked_servers_count": len(self.blocked_servers),
            "total_ips_scanned": self.total_ips_scanned,
            "total_responsive": self.total_responsive,
            "total_blocked": self.total_blocked,
            "countries_scanned": self.countries_scanned,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "next_scan_at": self.next_scan_at.isoformat() if self.next_scan_at else None,
            "scan_interval_minutes": self.scan_interval_minutes,
            "servers_by_country": {
                country: [s.to_dict() for s in servers]
                for country, servers in self.servers_by_country().items()
            },
        }


@dataclass
class ScanUpdate:
    """Update yielded during scan_iter for real-time UI updates."""
    summary: ScanSummary
    server: Optional[ServerScanResult] = None
    total_expected: int = 0


class EnhancedScanner:
    """
    Enhanced scanner with .conf file integration.
    
    Workflow:
    1. Scan conf directory for .conf files
    2. Get country list from conf files
    3. Fetch API data for those countries only
    4. For each server, lookup exit IPs using DNS (dig commands)
    5. Ping all discovered IPs
    6. DroneBL check all responsive IPs
    """
    
    def __init__(
        self,
        config_dir: Path = None,
        scan_concurrency: int = 50,
        ping_concurrency: int = 20,
        country_filter: set[str] = None,
        country_exclude: set[str] = None,
        city_filter: dict[str, set[str]] = None,
        server_exclude: set[str] = None,
    ):
        self.config_dir = config_dir or Path("./conf")
        self.scan_concurrency = scan_concurrency
        self.ping_concurrency = ping_concurrency
        
        # Country filtering (set from web UI settings)
        self._country_filter = country_filter or set()  # If set, only scan these countries
        self._country_exclude = country_exclude or set()  # Exclude these countries
        self._server_filter = set()  # If set, only scan these servers (by name)
        self._server_exclude = {s.lower() for s in (server_exclude or set())}  # Always exclude these servers (case-insensitive)
        self._city_filter = city_filter or {}  # country_code -> set of city names
        
        # Cache
        self._configs: list[WireGuardConfig] = []
        self._api_status: Optional[AirVPNStatus] = None
    
    def load_configs(self) -> list[WireGuardConfig]:
        """Load and cache WireGuard configs."""
        self._configs = scan_config_directory(self.config_dir)
        return self._configs
    
    def get_countries_to_scan(self) -> list[str]:
        """Get list of country codes from config files, applying filters."""
        if not self._configs:
            self.load_configs()
        
        countries = set()
        for config in get_scannable_configs(self._configs):
            country = config.country_code.upper()
            
            # Apply include filter
            if self._country_filter and country not in {c.upper() for c in self._country_filter}:
                continue
            
            # Apply exclude filter
            if self._country_exclude and country in {c.upper() for c in self._country_exclude}:
                continue
            
            countries.add(config.country_code)
        
        return sorted(countries)
    
    def get_servers_for_country(
        self,
        country_code: str,
    ) -> list[tuple[WireGuardConfig, Optional[AirVPNServer]]]:
        """
        Get all servers for a country from both conf and API.
        
        Returns list of (config, api_server) tuples.
        Config is required, api_server may be None if not in API.
        """
        if not self._configs:
            self.load_configs()
        
        # Get configs for this country
        country_configs = [
            c for c in get_scannable_configs(self._configs)
            if c.country_code.upper() == country_code.upper()
        ]
        
        # Apply server filter if set
        if self._server_filter:
            country_configs = [
                c for c in country_configs
                if c.server_name.lower() in {s.lower() for s in self._server_filter}
            ]
        
        # Always exclude disabled servers
        if self._server_exclude:
            original_count = len(country_configs)
            country_configs = [
                c for c in country_configs
                if c.server_name.lower() not in self._server_exclude
            ]
            if len(country_configs) < original_count:
                logger.debug(f"Excluded {original_count - len(country_configs)} disabled server(s) for {country_code}")
        
        # Apply city filter if set for this country
        if country_code.upper() in self._city_filter:
            allowed_cities = {city.lower() for city in self._city_filter[country_code.upper()]}
            original_count = len(country_configs)
            country_configs = [
                c for c in country_configs
                if c.city.lower() in allowed_cities
            ]
            logger.debug(f"City filter for {country_code}: {original_count} -> {len(country_configs)} configs (allowed cities: {allowed_cities})")
        
        # Match with API servers by name
        results = []
        
        # Build normalized API server map for faster/better matching
        api_map = {}
        if self._api_status:
            for server in self._api_status.servers:
                # Normalize: lowercase, strip, remove spaces/special chars if needed
                # For now just lower/strip is likely enough, but being robust helps
                key = server.public_name.lower().strip()
                api_map[key] = server
                # Also add version without spaces if different
                no_space_key = key.replace(" ", "")
                if no_space_key != key:
                    api_map[no_space_key] = server

        for config in country_configs:
            api_server = None
            if self._api_status:
                search_key = config.server_name.lower().strip()
                api_server = api_map.get(search_key)
                
                # Try fallback without spaces
                if not api_server and " " in search_key:
                    api_server = api_map.get(search_key.replace(" ", ""))
                    
                if not api_server:
                     # Debug logging for valid/active servers to trace missing load issues
                     logger.debug(f"API match failed for config server: '{config.server_name}' (Search key: '{search_key}'). Available API servers for {country_code}: {list(api_map.keys())[:5]}...")

            results.append((config, api_server))
        
        return results
    
    async def scan_server(
        self,
        config: WireGuardConfig,
        api_server: Optional[AirVPNServer] = None,
        progress_callback=None,
    ) -> ServerScanResult:
        """
        Scan a single server.
        
        1. Get all IPs from config + API
        2. Lookup exit IPs using DNS (dig commands)
        3. Ping all discovered IPs
        4. DroneBL check all responsive IPs
        """
        server_name = config.server_name
        
        # Validate and collect IPv4 IPs only
        # Prioritize config IP, then add API IPs
        config_ip = None
        api_ips = []
        
        # Validate endpoint IP is IPv4
        try:
            endpoint_addr = ipaddress.ip_address(config.endpoint_ip)
            if isinstance(endpoint_addr, ipaddress.IPv4Address):
                config_ip = config.endpoint_ip
            else:
                logger.warning(f"{server_name} endpoint IP is not IPv4: {config.endpoint_ip}, skipping")
        except ValueError:
            logger.warning(f"{server_name} has invalid endpoint IP: {config.endpoint_ip}, skipping")
        
        # Add API IPv4 addresses (excluding config IP if it matches)
        if api_server:
            for ip in api_server.all_ipv4:
                try:
                    addr = ipaddress.ip_address(ip)
                    if isinstance(addr, ipaddress.IPv4Address):
                        # Skip if this IP matches the config IP
                        if ip != config_ip:
                            api_ips.append(ip)
                except ValueError:
                    logger.warning(f"Invalid IPv4 from API for {server_name}: {ip}")
        
        # Build entry IPs list from API (entry 1 and 3)
        entry1_ip = api_server.ip_v4_in1 if api_server else None
        entry3_ip = api_server.ip_v4_in3 if api_server else None
        
        # Override with matching config endpoint if applicable
        if config_ip:
            if config.entry_number == 1:
                entry1_ip = config_ip
            elif config.entry_number == 3:
                entry3_ip = config_ip
        
        entry_ips_list = [ip for ip in [entry1_ip, entry3_ip] if ip]
        
        # Ping entry IPs
        entry1_ping_result = None
        entry3_ping_result = None
        
        if entry_ips_list:
            if progress_callback:
                if asyncio.iscoroutinefunction(progress_callback):
                    await progress_callback(server_name, "entry ping", 0, len(entry_ips_list))
                else:
                    progress_callback(server_name, "entry ping", 0, len(entry_ips_list))
            
            entry_ping_results = await ping_batch(
                entry_ips_list,
                concurrency=self.ping_concurrency,
            )
            
            for ping_result in entry_ping_results:
                if entry1_ip and ping_result.ip == entry1_ip:
                    entry1_ping_result = ping_result
                elif entry3_ip and ping_result.ip == entry3_ip:
                    entry3_ping_result = ping_result
        
        # Lookup exit IPs using DNS (replaces subnet scanning)
        if progress_callback:
            if asyncio.iscoroutinefunction(progress_callback):
                await progress_callback(server_name, "DNS lookup", 0, 1)
            else:
                progress_callback(server_name, "DNS lookup", 0, 1)
        
        # Query DNS for server exit IPs
        dns_ips = await lookup_server_exit_ips(server_name)
        
        logger.debug(f"DNS lookup for {server_name}: found {len(dns_ips)} exit IPs: {dns_ips}")
        
        # Only check DNS exit IPs in DroneBL (not config/API IPs)
        if not dns_ips:
            logger.warning(f"No DNS exit IPs found for server {server_name}")
            return ServerScanResult(
                server_name=server_name,
                country_code=config.country_code,
                country_name=config.country_name,
                location=config.city,
                load_percent=api_server.load_percent if api_server else 0,
                users=api_server.users if api_server else 0,
                bandwidth_current=api_server.bandwidth_current if api_server else 0,
                bandwidth_max=api_server.bandwidth_max if api_server else 0,
                config_file=config.file_path,
                scanned_ips=[],
                exit_ping=None,
                entry1_ping=entry1_ping_result,
                entry3_ping=entry3_ping_result,
            )
        
        # Ping DNS exit IPs to check responsiveness
        exit_ping_results = []
        if dns_ips:
            if progress_callback:
                if asyncio.iscoroutinefunction(progress_callback):
                    await progress_callback(server_name, "exit ping", 0, len(dns_ips))
                else:
                    progress_callback(server_name, "exit ping", 0, len(dns_ips))
            
            exit_ping_results = await ping_batch(
                list(dns_ips),
                concurrency=self.ping_concurrency,
            )
        
        ping_map = {result.ip: result for result in exit_ping_results}
        
        # Filter to only responsive DNS IPs (those that respond to ping)
        responsive_dns_ips = {result.ip for result in exit_ping_results if result.is_alive}
        
        # Get the best exit ping (lowest latency, or first if all same)
        exit_ping = None
        if exit_ping_results:
            # Find the best exit ping (lowest latency among alive ones, or first if none alive)
            alive_exit_pings = [p for p in exit_ping_results if p.is_alive]
            if alive_exit_pings:
                exit_ping = min(alive_exit_pings, key=lambda p: p.avg_rtt_ms if p.avg_rtt_ms else float('inf'))
                logger.debug(f"Best exit ping for {server_name}: {exit_ping.ip} ({exit_ping.avg_rtt_ms:.1f}ms)")
            else:
                # If none are alive, use the first one anyway but log a warning
                exit_ping = exit_ping_results[0]
                logger.warning(f"All exit IPs failed to respond for {server_name}. IPs tried: {[r.ip for r in exit_ping_results]}, errors: {[r.error for r in exit_ping_results]}")
        
        # If no responsive DNS IPs, return empty result
        if not responsive_dns_ips:
            return ServerScanResult(
                server_name=server_name,
                country_code=config.country_code,
                country_name=config.country_name,
                location=config.city,
                load_percent=api_server.load_percent if api_server else 0,
                users=api_server.users if api_server else 0,
                bandwidth_current=api_server.bandwidth_current if api_server else 0,
                bandwidth_max=api_server.bandwidth_max if api_server else 0,
                config_file=config.file_path,
                scanned_ips=[],
                exit_ping=exit_ping,
                entry1_ping=entry1_ping_result,
                entry3_ping=entry3_ping_result,
            )
        
        # DroneBL check only on responsive DNS exit IPs
        if progress_callback:
            if asyncio.iscoroutinefunction(progress_callback):
                await progress_callback(server_name, "DroneBL check", 0, len(responsive_dns_ips))
            else:
                progress_callback(server_name, "DroneBL check", 0, len(responsive_dns_ips))
        
        dronebl_results = await check_dronebl_batch(
            list(responsive_dns_ips),
            concurrency=self.scan_concurrency,
        )
        dronebl_map = {r.ip: r for r in dronebl_results}
        
        # Build scanned IPs list from responsive DNS exit IPs only
        scanned_ips = []
        for ip in responsive_dns_ips:
            scanned_ip = ScannedIP(
                ip=ip,
                server_name=server_name,
                country_code=config.country_code,
                country_name=config.country_name,
                location=config.city,
                is_from_config=(ip == config.endpoint_ip),
                is_from_api=(api_server and ip in api_server.all_ipv4),
                is_from_dns=(ip in dns_ips),
                dronebl=dronebl_map.get(ip),
                ping=ping_map.get(ip),
                is_responsive=True,  # All IPs in this list are responsive
            )
            scanned_ips.append(scanned_ip)
        
        return ServerScanResult(
            server_name=server_name,
            country_code=config.country_code,
            country_name=config.country_name,
            location=config.city,
            load_percent=api_server.load_percent if api_server else 0,
            users=api_server.users if api_server else 0,
            bandwidth_current=api_server.bandwidth_current if api_server else 0,
            bandwidth_max=api_server.bandwidth_max if api_server else 0,
            config_file=config.file_path,
            wg_pubkey=config.public_key or "",
            scanned_ips=scanned_ips,
            exit_ping=exit_ping,
            entry1_ping=entry1_ping_result,
            entry3_ping=entry3_ping_result,
        )
    
    async def scan_all(
        self,
        progress_callback=None,
    ) -> ScanSummary:
        """
        Scan all servers from config files.
        
        Only scans countries present in conf directory.
        Applies US Europe-friendly filter.
        """
        # Load configs
        self.load_configs()
        
        if not self._configs:
            return ScanSummary(
                countries_scanned=[],
            )
        
        # Fetch API data
        if progress_callback:
            if asyncio.iscoroutinefunction(progress_callback):
                await progress_callback("Fetching API", "initializing", 0, 1)
            else:
                progress_callback("Fetching API", "initializing", 0, 1)
        
        try:
            self._api_status = await get_airvpn_status()
        except Exception as e:
            logger.warning(f"Failed to fetch API: {e}")
            self._api_status = None
        
        # Get countries to scan
        countries = self.get_countries_to_scan()
        
        if progress_callback:
            if asyncio.iscoroutinefunction(progress_callback):
                await progress_callback("Scanning", "starting", 0, len(countries))
            else:
                progress_callback("Scanning", "starting", 0, len(countries))
        
        summary = ScanSummary(countries_scanned=countries)
        
        # Scan each country's servers
        server_index = 0
        total_servers = sum(
            len(self.get_servers_for_country(c)) for c in countries
        )
        
        for country_code in countries:
            servers = self.get_servers_for_country(country_code)
            
            for config, api_server in servers:
                server_index += 1
                
                if progress_callback:
                    if asyncio.iscoroutinefunction(progress_callback):
                        await progress_callback(
                            config.server_name,
                            f"scanning ({server_index}/{total_servers})",
                            server_index,
                            total_servers,
                        )
                    else:
                        progress_callback(
                            config.server_name,
                            f"scanning ({server_index}/{total_servers})",
                            server_index,
                            total_servers,
                        )
                
                try:
                    result = await self.scan_server(config, api_server)
                    summary.servers.append(result)
                except Exception as e:
                    logger.error(f"Error scanning {config.server_name}: {e}")
        
        summary.completed_at = datetime.now()
        return summary
    
    async def scan_iter(self) -> "AsyncGenerator[ScanUpdate, None]":
        """
        Async generator that yields updates after each server scan.
        
        Yields ScanUpdate objects with summary and the just-scanned server.
        This allows real-time UI updates during scanning.
        """
        # Load configs
        self.load_configs()
        
        if not self._configs:
            yield ScanUpdate(
                summary=ScanSummary(countries_scanned=[]),
                server=None,
                total_expected=0
            )
            return
        
        # Fetch API data
        try:
            self._api_status = await get_airvpn_status()
        except Exception as e:
            logger.warning(f"Failed to fetch API: {e}")
            self._api_status = None
        
        # Get countries to scan
        countries = self.get_countries_to_scan()
        
        summary = ScanSummary(countries_scanned=countries)
        
        # Calculate total servers
        total_servers = sum(
            len(self.get_servers_for_country(c)) for c in countries
        )
        
        server_index = 0
        
        for country_code in countries:
            servers = self.get_servers_for_country(country_code)
            
            for config, api_server in servers:
                server_index += 1
                
                try:
                    result = await self.scan_server(config, api_server)
                    summary.servers.append(result)
                    
                    yield ScanUpdate(
                        summary=summary,
                        server=result,
                        total_expected=total_servers
                    )
                except Exception as e:
                    logger.error(f"Error scanning {config.server_name}: {e}")
        
        summary.completed_at = datetime.now()


# Convenience function
async def run_full_scan(config_dir: Path = None) -> ScanSummary:
    """Run a full scan of all servers in config directory."""
    scanner = EnhancedScanner(config_dir=config_dir)
    return await scanner.scan_all()
