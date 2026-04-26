"""
AirVPN API Client Module.

Fetches server information from the AirVPN status API.
"""

import asyncio
from dataclasses import dataclass, field
from typing import Optional
from datetime import datetime
import ipaddress

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from .config import settings


@dataclass
class AirVPNServer:
    """Represents an AirVPN server."""
    public_name: str
    country_name: str
    country_code: str
    location: str
    continent: str
    bandwidth_current: int  # Current bandwidth in Mbit/s
    bandwidth_max: int       # Max bandwidth in Mbit/s
    users: int               # Current connected users
    load_percent: int        # Current load percentage
    
    # IPv4 entry points ONLY 1 and 3
    ip_v4_in1: str
    ip_v4_in3: Optional[str] = None
    
    # IPv6 entry points ONLY 1 and 3
    ip_v6_in1: Optional[str] = None
    ip_v6_in3: Optional[str] = None
    
    health: str = "unknown"
    
    @property
    def all_ipv4(self) -> list[str]:
        """Get all IPv4 addresses for this server (Entry 1 and 3)."""
        ips = [self.ip_v4_in1]
        if self.ip_v4_in3:
            ips.append(self.ip_v4_in3)
        return ips
    
    @property
    def load_color(self) -> str:
        """Return color based on load percentage."""
        if self.load_percent < 50:
            return "green"
        elif self.load_percent < 80:
            return "yellow"
        else:
            return "red"
    
    @property
    def primary_subnet(self) -> str:
        """Get the /24 subnet for the primary IP."""
        try:
            network = ipaddress.ip_network(f"{self.ip_v4_in1}/24", strict=False)
            return str(network)
        except ValueError:
            return f"{self.ip_v4_in1}/24"
    
    def get_subnet_ips(self, mask: int = 24) -> list[str]:
        """
        Generate all IPs in the server's subnet.
        
        Args:
            mask: Subnet mask (default /24 = 256 IPs)
            
        Returns:
            List of IP addresses in the subnet
        """
        try:
            network = ipaddress.ip_network(f"{self.ip_v4_in1}/{mask}", strict=False)
            # Skip network and broadcast addresses for /24
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return self.all_ipv4


@dataclass
class AirVPNCountry:
    """Aggregated country information."""
    country_name: str
    country_code: str
    server_best: str
    bandwidth_current: int
    bandwidth_max: int
    users: int
    server_count: int
    load_percent: int
    health: str = "ok"


@dataclass  
class AirVPNStatus:
    """Complete AirVPN status response."""
    servers: list[AirVPNServer]
    countries: list[AirVPNCountry]
    fetched_at: datetime = field(default_factory=datetime.now)
    
    @property
    def total_servers(self) -> int:
        return len(self.servers)
    
    @property
    def total_users(self) -> int:
        return sum(s.users for s in self.servers)
    
    def servers_by_country(self, country_code: str) -> list[AirVPNServer]:
        """Get all servers for a specific country."""
        return [s for s in self.servers if s.country_code.lower() == country_code.lower()]
    
    def servers_by_continent(self, continent: str) -> list[AirVPNServer]:
        """Get all servers for a specific continent."""
        return [s for s in self.servers if s.continent.lower() == continent.lower()]


class AirVPNClient:
    """Async client for AirVPN API."""
    
    def __init__(self, api_url: str = None):
        self.api_url = api_url or settings.airvpn_api_url
        self._client: Optional[httpx.AsyncClient] = None
    
    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=30.0)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._client:
            await self._client.aclose()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def fetch_status(self) -> AirVPNStatus:
        """
        Fetch current server status from AirVPN API.
        
        Returns:
            AirVPNStatus object with servers and countries
        """
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=30.0)
        
        response = await self._client.get(self.api_url)
        response.raise_for_status()
        data = response.json()
        
        # Parse servers
        servers = []
        for s in data.get("servers", []):
            # Skip aggregated entries (countries/continents have "server_best" key)
            if "server_best" in s:
                continue
            
            server = AirVPNServer(
                public_name=s.get("public_name", "Unknown"),
                country_name=s.get("country_name", "Unknown"),
                country_code=s.get("country_code", "??"),
                location=s.get("location", "Unknown"),
                continent=s.get("continent", "Unknown"),
                bandwidth_current=s.get("bw", 0),
                bandwidth_max=s.get("bw_max", 0),
                users=s.get("users", 0),
                load_percent=s.get("currentload", 0),
                ip_v4_in1=s.get("ip_v4_in1", ""),
                ip_v4_in3=s.get("ip_v4_in3"),
                ip_v6_in1=s.get("ip_v6_in1"),
                ip_v6_in3=s.get("ip_v6_in3"),
                health=s.get("health", "unknown"),
            )
            servers.append(server)
        
        # Parse countries
        countries = []
        for c in data.get("countries", []):
            country = AirVPNCountry(
                country_name=c.get("country_name", "Unknown"),
                country_code=c.get("country_code", "??"),
                server_best=c.get("server_best", "Unknown"),
                bandwidth_current=c.get("bw", 0),
                bandwidth_max=c.get("bw_max", 0),
                users=c.get("users", 0),
                server_count=c.get("servers", 0),
                load_percent=c.get("currentload", 0),
                health=c.get("health", "unknown"),
            )
            countries.append(country)
        
        return AirVPNStatus(servers=servers, countries=countries)


async def get_airvpn_status() -> AirVPNStatus:
    """Convenience function to fetch AirVPN status."""
    async with AirVPNClient() as client:
        return await client.fetch_status()


# Synchronous wrapper
def get_airvpn_status_sync() -> AirVPNStatus:
    """Synchronous wrapper for get_airvpn_status."""
    return asyncio.run(get_airvpn_status())

