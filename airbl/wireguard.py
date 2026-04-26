"""
WireGuard Configuration Parser for AirVPN/Hummingbird.

Parses .conf files to extract server information and endpoint IPs.
File naming convention: AirVPN_AT-Vienna_Alderamin_UDP-1637-Entry3.conf
"""

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import ipaddress

logger = logging.getLogger("airbl.wireguard")


# Country code mapping for AirVPN naming
COUNTRY_CODE_MAP = {
    "AT": "Austria",
    "AU": "Australia",
    "BE": "Belgium",
    "BR": "Brazil",
    "BG": "Bulgaria",
    "CA": "Canada",
    "CZ": "Czech Republic",
    "DK": "Denmark",
    "FI": "Finland",
    "FR": "France",
    "DE": "Germany",
    "HK": "Hong Kong",
    "HU": "Hungary",
    "IN": "India",
    "IE": "Ireland",
    "IL": "Israel",
    "IT": "Italy",
    "JP": "Japan",
    "LV": "Latvia",
    "LT": "Lithuania",
    "LU": "Luxembourg",
    "MY": "Malaysia",
    "MX": "Mexico",
    "NL": "Netherlands",
    "NZ": "New Zealand",
    "NO": "Norway",
    "PL": "Poland",
    "PT": "Portugal",
    "RO": "Romania",
    "RS": "Serbia",
    "SG": "Singapore",
    "SK": "Slovakia",
    "ZA": "South Africa",
    "KR": "South Korea",
    "ES": "Spain",
    "SE": "Sweden",
    "CH": "Switzerland",
    "TW": "Taiwan",
    "TH": "Thailand",
    "TR": "Turkey",
    "UA": "Ukraine",
    "AE": "UAE",
    "GB": "United Kingdom",
    "UK": "United Kingdom",
    "US": "United States",
    "USA": "United States",
}

# US cities closer to Europe (allowed for scanning)
US_ALLOWED_LOCATIONS = [
    "newyork", "new york", "ny",
    "chicago", "chi",
    "dallas", "texas", "tx",
    "atlanta", "atl",
    "washington", "dc",
    "boston",
    "philadelphia",
]

# US cities to exclude (too far from Europe)
US_EXCLUDED_LOCATIONS = [
    "miami", "fl", "florida",
    "losangeles", "los angeles", "la", "california", "ca",
    "seattle", "wa", "washington state",
    "portland", "oregon", "or",
    "phoenix", "az", "arizona",
    "denver", "co", "colorado",
    "sanfrancisco", "san francisco", "sf",
    "sanjose", "san jose",
    "lasvegas", "las vegas", "nevada", "nv",
    "honolulu", "hawaii", "hi",
]


@dataclass
class WireGuardConfig:
    """Parsed WireGuard configuration."""
    file_path: Path
    filename: str
    
    # Extracted from filename
    country_code: str
    country_name: str
    city: str
    server_name: str
    protocol: str
    port: int
    entry_number: int
    
    # Extracted from config content
    endpoint_ip: str
    endpoint_port: int
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    preshared_key: Optional[str] = None
    address: Optional[str] = None
    dns: Optional[str] = None
    allowed_ips: Optional[str] = None
    
    # Computed
    subnet: Optional[str] = None
    is_us_europe_friendly: bool = True  # For US servers, is it close to Europe?
    
    def __post_init__(self):
        """Compute derived fields."""
        # Calculate /24 subnet from endpoint IP
        try:
            network = ipaddress.ip_network(f"{self.endpoint_ip}/24", strict=False)
            self.subnet = str(network)
        except ValueError:
            self.subnet = None
        
        # Check if US server is Europe-friendly
        if self.country_code.upper() in ["US", "USA"]:
            city_lower = self.city.lower().replace(" ", "").replace("-", "")
            self.is_us_europe_friendly = any(
                loc in city_lower for loc in US_ALLOWED_LOCATIONS
            )
    
    @property
    def display_name(self) -> str:
        """Human-readable display name."""
        return f"{self.server_name} ({self.city}, {self.country_code})"
    
    @property
    def should_scan(self) -> bool:
        """Whether this server should be scanned (US filtering)."""
        if self.country_code.upper() in ["US", "USA"]:
            return self.is_us_europe_friendly
        return True


def parse_filename(filename: str) -> dict:
    """
    Parse AirVPN config filename to extract metadata.
    
    Format: AirVPN_AT-Vienna_Alderamin_UDP-1637-Entry3.conf
    
    Returns dict with: country_code, city, server_name, protocol, port, entry_number
    """
    # Remove .conf extension
    name = filename.replace(".conf", "")
    
    # Pattern: AirVPN_CC-City_ServerName_Protocol-Port-EntryN
    pattern = r"AirVPN_([A-Z]{2,3})-([^_]+)_([^_]+)_([A-Z]+)-(\d+)-Entry(\d+)"
    match = re.match(pattern, name, re.IGNORECASE)
    
    if not match:
        # Try alternative pattern without Entry number
        pattern_alt = r"AirVPN_([A-Z]{2,3})-([^_]+)_([^_]+)_([A-Z]+)-(\d+)"
        match = re.match(pattern_alt, name, re.IGNORECASE)
        if match:
            country_code, city, server_name, protocol, port = match.groups()
            entry_number = 1
        else:
            # Try confgen format: CC-City_Server-Port-EN
            pattern_gen = r"([A-Z]{2,3})-([^_]+)_([^-]+)-(\d+)-E(\d+)"
            match = re.match(pattern_gen, name, re.IGNORECASE)
            if match:
                country_code, city, server_name, port, entry_number = match.groups()
                protocol = "UDP"  # Default assumption for generated configs
            else:
                raise ValueError(f"Cannot parse filename: {filename}")
    else:
        country_code, city, server_name, protocol, port, entry_number = match.groups()
    
    return {
        "country_code": country_code.upper(),
        "country_name": COUNTRY_CODE_MAP.get(country_code.upper(), country_code),
        "city": city.replace("-", " "),
        "server_name": server_name,
        "protocol": protocol.upper(),
        "port": int(port),
        "entry_number": int(entry_number),
    }


def parse_config_content(content: str) -> dict:
    """
    Parse WireGuard config file content.
    
    Extracts: Endpoint, PrivateKey, PublicKey, Address, DNS, AllowedIPs
    """
    result = {}
    
    # Extract Endpoint (IP:Port)
    endpoint_match = re.search(r"Endpoint\s*=\s*([^:\s]+):(\d+)", content)
    if endpoint_match:
        result["endpoint_ip"] = endpoint_match.group(1)
        result["endpoint_port"] = int(endpoint_match.group(2))
    
    # Extract other fields
    patterns = {
        "private_key": r"PrivateKey\s*=\s*(.+)",
        "public_key": r"PublicKey\s*=\s*(.+)",
        "preshared_key": r"PresharedKey\s*=\s*(.+)",
        "address": r"Address\s*=\s*(.+)",
        "dns": r"DNS\s*=\s*(.+)",
        "allowed_ips": r"AllowedIPs\s*=\s*(.+)",
    }
    
    for key, pattern in patterns.items():
        match = re.search(pattern, content, re.IGNORECASE)
        if match:
            result[key] = match.group(1).strip()
    
    return result


def parse_config_file(file_path: Path) -> WireGuardConfig:
    """
    Parse a single WireGuard config file.
    
    Args:
        file_path: Path to .conf file
        
    Returns:
        WireGuardConfig object with all extracted data
    """
    # Parse filename
    filename_data = parse_filename(file_path.name)
    
    # Parse content
    content = file_path.read_text()
    content_data = parse_config_content(content)
    
    # Merge and create config
    return WireGuardConfig(
        file_path=file_path,
        filename=file_path.name,
        **filename_data,
        **content_data,
    )


def scan_config_directory(config_dir: Path) -> list[WireGuardConfig]:
    """
    Scan directory for all WireGuard config files.
    
    Args:
        config_dir: Path to directory containing .conf files
        
    Returns:
        List of WireGuardConfig objects
    """
    configs = []
    
    if not config_dir.exists():
        return configs
    
    for conf_file in sorted(config_dir.glob("*.conf")):
        try:
            config = parse_config_file(conf_file)
            configs.append(config)
        except Exception as e:
            logger.warning(f"Failed to parse {conf_file.name}: {e}")
    
    return configs


def get_unique_countries(configs: list[WireGuardConfig]) -> dict[str, list[WireGuardConfig]]:
    """
    Group configs by country.
    
    Returns:
        Dict mapping country_code to list of configs
    """
    by_country = {}
    for config in configs:
        if config.country_code not in by_country:
            by_country[config.country_code] = []
        by_country[config.country_code].append(config)
    return by_country


def get_unique_subnets(configs: list[WireGuardConfig]) -> set[str]:
    """Get all unique /24 subnets from configs."""
    return {c.subnet for c in configs if c.subnet}


def get_scannable_configs(configs: list[WireGuardConfig]) -> list[WireGuardConfig]:
    """
    Filter configs to only those that should be scanned.
    
    Applies US Europe-friendly filter.
    """
    return [c for c in configs if c.should_scan]


def get_all_endpoint_ips(configs: list[WireGuardConfig]) -> list[str]:
    """Get all unique endpoint IPs from configs."""
    return list(set(c.endpoint_ip for c in configs if c.endpoint_ip))

