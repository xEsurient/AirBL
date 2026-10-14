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

# US cities closer to Europe, kept by the opt-in regions.us_near_europe_only
# setting. Each entry is matched as whole word(s) of the city name.
US_ALLOWED_LOCATIONS = [
    "new york", "newyork", "ny",
    "chicago",
    "dallas", "texas", "tx",
    "atlanta",
    "washington dc", "dc", "ashburn",
    "boston",
    "philadelphia",
]


def _city_tokens(city: str) -> list[str]:
    """Split "NewYorkCity" / "Atlanta Georgia" / "Los-Angeles" into lowercase words."""
    return [t.lower() for t in re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", city or "")]


def is_us_city_near_europe(city: str) -> bool:
    """True if the city name contains an allowed location as whole word(s)."""
    tokens = _city_tokens(city)
    return any(_city_matches(tokens, loc) for loc in US_ALLOWED_LOCATIONS)


# Regions for grouping cities in the dashboard (display only), by time zone.
# AirVPN's API has no coordinates, only names like "Fremont-California", so
# every state/province is listed: new servers named "City-State" group
# themselves. REGION_CITIES covers names without a state ("Miami").
# Each entry is matched as whole word(s); states are checked before cities.
REGION_STATES = {
    "US": {
        "East": [
            # "washington dc" must come before the state of Washington (West).
            "washington dc", "dc", "district of columbia",
            "connecticut", "delaware", "florida", "georgia", "indiana",
            "kentucky", "maine", "maryland", "massachusetts", "michigan",
            "new hampshire", "new jersey", "new york", "north carolina",
            "ohio", "pennsylvania", "rhode island", "south carolina",
            "vermont", "virginia", "west virginia",
        ],
        "Central": [
            "alabama", "arkansas", "illinois", "iowa", "kansas", "louisiana",
            "minnesota", "mississippi", "missouri", "nebraska", "north dakota",
            "oklahoma", "south dakota", "tennessee", "texas", "wisconsin",
        ],
        "Mountain": [
            "arizona", "colorado", "idaho", "montana", "new mexico", "utah",
            "wyoming",
        ],
        "West": [
            "california", "nevada", "oregon", "washington", "alaska", "hawaii",
        ],
    },
    "CA": {
        "East": [
            "ontario", "quebec", "new brunswick", "nova scotia",
            "prince edward island", "newfoundland",
        ],
        "Central": ["manitoba", "saskatchewan"],
        "West": ["alberta", "british columbia"],
    },
}

REGION_CITIES = {
    "US": {
        "East": [
            "newyork", "ny", "nyc", "newark", "secaucus", "boston",
            "philadelphia", "ashburn", "baltimore", "atlanta", "miami",
            "orlando", "tampa", "jacksonville", "raleigh", "charlotte",
            "pittsburgh", "detroit", "columbus", "cleveland", "indianapolis",
            "buffalo",
        ],
        "Central": [
            "chicago", "dallas", "houston", "austin", "san antonio",
            "sanantonio", "st louis", "stlouis", "minneapolis", "nashville",
            "memphis", "new orleans", "neworleans", "omaha", "milwaukee",
        ],
        "Mountain": [
            "phoenix", "denver", "salt lake", "saltlake", "albuquerque",
            "boise",
        ],
        "West": [
            "los angeles", "losangeles", "san jose", "sanjose", "fremont",
            "san francisco", "sanfrancisco", "san diego", "sandiego",
            "santa clara", "santaclara", "seattle", "portland", "las vegas",
            "lasvegas",
        ],
    },
    "CA": {
        "East": ["montreal", "toronto", "ottawa"],
        "Central": ["winnipeg", "regina"],
        "West": ["vancouver", "calgary", "edmonton"],
    },
}


def _city_matches(tokens: list[str], loc: str) -> bool:
    want = loc.split()
    n = len(want)
    return any(tokens[i:i + n] == want for i in range(len(tokens) - n + 1))


def city_region(country_code: str, city: str) -> str | None:
    """Region name for a city ("East", "West", ...), or None if ungrouped."""
    code = (country_code or "").upper()
    tokens = _city_tokens(city)
    for table in (REGION_STATES, REGION_CITIES):
        for region, locs in table.get(code, {}).items():
            if any(_city_matches(tokens, loc) for loc in locs):
                return region
    return None


def city_regions_for(cities_by_country: dict) -> dict:
    """{country: {city: region}} for the cities that belong to a region."""
    out = {}
    for code, cities in cities_by_country.items():
        found = {c: r for c in cities if (r := city_region(code, c))}
        if found:
            out[code.upper()] = found
    return out


def _us_filter_enabled() -> bool:
    """Current regions.us_near_europe_only setting (off by default)."""
    try:
        from .config import config_manager
        return bool(config_manager.config.regions.us_near_europe_only)
    except Exception:
        return False


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
    mtu: Optional[int] = None
    
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
        
        # Informational unless regions.us_near_europe_only is enabled
        if self.country_code.upper() in ["US", "USA"]:
            self.is_us_europe_friendly = is_us_city_near_europe(self.city)
    
    @property
    def display_name(self) -> str:
        """Human-readable display name."""
        return f"{self.server_name} ({self.city}, {self.country_code})"
    
    def passes_us_filter(self, us_near_europe_only: bool) -> bool:
        """False only for a far-from-Europe US server when the filter is on."""
        if us_near_europe_only and self.country_code.upper() in ["US", "USA"]:
            return self.is_us_europe_friendly
        return True

    @property
    def should_scan(self) -> bool:
        """Whether this server should be scanned (opt-in US filter from settings)."""
        return self.passes_us_filter(_us_filter_enabled())


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


# key (lowercase) -> (result field, section it belongs to)
_CONF_KEYS = {
    "privatekey": ("private_key", "interface"),
    "address": ("address", "interface"),
    "dns": ("dns", "interface"),
    "mtu": ("mtu", "interface"),
    "publickey": ("public_key", "peer"),
    "presharedkey": ("preshared_key", "peer"),
    "allowedips": ("allowed_ips", "peer"),
    "endpoint": ("endpoint", "peer"),
}


def _split_endpoint(value: str) -> Optional[tuple[str, int]]:
    """"1.2.3.4:1637" or "[2001:db8::1]:1637" -> (host, port)."""
    m = re.fullmatch(r"\[([^\]]+)\]:(\d+)", value) or re.fullmatch(r"([^:\s\[\]]+):(\d+)", value)
    if not m:
        return None
    return m.group(1), int(m.group(2))


def parse_config_content(content: str) -> dict:
    """
    Parse WireGuard config file content.
    
    Line-based and section-aware: comments (# or ;) are ignored, Interface keys
    are only read from [Interface], peer keys from the first [Peer].
    Extracts: Endpoint, PrivateKey, PublicKey, PresharedKey, Address, DNS, AllowedIPs, MTU
    """
    result = {}
    section = None
    peers_seen = 0
    
    for raw in content.splitlines():
        line = re.split(r"[#;]", raw, maxsplit=1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            if section == "peer":
                peers_seen += 1
            continue
        if "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        spec = _CONF_KEYS.get(key.lower())
        if not spec or not value:
            continue
        field_name, wanted_section = spec
        # Keys outside any section are accepted for headerless snippets
        if section is not None and section != wanted_section:
            continue
        if wanted_section == "peer" and peers_seen > 1:
            continue
        if field_name in result or (field_name == "endpoint" and "endpoint_ip" in result):
            continue  # first occurrence wins
        if field_name == "endpoint":
            parsed = _split_endpoint(value)
            if parsed:
                result["endpoint_ip"], result["endpoint_port"] = parsed
        elif field_name == "mtu":
            if value.isdigit():
                result["mtu"] = int(value)
        else:
            result[field_name] = value
    
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


def unparsed_config_files(config_dir: Path) -> list[str]:
    """Names of .conf files that aren't per-server AirVPN configs (skipped by the scan)."""
    if not config_dir.exists():
        return []
    skipped = []
    for conf_file in sorted(config_dir.glob("*.conf")):
        try:
            parse_filename(conf_file.name)
        except ValueError:
            skipped.append(conf_file.name)
    return skipped


def no_configs_message(config_dir: Path, api_failed: bool = False) -> str:
    """Why nothing can be scanned: no per-server .conf files, and none could be built."""
    skipped = unparsed_config_files(config_dir)
    msg = f"No per-server AirVPN WireGuard configs found in {config_dir}."
    if not skipped:
        return msg + (" Add an AirVPN WireGuard config: one per server"
                      " (e.g. AirVPN_AT-Vienna_Alderamin_UDP-1637-Entry3.conf) or a region config"
                      " (e.g. AirVPN_Europe_UDP-1637-Entry3.conf).")
    shown = ", ".join(skipped[:3]) + (f" (+{len(skipped) - 3} more)" if len(skipped) > 3 else "")
    if api_failed:
        return msg + (f" Server configs are built from {shown} using the AirVPN server list,"
                      " which couldn't be loaded. Check the container's internet access and try again.")
    from .confgen import extract_client_identity
    if extract_client_identity(config_dir):
        return msg + f" Building server configs from {shown} failed; see the Debug page for details."
    return msg + (f" The skipped file(s) ({shown}) have no PrivateKey and Address to build server"
                  " configs from. Use an unmodified config from AirVPN's Config Generator.")


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


def get_scannable_configs(
    configs: list[WireGuardConfig],
    us_near_europe_only: Optional[bool] = None,
) -> list[WireGuardConfig]:
    """
    Filter configs to only those that should be scanned.
    
    Applies the US "close to Europe" filter only when enabled
    (None = use the regions.us_near_europe_only setting, off by default).
    """
    if us_near_europe_only is None:
        us_near_europe_only = _us_filter_enabled()
    return [c for c in configs if c.passes_us_filter(us_near_europe_only)]


def get_all_endpoint_ips(configs: list[WireGuardConfig]) -> list[str]:
    """Get all unique endpoint IPs from configs."""
    return list(set(c.endpoint_ip for c in configs if c.endpoint_ip))

