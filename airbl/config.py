"""
Configuration management for AirBL.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, model_validator, BaseModel
from typing import Optional, List, Dict, Any, Set
from pathlib import Path
import json
import logging
import os
import shutil

logger = logging.getLogger("airbl.config")


class Settings(BaseSettings):
    """Application settings with environment variable support."""
    
    model_config = SettingsConfigDict(
        env_prefix="AIRBL_",
        env_file=".env",
        extra="ignore",
    )
    
    # AirVPN API
    airvpn_api_url: str = "https://airvpn.org/api/status/"
    
    # DroneBL Settings
    dronebl_dnsbl_host: str = "dnsbl.dronebl.org"
    dronebl_lookup_timeout: float = 5.0
    
    # Scanning
    scan_concurrency: int = Field(default=50, ge=1, le=200)
    
    # Ping Settings
    ping_count: int = Field(default=3, ge=1, le=10)
    ping_timeout: float = Field(default=2.0, ge=0.5, le=10.0)
    ping_interval: float = Field(default=0.5, ge=0.1, le=2.0)
    
    # Rate Limiting
    dns_queries_per_second: int = Field(default=20, ge=1, le=100)
    api_requests_per_second: int = Field(default=5, ge=1, le=20)
    
    # Refresh Settings
    refresh_interval_seconds: int = Field(default=300, ge=60, le=3600)  # 5 minutes default
    
    # Data Storage
    config_dir: Path = Field(default=Path("/app/conf"))
    cache_dir: Path = Field(default=Path("/app/data"))
    db_path: Optional[Path] = None
    
    # Display Settings
    max_display_rows: int = Field(default=50, ge=10, le=500)
    
    @model_validator(mode="after")
    def set_defaults_and_create_dirs(self) -> "Settings":
        """Set default db_path and ensure cache directory exists."""
        if self.db_path is None:
            object.__setattr__(self, "db_path", self.cache_dir / "airbl.db")
        
        # Ensure directories exist
        try:
            self.cache_dir.mkdir(parents=True, exist_ok=True)
            # Don't try to create config_dir as it might be a read-only mount
        except Exception as e:
            logger.warning(f"Could not create cache directory: {e}")
            
        return self


# --- Configuration File Models ---

class RegionConfig(BaseModel):
    mode: str = "all"  # "all", "none", "manual", "config_only"
    countries: List[str] = Field(default_factory=list)
    excluded_countries: List[str] = Field(default_factory=list)

class ScanConfig(BaseModel):
    auto_scan_enabled: bool = True
    scan_interval_minutes: int = 120
    speedtest_enabled: bool = True
    # Port/Entry discovery: test all combos each scan for N days to find optimal
    port_discovery_enabled: bool = False
    preferred_port: int = 1637           # Discovered or manually set best port
    preferred_entry_ip: str = "ENTRY3"    # ENTRY1 | ENTRY3 | AUTO
    discovery_test_count: int = 3         # Number of tests per combo during discovery
    discovery_duration_days: int = 3      # How many days to run discovery (3, 5, or 7)
    discovery_entry_filter: str = "ALL"   # ALL | ENTRY1 | ENTRY3
    discovery_started_at: Optional[str] = None   # ISO timestamp when discovery started
    discovery_auto_port: Optional[int] = None    # Best port found by discovery
    discovery_auto_entry: Optional[str] = None   # Best entry found by discovery
    post_server_wait: int = 120           # Seconds to wait after testing a server
    # Available AirVPN ports (hardcoded, overridable via config)
    available_ports: List[int] = Field(default_factory=lambda: [1637, 47107, 51820])
    # Generated config directory (internal)
    confgen_dir: str = "/app/confgen"
    preferred_mtu: int = 1320             # WireGuard MTU override (Default AirVPN is 1320)
    # Persisted discovery results: {"PORT_ENTRY": {download_mbps, upload_mbps, ping_ms, tests}}
    discovery_results: Dict[str, Dict] = Field(default_factory=dict)

class SpeedtestBlacklistConfig(BaseModel):
    duration_days: int = 2
    max_failures: int = 3

class PerformanceConfig(BaseModel):
    disabled_servers: List[str] = Field(default_factory=list)
    threshold_download: float = 50.0
    threshold_upload: float = 10.0
    check_count: int = 3
    # History is now better stored in SQLite, but keeping for backward compatibility in config until migration
    history: Dict[str, List[Dict]] = Field(default_factory=dict)

class ScoringConfig(BaseModel):
    """Scoring and signal bar settings."""
    # Deviation score weights (must sum to 1.0)
    deviation_download_weight: float = 0.4  # 40% weight for download
    deviation_upload_weight: float = 0.6    # 60% weight for upload
    
    # Signal bar thresholds (based on score 0-100)
    signal_good_threshold: int = 80   # Score >= 80 = good (3 bars)
    signal_medium_threshold: int = 50  # Score >= 50 = medium (2 bars), < 50 = bad (1 bar)

class GluetunProfileConfig(BaseModel):
    """A distinct output profile for Gluetun custom servers.json generation."""
    name: str = "Standard Profile"
    enabled: bool = False
    output_path: Path = Field(default=Path("/app/gluetun/servers.json"))
    endpoint_strategy: str = "ALL"
    min_download_mbps: float = 50.0
    min_upload_mbps: float = 10.0
    require_clean: bool = True
    allowed_countries: List[str] = Field(default_factory=list)
    allowed_cities: List[str] = Field(default_factory=list)

class GluetunConfig(BaseModel):
    """Global settings and list of profiles for Gluetun generation."""
    force_update_enabled: bool = False
    force_update_mode: str = "NOT_TOP4"  # NOT_TOP4 | NOT_BEST | ALWAYS | DISABLED
    control_server_host: str = "127.0.0.1"
    control_server_port: int = 8000
    profiles: List[GluetunProfileConfig] = Field(default_factory=lambda: [
        GluetunProfileConfig(
            name="Fast Servers",
            enabled=False,
            output_path=Path("/app/gluetun/fast_servers.json"),
            endpoint_strategy="ALL",
            min_download_mbps=100.0,
            require_clean=False
        ),
        GluetunProfileConfig(
            name="Clean Servers",
            enabled=False,
            output_path=Path("/app/gluetun/clean_servers.json"),
            endpoint_strategy="PING_PRIORITY",
            min_download_mbps=0.0,
            min_upload_mbps=0.0,
            require_clean=True
        )
    ])

class WireGuardProfileConfig(BaseModel):
    """A WireGuard profile output configuration."""
    name: str = "Default WG Profile"
    enabled: bool = False
    output_dir: str = "/app/wireguard"
    entry_ip: str = "ENTRY3"          # ENTRY1 | ENTRY3
    ip_protocol: str = "IPv4"         # IPv4 | IPv6
    port: int = 1637                  # 1637 | 47107 | 51820
    ip_layer_exit: str = "Both"       # Both | IPv4 | IPv6
    mtu: int = 1320
    keepalive: int = 25
    private_key: str = ""
    public_key: str = ""
    mode: str = "custom"              # countries | cities | use_speedtest | custom
    countries: List[str] = Field(default_factory=list)
    cities: List[str] = Field(default_factory=list)
    auto_update_wg0: bool = False

class WireGuardSettings(BaseModel):
    """Global WireGuard generation settings."""
    profiles: List[WireGuardProfileConfig] = Field(default_factory=lambda: [
        WireGuardProfileConfig()
    ])

class AirBLConfig(BaseModel):
    """Represents the structure of airbl-config.json."""
    regions: RegionConfig = Field(default_factory=RegionConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    speedtest_blacklist: SpeedtestBlacklistConfig = Field(default_factory=SpeedtestBlacklistConfig)
    performance: PerformanceConfig = Field(default_factory=PerformanceConfig)
    scoring: ScoringConfig = Field(default_factory=ScoringConfig)
    gluetun: GluetunConfig = Field(default_factory=GluetunConfig)
    wireguard: WireGuardSettings = Field(default_factory=WireGuardSettings)
    servers: List[str] = Field(default_factory=list)  # Enabled servers whitelist
    cities: Dict[str, List[str]] = Field(default_factory=dict)  # Country -> Cities whitelist


class SettingsManager:
    """
    Manages loading and saving of configuration.
    
    Layer 1: Base Config (Read-Only) - /app/conf/airbl-config.json
    Layer 2: User Settings (Read-Write) - /app/data/airbl-settings.json
    
    The final configuration is Layer 1 merged with Layer 2.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_config_path = settings.config_dir / "airbl-config.json"
        self.user_settings_path = settings.cache_dir / "airbl-settings.json"
        self.config = AirBLConfig()
        
    def load(self) -> AirBLConfig:
        """Load configuration from both layers and merge."""
        base_data = {}
        user_data = {}
        
        # Load Base Config
        if self.base_config_path.exists():
            try:
                with open(self.base_config_path, 'r') as f:
                    base_data = json.load(f)
                logger.info(f"Loaded base config from {self.base_config_path}")
            except Exception as e:
                logger.error(f"Failed to load base config: {e}")
        
        # Load User Settings
        if self.user_settings_path.exists():
            try:
                with open(self.user_settings_path, 'r') as f:
                    user_data = json.load(f)
                logger.info(f"Loaded user settings from {self.user_settings_path}")
            except Exception as e:
                logger.error(f"Failed to load user settings: {e}")
        
        # Merge: Base + User (User overwrites Base)
        merged_data = self._deep_merge(base_data, user_data)
        
        try:
            self.config = AirBLConfig(**merged_data)
        except Exception as e:
            logger.error(f"Configuration validation failed: {e}")
            # Fallback to defaults or partial load if possible
            # For now, just try to initialize with valid parts or defaults
            self.config = AirBLConfig()
            
        return self.config
    
    def _deep_merge(self, base: Dict, override: Dict) -> Dict:
        """Deep merge two dictionaries."""
        result = base.copy()
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._deep_merge(result[key], value)
            else:
                result[key] = value
        return result
    
    def save(self) -> bool:
        """Save current configuration state to User Settings file."""
        try:
            # We save the *entire* current state as the user settings
            # This implicitly means "current state becomes the new persistent state"
            # Optimization: We could potentially only save diffs, but saving full state 
            # is safer ensuring what you see is what you get.
            
            # Use model_dump (Pydantic v2) or dict()
            config_data = self.config.model_dump(mode='json')
            
            # Atomic write
            temp_path = self.user_settings_path.with_suffix('.tmp')
            with open(temp_path, 'w') as f:
                json.dump(config_data, f, indent=2)
            
            shutil.move(temp_path, self.user_settings_path)
            logger.info(f"Saved settings to {self.user_settings_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to save settings: {e}")
            return False


# Global settings instance
settings = Settings()
# Global config manager instance
config_manager = SettingsManager(settings)


# DroneBL response codes mapping
DRONEBL_CODES = {
    2: "Sample",
    3: "IRC Drone",
    5: "Bottler",
    6: "Unknown spambot/drone",
    7: "DDoS Drone",
    8: "SOCKS Proxy",
    9: "HTTP Proxy",
    10: "ProxyChain",
    11: "Web Page Proxy",
    12: "Open DNS Resolver",
    13: "Brute force attacker",
    14: "Open Wingate Proxy",
    15: "Compromised router/gateway",
    16: "Autorooting worm",
    17: "Botnet IP (Hydra)",
    18: "DNS/MX type hostname",
    19: "Abused VPN Service",
    255: "Unknown",
}


def get_dronebl_reason(code: int) -> str:
    """Get human-readable reason for DroneBL listing code."""
    return DRONEBL_CODES.get(code, f"Unknown code: {code}")

