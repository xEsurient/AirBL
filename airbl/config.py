"""
Configuration management for AirBL.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, model_validator, BaseModel, AliasChoices
from typing import Optional, List, Dict, Any, Set
from pathlib import Path
import json
import logging
import os
import shutil
from datetime import datetime

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
    
    # Resolvers for DroneBL DNSBL lookups (DNS_SERVERS env, comma list; empty = system resolver)
    dns_servers: str = Field(default="", validation_alias=AliasChoices("DNS_SERVERS", "AIRBL_DNS_SERVERS"))
    
    # Ping Settings
    ping_count: int = Field(default=3, ge=1, le=10)
    ping_timeout: float = Field(default=2.0, ge=0.5, le=10.0)
    
    # Data Storage
    config_dir: Path = Field(default=Path("/app/conf"))
    config_file: Optional[Path] = None  # AIRBL_CONFIG_FILE; default config_dir/airbl-config.json
    cache_dir: Path = Field(default=Path("/app/data"))
    db_path: Optional[Path] = None
    
    @property
    def dns_server_list(self) -> list[str]:
        """DNS_SERVERS as a list of nameserver IPs (invalid entries dropped)."""
        import ipaddress
        out = []
        for item in self.dns_servers.split(","):
            item = item.strip()
            try:
                out.append(str(ipaddress.ip_address(item)))
            except ValueError:
                if item:
                    logger.warning(f"Ignoring invalid DNS_SERVERS entry: {item!r}")
        return out
    
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
    us_near_europe_only: bool = False  # Opt-in: scan only US cities close to Europe

class ScanConfig(BaseModel):
    auto_scan_enabled: bool = True
    scan_mode: str = "interval"  # "interval" or "schedule"
    scan_interval_minutes: int = 120
    scan_schedule_time: str = "20:00"
    scan_schedule_days: List[str] = Field(default_factory=lambda: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
    speedtest_enabled: bool = True
    # Port/Entry discovery: test all combos each scan for N days to find optimal
    port_discovery_enabled: bool = False
    preferred_port: int = 1637           # Discovered or manually set best port
    preferred_entry_ip: str = "ENTRY3"    # ENTRY1 | ENTRY3 | AUTO
    discovery_test_count: int = 3         # Number of tests per combo during discovery
    speedtest_test_count: Optional[int] = None  # Tests per server for normal speedtests (None = use discovery_test_count, legacy)
    discovery_duration_days: int = 3      # How many days to run discovery (3, 5, or 7)
    discovery_entry_filter: str = "ALL"   # ALL | ENTRY1 | ENTRY3
    discovery_started_at: Optional[str] = None   # ISO timestamp (UTC) when the current discovery period started
    discovery_finished_at: Optional[str] = None  # ISO timestamp (UTC) of the last finalize
    discovery_outcome: Optional[str] = None      # Last finalize result, e.g. "47107/ENTRY3" or "inconclusive: ..."
    discovery_scan_count: int = 0                # Discovery runs so far in this period (server rotation)
    discovery_auto_port: Optional[int] = None    # Best port found by discovery (informational)
    discovery_auto_entry: Optional[str] = None   # Best entry found by discovery (informational)
    post_server_wait: int = 120           # Seconds to wait after testing a server
    # Available AirVPN ports (hardcoded, overridable via config)
    available_ports: List[int] = Field(default_factory=lambda: [1637, 47107, 51820])
    # Generated config directory (internal)
    confgen_dir: str = "/app/confgen"
    preferred_mtu: int = 1320             # MTU for generated test configs (discovery / non-default port or entry), 1280-1500
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
    api_key: str = ""  # Gluetun control server API key (sent as X-API-Key)
    control_profile: str = ""  # Profile pushed to Gluetun; empty = first enabled
    # Same clean 120/120 profile for both Gluetun storage layouts; AirBL's
    # /app/gluetun is meant to be the same folder as Gluetun's /gluetun.
    profiles: List[GluetunProfileConfig] = Field(default_factory=lambda: [
        GluetunProfileConfig(
            name="Clean 120/120 (current Gluetun)",
            enabled=False,
            output_path=Path("/app/gluetun/servers/airvpn.json"),
            endpoint_strategy="PING_PRIORITY",
            min_download_mbps=120.0,
            min_upload_mbps=120.0,
            require_clean=True
        ),
        GluetunProfileConfig(
            name="Clean 120/120 (older Gluetun)",
            enabled=False,
            output_path=Path("/app/gluetun/servers.json"),
            endpoint_strategy="PING_PRIORITY",
            min_download_mbps=120.0,
            min_upload_mbps=120.0,
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
    mode: str = "clean"               # clean | custom (all servers) | fastest | fastest_clean | countries | cities | use_speedtest
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
    
    Layer 1: Base Config (Read-Only) - AIRBL_CONFIG_FILE or /app/conf/airbl-config.json
    Layer 2: User Settings (Read-Write) - /app/data/airbl-settings.json
    
    The final configuration is Layer 1 merged with Layer 2. Layer 2 only holds
    values that differ from Layer 1, so later edits to the base file still apply.
    """
    
    def __init__(self, settings: Settings):
        self.settings = settings
        self.base_config_path = settings.config_file or (settings.config_dir / "airbl-config.json")
        self.user_settings_path = settings.cache_dir / "airbl-settings.json"
        self.config = AirBLConfig()
        
    def _load_base(self, quiet: bool = False) -> Dict:
        """Raw base config file contents ({} if missing or unreadable)."""
        if not self.base_config_path.exists():
            return {}
        try:
            with open(self.base_config_path, 'r') as f:
                data = json.load(f)
            if not isinstance(data, dict):
                raise ValueError("top level is not a JSON object")
            if not quiet:
                logger.info(f"Loaded base config from {self.base_config_path}")
            return data
        except Exception as e:
            logger.error(f"Failed to load base config: {e}")
            return {}

    def load(self) -> AirBLConfig:
        """Load configuration from both layers and merge."""
        user_data = {}
        
        # Load Base Config
        base_data = self._load_base()
        
        # Load User Settings
        if self.user_settings_path.exists():
            try:
                with open(self.user_settings_path, 'r') as f:
                    user_data = json.load(f)
                logger.info(f"Loaded user settings from {self.user_settings_path}")
            except Exception as e:
                logger.error(f"Failed to load user settings: {e}")
                # Keep the unreadable file: the next save would otherwise replace it
                self._preserve_copy("unreadable")
        
        # Merge: Base + User (User overwrites Base)
        merged_data = self._merge_model(AirBLConfig, base_data, user_data)
        
        try:
            self.config = AirBLConfig(**merged_data)
        except Exception as e:
            # Never fall back to all defaults: the next UI save would then overwrite
            # every user setting. Keep each valid section/field, drop only the bad ones.
            logger.error(f"Configuration validation failed, keeping valid settings only: {e}")
            self._preserve_copy("invalid")
            self.config = self._salvage(merged_data)
            
        return self.config

    def _salvage(self, data: Dict) -> AirBLConfig:
        """Build a config from the valid parts of `data`, logging every dropped value."""
        kept: Dict[str, Any] = {}
        for name, field_info in AirBLConfig.model_fields.items():
            if name not in data:
                continue
            value = data[name]
            try:
                AirBLConfig(**{name: value})
                kept[name] = value
                continue
            except Exception:
                pass
            section_model = field_info.annotation
            if isinstance(value, dict) and isinstance(section_model, type) and issubclass(section_model, BaseModel):
                # Section-level salvage: add keys one by one, keep those that validate
                good: Dict[str, Any] = {}
                for key, sub in value.items():
                    try:
                        section_model(**{**good, key: sub})
                        good[key] = sub
                    except Exception as e:
                        logger.warning(f"Dropping invalid setting {name}.{key}={sub!r}: {e}")
                kept[name] = good
            else:
                logger.warning(f"Dropping invalid setting {name}={value!r}")
        return AirBLConfig(**kept)

    def _preserve_copy(self, reason: str) -> None:
        """Copy the user settings file aside (once per reason) before it can be overwritten."""
        if not self.user_settings_path.exists():
            return
        dest = self.user_settings_path.with_name(f"{self.user_settings_path.name}.{reason}-{datetime.now():%Y%m%d-%H%M%S}")
        try:
            shutil.copy2(self.user_settings_path, dest)
            logger.warning(f"Saved a copy of the original settings to {dest}")
        except Exception as e:
            logger.error(f"Could not back up settings file: {e}")
    
    @staticmethod
    def _section_model(model: type, key: str) -> Optional[type]:
        """The nested BaseModel class of a field, or None for plain values/maps/lists."""
        field_info = model.model_fields.get(key) if model else None
        ann = field_info.annotation if field_info else None
        return ann if isinstance(ann, type) and issubclass(ann, BaseModel) else None

    def _merge_model(self, model: type, base: Dict, override: Dict) -> Dict:
        """Merge override into base, recursing only into model sections.

        Free-form maps (cities, discovery_results, ...) are replaced whole, so a key
        removed in the user layer doesn't come back from the base file.
        """
        result = base.copy()
        for key, value in override.items():
            sub = self._section_model(model, key)
            if sub and isinstance(result.get(key), dict) and isinstance(value, dict):
                result[key] = self._merge_model(sub, result[key], value)
            else:
                result[key] = value
        return result

    def _diff_model(self, model: type, current: Dict, base: Dict) -> Dict:
        """Values of `current` that differ from `base` (per section field)."""
        out: Dict[str, Any] = {}
        for key, value in current.items():
            if key in base and base[key] == value:
                continue
            sub = self._section_model(model, key)
            if sub and isinstance(value, dict) and isinstance(base.get(key), dict):
                d = self._diff_model(sub, value, base[key])
                if d:
                    out[key] = d
            else:
                out[key] = value
        return out

    def _base_dump(self) -> Dict:
        """Base layer as it validates on its own (base file over defaults)."""
        base_data = self._load_base(quiet=True)
        try:
            base = AirBLConfig(**base_data)
        except Exception:
            base = self._salvage(base_data)
        return base.model_dump(mode='json')
    
    def save(self) -> bool:
        """Save the values that differ from the base layer to the User Settings file."""
        try:
            # Only the diff vs base (file + defaults): a value set back to the base
            # value simply drops out and the base value applies again.
            config_data = self._diff_model(AirBLConfig, self.config.model_dump(mode='json'), self._base_dump())
            
            # Keep the previous version, then write atomically
            if self.user_settings_path.exists():
                try:
                    shutil.copy2(self.user_settings_path, self.user_settings_path.with_name(self.user_settings_path.name + ".bak"))
                except Exception as e:
                    logger.warning(f"Could not write settings backup: {e}")
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

