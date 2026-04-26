"""
Global application state and logging for AirBL Web UI.
"""

from typing import Optional, Callable, Awaitable
from pathlib import Path
from datetime import datetime
from collections import deque
import logging
import asyncio
import sys

# Avoid circular imports but allow type checking
from ..scanner import ScanSummary
from ..config import config_manager, settings, SettingsManager
# Database manager
from ..database import DatabaseManager

# Global broadcast function (will be injected from websockets module)
_broadcast_func: Optional[Callable[[str, dict], Awaitable[None]]] = None


def set_broadcast_func(func: Callable[[str, dict], Awaitable[None]]):
    """Set the global broadcast function."""
    global _broadcast_func
    _broadcast_func = func


async def broadcast_log(log_entry: dict):
    """Helper to broadcast a log entry safely."""
    if _broadcast_func:
        try:
            await _broadcast_func("debug_log", log_entry)
        except Exception:
            pass


class AppState:
    def __init__(self):
        self.current_scan: Optional[ScanSummary] = None
        self.is_scanning: bool = False
        self.is_paused: bool = False
        self.scan_progress: dict = {"phase": "idle", "current": 0, "total": 0, "server": "", "country": "", "next": ""}
        self.next_scan_at: Optional[datetime] = None
        
        # NOTE: scan_interval_minutes is now managed by SettingsManager (config_manager.config.scan.scan_interval_minutes)
        # But we keep a property wrapper using it.
        
        self.websocket_clients: list = []  # Type: list[WebSocket]
        self.scan_task: Optional[asyncio.Task] = None
        self.scan_cancelled: bool = False
        
        # Load initial settings
        config_manager.load()
        
        # Database Manager (Initialized on startup)
        self.db: Optional[DatabaseManager] = None
        
        # Config manager override (can be set at runtime)
        self.config_manager: Optional[SettingsManager] = None
        
        # Runtime Data (Available countries, etc.)
        self.all_countries: dict[str, str] = {}  # code -> name (all from API)
        self.all_cities_by_country: dict[str, set[str]] = {}  # country_code -> cities (from API)
        self.all_servers: set[str] = set()  # All server names from API
        self.countries_with_configs: set[str] = set()
        self.servers_with_configs: set[str] = set()  # All server names with configs
        self.servers_by_country: dict[str, str] = {}  # server_name -> country_code
        self.cities_by_country: dict[str, set[str]] = {}  # country_code -> set of city names (from configs)
        self.extracted_private_key: str = ""  # Reusable private key automatically fetched from the first valid .conf file
        
        
        # Baseline speedtest (run without VPN for comparison)
        self.baseline_speedtest: Optional[dict] = None
        
        # Metrics cache (for efficient API response before falling back to DB)
        self.scan_history: list[dict] = []  
        self.speedtest_history: list[dict] = []
        
        # Performance tracking history (in-memory cache for quick access)
        self.server_performance_history: dict[str, list[dict]] = config_manager.config.performance.history.copy()
        
        # Ban frequency tracking: server_name -> total ban count across all scans
        self.ban_history: dict[str, int] = {}
        
        # Port/Entry discovery state
        self.port_discovery_results: dict[str, dict] = {}  # "PORT_ENTRY" -> {download, upload, ping, tests}
        self.port_discovery_complete: bool = False
        
        # DB-restored cache for metrics (populated on startup, overwritten by live scans)
        self._last_scan_servers: list[dict] = []
        self._last_scan_entry_pings: list[dict] = []

    async def startup(self):
        """Asynchronous startup initialization."""
        logger = logging.getLogger("airbl.state")
        
        # Initialize Database
        db_path = settings.cache_dir / "airbl.db"
        self.db = DatabaseManager(db_path)
        
        # Pre-load recent history into cache for faster dashboard load
        try:
            self.scan_history = await self.db.get_scan_history(limit=50)
        except Exception as e:
            logger.error(f"Failed to load DB scan history: {e}")
        
        # Restore ban frequency history from DB
        try:
            self.ban_history = await self.db.get_ban_history()
            if self.ban_history:
                logger.info(f"Restored ban history for {len(self.ban_history)} servers from DB")
        except Exception as e:
            logger.error(f"Failed to restore ban history: {e}")
        
        # Restore last scan's per-server data for metrics charts
        try:
            self._last_scan_servers = await self.db.get_last_scan_servers()
            self._last_scan_entry_pings = await self.db.get_last_scan_entry_pings()
            if self._last_scan_servers:
                logger.info(f"Restored last scan metrics for {len(self._last_scan_servers)} servers from DB")
        except Exception as e:
            logger.error(f"Failed to restore last scan data: {e}")
        
        # Restore port discovery results from persisted config
        persisted_discovery = config_manager.config.scan.discovery_results
        if persisted_discovery:
            self.port_discovery_results = persisted_discovery
            logger.info(f"Restored {len(persisted_discovery)} discovery results from config")
        
        # Scan config directory for WireGuard configs
        try:
            from ..wireguard import scan_config_directory
            configs = scan_config_directory(self.config_dir)
            logger.info(f"Found {len(configs)} config files in {self.config_dir}")
            
            for config in configs:
                # Track countries with configs
                self.countries_with_configs.add(config.country_code.upper())
                
                # Track servers with configs and their country
                self.servers_with_configs.add(config.server_name)
                self.servers_by_country[config.server_name] = config.country_code.upper()
                
                # Track cities by country
                country = config.country_code.upper()
                if country not in self.cities_by_country:
                    self.cities_by_country[country] = set()
                self.cities_by_country[country].add(config.city)
                
                # Snag a private key from the configs as a sane default for the frontend
                if config.private_key and not self.extracted_private_key:
                    self.extracted_private_key = config.private_key
                
                
        except Exception as e:
            logger.error(f"Failed to scan config directory: {e}")
        
        # Fetch API data to get all available countries, cities, and servers
        try:
            from ..airvpn import get_airvpn_status
            status = await get_airvpn_status()
            for server in status.servers:
                code = server.country_code.upper()
                # Track all countries
                self.all_countries[code] = server.country_name
                # Track all servers
                self.all_servers.add(server.public_name)
                # Track all cities by country
                if code not in self.all_cities_by_country:
                    self.all_cities_by_country[code] = set()
                self.all_cities_by_country[code].add(server.location)
            
            logger.info(f"Loaded from API: {len(self.all_countries)} countries, {len(self.all_servers)} servers")
        except Exception as e:
            logger.warning(f"Failed to fetch API data: {e}")

    @property
    def config_dir(self) -> Path:
        # Return override if set, otherwise use settings
        return getattr(self, '_config_dir_override', None) or settings.config_dir
    
    @config_dir.setter
    def config_dir(self, value: Path):
        # Store override for runtime configuration
        self._config_dir_override = value
        
    @property
    def disabled_servers(self) -> set[str]:
        return set(config_manager.config.performance.disabled_servers)
        
    @property
    def enabled_countries(self) -> set[str]:
        return set(config_manager.config.regions.countries)
        
    @property
    def enabled_servers(self) -> set[str]:
        return set(config_manager.config.servers)
    
    @property
    def enabled_cities(self) -> dict[str, set[str]]:
        return {k: set(v) for k, v in config_manager.config.cities.items()}
     
    @property
    def auto_scan_enabled(self) -> bool:
        return config_manager.config.scan.auto_scan_enabled
    
    @auto_scan_enabled.setter
    def auto_scan_enabled(self, value: bool):
        # Allow setting at runtime - update the config
        config_manager.config.scan.auto_scan_enabled = value
        
    @property
    def speedtest_enabled(self) -> bool:
        return config_manager.config.scan.speedtest_enabled
    
    @property
    def scan_interval_minutes(self) -> int:
        return config_manager.config.scan.scan_interval_minutes
        
    @scan_interval_minutes.setter
    def scan_interval_minutes(self, value: int):
        # We need this setter because run_server might try to set it during init
        # Ideally we update the SettingsManager, but for simplicity we can allow it
        # or better, update the config_manager
        pass # It's managed by config now, ignoring direct set or implement update logic if needed during startup override


# Global state instance
state = AppState()

# Debug log buffer (circular buffer for last 1000 entries)
debug_log_buffer = deque(maxlen=1000)
debug_log_paused = False


class DebugLogHandler(logging.Handler):
    """Custom logging handler that writes to debug log buffer."""
    
    def emit(self, record):
        """Emit a log record to the debug buffer."""
        global debug_log_paused
        if debug_log_paused:
            return
        
        # Filter out noisy third-party library DEBUG logs
        if record.levelno == logging.DEBUG:
            if not record.name.startswith("airbl"):
                return  # Skip DEBUG logs from third-party libraries
        
        try:
            log_entry = {
                "timestamp": datetime.now().isoformat(),
                "level": record.levelname,
                "message": self.format(record),
                "module": record.module,
                "funcName": record.funcName,
                "lineno": record.lineno,
            }
            debug_log_buffer.append(log_entry)
            
            # Broadcast to WebSocket clients
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(broadcast_log(log_entry))
            except RuntimeError:
                pass # No running loop
            except Exception:
                pass
        except Exception:
            pass  # Don't fail on logging errors


def setup_debug_logging():
    """Set up debug logging handler."""
    handler = DebugLogHandler()
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    
    # Add to root logger
    root_logger = logging.getLogger()
    root_logger.addHandler(handler)
    root_logger.setLevel(logging.DEBUG)
    
    # Suppress DEBUG logs from third-party libraries
    logging.getLogger("httpcore").setLevel(logging.INFO)
    logging.getLogger("httpx").setLevel(logging.INFO)
    logging.getLogger("urllib3").setLevel(logging.INFO)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    
    # Keep DEBUG for airbl package only
    logging.getLogger("airbl").setLevel(logging.DEBUG)
    
    # Also capture print statements by redirecting stdout
    
    class PrintCapture:
        def write(self, text):
            if text.strip():
                # Filter out noisy uvicorn access logs for the debug logs poller itself
                if "/api/debug/logs" in text or "GET /api/debug/logs" in text:
                    sys.__stdout__.write(text)
                    return
                
                log_entry = {
                    "timestamp": datetime.now().isoformat(),
                    "level": "INFO",
                    "message": text.strip(),
                    "module": "stdout",
                    "funcName": "",
                    "lineno": 0,
                }
                if not debug_log_paused:
                    debug_log_buffer.append(log_entry)
                    # Broadcast asynchronously
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(broadcast_log(log_entry))
                    except RuntimeError:
                        pass
                    except Exception:
                        pass
            sys.__stdout__.write(text)
        
        def flush(self):
            sys.__stdout__.flush()
        
        def isatty(self):
            return sys.__stdout__.isatty()
        
        def fileno(self):
            return sys.__stdout__.fileno()
    
    sys.stdout = PrintCapture()
