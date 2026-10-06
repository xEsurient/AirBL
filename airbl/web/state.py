"""
Global application state and logging for AirBL Web UI.
"""

from typing import Optional
from pathlib import Path
from datetime import datetime
from collections import deque
import logging
import asyncio
import copy
import json
import sys

# Avoid circular imports but allow type checking
from ..scanner import ScanSummary
from ..config import config_manager, settings
# Database manager
from ..database import DatabaseManager


class AppState:
    def __init__(self):
        # Last completed scan (what results, exports and Gluetun use)
        self.current_scan: Optional[ScanSummary] = None
        # Scan in progress; promoted to current_scan only when it completes
        self.live_scan: Optional[ScanSummary] = None
        self.current_scan_id: Optional[int] = None
        self.is_scanning: bool = False
        self.is_paused: bool = False
        self.scan_progress: dict = {"phase": "idle", "current": 0, "total": 0, "server": "", "country": "", "next": ""}
        self.next_scan_at: Optional[datetime] = None
        
        # NOTE: scan_interval_minutes is now managed by SettingsManager (config_manager.config.scan.scan_interval_minutes)
        # But we keep a property wrapper using it.
        
        self.websocket_clients: list = []  # Type: list[WebSocket]
        self.scan_task: Optional[asyncio.Task] = None
        self.scan_cancelled: bool = False
        
        self.settings_updated_event = None
        
        # Load initial settings
        config_manager.load()
        
        # Database Manager (Initialized on startup)
        self.db: Optional[DatabaseManager] = None
        
        # Runtime Data (Available countries, etc.)
        self.all_countries: dict[str, str] = {}  # code -> name (all from API)
        self.all_cities_by_country: dict[str, set[str]] = {}  # country_code -> cities (from API)
        self.all_servers: set[str] = set()  # All server names from API
        self.countries_with_configs: set[str] = set()
        self.servers_with_configs: set[str] = set()  # All server names with configs
        self.servers_by_country: dict[str, str] = {}  # server_name -> country_code
        self.server_to_city_api: dict[str, str] = {}  # server_name -> city (from API)
        self.cities_by_country: dict[str, set[str]] = {}  # country_code -> set of city names (from configs)
        self.extracted_private_key: str = ""  # Reusable private key automatically fetched from the first valid .conf file
        
        
        # Baseline speedtest (run without VPN for comparison)
        self.baseline_speedtest: Optional[dict] = None
        
        # Metrics cache (for efficient API response before falling back to DB)
        self.scan_history: list[dict] = []
        
        # Performance tracking history (in-memory cache for quick access)
        self.server_performance_history: dict[str, list[dict]] = config_manager.config.performance.history.copy()
        
        # Ban frequency tracking: server_name -> total ban count across all scans
        self.ban_history: dict[str, int] = {}
        
        # Port/Entry discovery state
        self.port_discovery_results: dict[str, dict] = {}  # "PORT_ENTRY" -> {download, upload, ping, tests}
        
        # DB-restored cache for metrics (populated on startup, overwritten by live scans)
        self._last_scan_servers: list[dict] = []
        self._last_scan_entry_pings: list[dict] = []

    def save_baseline(self, baseline: dict) -> None:
        """Keep the no-VPN baseline across restarts (deviation scores depend on it)."""
        self.baseline_speedtest = baseline
        path = settings.cache_dir / "baseline.json"
        try:
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(baseline))
            tmp.replace(path)
        except Exception as e:
            logging.getLogger("airbl.state").warning(f"Could not save baseline: {e}")

    def _load_baseline(self) -> None:
        path = settings.cache_dir / "baseline.json"
        try:
            data = json.loads(path.read_text())
            if isinstance(data, dict) and data.get("download_mbps"):
                self.baseline_speedtest = data
        except FileNotFoundError:
            pass
        except Exception as e:
            logging.getLogger("airbl.state").warning(f"Ignoring unreadable baseline file: {e}")

    async def startup(self):
        """Asynchronous startup initialization."""
        logger = logging.getLogger("airbl.state")
        
        self.settings_updated_event = asyncio.Event()
        self._load_baseline()
        
        # Initialize Database
        db_path = settings.cache_dir / "airbl.db"
        self.db = DatabaseManager(db_path)
        await self.db.init()
        
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
            # Copy: the live dict is mutated during discovery and saved back explicitly
            self.port_discovery_results = copy.deepcopy(persisted_discovery)
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
                # Map server to country and city globally
                self.servers_by_country[server.public_name] = code
                self.server_to_city_api[server.public_name] = server.location
                # Track all cities by country
                if code not in self.all_cities_by_country:
                    self.all_cities_by_country[code] = set()
                self.all_cities_by_country[code].add(server.location)
            
            logger.info(f"Loaded from API: {len(self.all_countries)} countries, {len(self.all_servers)} servers")
        except Exception as e:
            logger.warning(f"Failed to fetch API data: {e}")

        # After a restart, rebuild the last completed scan so results, exports and manual tests work
        if self.current_scan is None and self.db:
            try:
                self.current_scan = await self._restore_last_scan()
            except Exception as e:
                logger.error(f"Failed to rebuild last scan from DB: {e}", exc_info=True)

    async def _restore_last_scan(self) -> Optional[ScanSummary]:
        """ScanSummary for the last completed scan, rebuilt from the DB (marked restored=True).

        The DB keeps one exit IP and the reputation per server, so each server gets a single
        ScannedIP whose DroneBL result reproduces clean/blocked; unknown rows get none.
        """
        from ..scanner import ServerScanResult, ScannedIP
        from ..dronebl import DroneBLResult
        from ..pinger import PingResult
        from ..speedtest import SpeedTestResult
        from ..database import row_is_clean
        from ..wireguard import scan_config_directory
        logger = logging.getLogger("airbl.state")

        scan = await self.db.get_last_complete_scan()
        rows = self._last_scan_servers
        if not scan or not rows:
            return None
        try:
            scanned_at = datetime.fromisoformat(scan["timestamp"])
        except (TypeError, ValueError):
            scanned_at = datetime.now()

        pings: dict[str, dict] = {}
        for ep in self._last_scan_entry_pings:
            pings.setdefault(ep["server_name"], {})[ep["entry_type"]] = ep

        # Latest speedtest per server since that scan started (its batch tests and later manual ones)
        speedtests: dict[str, dict] = {}
        for st in await self.db.get_speedtest_history(limit=1000):
            name = st.get("vpn_server_name")
            if not name or name in speedtests or (st.get("timestamp") or "") < scan["timestamp"]:
                continue
            if st.get("is_success"):
                res = SpeedTestResult(download_mbps=st.get("download_mbps") or 0.0,
                                      upload_mbps=st.get("upload_mbps") or 0.0,
                                      ping_ms=st.get("ping_ms") or 0.0, server_name=st.get("server_name"))
                dct = res.to_dict()
                dct["tested_at"] = st.get("timestamp")
            else:
                dct = {"error": st.get("error_message") or "Speedtest failed"}
            dct.update(vpn_server_name=name, vpn_country_code=st.get("vpn_country_code"),
                       vpn_port=st.get("vpn_port"), vpn_entry=st.get("vpn_entry"), restored=True)
            speedtests[name] = dct

        configs = {}
        try:
            for c in scan_config_directory(self.config_dir):
                configs.setdefault(c.server_name, c)
        except Exception as e:
            logger.debug(f"Restore: config scan failed: {e}")

        def ping(ip, alive, ms):
            return PingResult(ip=ip or "", is_alive=bool(alive), avg_rtt_ms=ms)

        servers = []
        for row in rows:
            name = row["server_name"]
            conf = configs.get(name)
            code = (conf.country_code.upper() if conf else
                    self.servers_by_country.get(name) or self.servers_by_country.get(name.replace("AirVPN ", ""), "??"))
            exit_ip = row.get("exit_ip")
            exit_ping = ping(exit_ip, row.get("exit_ping_ms") is not None, row.get("exit_ping_ms")) if exit_ip else None

            reputation = row.get("reputation") or ("clean" if row_is_clean(row) else "blocked")
            scanned_ips = []
            if exit_ip or reputation != "unknown":
                scanned_ips.append(ScannedIP(
                    ip=exit_ip or "", server_name=name, country_code=code,
                    country_name=self.all_countries.get(code, code), location=conf.city if conf else "",
                    is_from_dns=True, ping=exit_ping, is_responsive=bool(row.get("is_responsive")),
                    dronebl=(DroneBLResult(ip=exit_ip or "", is_listed=reputation == "blocked", checked_at=scanned_at)
                             if reputation in ("clean", "blocked") else None),
                ))

            entry = pings.get(name, {})
            e1, e3 = entry.get("ENTRY1"), entry.get("ENTRY3")
            servers.append(ServerScanResult(
                server_name=name,
                country_code=code,
                country_name=(conf.country_name if conf else None) or self.all_countries.get(code, code),
                location=(conf.city if conf else None) or self.server_to_city_api.get(name, ""),
                load_percent=row.get("load_percent") or 0,
                users=row.get("users") or 0,
                bandwidth_current=0,
                bandwidth_max=0,
                config_file=conf.file_path if conf else None,
                wg_pubkey=(conf.public_key if conf else "") or "",
                scanned_ips=scanned_ips,
                scanned_at=scanned_at,
                speedtest_result=speedtests.get(name),
                exit_ping=exit_ping,
                entry1_ping=ping(e1["ip"], e1["is_alive"], e1["latency_ms"]) if e1 else None,
                entry3_ping=ping(e3["ip"], e3["is_alive"], e3["latency_ms"]) if e3 else None,
            ))

        summary = ScanSummary(
            servers=servers,
            countries_scanned=sorted({s.country_code for s in servers}),
            started_at=scanned_at,
            completed_at=scanned_at,
            scan_interval_minutes=self.scan_interval_minutes,
        )
        summary.restored = True
        logger.info(f"Restored last completed scan #{scan['id']} from DB: {summary.total_servers} servers "
                    f"({summary.clean_servers_count} clean, {summary.blocked_servers_count} blocked, "
                    f"{len(speedtests)} speedtests)")
        return summary

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
        # Runtime override (SCAN_INTERVAL / --interval); same bounds as the settings page
        config_manager.config.scan.scan_interval_minutes = max(5, min(1440, int(value)))


# Global state instance
state = AppState()

# Debug log buffer (circular buffer for last 1000 entries); the debug page polls it.
# Not pushed over the WebSocket: that cost a task per line and every tab got the stream.
debug_log_buffer = deque(maxlen=1000)


class DebugLogHandler(logging.Handler):
    """Custom logging handler that writes to debug log buffer."""
    
    def emit(self, record):
        """Emit a log record to the debug buffer."""
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
                debug_log_buffer.append(log_entry)
            sys.__stdout__.write(text)
        
        def flush(self):
            sys.__stdout__.flush()
        
        def isatty(self):
            return sys.__stdout__.isatty()
        
        def fileno(self):
            return sys.__stdout__.fileno()
    
    sys.stdout = PrintCapture()
