"""
API Routes for AirBL Web UI.
"""

from fastapi import APIRouter, BackgroundTasks, Request, WebSocket, HTTPException, Response
from datetime import datetime
import logging
import asyncio

from ..state import state, debug_log_buffer, debug_log_paused
from ...config import config_manager
from ..tasks import run_scan_task, run_speedtest_task
from ..websockets import websocket_handler, broadcast_update
from ...airvpn import get_airvpn_status

router = APIRouter()
logger = logging.getLogger("airbl.web.api")


# --- Metrics & Status ---

@router.post("/baseline-speedtest")
async def trigger_baseline_speedtest(background_tasks: BackgroundTasks):
    """Trigger a baseline speedtest (run without VPN)."""
    from ..tasks import run_baseline_speedtest
    background_tasks.add_task(run_baseline_speedtest)
    return {"status": "started", "message": "Baseline speedtest started"}

@router.get("/baseline-speedtest")
async def get_baseline_speedtest():
    """Get the current baseline speedtest result."""
    if state.baseline_speedtest:
        return {"baseline": state.baseline_speedtest}
    return {"baseline": None, "message": "No baseline speedtest available. Run one first."}

@router.get("/metrics")
async def get_metrics():
    """Get metrics data for charts."""
    scan_hist = state.scan_history[-50:]
    speed_hist = state.speedtest_history[-100:]
    
    if state.db:
        try:
            scan_hist = await state.db.get_scan_history(limit=50)
            if not speed_hist:
                 speed_hist = await state.db.get_speedtest_history(limit=100)
        except Exception:
            pass

    # Build per-country breakdown, ping averages, and per-server pings
    country_stats = []
    ping_by_country = []
    ping_by_server = []
    
    if state.current_scan:
        # Live scan data available — use rich dataclass objects
        by_country = state.current_scan.servers_by_country()
        disabled_set = set(s.lower() for s in config_manager.config.performance.disabled_servers)
        for code in sorted(by_country.keys()):
            servers = by_country[code]
            clean = len([s for s in servers if s.is_clean and s.server_name.lower() not in disabled_set])
            blocked = len([s for s in servers if not s.is_clean])
            disabled = len([s for s in servers if s.server_name.lower() in disabled_set])
            country_stats.append({
                "country_code": code,
                "country_name": servers[0].country_name if servers else code,
                "clean": clean,
                "blocked": blocked,
                "disabled": disabled
            })

            # Collect pings for country averaging
            e1_pings = []
            e3_pings = []
            for s in servers:
                name = s.server_name.replace("AirVPN ", "")
                e1 = None
                e3 = None
                if s.entry1_ping and s.entry1_ping.avg_rtt_ms:
                    e1 = round(s.entry1_ping.avg_rtt_ms, 1)
                    e1_pings.append(e1)
                if s.entry3_ping and s.entry3_ping.avg_rtt_ms:
                    e3 = round(s.entry3_ping.avg_rtt_ms, 1)
                    e3_pings.append(e3)
                ping_by_server.append({
                    "server_name": name,
                    "country_code": code,
                    "entry1_ping": e1,
                    "entry3_ping": e3,
                })

            ping_by_country.append({
                "country_code": code,
                "avg_entry1": round(sum(e1_pings) / len(e1_pings), 1) if e1_pings else None,
                "avg_entry3": round(sum(e3_pings) / len(e3_pings), 1) if e3_pings else None,
            })
    
    elif state._last_scan_servers:
        # No live scan yet — fall back to DB-restored last scan data
        disabled_set = set(s.lower() for s in config_manager.config.performance.disabled_servers)
        
        # Build entry ping lookup from DB cache
        entry_pings = {}  # server_name -> {ENTRY1: latency, ENTRY3: latency}
        for ep in state._last_scan_entry_pings:
            name = ep["server_name"]
            if name not in entry_pings:
                entry_pings[name] = {}
            if ep.get("is_alive") and ep.get("latency_ms"):
                entry_pings[name][ep["entry_type"]] = round(ep["latency_ms"], 1)
        
        # Group servers by country using servers_by_country mapping
        by_country: dict[str, list[dict]] = {}
        for srv in state._last_scan_servers:
            name = srv["server_name"]
            code = state.servers_by_country.get(name, state.servers_by_country.get(name.replace("AirVPN ", ""), "??"))
            if code not in by_country:
                by_country[code] = []
            by_country[code].append(srv)
        
        for code in sorted(by_country.keys()):
            servers = by_country[code]
            clean = len([s for s in servers if not s.get("is_blocked") and s["server_name"].lower() not in disabled_set])
            blocked = len([s for s in servers if s.get("is_blocked")])
            disabled = len([s for s in servers if s["server_name"].lower() in disabled_set])
            country_stats.append({
                "country_code": code,
                "country_name": state.all_countries.get(code, code),
                "clean": clean,
                "blocked": blocked,
                "disabled": disabled
            })
            
            e1_pings_list = []
            e3_pings_list = []
            for s in servers:
                name = s["server_name"].replace("AirVPN ", "")
                pings = entry_pings.get(s["server_name"], {})
                e1 = pings.get("ENTRY1")
                e3 = pings.get("ENTRY3")
                if e1: e1_pings_list.append(e1)
                if e3: e3_pings_list.append(e3)
                ping_by_server.append({
                    "server_name": name,
                    "country_code": code,
                    "entry1_ping": e1,
                    "entry3_ping": e3,
                })
            
            ping_by_country.append({
                "country_code": code,
                "avg_entry1": round(sum(e1_pings_list) / len(e1_pings_list), 1) if e1_pings_list else None,
                "avg_entry3": round(sum(e3_pings_list) / len(e3_pings_list), 1) if e3_pings_list else None,
            })

    total_servers = len(state.current_scan.servers) if state.current_scan else len(state._last_scan_servers)
    clean_count = len([s for s in state.current_scan.servers if s.is_clean]) if state.current_scan else len([s for s in state._last_scan_servers if not s.get("is_blocked")])
    blocked_count = len([s for s in state.current_scan.servers if not s.is_clean]) if state.current_scan else len([s for s in state._last_scan_servers if s.get("is_blocked")])

    return {
        "scan_history": scan_hist,
        "speedtest_history": speed_hist,
        "current_stats": {
            "total_servers": total_servers,
            "clean_servers": clean_count,
            "blocked_servers": blocked_count,
            "disabled_servers": len(state.disabled_servers),
        },
        "country_stats": country_stats,
        "ping_by_country": ping_by_country,
        "ping_by_server": ping_by_server,
        "ban_history": sorted(
            [{"server_name": k.replace("AirVPN ", ""), "ban_count": v} for k, v in state.ban_history.items()],
            key=lambda x: x["ban_count"],
            reverse=True
        ),
    }

@router.get("/metrics/advanced")
async def get_advanced_metrics():
    """Get advanced historical averages for periods."""
    if state.db:
        try:
            return await state.db.get_historical_averages()
        except Exception as e:
            logger.error(f"Error fetching advanced metrics: {e}")
    _empty = {"total_scans": 0, "avg_clean": 0, "avg_blocked": 0}
    return {"7d": _empty.copy(), "30d": _empty.copy(), "180d": _empty.copy()}


@router.get("/status")
async def get_status():
    """Get current scan status."""
    # Check WG key availability for dashboard banner
    try:
        from ...confgen import has_client_identity
        wg_keys_ok = has_client_identity()
    except Exception:
        wg_keys_ok = False

    result = {
        "is_scanning": state.is_scanning,
        "is_paused": state.is_paused,
        "progress": state.scan_progress,
        "next_scan_at": state.next_scan_at.isoformat() if state.next_scan_at else None,
        "next_scan_in_seconds": (
            (state.next_scan_at - datetime.now()).total_seconds()
            if state.next_scan_at and state.next_scan_at > datetime.now()
            else None
        ),
        "scan_interval_minutes": state.scan_interval_minutes,
        "has_results": state.current_scan is not None,
        "auto_scan_enabled": state.auto_scan_enabled,
        "baseline_speedtest": state.baseline_speedtest,
        "wg_keys_available": wg_keys_ok,
        "scoring": {
            "signal_good_threshold": config_manager.config.scoring.signal_good_threshold,
            "signal_medium_threshold": config_manager.config.scoring.signal_medium_threshold,
        },
    }
    # Include summary stats if available
    if state.current_scan:
        result["summary"] = state.current_scan.to_dict()
    return result


@router.get("/results")
async def get_results():
    """Get current scan results."""
    if state.current_scan is None:
        return {"error": "No scan results available"}
    return state.current_scan.to_dict()


# --- Server Querying ---

@router.get("/servers")
async def get_servers(
    country: str = None,
    status: str = None,  # "clean", "blocked", "all"
    min_score: float = None,
    max_load: int = None,
    max_ping: float = None,
    min_dev: float = None,
    min_download: float = None,
    min_upload: float = None,
):
    """Get servers with optional filtering."""
    if state.current_scan is None:
        return {"servers": [], "countries": []}
    
    # Group by country and sort
    by_country = state.current_scan.servers_by_country()
    
    result = []
    for country_code in sorted(by_country.keys()):
        # Country filter
        if country and country.upper() != country_code.upper():
            continue
        
        servers = by_country[country_code]
        if not servers:
            continue
        
        # Apply filters to servers
        filtered_servers = []
        for s in servers:
            # Status filter
            if status == "clean" and not s.is_clean:
                continue
            if status == "blocked" and s.is_clean:
                continue
            
            # Score filter
            if min_score is not None and s.score < min_score:
                continue
            
            # Load filter
            if max_load is not None and s.load_percent > max_load:
                continue
            
            # Ping filter
            if max_ping is not None:
                best = s.best_ip
                if best and best.latency_ms and best.latency_ms > max_ping:
                    continue
            
            # Download speed filter
            if min_download is not None:
                if not s.speedtest_result or not s.speedtest_result.get("download_mbps"):
                    continue
                if s.speedtest_result.get("download_mbps", 0) < min_download:
                    continue
            
            # Upload speed filter
            if min_upload is not None:
                if not s.speedtest_result or not s.speedtest_result.get("upload_mbps"):
                    continue
                if s.speedtest_result.get("upload_mbps", 0) < min_upload:
                    continue
            
            # Deviation score filter (percentage of baseline)
            if min_dev is not None:
                if not s.speedtest_result or not s.speedtest_result.get("deviation_score"):
                    continue
                if s.speedtest_result.get("deviation_score", 0) < min_dev:
                    continue
            
            filtered_servers.append(s)
        
        if not filtered_servers:
            continue
        
        country_data = {
            "country_code": country_code,
            "country_name": servers[0].country_name,
            "servers": [s.to_dict() for s in filtered_servers],
            "best_server": filtered_servers[0].to_dict() if filtered_servers and filtered_servers[0].is_clean else None,
            "total_servers": len(filtered_servers),
            "clean_servers": len([s for s in filtered_servers if s.is_clean]),
            "blocked_servers": len([s for s in filtered_servers if not s.is_clean]),
        }
        result.append(country_data)
    
    return {"countries": result}


@router.get("/export/gluetun")
async def export_gluetun_servers(country: str = None):
    """Export clean servers as a plain-text SERVER_NAMES string for Gluetun."""
    if state.current_scan is None:
        return Response(content="Error: No scan results available", media_type="text/plain", status_code=400)
    
    servers = state.current_scan.servers
    if country:
        servers = [s for s in servers if s.country_code.upper() == country.upper()]
    
    clean_servers = [s.server_name for s in servers if s.is_clean]
    
    if not clean_servers:
        return Response(content="Error: No clean servers found", media_type="text/plain", status_code=404)
    
    server_list = ",".join(clean_servers)
    return Response(content=f"SERVER_NAMES={server_list}", media_type="text/plain")


# --- Gluetun Status ---

@router.get("/gluetun/status")
async def get_gluetun_vpn_status():
    """Get current Gluetun VPN connection status."""
    cfg = config_manager.config.gluetun
    if not cfg.force_update_enabled:
        return {"connected": False, "enabled": False}
    
    from ...gluetun import get_gluetun_status
    status = await get_gluetun_status(cfg.control_server_host, cfg.control_server_port)
    status["enabled"] = True
    return status


# --- Discovery ---

@router.post("/discovery/restart")
async def restart_discovery():
    """Reset discovery state and restart the discovery period."""
    from datetime import datetime
    cfg = config_manager.config.scan
    cfg.port_discovery_enabled = True
    cfg.discovery_started_at = datetime.now().isoformat()
    cfg.discovery_auto_port = None
    cfg.discovery_auto_entry = None
    cfg.discovery_results = {}
    state.port_discovery_results = {}
    state.port_discovery_complete = False
    config_manager.save()
    return {"status": "ok", "message": "Discovery restarted", "started_at": cfg.discovery_started_at}


# --- Settings ---

@router.get("/settings")
async def get_settings():
    """Get current settings."""
    # Ensure countries list is up to date if possible (though blocking API call isn't ideal here)
    # Ideally this runs background, but for now we follow old pattern or skip if cached
    if not state.all_countries:
        try:
           status = await get_airvpn_status()
           for server in status.servers:
                code = server.country_code.upper()
                state.all_countries[code] = server.country_name
        except:
             pass

    cfg = config_manager.config
    
    return {
        "scan_interval_minutes": cfg.scan.scan_interval_minutes,
        "auto_scan_enabled": cfg.scan.auto_scan_enabled,
        "speedtest_enabled": cfg.scan.speedtest_enabled,
        # Port discovery
        "port_discovery_enabled": cfg.scan.port_discovery_enabled,
        "preferred_port": cfg.scan.preferred_port,
        "preferred_mtu": cfg.scan.preferred_mtu,
        "preferred_entry_ip": cfg.scan.preferred_entry_ip,
        "discovery_test_count": cfg.scan.discovery_test_count,
        "discovery_duration_days": cfg.scan.discovery_duration_days,
        "discovery_entry_filter": cfg.scan.discovery_entry_filter,
        "discovery_started_at": cfg.scan.discovery_started_at,
        "discovery_auto_port": cfg.scan.discovery_auto_port,
        "discovery_auto_entry": cfg.scan.discovery_auto_entry,
        "available_ports": cfg.scan.available_ports,
        "post_server_wait": cfg.scan.post_server_wait,
        "port_discovery_results": state.port_discovery_results,
        "all_countries": state.all_countries,
        "all_cities_by_country": {k: list(v) for k, v in state.all_cities_by_country.items()},
        "all_servers": list(state.all_servers),
        "countries_with_configs": list(state.countries_with_configs),
        "enabled_countries": list(cfg.regions.countries),
        "excluded_countries": list(cfg.regions.excluded_countries),
        "servers_with_configs": list(state.servers_with_configs),
        "enabled_servers": list(cfg.servers),
        "cities_by_country": {k: list(v) for k, v in state.cities_by_country.items()},
        "enabled_cities": {k: list(v) for k, v in cfg.cities.items()},
        "performance_threshold_download": cfg.performance.threshold_download,
        "performance_threshold_upload": cfg.performance.threshold_upload,
        "performance_check_count": cfg.performance.check_count,
        "disabled_servers": list(cfg.performance.disabled_servers),
        "speedtest_blacklist_duration_days": cfg.speedtest_blacklist.duration_days,
        "speedtest_blacklist_max_failures": cfg.speedtest_blacklist.max_failures,
        "extracted_private_key": getattr(state, "extracted_private_key", ""),
        # Scoring settings
            "deviation_download_weight": cfg.scoring.deviation_download_weight,
        "deviation_upload_weight": cfg.scoring.deviation_upload_weight,
        "signal_good_threshold": cfg.scoring.signal_good_threshold,
        "signal_medium_threshold": cfg.scoring.signal_medium_threshold,
        
        # Gluetun settings
        "gluetun_force_update": cfg.gluetun.force_update_enabled,
        "gluetun_force_update_mode": cfg.gluetun.force_update_mode,
        "gluetun_control_host": cfg.gluetun.control_server_host,
        "gluetun_control_port": cfg.gluetun.control_server_port,
        "gluetun_profiles": [
            {
                "name": p.name,
                "enabled": p.enabled,
                "output_path": str(p.output_path),
                "endpoint_strategy": p.endpoint_strategy,
                "min_download_mbps": p.min_download_mbps,
                "min_upload_mbps": p.min_upload_mbps,
                "require_clean": p.require_clean,
                "allowed_countries": p.allowed_countries,
                "allowed_cities": p.allowed_cities
            } for p in cfg.gluetun.profiles
        ],
        # WireGuard settings
        "wg_profiles": [
            p.model_dump(mode='json') for p in cfg.wireguard.profiles
        ],
    }


@router.post("/settings")
async def update_settings(request: Request):
    """Update settings via SettingsManager."""
    data = await request.json()
    cfg = config_manager.config
    current_disabled = set(cfg.performance.disabled_servers)
    
    # Update Config Object
    if "scan_interval_minutes" in data:
        cfg.scan.scan_interval_minutes = max(5, min(1440, int(data["scan_interval_minutes"])))
    
    if "auto_scan_enabled" in data:
        cfg.scan.auto_scan_enabled = bool(data["auto_scan_enabled"])
    
    if "speedtest_enabled" in data:
        cfg.scan.speedtest_enabled = bool(data["speedtest_enabled"])
    
    # Port Discovery Settings
    if "port_discovery_enabled" in data:
        was_enabled = cfg.scan.port_discovery_enabled
        cfg.scan.port_discovery_enabled = bool(data["port_discovery_enabled"])
        # Auto-set discovery_started_at when first enabled
        if cfg.scan.port_discovery_enabled and not was_enabled and not cfg.scan.discovery_started_at:
            from datetime import datetime
            cfg.scan.discovery_started_at = datetime.now().isoformat()
    if "preferred_port" in data:
        port = int(data["preferred_port"])
        if port in cfg.scan.available_ports:
            cfg.scan.preferred_port = port
    if "preferred_mtu" in data:
        cfg.scan.preferred_mtu = int(data["preferred_mtu"])
    if "preferred_entry_ip" in data:
        entry = str(data["preferred_entry_ip"])
        if entry in ("ENTRY1", "ENTRY3", "AUTO"):
            cfg.scan.preferred_entry_ip = entry
    if "discovery_test_count" in data:
        cfg.scan.discovery_test_count = max(1, min(10, int(data["discovery_test_count"])))
    if "discovery_duration_days" in data:
        days = int(data["discovery_duration_days"])
        if days in (3, 5, 7):
            cfg.scan.discovery_duration_days = days
    if "discovery_entry_filter" in data:
        f = str(data["discovery_entry_filter"])
        if f in ("ALL", "ENTRY1", "ENTRY3"):
            cfg.scan.discovery_entry_filter = f
    if "post_server_wait" in data:
        wait = int(data["post_server_wait"])
        if wait in (120, 180):
            cfg.scan.post_server_wait = wait
    
    if "enabled_countries" in data:
        cfg.regions.countries = list(data["enabled_countries"])
    
    if "excluded_countries" in data:
        cfg.regions.excluded_countries = list(data["excluded_countries"])
    
    # Get enabled countries set for filtering
    enabled_countries_set = set(c.upper() for c in cfg.regions.countries)
    
    if "enabled_servers" in data:
        new_enabled = list(data["enabled_servers"])
        # Filter servers to only include those from enabled countries
        if enabled_countries_set and hasattr(state, 'servers_by_country'):
            filtered_servers = []
            for server in new_enabled:
                server_country = state.servers_by_country.get(server)
                if server_country is None or server_country.upper() in enabled_countries_set:
                    filtered_servers.append(server)
            new_enabled = filtered_servers
        
        cfg.servers = new_enabled
        # Remove explicitly enabled servers from disabled list
        enabled_lower = {s.lower() for s in new_enabled}
        cfg.performance.disabled_servers = [
            s for s in cfg.performance.disabled_servers 
            if s.lower() not in enabled_lower
        ]
    
    if "enabled_cities" in data:
        cfg.cities = {}
        for country_code, cities in data["enabled_cities"].items():
            # Only include cities from enabled countries
            if cities and (not enabled_countries_set or country_code.upper() in enabled_countries_set):
                cfg.cities[country_code.upper()] = list(cities)

    # Performance Settings
    if "performance_threshold_download" in data:
        cfg.performance.threshold_download = max(1.0, float(data["performance_threshold_download"]))
    
    if "performance_threshold_upload" in data:
        cfg.performance.threshold_upload = max(1.0, float(data["performance_threshold_upload"]))
    
    if "performance_check_count" in data:
        cfg.performance.check_count = max(1, min(10, int(data["performance_check_count"])))
        
    if "speedtest_blacklist_duration_days" in data:
        cfg.speedtest_blacklist.duration_days = max(1, min(365, int(data["speedtest_blacklist_duration_days"])))
        
    if "speedtest_max_blacklist_failures" in data:
        cfg.speedtest_blacklist.max_failures = max(1, min(10, int(data["speedtest_max_blacklist_failures"])))
    
    # Allow manual updating of disabled/blocked servers (e.g. to unblock them)
    if "disabled_servers" in data:
        if isinstance(data["disabled_servers"], list):
            cfg.performance.disabled_servers = [str(s) for s in data["disabled_servers"]]

    # Scoring Settings
    if "deviation_download_weight" in data:
        weight = max(0.0, min(1.0, float(data["deviation_download_weight"])))
        cfg.scoring.deviation_download_weight = weight
        cfg.scoring.deviation_upload_weight = 1.0 - weight  # Ensure they sum to 1.0
    
    if "deviation_upload_weight" in data:
        weight = max(0.0, min(1.0, float(data["deviation_upload_weight"])))
        cfg.scoring.deviation_upload_weight = weight
        cfg.scoring.deviation_download_weight = 1.0 - weight  # Ensure they sum to 1.0
    
    if "signal_good_threshold" in data:
        cfg.scoring.signal_good_threshold = max(1, min(100, int(data["signal_good_threshold"])))
    
    if "signal_medium_threshold" in data:
        cfg.scoring.signal_medium_threshold = max(1, min(100, int(data["signal_medium_threshold"])))
    
    # Gluetun Settings
    gluetun_changed = False

    if "gluetun_force_update" in data:
        cfg.gluetun.force_update_enabled = bool(data["gluetun_force_update"])
    if "gluetun_force_update_mode" in data:
        mode = str(data["gluetun_force_update_mode"])
        if mode in ("CLEAN_ONLY", "NOT_TOP4", "NOT_BEST", "ALWAYS", "DISABLED"):
            cfg.gluetun.force_update_mode = mode
    if "gluetun_control_host" in data:
        cfg.gluetun.control_server_host = str(data["gluetun_control_host"]).strip() or "127.0.0.1"
    if "gluetun_control_port" in data:
        cfg.gluetun.control_server_port = max(1, min(65535, int(data["gluetun_control_port"])))
        
    if "gluetun_profiles" in data and isinstance(data["gluetun_profiles"], list):
        updated_profiles = []
        from airbl.config import GluetunProfileConfig
        for p_data in data["gluetun_profiles"]:
            try:
                profile = GluetunProfileConfig(
                    name=str(p_data.get("name", "Custom Profile")),
                    enabled=bool(p_data.get("enabled", False)),
                    output_path=str(p_data.get("output_path", "/app/gluetun/servers.json")),
                    endpoint_strategy=str(p_data.get("endpoint_strategy", "ALL")),
                    min_download_mbps=float(p_data.get("min_download_mbps", 0)),
                    min_upload_mbps=float(p_data.get("min_upload_mbps", 0)),
                    require_clean=bool(p_data.get("require_clean", True)),
                    allowed_countries=p_data.get("allowed_countries", []),
                    allowed_cities=p_data.get("allowed_cities", [])
                )
                updated_profiles.append(profile)
            except Exception as e:
                logger.warning(f"Skipping invalid profile data in save: {e}")
        if updated_profiles:
            cfg.gluetun.profiles = updated_profiles
            gluetun_changed = True

    # WireGuard Settings
    if "wg_profiles" in data and isinstance(data["wg_profiles"], list):
        from airbl.config import WireGuardProfileConfig
        updated_wg = []
        for wp in data["wg_profiles"]:
            try:
                updated_wg.append(WireGuardProfileConfig(**wp))
            except Exception as e:
                logger.warning(f"Skipping invalid WG profile: {e}")
        cfg.wireguard.profiles = updated_wg
    
    # Save Config
    if config_manager.save():
        logger.info("Settings updated and saved successfully.")
        
        # Trigger generation asynchronously if Gluetun config changed
        if gluetun_changed:
            has_enabled = any(p.enabled for p in cfg.gluetun.profiles)
            if has_enabled:
                from ...gluetun import generate_gluetun_servers_json
                asyncio.create_task(generate_gluetun_servers_json())
    else:
        logger.error("Failed to save settings.")
        return {"error": "Failed to persist settings"}

    await broadcast_update("settings_changed", {
        "scan_interval_minutes": cfg.scan.scan_interval_minutes,
        "auto_scan_enabled": cfg.scan.auto_scan_enabled,
        "enabled_countries": list(cfg.regions.countries),
        "enabled_servers": list(cfg.servers),
    })
    
    return {"status": "Settings updated"}


# --- Scan Control ---

@router.post("/scan/start")
async def start_scan(background_tasks: BackgroundTasks):
    """Start a new scan."""
    if state.is_scanning:
        return {"error": "Scan already in progress"}
    
    # Reset cancelled flag
    state.scan_cancelled = False
    state.is_paused = False
    
    # Start background task
    state.scan_task = asyncio.create_task(run_scan_task())
    
    return {"status": "Scan started"}


@router.post("/scan/stop")
async def stop_scan():
    """Stop current scan."""
    if not state.is_scanning:
        return {"error": "No scan in progress"}
    
    state.scan_cancelled = True
    if state.scan_task:
        state.scan_task.cancel()
        try:
            await state.scan_task
        except asyncio.CancelledError:
            pass
    
    await broadcast_update("scan_cancelled", {})
    return {"status": "Scan stopping..."}


@router.post("/scan/pause")
async def pause_scan():
    """Pause current scan."""
    if not state.is_scanning:
        return {"error": "No scan in progress"}
    
    state.is_paused = not state.is_paused
    status = "paused" if state.is_paused else "resumed"
    
    await broadcast_update(f"scan_{status}", {})
    
    # Broadcast status update immediately
    await broadcast_update("status", {
        "is_scanning": state.is_scanning,
        "is_paused": state.is_paused,
        "progress": state.scan_progress
    })
    
    return {"status": f"Scan {status}"}


@router.post("/scan/restart")
async def restart_scan(background_tasks: BackgroundTasks):
    """Restart current scan (stop and start new)."""
    # Create background task for restart to avoid blocking response
    async def _restart():
        if state.is_scanning:
            state.scan_cancelled = True
            if state.scan_task:
                state.scan_task.cancel()
                try:
                    await state.scan_task
                except asyncio.CancelledError:
                    pass
            await asyncio.sleep(1)  # Give time for cleanup
        
        state.scan_cancelled = False
        state.is_paused = False
        state.scan_task = asyncio.create_task(run_scan_task())
    
    background_tasks.add_task(_restart)
    return {"status": "Restarting scan..."}


@router.post("/speedtest/{server_name}")
async def run_single_speedtest(server_name: str, background_tasks: BackgroundTasks):
    """Queue a speedtest for a specific server."""
    if state.is_scanning and state.scan_progress.get("phase") == "speedtesting":
        return {"error": "Mass speedtest in progress, please wait"}
    
    if not state.current_scan:
        return {"error": "No scan results available"}
    
    # Find server
    server = next((s for s in state.current_scan.servers if s.server_name == server_name), None)
    if not server:
        return {"error": "Server not found in current results"}
    
    if not server.is_clean:
         # Warn but allow if user insists? Current logic implies clean servers only usually.
         # app.py logic didn't seem to block it strictly, but let's assume valid server.
         pass

    # Manually trigger speedtest task
    background_tasks.add_task(run_speedtest_task, server, 1, 1, None)
    return {"status": f"Speedtest queued for {server_name}"}


# --- Debug ---

@router.get("/debug/logs")
async def get_debug_logs():
    """Get debug logs."""
    return list(debug_log_buffer)


@router.post("/debug/pause")
async def pause_debug_logs():
    """Pause/unpause debug log updates."""
    global debug_log_paused
    debug_log_paused = not debug_log_paused
    return {"paused": debug_log_paused}


@router.post("/debug/clear")
async def clear_debug_logs():
    """Clear debug logs."""
    debug_log_buffer.clear()
    await broadcast_update("debug_log_cleared", {})
    return {"status": "Logs cleared"}

# --- WebSocket ---

@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket_handler(websocket)
