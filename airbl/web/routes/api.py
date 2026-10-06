"""
API Routes for AirBL Web UI.
"""

from fastapi import APIRouter, BackgroundTasks, Request, WebSocket, HTTPException, Response
from fastapi.responses import JSONResponse
from datetime import datetime
import logging
import math
import re
import asyncio

from ..state import state, debug_log_buffer
from ...config import config_manager
from ...database import row_is_clean
from ..tasks import run_scan_task, run_speedtest_task, network_owner
from ..websockets import websocket_handler, broadcast_update
from ...airvpn import get_airvpn_status

router = APIRouter()
logger = logging.getLogger("airbl.web.api")


# --- Metrics & Status ---

@router.post("/baseline-speedtest")
async def trigger_baseline_speedtest(background_tasks: BackgroundTasks):
    """Trigger a baseline speedtest (run without VPN)."""
    from ..tasks import run_baseline_speedtest
    if state.is_scanning:
        # The scan runs its own baseline; a queued one would wait for the whole cycle
        return {"error": "A scan is running (it measures its own baseline). Try again when it finishes."}
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
    speed_hist = []
    
    if state.db:
        try:
            scan_hist = await state.db.get_scan_history(limit=50)
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
            blocked = len([s for s in servers if s.is_blocked and s.server_name.lower() not in disabled_set])
            disabled = len([s for s in servers if s.server_name.lower() in disabled_set])
            unknown = len([s for s in servers if s.reputation == "unknown" and s.server_name.lower() not in disabled_set])
            country_stats.append({
                "country_code": code,
                "country_name": servers[0].country_name if servers else code,
                "clean": clean,
                "blocked": blocked,
                "disabled": disabled,
                "unknown": unknown,
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
            clean = len([s for s in servers if row_is_clean(s) and s["server_name"].lower() not in disabled_set])
            blocked = len([s for s in servers if s.get("is_blocked") and s["server_name"].lower() not in disabled_set])
            disabled = len([s for s in servers if s["server_name"].lower() in disabled_set])
            unknown = len([s for s in servers if s.get("reputation") == "unknown" and s["server_name"].lower() not in disabled_set])
            country_stats.append({
                "country_code": code,
                "country_name": state.all_countries.get(code, code),
                "clean": clean,
                "blocked": blocked,
                "disabled": disabled,
                "unknown": unknown,
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
    clean_count = len([s for s in state.current_scan.servers if s.is_clean]) if state.current_scan else len([s for s in state._last_scan_servers if row_is_clean(s)])
    blocked_count = len([s for s in state.current_scan.servers if s.is_blocked]) if state.current_scan else len([s for s in state._last_scan_servers if s.get("is_blocked")])

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
        "network_owner": network_owner(),
        "is_paused": state.is_paused,
        "progress": state.scan_progress,
        "next_scan_at": state.next_scan_at.astimezone().isoformat() if state.next_scan_at else None,
        "next_scan_in_seconds": (
            (state.next_scan_at - datetime.now()).total_seconds()
            if state.next_scan_at and state.next_scan_at > datetime.now()
            else None
        ),
        "scan_interval_minutes": state.scan_interval_minutes,
        "has_results": state.current_scan is not None,
        # Results rebuilt from the DB after a restart (one exit IP per server, no live details)
        "results_restored": bool(getattr(state.current_scan, "restored", False)),
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
            if status == "blocked" and not s.is_blocked:
                continue
            if status == "unknown" and s.reputation != "unknown":
                continue
            
            # Score filter
            if min_score is not None and s.score < min_score:
                continue
            
            # Load filter
            if max_load is not None and s.load_percent > max_load:
                continue
            
            # Ping filter
            if max_ping is not None:
                # Lowest entry ping (what a connection sees), else exit ping; no data = excluded
                pings = [p.avg_rtt_ms for p in (s.entry1_ping, s.entry3_ping)
                         if p and p.is_alive and p.avg_rtt_ms is not None]
                if not pings and s.exit_ping and s.exit_ping.is_alive and s.exit_ping.avg_rtt_ms is not None:
                    pings = [s.exit_ping.avg_rtt_ms]
                if not pings or min(pings) > max_ping:
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
            "blocked_servers": len([s for s in filtered_servers if s.is_blocked]),
            "unknown_servers": len([s for s in filtered_servers if s.reputation == "unknown"]),
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
    status = await get_gluetun_status(cfg)
    status["enabled"] = True
    return status


@router.post("/gluetun/test")
async def test_gluetun_connection(request: Request):
    """Test the Gluetun control server connection (reachability + API key).

    Accepts unsaved host/port/api_key from the settings form; empty api_key uses the saved one.
    """
    try:
        data = await request.json()
    except ValueError:
        data = None
    if not isinstance(data, dict):
        return JSONResponse({"ok": False, "error": "Expected a JSON object"}, status_code=400)
    cfg = config_manager.config.gluetun.model_copy()
    if data.get("host"):
        cfg.control_server_host = str(data["host"]).strip()
    if data.get("port") not in (None, ""):
        try:
            port = _as_int(data, "port", -1, 65536)
        except _BadSetting as e:
            return JSONResponse({"ok": False, "error": str(e)}, status_code=400)
        if not 1 <= port <= 65535:
            return JSONResponse({"ok": False, "error": "port: must be 1-65535"}, status_code=400)
        cfg.control_server_port = port
    if data.get("api_key"):
        cfg.api_key = str(data["api_key"]).strip()

    from ...gluetun import get_gluetun_status
    status = await get_gluetun_status(cfg)
    status["ok"] = status["error"] is None
    return status


@router.post("/gluetun/apply")
async def apply_gluetun_selection():
    """Push the control profile's servers to Gluetun now, following the force update mode."""
    cfg = config_manager.config.gluetun
    from ...gluetun import (_control_profile, _filter_profile_servers,
                            _get_servers_for_gluetun_generation, update_gluetun_server_selection)
    profile = _control_profile(cfg)
    if profile is None:
        return {"applied": False, "reason": "No enabled Gluetun profile"}
    servers = await _get_servers_for_gluetun_generation()
    if not servers:
        return {"applied": False, "reason": "No scan results available yet"}
    return await update_gluetun_server_selection(_filter_profile_servers(profile, servers))


# --- Discovery ---

@router.post("/discovery/restart")
async def restart_discovery():
    """Reset discovery results and start a new discovery period."""
    if state.is_scanning:
        # A running discovery phase would write into the fresh results
        return JSONResponse({"error": "A scan is running. Restart discovery when it has finished."}, status_code=409)
    from ..tasks import reset_discovery
    reset_discovery(start=True)
    config_manager.save()
    return {"status": "ok", "message": "Discovery restarted",
            "started_at": config_manager.config.scan.discovery_started_at}


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
        "scan_mode": getattr(cfg.scan, 'scan_mode', 'interval'),
        "scan_schedule_time": getattr(cfg.scan, 'scan_schedule_time', '20:00'),
        "scan_schedule_days": getattr(cfg.scan, 'scan_schedule_days', ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]),
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
        "discovery_finished_at": cfg.scan.discovery_finished_at,
        "discovery_outcome": cfg.scan.discovery_outcome,
        "discovery_min_success": 3,
        "speedtest_test_count": cfg.scan.speedtest_test_count or cfg.scan.discovery_test_count,
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
        "speedtest_max_blacklist_failures": cfg.speedtest_blacklist.max_failures,  # name the form uses
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
        # The key itself is never sent back to the browser.
        "gluetun_api_key_set": bool(cfg.gluetun.api_key),
        "gluetun_control_profile": cfg.gluetun.control_profile,
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


_DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")


class _BadSetting(ValueError):
    pass


def _as_int(data: dict, key: str, lo: int, hi: int) -> int:
    """Integer clamped to [lo, hi]; None/NaN/non-numbers are rejected (a cleared field sends null)."""
    v = data[key]
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise _BadSetting(f"{key}: expected a number")
    try:
        n = int(float(v)) if isinstance(v, str) else int(v)
    except (ValueError, OverflowError):
        raise _BadSetting(f"{key}: expected a number")
    return max(lo, min(hi, n))


def _as_float(data: dict, key: str, lo: float, hi: float) -> float:
    v = data[key]
    if isinstance(v, bool) or not isinstance(v, (int, float, str)):
        raise _BadSetting(f"{key}: expected a number")
    try:
        n = float(v)
    except ValueError:
        raise _BadSetting(f"{key}: expected a number")
    if not math.isfinite(n):
        raise _BadSetting(f"{key}: expected a number")
    return max(lo, min(hi, n))


def _as_choice(data: dict, key: str, choices) -> object:
    v = data[key]
    choices = list(choices)
    if not choices:
        raise _BadSetting(f"{key}: no valid choices are configured")
    if isinstance(choices[0], int):
        v = _as_int(data, key, -2**31, 2**31)
    if v not in choices:
        raise _BadSetting(f"{key}: must be one of {', '.join(map(str, choices))}")
    return v


def _as_bool(data: dict, key: str) -> bool:
    v = data[key]
    if isinstance(v, bool):
        return v
    if isinstance(v, int) and v in (0, 1):
        return bool(v)
    if isinstance(v, str) and v.strip().lower() in ("true", "false", "1", "0", "on", "off"):
        return v.strip().lower() in ("true", "1", "on")
    raise _BadSetting(f"{key}: expected true or false")


def _as_str_list(data: dict, key: str, allow_none: bool = False) -> list[str]:
    v = data[key]
    if v is None and allow_none:
        return []
    if not isinstance(v, list) or not all(isinstance(x, (str, int)) and not isinstance(x, bool) for x in v):
        raise _BadSetting(f"{key}: expected a list of names")
    return [str(x).strip() for x in v if str(x).strip()]


def _parse_settings(data: dict, cfg) -> tuple[dict, list[str]]:
    """Validate and convert every submitted setting without touching cfg.

    Returns (parsed values keyed like the request, warnings). Raises _BadSetting.
    """
    p: dict = {}
    warnings: list[str] = []

    if "scan_interval_minutes" in data:
        p["scan_interval_minutes"] = _as_int(data, "scan_interval_minutes", 5, 1440)
    if "scan_mode" in data:
        p["scan_mode"] = _as_choice(data, "scan_mode", ("interval", "schedule"))
    if "scan_schedule_time" in data:
        # HH:MM, 00:00-23:59 (an invalid value used to stop scheduled scans entirely)
        m = re.fullmatch(r"\s*(\d{1,2}):(\d{2})\s*", str(data["scan_schedule_time"]))
        if not (m and int(m.group(1)) < 24 and int(m.group(2)) < 60):
            raise _BadSetting("scan_schedule_time: expected HH:MM (00:00-23:59)")
        p["scan_schedule_time"] = f"{int(m.group(1)):02d}:{m.group(2)}"
    if "scan_schedule_days" in data:
        days = _as_str_list(data, "scan_schedule_days")
        full = ("monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday")
        by_lower = {d.lower(): d for d in _DAY_NAMES}
        by_lower.update(zip(full, _DAY_NAMES))
        bad = [d for d in days if d.lower() not in by_lower]
        if bad:
            raise _BadSetting(f"scan_schedule_days: unknown day(s) {', '.join(bad)}")
        wanted = {by_lower[d.lower()] for d in days}
        p["scan_schedule_days"] = [d for d in _DAY_NAMES if d in wanted]
    for key in ("auto_scan_enabled", "speedtest_enabled", "port_discovery_enabled", "gluetun_force_update"):
        if key in data:
            p[key] = _as_bool(data, key)

    # Port discovery
    if "preferred_port" in data:
        p["preferred_port"] = _as_choice(data, "preferred_port", tuple(cfg.scan.available_ports))
    if "preferred_mtu" in data:
        p["preferred_mtu"] = _as_int(data, "preferred_mtu", 1280, 1500)
    if "speedtest_test_count" in data:
        p["speedtest_test_count"] = _as_int(data, "speedtest_test_count", 1, 10)
    if "preferred_entry_ip" in data:
        p["preferred_entry_ip"] = _as_choice(data, "preferred_entry_ip", ("ENTRY1", "ENTRY3", "AUTO"))
    if "discovery_test_count" in data:
        p["discovery_test_count"] = _as_int(data, "discovery_test_count", 1, 10)
    if "discovery_duration_days" in data:
        p["discovery_duration_days"] = _as_choice(data, "discovery_duration_days", (3, 5, 7))
    if "discovery_entry_filter" in data:
        p["discovery_entry_filter"] = _as_choice(data, "discovery_entry_filter", ("ALL", "ENTRY1", "ENTRY3"))
    if "post_server_wait" in data:
        p["post_server_wait"] = _as_choice(data, "post_server_wait", (120, 180))

    # Regions / servers
    if "enabled_countries" in data:
        p["enabled_countries"] = _as_str_list(data, "enabled_countries")
    if "excluded_countries" in data:
        p["excluded_countries"] = sorted({c.upper() for c in _as_str_list(data, "excluded_countries", allow_none=True)
                                          if len(c) == 2 and c.isalpha()})
    if "enabled_servers" in data:
        p["enabled_servers"] = _as_str_list(data, "enabled_servers")
    if "enabled_cities" in data:
        cities = data["enabled_cities"]
        if not isinstance(cities, dict):
            raise _BadSetting("enabled_cities: expected an object of country -> list of cities")
        p["enabled_cities"] = {}
        for code, names in cities.items():
            p["enabled_cities"][str(code).strip().upper()] = _as_str_list({"enabled_cities": names}, "enabled_cities",
                                                                         allow_none=True)
    if "disabled_servers" in data:
        p["disabled_servers"] = _as_str_list(data, "disabled_servers")

    # Performance
    if "performance_threshold_download" in data:
        p["performance_threshold_download"] = _as_float(data, "performance_threshold_download", 1.0, 100000.0)
    if "performance_threshold_upload" in data:
        p["performance_threshold_upload"] = _as_float(data, "performance_threshold_upload", 1.0, 100000.0)
    if "performance_check_count" in data:
        p["performance_check_count"] = _as_int(data, "performance_check_count", 1, 10)
    if "speedtest_blacklist_duration_days" in data:
        p["speedtest_blacklist_duration_days"] = _as_int(data, "speedtest_blacklist_duration_days", 1, 365)
    if "speedtest_max_blacklist_failures" in data:
        p["speedtest_max_blacklist_failures"] = _as_int(data, "speedtest_max_blacklist_failures", 1, 10)

    # Scoring
    if "deviation_download_weight" in data:
        p["deviation_download_weight"] = round(_as_float(data, "deviation_download_weight", 0.0, 1.0), 2)
    if "deviation_upload_weight" in data:
        p["deviation_upload_weight"] = round(_as_float(data, "deviation_upload_weight", 0.0, 1.0), 2)
    if "signal_good_threshold" in data:
        p["signal_good_threshold"] = _as_int(data, "signal_good_threshold", 1, 100)
    if "signal_medium_threshold" in data:
        p["signal_medium_threshold"] = _as_int(data, "signal_medium_threshold", 1, 100)

    # Gluetun
    if "gluetun_force_update_mode" in data:
        p["gluetun_force_update_mode"] = _as_choice(data, "gluetun_force_update_mode",
                                                    ("CLEAN_ONLY", "NOT_TOP4", "NOT_BEST", "ALWAYS", "DISABLED"))
    if "gluetun_control_host" in data:
        p["gluetun_control_host"] = str(data["gluetun_control_host"] or "").strip() or "127.0.0.1"
    if "gluetun_control_port" in data:
        p["gluetun_control_port"] = _as_int(data, "gluetun_control_port", 1, 65535)
    if data.get("gluetun_api_key_clear"):
        p["gluetun_api_key"] = ""
    elif data.get("gluetun_api_key"):
        p["gluetun_api_key"] = str(data["gluetun_api_key"]).strip()
    if "gluetun_control_profile" in data:
        p["gluetun_control_profile"] = str(data["gluetun_control_profile"] or "").strip()

    # Profiles: an invalid entry keeps the previous list (reported as a warning, not an error)
    if "gluetun_profiles" in data:
        from airbl.config import GluetunProfileConfig
        profiles, invalid = [], 0
        if not isinstance(data["gluetun_profiles"], list):
            invalid = 1
        else:
            for p_data in data["gluetun_profiles"]:
                try:
                    if not isinstance(p_data, dict):
                        raise ValueError("profile is not an object")
                    profiles.append(GluetunProfileConfig(
                        name=str(p_data.get("name", "Custom Profile")),
                        enabled=bool(p_data.get("enabled", False)),
                        output_path=str(p_data.get("output_path", "/app/gluetun/servers.json")),
                        endpoint_strategy=str(p_data.get("endpoint_strategy", "ALL")),
                        min_download_mbps=float(p_data.get("min_download_mbps", 0)),
                        min_upload_mbps=float(p_data.get("min_upload_mbps", 0)),
                        require_clean=bool(p_data.get("require_clean", True)),
                        allowed_countries=p_data.get("allowed_countries", []),
                        allowed_cities=p_data.get("allowed_cities", [])
                    ))
                except Exception as e:
                    invalid += 1
                    logger.warning(f"Invalid Gluetun profile in save: {e}")
        if invalid:
            logger.warning("Keeping previous Gluetun profiles because some submitted profiles were invalid.")
            warnings.append(f"{invalid} Gluetun profile(s) invalid; previous Gluetun profiles kept")
        else:
            p["gluetun_profiles"] = profiles  # may be empty: user removed all profiles

    if "wg_profiles" in data:
        from airbl.config import WireGuardProfileConfig
        profiles, invalid = [], 0
        if not isinstance(data["wg_profiles"], list):
            invalid = 1
        else:
            for wp in data["wg_profiles"]:
                try:
                    if not isinstance(wp, dict):
                        raise ValueError("profile is not an object")
                    profiles.append(WireGuardProfileConfig(**wp))
                except Exception as e:
                    invalid += 1
                    logger.warning(f"Invalid WG profile in save: {e}")
        if invalid:
            logger.warning("Keeping previous WireGuard profiles because some submitted profiles were invalid.")
            warnings.append(f"{invalid} WireGuard profile(s) invalid; previous WireGuard profiles kept")
        else:
            p["wg_profiles"] = profiles

    return p, warnings


@router.post("/settings")
async def update_settings(request: Request):
    """Update settings via SettingsManager. Everything is validated first: a bad value
    returns 400 and changes nothing."""
    try:
        data = await request.json()
    except ValueError:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)
    if not isinstance(data, dict):
        return JSONResponse({"error": "Expected a JSON object"}, status_code=400)
    cfg = config_manager.config
    try:
        p, warnings = _parse_settings(data, cfg)
    except _BadSetting as e:
        return JSONResponse({"error": str(e)}, status_code=400)

    # --- Apply (no failures past this point) ---
    if "scan_interval_minutes" in p:
        cfg.scan.scan_interval_minutes = p["scan_interval_minutes"]
    if "scan_mode" in p:
        cfg.scan.scan_mode = p["scan_mode"]
    if "scan_schedule_time" in p:
        cfg.scan.scan_schedule_time = p["scan_schedule_time"]
    if "scan_schedule_days" in p:
        cfg.scan.scan_schedule_days = p["scan_schedule_days"]
    if "auto_scan_enabled" in p:
        cfg.scan.auto_scan_enabled = p["auto_scan_enabled"]
    if "speedtest_enabled" in p:
        cfg.scan.speedtest_enabled = p["speedtest_enabled"]
    
    # Port Discovery Settings
    if "port_discovery_enabled" in p:
        was_enabled = cfg.scan.port_discovery_enabled
        now_enabled = p["port_discovery_enabled"]
        if now_enabled and not was_enabled:
            # Off -> on always starts a fresh period (old results/start time would
            # otherwise finalize immediately on stale data)
            from ..tasks import reset_discovery
            reset_discovery(start=True)
        elif was_enabled and not now_enabled:
            cfg.scan.discovery_started_at = None  # abandon the running period
        cfg.scan.port_discovery_enabled = now_enabled
    for key in ("preferred_port", "preferred_mtu", "speedtest_test_count", "preferred_entry_ip",
                "discovery_test_count", "discovery_duration_days", "discovery_entry_filter", "post_server_wait"):
        if key in p:
            setattr(cfg.scan, key, p[key])
    
    if "enabled_countries" in p:
        cfg.regions.countries = p["enabled_countries"]
    if "excluded_countries" in p:
        cfg.regions.excluded_countries = p["excluded_countries"]
    
    # Get enabled countries set for filtering
    enabled_countries_set = set(c.upper() for c in cfg.regions.countries)
    
    if "enabled_servers" in p:
        new_enabled = p["enabled_servers"]
        # Filter servers to only include those from enabled countries
        if enabled_countries_set:
            new_enabled = [
                server for server in new_enabled
                if (state.servers_by_country.get(server) or "").upper() in enabled_countries_set
                or state.servers_by_country.get(server) is None
            ]
        cfg.servers = new_enabled
        # Remove explicitly enabled servers from disabled list
        enabled_lower = {s.lower() for s in new_enabled}
        cfg.performance.disabled_servers = [
            s for s in cfg.performance.disabled_servers
            if s.lower() not in enabled_lower
        ]
    
    if "enabled_cities" in p:
        # Only include cities from enabled countries
        cfg.cities = {
            code: cities for code, cities in p["enabled_cities"].items()
            if cities and (not enabled_countries_set or code in enabled_countries_set)
        }

    # Performance Settings
    if "performance_threshold_download" in p:
        cfg.performance.threshold_download = p["performance_threshold_download"]
    if "performance_threshold_upload" in p:
        cfg.performance.threshold_upload = p["performance_threshold_upload"]
    if "performance_check_count" in p:
        cfg.performance.check_count = p["performance_check_count"]
    if "speedtest_blacklist_duration_days" in p:
        cfg.speedtest_blacklist.duration_days = p["speedtest_blacklist_duration_days"]
    if "speedtest_max_blacklist_failures" in p:
        cfg.speedtest_blacklist.max_failures = p["speedtest_max_blacklist_failures"]
    
    # Manual replacement of the disabled list (prefer POST /servers/{name}/enable to unblock one)
    if "disabled_servers" in p:
        cfg.performance.disabled_servers = p["disabled_servers"]

    # Scoring Settings (the two weights always sum to 1.0)
    if "deviation_download_weight" in p:
        cfg.scoring.deviation_download_weight = p["deviation_download_weight"]
        cfg.scoring.deviation_upload_weight = round(1.0 - p["deviation_download_weight"], 2)
    if "deviation_upload_weight" in p:
        cfg.scoring.deviation_upload_weight = p["deviation_upload_weight"]
        cfg.scoring.deviation_download_weight = round(1.0 - p["deviation_upload_weight"], 2)
    if "signal_good_threshold" in p:
        cfg.scoring.signal_good_threshold = p["signal_good_threshold"]
    if "signal_medium_threshold" in p:
        cfg.scoring.signal_medium_threshold = p["signal_medium_threshold"]
    # Medium must stay below good, or the 2-bar band disappears
    if cfg.scoring.signal_medium_threshold >= cfg.scoring.signal_good_threshold:
        cfg.scoring.signal_medium_threshold = max(1, cfg.scoring.signal_good_threshold - 1)
    
    # Gluetun Settings
    if "gluetun_force_update" in p:
        cfg.gluetun.force_update_enabled = p["gluetun_force_update"]
    if "gluetun_force_update_mode" in p:
        cfg.gluetun.force_update_mode = p["gluetun_force_update_mode"]
    if "gluetun_control_host" in p:
        cfg.gluetun.control_server_host = p["gluetun_control_host"]
    if "gluetun_control_port" in p:
        cfg.gluetun.control_server_port = p["gluetun_control_port"]
    if "gluetun_api_key" in p:
        cfg.gluetun.api_key = p["gluetun_api_key"]
    if "gluetun_control_profile" in p:
        cfg.gluetun.control_profile = p["gluetun_control_profile"]
    gluetun_changed = "gluetun_profiles" in p
    if gluetun_changed:
        cfg.gluetun.profiles = p["gluetun_profiles"]

    # WireGuard Settings
    if "wg_profiles" in p:
        cfg.wireguard.profiles = p["wg_profiles"]
    
    # Save Config
    if config_manager.save():
        logger.info("Settings updated and saved successfully.")
        
        # Signal the auto-scan loop to recalculate its sleep timer
        if state.settings_updated_event:
            state.settings_updated_event.set()
        
        # Trigger generation asynchronously if Gluetun config changed
        if gluetun_changed:
            has_enabled = any(prof.enabled for prof in cfg.gluetun.profiles)
            if has_enabled:
                from ...gluetun import generate_gluetun_servers_json
                asyncio.create_task(generate_gluetun_servers_json())
    else:
        logger.error("Failed to save settings.")
        return JSONResponse({"error": "Failed to persist settings"}, status_code=500)

    await broadcast_update("settings_changed", {
        "scan_interval_minutes": cfg.scan.scan_interval_minutes,
        "auto_scan_enabled": cfg.scan.auto_scan_enabled,
        "enabled_countries": list(cfg.regions.countries),
        "enabled_servers": list(cfg.servers),
    })
    
    return {"status": "Settings updated", "warnings": warnings}


@router.post("/servers/{server_name}/enable")
async def enable_server(server_name: str):
    """Re-enable one disabled server (case-insensitive) without touching the rest of the list."""
    perf = config_manager.config.performance
    target = server_name.strip().lower()
    perf.disabled_servers = [s for s in perf.disabled_servers if s.lower() != target]
    # Drop its performance history too, or the next speedtest re-disables it on the old numbers
    for history in (state.server_performance_history, perf.history):
        for name in [n for n in history if n.lower() == target]:
            del history[name]
    if not config_manager.save():
        return JSONResponse({"error": "Failed to persist settings"}, status_code=500)
    logger.info(f"Server re-enabled: {server_name}")
    return {"status": "ok", "disabled_servers": list(perf.disabled_servers)}


# --- Scan Control ---

@router.post("/scan/start")
async def start_scan(background_tasks: BackgroundTasks):
    """Start a new scan."""
    if state.is_scanning:
        return {"error": "Scan already in progress"}
    
    # Reset cancelled flag
    state.scan_cancelled = False
    state.is_paused = False
    
    # Mark scanning before the task runs, so a second click can't start another one
    state.is_scanning = True
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


_restart_lock = asyncio.Lock()


@router.post("/scan/restart")
async def restart_scan(background_tasks: BackgroundTasks):
    """Restart current scan (stop and start new)."""
    # Create background task for restart to avoid blocking response
    async def _restart():
        # Serialise restarts: two at once would each start a scan
        async with _restart_lock:
            if state.is_scanning:
                state.scan_cancelled = True
                if state.scan_task:
                    state.scan_task.cancel()
                    try:
                        await state.scan_task
                    except asyncio.CancelledError:
                        pass
                await asyncio.sleep(1)  # Give time for cleanup
            if state.is_scanning:
                return  # something else started a scan meanwhile
        
            state.scan_cancelled = False
            state.is_paused = False
            state.is_scanning = True
            state.scan_task = asyncio.create_task(run_scan_task())
    
    background_tasks.add_task(_restart)
    return {"status": "Restarting scan..."}


@router.post("/speedtest/{server_name}")
async def run_single_speedtest(server_name: str, background_tasks: BackgroundTasks):
    """Queue a speedtest for a specific server."""
    if state.is_scanning:
        # Any scan phase: speedtesting uses the VPN, and earlier phases need direct routing
        return {"error": "A scan is running and owns the VPN. Try again when it finishes."}
    
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
    """Kept for old pages: pausing is per tab, so the debug page does it client-side."""
    return {"paused": False, "note": "pause is client-side"}


@router.post("/debug/clear")
async def clear_debug_logs():
    """Clear debug logs."""
    debug_log_buffer.clear()
    return {"status": "Logs cleared"}

# --- WebSocket ---

@router.websocket("/ws")
async def ws_endpoint(websocket: WebSocket):
    await websocket_handler(websocket)
