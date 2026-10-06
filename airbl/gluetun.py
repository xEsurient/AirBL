"""
Gluetun Servers.json Generator.

Downloads the official Gluetun servers.json, filters the AirVPN section
based on user performance thresholds, and generates a custom servers.json for Gluetun.
"""

import json
import os
import logging
import time
from pathlib import Path
import asyncio

from .config import config_manager
from .web.state import state

logger = logging.getLogger("airbl.gluetun")

WG_PUBKEY = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk="

# Country code -> region, covering every country AirVPN has (had) servers in plus neighbours,
# so no exported server ends up in region "Unknown".
REGION_MAP = {
    "US": "Americas", "CA": "Americas", "BR": "Americas", "MX": "Americas", "AR": "Americas",
    "CL": "Americas", "CO": "Americas", "PE": "Americas", "PA": "Americas", "CR": "Americas",
    "GB": "Europe", "UK": "Europe", "DE": "Europe", "NL": "Europe", "FR": "Europe", "CH": "Europe",
    "SE": "Europe", "ES": "Europe", "IT": "Europe", "RO": "Europe", "BG": "Europe", "AT": "Europe",
    "BE": "Europe", "CZ": "Europe", "DK": "Europe", "FI": "Europe", "HU": "Europe", "IE": "Europe",
    "LV": "Europe", "LT": "Europe", "LU": "Europe", "NO": "Europe", "PL": "Europe", "PT": "Europe",
    "RS": "Europe", "SK": "Europe", "UA": "Europe", "EE": "Europe", "IS": "Europe", "GR": "Europe",
    "HR": "Europe", "SI": "Europe", "CY": "Europe", "MT": "Europe", "MD": "Europe", "AL": "Europe",
    "BA": "Europe", "MK": "Europe", "ME": "Europe", "LI": "Europe", "MC": "Europe", "IM": "Europe",
    "AU": "Oceania", "NZ": "Oceania",
    "JP": "Asia", "SG": "Asia", "HK": "Asia", "IN": "Asia", "TW": "Asia", "TH": "Asia", "MY": "Asia",
    "KR": "Asia", "ID": "Asia", "PH": "Asia", "VN": "Asia", "KH": "Asia",
    "ZA": "Africa", "EG": "Africa", "NG": "Africa", "KE": "Africa",
    "IL": "Middle East", "AE": "Middle East", "TR": "Middle East", "SA": "Middle East", "QA": "Middle East",
}


async def _get_servers_for_gluetun_generation():
    """Get servers for generation. Prefers live scan state, falls back to DB."""
    if state.current_scan and state.current_scan.servers:
        return state.current_scan.servers
        
    if not state.db:
        return []
        
    logger.info("Falling back to DB for Gluetun generation.")
    
    # 1. Get last scan servers
    last_servers = await state.db.get_last_scan_servers()
    if not last_servers:
        return []
        
    # 2. Get entry pings
    entry_pings_raw = await state.db.get_last_scan_entry_pings()
    entry_pings = {}
    for ep in entry_pings_raw:
        name = ep["server_name"]
        if name not in entry_pings:
            entry_pings[name] = {}
        entry_pings[name][ep["entry_type"]] = ep
        
    # 3. Get recent speedtests
    recent_speedtests = await state.db.get_speedtest_history(limit=500)
    speedtest_map = {}
    for st in recent_speedtests:
        name = st.get("vpn_server_name")
        if name and name not in speedtest_map:
            speedtest_map[name] = st
            
    # 4. Get server -> city mapping from configs and API fallback
    server_to_city = {}
    if hasattr(state, 'server_to_city_api'):
        server_to_city.update(state.server_to_city_api)
    try:
        from .wireguard import scan_config_directory
        configs = scan_config_directory(state.config_dir)
        for c in configs:
            server_to_city[c.server_name] = c.city
    except Exception as e:
        logger.debug(f"Failed to scan configs for city mapping: {e}")
            
    # 5. Construct mock ServerScanResult objects
    class MockPing:
        def __init__(self, ip, is_alive, avg_rtt_ms):
            self.ip = ip
            self.is_alive = is_alive
            self.avg_rtt_ms = avg_rtt_ms
            
    class MockServer:
        def __init__(self, name, is_clean, score):
            self.server_name = name
            self.is_clean = is_clean
            self.score = score
            self.speedtest_result = speedtest_map.get(name)
            
            self.country_code = state.servers_by_country.get(name, "Unknown")
            if self.country_code == "Unknown":
                self.country_code = state.servers_by_country.get(name.replace("AirVPN ", ""), "Unknown")
            self.country_name = state.all_countries.get(self.country_code, self.country_code)
            self.location = server_to_city.get(name, "Unknown")
            self.wg_pubkey = WG_PUBKEY
            self.entry1_ping = None
            self.entry3_ping = None
            
            pings = entry_pings.get(name, {})
            if "ENTRY1" in pings:
                ep = pings["ENTRY1"]
                self.entry1_ping = MockPing(ep.get("ip"), ep.get("is_alive"), ep.get("latency_ms"))
            if "ENTRY3" in pings:
                ep = pings["ENTRY3"]
                self.entry3_ping = MockPing(ep.get("ip"), ep.get("is_alive"), ep.get("latency_ms"))
                
    servers = []
    for s_raw in last_servers:
        name = s_raw["server_name"]
        from .database import row_is_clean
        is_clean = row_is_clean(s_raw)
        score = s_raw.get("score", 0)
        servers.append(MockServer(name, is_clean, score))
        
    return servers


def _gluetun_name(server) -> str:
    """Server name as Gluetun knows it (no 'AirVPN ' prefix)."""
    return server.server_name.replace("AirVPN ", "").strip()


def _server_ips(server) -> set:
    """All known IPs of a server: entry IPs plus scanned exit IPs."""
    ips = set()
    for ping in (getattr(server, "entry1_ping", None), getattr(server, "entry3_ping", None),
                 getattr(server, "exit_ping", None)):
        if ping and ping.ip:
            ips.add(ping.ip)
    for scanned in getattr(server, "scanned_ips", None) or []:
        ips.add(scanned.ip)
    return ips


def _endpoint_ips(server, strategy: str) -> list:
    """Pick entry IPs to export according to the profile endpoint strategy."""
    entry1 = server.entry1_ping
    entry3 = server.entry3_ping
    e1_ok = bool(entry1 and entry1.is_alive and entry1.ip)
    e3_ok = bool(entry3 and entry3.is_alive and entry3.ip)

    if strategy == "ENTRY1":
        return [entry1.ip] if e1_ok else []
    if strategy == "ENTRY3":
        return [entry3.ip] if e3_ok else []
    if strategy == "PING_PRIORITY":
        candidates = [p for p, ok in ((entry1, e1_ok), (entry3, e3_ok)) if ok and p.avg_rtt_ms is not None]
        if not candidates:
            return []
        return [min(candidates, key=lambda p: p.avg_rtt_ms).ip]
    # ALL
    return [p.ip for p, ok in ((entry1, e1_ok), (entry3, e3_ok)) if ok]


def _filter_profile_servers(profile, servers) -> list:
    """Apply a profile's thresholds. Returns [(server, [endpoint ips])]."""
    strategy = getattr(profile, 'endpoint_strategy', 'ALL')
    allowed_countries = {c.upper() for c in profile.allowed_countries}
    allowed_cities = {c.lower() for c in profile.allowed_cities}

    result = []
    for server in servers:
        if profile.require_clean and not server.is_clean:
            continue
        if allowed_countries and server.country_code.upper() not in allowed_countries:
            continue
        if allowed_cities and server.location.lower() not in allowed_cities:
            continue

        speedtest = server.speedtest_result
        if not speedtest:
            if profile.min_download_mbps > 0 or profile.min_upload_mbps > 0:
                continue
        else:
            dl = speedtest.get("download_mbps") or 0
            ul = speedtest.get("upload_mbps") or 0
            if dl < profile.min_download_mbps or ul < profile.min_upload_mbps:
                continue

        ips = _endpoint_ips(server, strategy)
        if not ips:
            logger.debug(f"Skipping {server.server_name}: no alive endpoint for strategy {strategy}.")
            continue
        result.append((server, ips))
    return result


def _write_servers_json(profile, filtered) -> bool:
    """Write a Gluetun-compatible servers.json (same schema as Gluetun's own file)."""
    output_path = Path(profile.output_path)
    entries = []
    for server, ips in filtered:
        entries.append({
            "vpn": "wireguard",
            "country": server.country_name,
            "region": REGION_MAP.get(server.country_code.upper(), "Unknown"),
            "city": server.location,
            "server_name": _gluetun_name(server),
            "hostname": f"{server.country_code.lower()}.vpn.airdns.org",
            "wgpubkey": server.wg_pubkey or WG_PUBKEY,
            "ips": ips,
        })

    if not entries:
        # An empty-but-newer file would make Gluetun drop every AirVPN server.
        logger.warning(f"Profile '{profile.name}' matched no servers; keeping previous {output_path}.")
        return False

    # Schema versions must match Gluetun's built-in ones (top-level 1, airvpn 1),
    # otherwise Gluetun silently discards the file. "preferred" makes newer Gluetun
    # use this list even if its built-in list has a newer timestamp.
    provider_data = {
        "version": 1,
        "timestamp": int(time.time()),
        "preferred": True,
        "servers": entries,
    }
    # Newer Gluetun migrates /gluetun/servers.json once into /gluetun/servers/<provider>.json
    # and ignores servers.json afterwards; a file named airvpn.json gets that per-provider format.
    if output_path.name == "airvpn.json":
        custom_data = provider_data
    else:
        custom_data = {"version": 1, "airvpn": provider_data}

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = output_path.with_name(output_path.name + ".tmp")
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(custom_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        temp_path.replace(output_path)
        logger.info(f"Profile '{profile.name}': wrote {len(entries)} servers to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Error writing Gluetun servers.json for '{profile.name}': {e}")
        return False


def _control_profile(cfg):
    """Profile whose server list is pushed to Gluetun: named control_profile, else first enabled."""
    enabled = [p for p in cfg.profiles if p.enabled]
    if cfg.control_profile:
        for p in enabled:
            if p.name == cfg.control_profile:
                return p
    return enabled[0] if enabled else None


async def generate_gluetun_servers_json():
    """
    Generate a custom servers.json per enabled profile, then (optionally) point a
    local or remote Gluetun at the chosen servers via its control server API.
    """
    cfg = config_manager.config.gluetun
    active_profiles = [p for p in cfg.profiles if p.enabled]
    if not active_profiles:
        logger.debug("No active Gluetun profiles. Generation disabled.")
        return

    servers = await _get_servers_for_gluetun_generation()
    if not servers:
        logger.warning("Cannot generate Gluetun servers.json: No scan results available yet.")
        return

    filtered_by_profile = {}
    for profile in active_profiles:
        filtered = _filter_profile_servers(profile, servers)
        filtered_by_profile[profile.name] = filtered
        _write_servers_json(profile, filtered)

    if not cfg.force_update_enabled or cfg.force_update_mode == "DISABLED":
        return

    profile = _control_profile(cfg)
    if profile is None:
        return
    await update_gluetun_server_selection(filtered_by_profile.get(profile.name, []))


async def update_gluetun_server_selection(filtered) -> dict:
    """
    Decide (per force_update_mode) whether Gluetun should move, and if so push the
    target server names via PUT /v1/vpn/settings. Gluetun only reads servers.json at
    startup, so the API is the only way to change servers on a running instance.
    """
    cfg = config_manager.config.gluetun
    mode = cfg.force_update_mode

    # Never steer Gluetun onto a blocklisted server, whatever the profile allows.
    ranked = sorted((s for s, _ in filtered if s.is_clean), key=lambda s: s.score or 0, reverse=True)
    if not ranked:
        logger.warning("Gluetun control: control profile has no clean servers, not changing selection.")
        return {"applied": False, "reason": "no clean servers in control profile"}

    if mode == "NOT_BEST":
        targets = ranked[:1]
    elif mode == "NOT_TOP4":
        targets = ranked[:4]
    else:  # ALWAYS, CLEAN_ONLY
        targets = ranked

    if mode != "ALWAYS":
        status = await get_gluetun_status(cfg)
        if status.get("error"):
            logger.warning(f"Gluetun control: {status['error']}; not changing selection.")
            return {"applied": False, "reason": status["error"]}
        current_ip = status.get("ip")
        if current_ip:
            if mode == "CLEAN_ONLY":
                current = _find_server_by_ip(current_ip)
                # Stay unless there is evidence of a listing; a failed lookup is not a ban
                if current is not None and not current.is_blocked:
                    logger.info(f"Gluetun control: {current.server_name} is not listed, staying connected.")
                    return {"applied": False, "reason": "current server still clean"}
            elif any(current_ip in _server_ips(s) for s in targets):
                logger.info(f"Gluetun control: current server is within target set ({mode}), staying connected.")
                return {"applied": False, "reason": "current server within target set"}

    names = sorted({_gluetun_name(s) for s in targets})
    return await set_gluetun_server_names(cfg, names)


def _find_server_by_ip(ip: str):
    if not state.current_scan or not state.current_scan.servers:
        return None
    for server in state.current_scan.servers:
        if ip in _server_ips(server):
            return server
    return None


def _base_url(cfg) -> str:
    host = cfg.control_server_host.strip()
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # bare IPv6
    return f"http://{host}:{cfg.control_server_port}"


def _headers(cfg) -> dict:
    return {"X-API-Key": cfg.api_key} if cfg.api_key else {}


def _http_error(resp) -> str:
    if resp.status_code == 401:
        return "Gluetun rejected the API key (401). Check the key and the role routes in Gluetun's auth config.toml."
    if resp.status_code == 403:
        return "Gluetun API key lacks access to this route (403). Add it to the role's routes."
    return f"Gluetun returned HTTP {resp.status_code}: {resp.text.strip()[:200]}"


async def get_gluetun_status(cfg) -> dict:
    """
    Get the current Gluetun public IP and, if it matches scanned data, the server.
    Gluetun reports the exit IP, so we match against exit IPs as well as entry IPs.
    """
    import httpx

    result = {"connected": False, "ip": None, "server_name": None, "country": None,
              "city": None, "vpn_status": None, "error": None}
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=_headers(cfg)) as client:
            resp = await client.get(f"{_base_url(cfg)}/v1/vpn/status")
            if resp.status_code != 200:
                result["error"] = _http_error(resp)
                return result
            result["vpn_status"] = resp.json().get("status")

            resp = await client.get(f"{_base_url(cfg)}/v1/publicip/ip")
            if resp.status_code != 200:
                result["error"] = _http_error(resp)
                return result
            # Gluetun sends JSON without an application/json content-type.
            try:
                public_ip = (resp.json() or {}).get("public_ip")
            except ValueError:
                public_ip = resp.text.strip()
    except httpx.HTTPError as e:
        result["error"] = f"Could not reach Gluetun control server at {_base_url(cfg)}: {e.__class__.__name__}"
        return result

    if not public_ip:
        return result  # VPN up but public IP not fetched yet

    result["connected"] = result["vpn_status"] == "running"
    result["ip"] = public_ip
    server = _find_server_by_ip(public_ip)
    if server is not None:
        result["server_name"] = _gluetun_name(server)
        result["country"] = server.country_code
        result["city"] = server.location
    return result


async def set_gluetun_server_names(cfg, names: list) -> dict:
    """Restrict Gluetun to the given server names; Gluetun reconnects on change."""
    import httpx

    url = f"{_base_url(cfg)}/v1/vpn/settings"
    # Gluetun ANDs all filters, so names alone would still be limited by its own
    # SERVER_COUNTRIES/CITIES/... and a mismatch leaves no server (VPN stops).
    # Its settings override (gosettings.OverrideWithSlice) replaces any non-null list,
    # so sending [] clears those filters and the names alone decide.
    payload = {"provider": {"server_selection": {
        "names": names, "countries": [], "regions": [], "cities": [], "hostnames": [],
    }}}
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=_headers(cfg)) as client:
            resp = await client.put(url, json=payload)
    except httpx.HTTPError as e:
        msg = f"Could not reach Gluetun control server at {_base_url(cfg)}: {e.__class__.__name__}"
        logger.error(msg)
        return {"applied": False, "reason": msg}

    if resp.status_code != 200:
        msg = _http_error(resp)
        logger.error(f"Gluetun server selection update failed: {msg}")
        return {"applied": False, "reason": msg}

    logger.info(f"Gluetun server selection set to {len(names)} server(s): {', '.join(names)} ({resp.text.strip()})")
    return {"applied": True, "names": names, "outcome": resp.text.strip()}


def get_stability_ranked_servers():
    """
    Get servers ranked by stability (ban frequency), for CLEAN_ONLY mode Gluetun server selection.
    Servers that are frequently banned score lower, making them less likely to be selected.
    """
    if not state.current_scan or not state.current_scan.servers:
        return []

    clean_servers = [s for s in state.current_scan.servers if s.is_clean]
    ban_history = state.ban_history

    # Sort by ban count (ascending = fewer bans is better), then by server name
    return sorted(
        clean_servers,
        key=lambda s: (ban_history.get(s.server_name, 0), -s.score if s.score else 0)
    )
