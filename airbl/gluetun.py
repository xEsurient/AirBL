"""
Gluetun Servers.json Generator.

Downloads the official Gluetun servers.json, filters the AirVPN section
based on user performance thresholds, and generates a custom servers.json for Gluetun.
"""

import json
import logging
import time
from pathlib import Path
import asyncio

from .config import config_manager
from .web.state import state

logger = logging.getLogger("airbl.gluetun")

WG_PUBKEY = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk="

REGION_MAP = {
    "US": "Americas", "CA": "Americas", "BR": "Americas", "MX": "Americas",
    "GB": "Europe", "UK": "Europe", "DE": "Europe", "NL": "Europe", "FR": "Europe", "CH": "Europe",
    "SE": "Europe", "ES": "Europe", "IT": "Europe", "RO": "Europe", "BG": "Europe", "AT": "Europe",
    "BE": "Europe", "CZ": "Europe", "DK": "Europe", "FI": "Europe", "HU": "Europe", "IE": "Europe",
    "LV": "Europe", "LT": "Europe", "LU": "Europe", "NO": "Europe", "PL": "Europe", "PT": "Europe",
    "RS": "Europe", "SK": "Europe", "UA": "Europe",
    "AU": "Oceania", "NZ": "Oceania",
    "JP": "Asia", "SG": "Asia", "HK": "Asia", "IN": "Asia", "TW": "Asia", "TH": "Asia", "MY": "Asia",
    "ZA": "Africa",
    "IL": "Middle East", "AE": "Middle East", "TR": "Middle East"
}


async def generate_gluetun_servers_json():
    """
    Generate the custom servers.json for Gluetun based natively on the live scanner state payload.
    Supports dynamic endpoint filtering strategies (ENTRY1, ENTRY3, PING_PRIORITY, ALL).
    """
    config = config_manager.config.gluetun
    profiles = config.profiles
    
    active_profiles = [p for p in profiles if p.enabled]
    if not active_profiles:
        logger.debug("No active Gluetun profiles. Generation disabled.")
        return
        
    if not state.current_scan or not state.current_scan.servers:
        logger.warning("Cannot generate Gluetun servers.json: No scan results available yet.")
        return
        
    # Process each profile
    for profile in active_profiles:
        logger.info(f"Processing Gluetun profile: {profile.name}")
        output_path = Path(profile.output_path)
        strategy = getattr(profile, 'endpoint_strategy', 'ALL')
        
        filtered_servers = []
        for server in state.current_scan.servers:
            # Threshold filtering
            if profile.require_clean and not server.is_clean:
                continue
                
            if profile.allowed_countries and server.country_code.upper() not in [c.upper() for c in profile.allowed_countries]:
                continue
                
            if profile.allowed_cities and server.location.lower() not in [c.lower() for c in profile.allowed_cities]:
                continue
                
            speedtest = server.speedtest_result
            if not speedtest:
                if profile.min_download_mbps > 0 or profile.min_upload_mbps > 0:
                    continue
            else:
                dl = speedtest.get("download_mbps", 0)
                ul = speedtest.get("upload_mbps", 0)
                if dl < profile.min_download_mbps or ul < profile.min_upload_mbps:
                    continue
                    
            # Determine mapping ips based on endpoint route strategy
            entry1 = server.entry1_ping
            entry3 = server.entry3_ping
            ips_to_export = []
            
            if strategy == "ALL":
                if entry1 and entry1.is_alive: ips_to_export.append(entry1.ip)
                if entry3 and entry3.is_alive: ips_to_export.append(entry3.ip)
            elif strategy == "ENTRY1":
                if entry1 and entry1.is_alive: ips_to_export.append(entry1.ip)
            elif strategy == "ENTRY3":
                if entry3 and entry3.is_alive: ips_to_export.append(entry3.ip)
            elif strategy == "PING_PRIORITY":
                best_ping = None
                best_ip = None
                
                if entry1 and entry1.is_alive and entry1.avg_rtt_ms is not None:
                    best_ping = entry1.avg_rtt_ms
                    best_ip = entry1.ip
                    
                if entry3 and entry3.is_alive and entry3.avg_rtt_ms is not None:
                    if best_ping is None or entry3.avg_rtt_ms < best_ping:
                        best_ip = entry3.ip
                        
                if best_ip:
                    ips_to_export.append(best_ip)
            
            # If no alive endpoints map, bypass generating node
            if not ips_to_export:
                logger.debug(f"Skipping {server.server_name} due to endpoint routing conditions failing or IPs offline.")
                continue

            # Inject the strictly formatted OpenVPN/Wireguard JSON wrapper schema expected by qdm12/gluetun
            region_str = REGION_MAP.get(server.country_code.upper(), "Unknown")
            
            for ip in ips_to_export:
                filtered_servers.append({
                    "vpn": "wireguard",
                    "country": server.country_name,
                    "region": region_str,
                    "city": server.location,
                    "server_name": server.server_name,
                    "hostname": f"{server.country_code.lower()}.vpn.airdns.org",
                    "wgpubkey": server.wg_pubkey or WG_PUBKEY,
                    "ips": [ip]
                })

        logger.info(f"Profile '{profile.name}' natively generated {len(filtered_servers)} server endpoints.")
        
        # Wrapping into expected root framework
        custom_data = {
            "version": 1,
            "airvpn": {
                "version": 1,
                "timestamp": int(time.time()),
                "servers": filtered_servers
            }
        }
        
        try:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(custom_data, f, indent=2)
            logger.info(f"Successfully generated offline Gluetun servers.json to {output_path}")
        except Exception as e:
            logger.error(f"Error persisting native Gluetun generation for '{profile.name}': {e}")

    # After all profiles are written, smart force restart Gluetun if enabled
    gluetun_cfg = config_manager.config.gluetun
    if gluetun_cfg.force_update_enabled and active_profiles:
        mode = gluetun_cfg.force_update_mode
        if mode == "DISABLED":
            logger.info("Gluetun force update is disabled by mode setting.")
        elif mode == "ALWAYS":
            await force_restart_gluetun(gluetun_cfg.control_server_host, gluetun_cfg.control_server_port)
        else:
            # Smart restart: check if current server is still good enough
            should_restart = await _should_smart_restart(
                gluetun_cfg.control_server_host,
                gluetun_cfg.control_server_port,
                mode
            )
            if should_restart:
                await force_restart_gluetun(gluetun_cfg.control_server_host, gluetun_cfg.control_server_port)
            else:
                logger.info("Gluetun smart restart: current server is still ranked well, skipping restart.")


async def get_gluetun_status(host: str, port: int) -> dict:
    """
    Get the current Gluetun VPN status including public IP.
    Returns dict with 'ip', 'country', 'city', 'server_name' if resolvable.
    """
    import httpx

    base_url = f"http://{host}:{port}"
    result = {"connected": False, "ip": None, "server_name": None, "country": None, "city": None}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"{base_url}/v1/publicip/ip")
            if resp.status_code == 200:
                data = resp.json() if resp.headers.get("content-type", "").startswith("application/json") else {"public_ip": resp.text.strip()}
                public_ip = data.get("public_ip", resp.text.strip())
                result["connected"] = True
                result["ip"] = public_ip

                # Try to resolve which server this IP belongs to
                if state.current_scan and state.current_scan.servers:
                    for server in state.current_scan.servers:
                        for ping in (server.entry1_ping, server.entry3_ping):
                            if ping and ping.ip == public_ip:
                                result["server_name"] = server.server_name.replace("AirVPN ", "")
                                result["country"] = server.country_code
                                result["city"] = server.location
                                return result
    except Exception as e:
        logger.debug(f"Could not get Gluetun status: {e}")

    return result


async def _should_smart_restart(host: str, port: int, mode: str) -> bool:
    """
    Determine if Gluetun should be restarted based on the current connected server's rank.
    """
    status = await get_gluetun_status(host, port)
    if not status["connected"] or not status["ip"]:
        logger.info("Cannot determine current Gluetun server — will restart.")
        return True

    if not state.current_scan or not state.current_scan.servers:
        return True

    current_ip = status["ip"]

    if mode == "CLEAN_ONLY":
        # Only restart if the current server is banned
        for server in state.current_scan.servers:
            for ping in (server.entry1_ping, server.entry3_ping):
                if ping and ping.ip == current_ip:
                    if server.is_clean:
                        logger.info(f"CLEAN_ONLY: Current server {server.server_name} is still clean, staying connected.")
                        return False
                    else:
                        logger.info(f"CLEAN_ONLY: Current server {server.server_name} is BANNED, will switch.")
                        return True
        # IP not found in scan results — can't verify, restart to be safe
        logger.info("CLEAN_ONLY: Current IP not found in scan data, restarting.")
        return True

    # Build ranked list of top servers (same logic as overview top servers)
    ranked = sorted(
        [s for s in state.current_scan.servers if s.is_clean and s.score > 0],
        key=lambda s: s.score,
        reverse=True
    )

    if mode == "NOT_BEST":
        # Restart if current server is not the #1 ranked server
        if ranked:
            best = ranked[0]
            for ping in (best.entry1_ping, best.entry3_ping):
                if ping and ping.ip == current_ip:
                    return False  # Currently on best server
        return True

    elif mode == "NOT_TOP4":
        # Restart if current server is not in top 4
        top4 = ranked[:4]
        for server in top4:
            for ping in (server.entry1_ping, server.entry3_ping):
                if ping and ping.ip == current_ip:
                    return False  # Currently on a top 4 server
        return True

    return True


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


async def force_restart_gluetun(host: str, port: int):
    """
    Force Gluetun to reload by cycling the VPN via the control server API.
    Sends PUT /v1/vpn/status {"status":"stopped"} then {"status":"running"}.
    """
    import httpx

    base_url = f"http://{host}:{port}"
    url = f"{base_url}/v1/vpn/status"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Stop VPN
            resp = await client.put(url, json={"status": "stopped"})
            if resp.status_code == 200:
                logger.info("Gluetun VPN stopped via control server.")
            else:
                logger.warning(f"Gluetun stop returned status {resp.status_code}: {resp.text}")
                return

            # Wait for VPN to fully stop
            await asyncio.sleep(2)

            # Start VPN
            resp = await client.put(url, json={"status": "running"})
            if resp.status_code == 200:
                logger.info("Gluetun VPN restarted via control server. Force update complete.")
            else:
                logger.warning(f"Gluetun start returned status {resp.status_code}: {resp.text}")
    except httpx.ConnectError:
        logger.error(f"Could not connect to Gluetun control server at {base_url}. Is it running?")
    except Exception as e:
        logger.error(f"Gluetun force restart failed: {e}")

