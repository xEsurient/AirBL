"""
WireGuard Configuration Generator.

Generates .conf files for WireGuard based on live scan data and user profile settings.
Supports per-server configs and an auto-updating wg0.conf for best-server selection.
"""

import logging
from pathlib import Path
from typing import Optional

from .config import config_manager, WireGuardProfileConfig
from .web.state import state

logger = logging.getLogger("airbl.wireguard_gen")

# AllowedIPs presets by IP layer exit mode
ALLOWED_IPS = {
    "Both": "0.0.0.0/0, ::/0",
    "IPv4": "0.0.0.0/0",
    "IPv6": "::/0",
}


def _build_conf(profile: WireGuardProfileConfig, endpoint_ip: str, server_pubkey: str) -> str:
    """Build a WireGuard .conf file string."""
    allowed_ips = ALLOWED_IPS.get(profile.ip_layer_exit, "0.0.0.0/0, ::/0")
    
    lines = [
        "[Interface]",
        f"PrivateKey = {profile.private_key}",
        f"Address = 10.128.0.2/10",
        f"MTU = {profile.mtu}",
        f"DNS = 10.128.0.1",
        "",
        "[Peer]",
        f"PublicKey = {server_pubkey}",
        f"Endpoint = {endpoint_ip}:{profile.port}",
        f"AllowedIPs = {allowed_ips}",
        f"PersistentKeepalive = {profile.keepalive}",
    ]
    return "\n".join(lines) + "\n"


def _get_entry_ip(server, profile: WireGuardProfileConfig) -> Optional[str]:
    """Get the appropriate entry IP for a server based on profile settings."""
    if profile.entry_ip == "ENTRY1":
        if server.entry1_ping and server.entry1_ping.is_alive:
            return server.entry1_ping.ip
    elif profile.entry_ip == "ENTRY3":
        if server.entry3_ping and server.entry3_ping.is_alive:
            return server.entry3_ping.ip
    elif profile.entry_ip == "AUTO":
        # AUTO: pick the entry with the lowest latency from the current scan
        e1 = server.entry1_ping
        e3 = server.entry3_ping
        e1_alive = e1 and e1.is_alive and e1.avg_rtt_ms is not None
        e3_alive = e3 and e3.is_alive and e3.avg_rtt_ms is not None
        
        if e1_alive and e3_alive:
            return e1.ip if e1.avg_rtt_ms <= e3.avg_rtt_ms else e3.ip
        elif e1_alive:
            return e1.ip
        elif e3_alive:
            return e3.ip
    return None


def _matches_profile(server, profile):
    """Check if a server matches the profile's location filters."""
    if profile.mode == "use_speedtest":
        # Use whatever countries/cities are enabled in the main speedtest config
        cfg = config_manager.config
        if cfg.regions.countries:
            if server.country_code.upper() not in [c.upper() for c in cfg.regions.countries]:
                return False
        if cfg.cities:
            country_cities = cfg.cities.get(server.country_code.upper(), [])
            if country_cities and server.location.lower() not in [c.lower() for c in country_cities]:
                return False
        return True
        
    # Standard location boundary checks proactively map across all manual profile modes
    if profile.countries:
        if server.country_code.upper() not in [c.upper() for c in profile.countries]:
            return False
            
    if profile.cities:
        if server.location.lower() not in [c.lower() for c in profile.cities]:
            return False
            
    return True


async def generate_wireguard_configs():
    """
    Generate WireGuard .conf files based on all active WG profiles.
    Called after each scan completes.
    """
    wg_settings = config_manager.config.wireguard
    active_profiles = [p for p in wg_settings.profiles if p.enabled]
    
    if not active_profiles:
        logger.debug("No active WireGuard profiles. Generation disabled.")
        return
    
    if not state.current_scan or not state.current_scan.servers:
        logger.warning("Cannot generate WireGuard configs: No scan results available.")
        return
    
    for profile in active_profiles:
        if not profile.private_key:
            logger.warning(f"WG profile '{profile.name}' has no private key set. Skipping.")
            continue
        
        output_dir = Path(profile.output_dir)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            logger.error(f"Cannot create output dir {output_dir}: {e}")
            continue
        
        generated = 0
        best_server = None
        best_score = -999
        
        # Scope processing constraints for absolute fastest modes
        servers_to_process = state.current_scan.servers
        if profile.mode in ("fastest", "fastest_clean"):
            target_score = -999
            target_srv = None
            for s in state.current_scan.servers:
                if profile.mode == "fastest_clean" and not s.is_clean:
                    continue
                if not _matches_profile(s, profile):
                    continue
                if s.score > target_score:
                    target_score = s.score
                    target_srv = s
            servers_to_process = [target_srv] if target_srv else []
        
        for server in servers_to_process:
            # Force hygiene constraints on standard wide-sweeping modes
            if profile.mode not in ("fastest", "fastest_clean") and not server.is_clean:
                continue
            
            if not _matches_profile(server, profile):
                continue
            
            entry_ip = _get_entry_ip(server, profile)
            if not entry_ip:
                continue
            
            # Get server pubkey (from scan data or profile override)
            server_pubkey = server.wg_pubkey or profile.public_key
            if not server_pubkey:
                continue
            
            # Generate per-server conf
            conf_content = _build_conf(profile, entry_ip, server_pubkey)
            safe_name = server.server_name.replace(" ", "_").replace("/", "-")
            conf_path = output_dir / f"{safe_name}.conf"
            
            try:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                generated += 1
            except Exception as e:
                logger.error(f"Failed to write {conf_path}: {e}")
            
            # Track best server for wg0.conf
            if server.score > best_score:
                best_score = server.score
                best_server = (server, entry_ip, server_pubkey)
        
        logger.info(f"WG profile '{profile.name}': generated {generated} server configs in {output_dir}")
        
        # Auto-update wg0.conf with best server
        if profile.auto_update_wg0 and best_server:
            server, entry_ip, server_pubkey = best_server
            wg0_content = _build_conf(profile, entry_ip, server_pubkey)
            wg0_path = output_dir / "wg0.conf"
            try:
                with open(wg0_path, 'w') as f:
                    f.write(wg0_content)
                logger.info(f"wg0.conf updated to best server: {server.server_name} (score: {best_score:.1f})")
            except Exception as e:
                logger.error(f"Failed to write wg0.conf: {e}")
