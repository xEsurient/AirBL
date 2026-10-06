"""
WireGuard Configuration Generator.

Generates .conf files for WireGuard based on live scan data and user profile settings.
Supports per-server configs and an auto-updating wg0.conf for best-server selection.
"""

import logging
import re
from pathlib import Path
from typing import Optional

from .config import config_manager, WireGuardProfileConfig
from .web.state import state
from .gluetun import WG_PUBKEY

logger = logging.getLogger("airbl.wireguard_gen")

AIRVPN_DNS = "10.128.0.1"


def _allowed_ips(ip_layer_exit: str, address: str) -> str:
    """AllowedIPs for the profile's exit mode, limited to what the Address can carry.

    ::/0 without an IPv6 Address would swallow IPv6 traffic into a tunnel that can't
    send it, so IPv6 is only routed when the identity has a v6 address. AirVPN's DNS
    (10.128.0.1) is always routed, otherwise "IPv6"-only configs lose DNS.
    """
    has_v6 = any(":" in a for a in address.split(","))
    if ip_layer_exit == "IPv6":
        if has_v6:
            return f"{AIRVPN_DNS}/32, ::/0"
        logger.debug("WG exit mode IPv6 but the client Address has no IPv6 entry; using IPv4")
        return "0.0.0.0/0"
    nets = ["0.0.0.0/0"]
    if ip_layer_exit != "IPv4" and has_v6:  # "Both" (default)
        nets.append("::/0")
    return ", ".join(nets)


def _build_conf(profile: WireGuardProfileConfig, endpoint_ip: str, server_pubkey: str) -> str:
    """Build a WireGuard .conf file string."""
    from .confgen import get_client_identity
    try:
        identity = get_client_identity()
    except ValueError:
        identity = None

    address = identity.address if identity else "10.128.0.2/10"
    allowed_ips = _allowed_ips(profile.ip_layer_exit, address)
    
    lines = [
        "[Interface]",
        f"PrivateKey = {profile.private_key}",
        f"Address = {address}",
        f"MTU = {profile.mtu}",
        f"DNS = {AIRVPN_DNS}",
        "",
        "[Peer]",
        f"PublicKey = {server_pubkey}",
        f"Endpoint = {endpoint_ip}:{profile.port}",
        f"AllowedIPs = {allowed_ips}",
        f"PersistentKeepalive = {profile.keepalive}",
    ]
    
    if identity and identity.preshared_key:
        lines.append(f"PresharedKey = {identity.preshared_key}")
        
    return "\n".join(lines) + "\n"


async def _get_entry_ip(server, profile: WireGuardProfileConfig) -> Optional[str]:
    """Get the appropriate entry IP for a server based on profile settings."""
    if profile.entry_ip == "ENTRY1":
        if server.entry1_ping and server.entry1_ping.is_alive:
            return server.entry1_ping.ip
    elif profile.entry_ip == "ENTRY3":
        if server.entry3_ping and server.entry3_ping.is_alive:
            return server.entry3_ping.ip
    elif profile.entry_ip == "AUTO":
        # AUTO: pick the entry with the lowest latency from historical DB map
        if state.db:
            try:
                best_entry = await state.db.get_best_entry_for_server(server.server_name)
                entry_number = 1 if best_entry == "ENTRY1" else 3
            except Exception as e:
                logger.debug(f"AUTO entry lookup failed for {server.server_name}: {e}")
                entry_number = 3
        else:
            entry_number = 3

        if entry_number == 1 and server.entry1_ping and server.entry1_ping.is_alive:
            return server.entry1_ping.ip
        elif server.entry3_ping and server.entry3_ping.is_alive:
            return server.entry3_ping.ip
        elif server.entry1_ping and server.entry1_ping.is_alive:
            return server.entry1_ping.ip
            
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


GENERATED_MANIFEST = ".airbl-generated"


def _manifest_path(output_dir: Path, profile_name: str) -> Path:
    """Per-profile manifest: profiles sharing an output dir must not see each
    other's files as stale."""
    safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", profile_name).strip("_") or "profile"
    return output_dir / f"{GENERATED_MANIFEST}-{safe}"


def _remove_stale_configs(output_dir: Path, written: set[str], profile_name: str) -> None:
    """Delete configs this profile wrote last time but not this time (e.g. a country with
    no clean server left), so no file keeps pointing at a now-blocked server.
    Only files listed in our own manifest are touched; wg0.conf is never removed."""
    manifest = _manifest_path(output_dir, profile_name)
    try:
        previous = set(manifest.read_text().split()) if manifest.exists() else set()
    except Exception:
        previous = set()
    # Never delete a file another profile in the same dir still generates
    others: set[str] = set()
    for other in output_dir.glob(f"{GENERATED_MANIFEST}-*"):
        if other != manifest:
            try:
                others |= set(other.read_text().split())
            except Exception:
                pass
    for name in sorted(previous - written - others):
        if name == "wg0.conf" or "/" in name or not name.endswith(".conf"):
            continue
        try:
            (output_dir / name).unlink(missing_ok=True)
            logger.info(f"Removed stale WireGuard config {output_dir / name}")
        except Exception as e:
            logger.warning(f"Could not remove stale config {name}: {e}")
    try:
        manifest.write_text("\n".join(sorted(written)) + "\n")
    except Exception as e:
        logger.warning(f"Could not write {manifest}: {e}")


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
        
        if getattr(profile, "ip_protocol", "IPv4") == "IPv6":
            # An IPv6 endpoint needs the servers' IPv6 entry addresses, which scans don't
            # collect (entry pings are IPv4), so IPv6 endpoints are unsupported for now.
            logger.warning(f"WG profile '{profile.name}': IPv6 endpoints are not supported "
                           "(no IPv6 entry addresses known); using IPv4 endpoints")
        
        generated = 0
        best_server = None
        best_score = -999
        written: set[str] = set()
        
        # 1. Eligible servers: location filters apply in every mode. "custom" (All Servers)
        #    and "fastest" deliberately include blocked servers; other modes are clean-only.
        include_blocked = profile.mode in ("custom", "fastest")
        eligible = [
            s for s in state.current_scan.servers
            if (include_blocked or s.is_clean) and _matches_profile(s, profile)
        ]
        eligible.sort(key=lambda s: s.score or 0, reverse=True)
        
        # 2. What to write: (file stem, candidates in preference order)
        if profile.mode in ("fastest", "fastest_clean"):
            targets = [(None, eligible)] if eligible else []
        elif profile.mode == "countries":
            # One config per country: its best server, e.g. CH.conf
            groups: dict[str, list] = {}
            for s in eligible:
                groups.setdefault(s.country_code.upper(), []).append(s)
            targets = sorted(groups.items())
        elif profile.mode == "cities":
            # One config per city: its best server, e.g. CH-Zurich.conf
            groups = {}
            for s in eligible:
                groups.setdefault(f"{s.country_code.upper()}-{s.location}", []).append(s)
            targets = sorted(groups.items())
        else:
            targets = [(None, [s]) for s in eligible]
        
        for stem, candidates in targets:
            # First candidate (best score) that has a usable entry IP and public key
            chosen = None
            for server in candidates:
                entry_ip = await _get_entry_ip(server, profile)
                # Profile override first, then the server's key, then AirVPN's shared key
                server_pubkey = (profile.public_key or "").strip() or server.wg_pubkey or WG_PUBKEY
                if entry_ip and server_pubkey:
                    chosen = (server, entry_ip, server_pubkey)
                    break
            if not chosen:
                continue
            server, entry_ip, server_pubkey = chosen
            
            conf_content = _build_conf(profile, entry_ip, server_pubkey)
            name = stem or server.server_name
            safe_name = name.replace(" ", "_").replace("/", "-")
            conf_path = output_dir / f"{safe_name}.conf"
            
            try:
                with open(conf_path, 'w') as f:
                    f.write(conf_content)
                generated += 1
                written.add(conf_path.name)
                if stem:
                    logger.debug(f"WG profile '{profile.name}': {conf_path.name} -> {server.server_name}")
            except Exception as e:
                logger.error(f"Failed to write {conf_path}: {e}")
            
            # Track best server for wg0.conf (never a blocked one unless the mode is "fastest")
            if (server.is_clean or profile.mode == "fastest") and (server.score or 0) > best_score:
                best_score = server.score or 0
                best_server = (server, entry_ip, server_pubkey)
        
        _remove_stale_configs(output_dir, written, profile.name)
        
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
