"""
WireGuard Config Generator.

Generates .conf files for speedtest port/entry discovery and AUTO entry selection.
Configs are stored in /app/confgen/ (internal, not user-facing).

Uses client identity (PrivateKey, PublicKey, Address) extracted from existing
configs in /app/conf/, with fallback to WireGuard profile settings.
"""

import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .config import config_manager
from .wireguard import parse_config_content, COUNTRY_CODE_MAP

logger = logging.getLogger("airbl.confgen")


@dataclass
class ClientIdentity:
    """Client-side WireGuard identity extracted from configs or settings."""
    private_key: str
    address: str       # e.g. "10.136.x.x/32"
    preshared_key: str = "" # Additional Symmetric Encryption key
    public_key: str = ""  # Server pubkeys vary — this is the client's WG pubkey (rarely needed)


_cached_identity: Optional[ClientIdentity] = None


def extract_client_identity(conf_dir: Path) -> Optional[ClientIdentity]:
    """
    Extract PrivateKey and Address from the first valid .conf in conf_dir.
    
    These values are per-account (same across all AirVPN configs for a user),
    so any config file will do.
    """
    if not conf_dir.exists():
        return None
    
    for conf_file in sorted(conf_dir.glob("*.conf")):
        try:
            content = conf_file.read_text()
            parsed = parse_config_content(content)
            
            private_key = parsed.get("private_key")
            address = parsed.get("address")
            preshared_key = parsed.get("preshared_key", "")
            
            if private_key and address:
                logger.debug(f"Extracted client identity from {conf_file.name}: address={address}")
                return ClientIdentity(
                    private_key=private_key,
                    address=address,
                    preshared_key=preshared_key,
                )
        except Exception as e:
            logger.debug(f"Failed to parse {conf_file.name}: {e}")
            continue
    
    return None


def get_client_identity() -> ClientIdentity:
    """
    Get client identity from existing configs, falling back to WireGuard profile settings.
    Caches the identity in memory to prevent continuous disk reads.
    
    Raises ValueError if no identity can be found anywhere.
    """
    global _cached_identity
    if _cached_identity is not None:
        return _cached_identity
    
    from .config import settings
    
    # Try extracting from existing configs first
    identity = extract_client_identity(settings.config_dir)
    if identity:
        _cached_identity = identity
        return identity
    
    # Fallback: try WireGuard profile settings
    wg_profiles = config_manager.config.wireguard.profiles
    for profile in wg_profiles:
        if profile.private_key:
            logger.info("Using WireGuard profile settings for client identity")
            identity = ClientIdentity(
                private_key=profile.private_key,
                address="10.128.0.2/10",  # Default AirVPN address if not extractable
            )
            _cached_identity = identity
            return identity
    
    raise ValueError(
        "No WireGuard keys available. Add .conf files to /app/conf/ "
        "or set keys in Settings → WireGuard Profiles."
    )


def has_client_identity() -> bool:
    """Check if a client identity is available (without raising)."""
    try:
        get_client_identity()
        return True
    except ValueError:
        return False


def _make_filename(country_code: str, city: str, server_name: str,
                   port: int, entry_number: int) -> str:
    """
    Build config filename: CC-City_Server-Port-EN.conf
    e.g. NL-Alblasserdam_Melnick-1637-E3.conf
    """
    safe_city = city.replace(" ", "-")
    safe_name = server_name.replace(" ", "-")
    return f"{country_code}-{safe_city}_{safe_name}-{port}-E{entry_number}.conf"


def generate_config(
    server_name: str,
    country_code: str,
    city: str,
    endpoint_ip: str,
    server_pubkey: str,
    port: int,
    entry_number: int,
    identity: Optional[ClientIdentity] = None,
) -> Path:
    """
    Generate a WireGuard .conf file and write it to confgen_dir.
    
    Args:
        server_name: AirVPN server name (e.g. "Melnick")
        country_code: 2-letter code (e.g. "NL")
        city: City name (e.g. "Alblasserdam")
        endpoint_ip: Entry IP address for this entry point
        server_pubkey: Server's WireGuard public key
        port: Port number (e.g. 1637)
        entry_number: Entry point number (1 or 3)
        identity: Client identity (auto-resolved if None)
    
    Returns:
        Path to the generated .conf file
    """
    if identity is None:
        identity = get_client_identity()
    
    confgen_dir = Path(config_manager.config.scan.confgen_dir)
    confgen_dir.mkdir(parents=True, exist_ok=True)
    
    filename = _make_filename(country_code, city, server_name, port, entry_number)
    conf_path = confgen_dir / filename
    
    mtu = config_manager.config.scan.preferred_mtu
    lines = [
        "[Interface]",
        f"PrivateKey = {identity.private_key}",
        f"Address = {identity.address}",
        f"DNS = 10.128.0.1",
    ]
    
    if mtu and mtu > 0:
        lines.append(f"MTU = {mtu}")
        
    lines.extend([
        "",
        "[Peer]",
        f"PublicKey = {server_pubkey}",
        f"Endpoint = {endpoint_ip}:{port}",
        f"AllowedIPs = 0.0.0.0/0, ::/0",
        f"PersistentKeepalive = 25",
    ])
    
    if identity.preshared_key:
        lines.insert(-2, f"PresharedKey = {identity.preshared_key}")
    
    conf_path.write_text("\n".join(lines) + "\n")
    logger.debug(f"Generated config: {filename}")
    return conf_path


def get_or_generate_config(
    server_name: str,
    country_code: str,
    city: str,
    endpoint_ip: str,
    server_pubkey: str,
    port: int,
    entry_number: int,
    identity: Optional[ClientIdentity] = None,
) -> Path:
    """
    Get an existing config or generate a new one.
    
    Checks /app/conf/ first (user-supplied), then /app/confgen/ (generated),
    creates if neither exists.
    """
    from .config import settings
    
    # Check user-supplied configs (match by server name + port + entry)
    for conf_file in settings.config_dir.glob("*.conf"):
        name = conf_file.stem.lower()
        # Match: server name, port, and entry number in the filename
        if (server_name.lower().replace(" ", "") in name.replace("-", "").replace("_", "") and
            str(port) in name and
            f"entry{entry_number}" in name.lower()):
            logger.debug(f"Found existing user config: {conf_file.name}")
            return conf_file
    
    # Check generated configs
    confgen_dir = Path(config_manager.config.scan.confgen_dir)
    expected_filename = _make_filename(country_code, city, server_name, port, entry_number)
    expected_path = confgen_dir / expected_filename
    
    if expected_path.exists():
        return expected_path
    
    # Generate new config
    return generate_config(
        server_name=server_name,
        country_code=country_code,
        city=city,
        endpoint_ip=endpoint_ip,
        server_pubkey=server_pubkey,
        port=port,
        entry_number=entry_number,
        identity=identity,
    )


def generate_all_combos(
    server_name: str,
    country_code: str,
    city: str,
    entry1_ip: Optional[str],
    entry3_ip: Optional[str],
    server_pubkey: str,
    ports: Optional[list[int]] = None,
    entry_filter: str = "ALL",
    identity: Optional[ClientIdentity] = None,
) -> list[tuple[Path, int, int]]:
    """
    Generate configs for all port×entry combos for a server.
    
    Args:
        entry_filter: "ALL", "ENTRY1", or "ENTRY3"
        ports: List of ports to test (defaults to available_ports from config)
    
    Returns:
        List of (config_path, port, entry_number) tuples
    """
    if ports is None:
        ports = config_manager.config.scan.available_ports
    
    if identity is None:
        identity = get_client_identity()
    
    # Determine which entries to include
    entries = []
    if entry_filter in ("ALL", "ENTRY1") and entry1_ip:
        entries.append((1, entry1_ip))
    if entry_filter in ("ALL", "ENTRY3") and entry3_ip:
        entries.append((3, entry3_ip))
    
    results = []
    for port in ports:
        for entry_number, entry_ip in entries:
            config_path = get_or_generate_config(
                server_name=server_name,
                country_code=country_code,
                city=city,
                endpoint_ip=entry_ip,
                server_pubkey=server_pubkey,
                port=port,
                entry_number=entry_number,
                identity=identity,
            )
            results.append((config_path, port, entry_number))
    
    logger.info(f"Generated {len(results)} combo configs for {server_name}")
    return results


def list_generated_configs() -> list[dict]:
    """List all generated configs in confgen_dir with parsed metadata."""
    confgen_dir = Path(config_manager.config.scan.confgen_dir)
    if not confgen_dir.exists():
        return []
    
    configs = []
    for conf_file in sorted(confgen_dir.glob("*.conf")):
        try:
            content = conf_file.read_text()
            parsed = parse_config_content(content)
            configs.append({
                "filename": conf_file.name,
                "path": str(conf_file),
                "endpoint_ip": parsed.get("endpoint_ip"),
                "endpoint_port": parsed.get("endpoint_port"),
                "address": parsed.get("address"),
            })
        except Exception as e:
            configs.append({
                "filename": conf_file.name,
                "path": str(conf_file),
                "error": str(e),
            })
    
    return configs
