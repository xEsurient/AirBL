"""
Hummingbird VPN Control Module.

Controls AirVPN's Hummingbird client for programmatic VPN connections.
Hummingbird is AirVPN's lightweight WireGuard-based client for Linux/macOS.
"""

import asyncio
import os
import signal
import subprocess
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional
import re


@dataclass
class HummingbirdStatus:
    """Status of Hummingbird connection."""
    is_connected: bool = False
    server_name: Optional[str] = None
    server_ip: Optional[str] = None
    public_ip: Optional[str] = None
    connected_at: Optional[datetime] = None
    config_file: Optional[str] = None
    error: Optional[str] = None


@dataclass
class ConnectionResult:
    """Result of a VPN connection attempt."""
    success: bool
    server_name: Optional[str] = None
    config_file: Optional[str] = None
    public_ip: Optional[str] = None
    connect_time_seconds: float = 0.0
    error: Optional[str] = None


class HummingbirdController:
    """
    Controller for Hummingbird VPN client.
    
    Hummingbird can be controlled via:
    1. Direct execution with config file
    2. WireGuard interface management
    
    On macOS, Hummingbird requires sudo for network operations.
    In Docker, it runs as root with NET_ADMIN capability.
    """
    
    def __init__(
        self,
        hummingbird_path: str = "/usr/local/bin/hummingbird",
        config_dir: Path = None,
        use_sudo: bool = True,
    ):
        self.hummingbird_path = hummingbird_path
        self.config_dir = config_dir or Path("./conf")
        self.use_sudo = use_sudo
        self._process: Optional[asyncio.subprocess.Process] = None
        self._current_config: Optional[Path] = None
    
    async def check_installed(self) -> bool:
        """Check if Hummingbird is installed."""
        try:
            # Try hummingbird --version or just check if binary exists
            if os.path.exists(self.hummingbird_path):
                return True
            
            # Try which command
            process = await asyncio.create_subprocess_exec(
                "which", "hummingbird",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()
            if stdout.strip():
                self.hummingbird_path = stdout.decode().strip()
                return True
            
            return False
        except Exception:
            return False
    
    async def connect(
        self,
        config_file: Path,
        timeout: int = 30,
    ) -> ConnectionResult:
        """
        Connect to VPN using specified config file.
        
        Args:
            config_file: Path to .conf file
            timeout: Connection timeout in seconds
            
        Returns:
            ConnectionResult with status
        """
        start_time = datetime.now()
        
        if not config_file.exists():
            return ConnectionResult(
                success=False,
                config_file=str(config_file),
                error=f"Config file not found: {config_file}",
            )
        
        # Disconnect any existing connection
        await self.disconnect()
        
        try:
            # Build command
            cmd = []
            if self.use_sudo:
                cmd.append("sudo")
            cmd.extend([self.hummingbird_path, str(config_file)])
            
            # Start Hummingbird
            self._process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            self._current_config = config_file
            
            # Wait for connection to establish
            # Hummingbird outputs connection status to stdout
            connected = False
            error_msg = None
            
            try:
                # Read output with timeout
                async def read_output():
                    nonlocal connected, error_msg
                    while True:
                        line = await self._process.stdout.readline()
                        if not line:
                            break
                        line_str = line.decode().strip()
                        
                        # Check for success indicators
                        if "connected" in line_str.lower() or "handshake" in line_str.lower():
                            connected = True
                            break
                        if "error" in line_str.lower() or "failed" in line_str.lower():
                            error_msg = line_str
                            break
                
                await asyncio.wait_for(read_output(), timeout=timeout)
                
            except asyncio.TimeoutError:
                # Timeout waiting for connection confirmation
                # Check if process is still running (might be connected anyway)
                if self._process.returncode is None:
                    connected = True  # Assume connected if still running
                else:
                    error_msg = "Connection timed out"
            
            duration = (datetime.now() - start_time).total_seconds()
            
            if connected:
                # Get public IP to confirm VPN is working
                public_ip = await self._get_public_ip()
                
                return ConnectionResult(
                    success=True,
                    server_name=config_file.stem,
                    config_file=str(config_file),
                    public_ip=public_ip,
                    connect_time_seconds=duration,
                )
            else:
                await self.disconnect()
                return ConnectionResult(
                    success=False,
                    config_file=str(config_file),
                    connect_time_seconds=duration,
                    error=error_msg or "Connection failed",
                )
                
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            await self.disconnect()
            return ConnectionResult(
                success=False,
                config_file=str(config_file),
                connect_time_seconds=duration,
                error=str(e),
            )
    
    async def disconnect(self) -> bool:
        """
        Disconnect from VPN.
        
        Returns:
            True if disconnected successfully
        """
        try:
            if self._process and self._process.returncode is None:
                # Send SIGTERM
                self._process.terminate()
                try:
                    await asyncio.wait_for(self._process.wait(), timeout=5)
                except asyncio.TimeoutError:
                    # Force kill if graceful termination fails
                    self._process.kill()
                    await self._process.wait()
            
            self._process = None
            self._current_config = None
            
            # Also try to clean up any WireGuard interfaces
            await self._cleanup_wg_interfaces()
            
            return True
        except Exception:
            return False
    
    async def _cleanup_wg_interfaces(self):
        """Clean up any lingering WireGuard interfaces."""
        try:
            # List WireGuard interfaces
            cmd = ["sudo", "wg", "show", "interfaces"] if self.use_sudo else ["wg", "show", "interfaces"]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await process.communicate()
            
            interfaces = stdout.decode().strip().split()
            for iface in interfaces:
                if iface.startswith(("wg", "hb", "airvpn")):
                    # Remove interface
                    rm_cmd = ["sudo", "ip", "link", "delete", iface] if self.use_sudo else ["ip", "link", "delete", iface]
                    await asyncio.create_subprocess_exec(*rm_cmd)
        except Exception:
            pass  # Ignore cleanup errors
    
    async def _get_public_ip(self, timeout: float = 10) -> Optional[str]:
        """Get current public IP address."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=timeout) as client:
                # Try multiple services
                services = [
                    "https://api.ipify.org",
                    "https://ifconfig.me/ip",
                    "https://icanhazip.com",
                ]
                for service in services:
                    try:
                        response = await client.get(service)
                        if response.status_code == 200:
                            return response.text.strip()
                    except Exception:
                        continue
        except Exception:
            pass
        return None
    
    async def get_status(self) -> HummingbirdStatus:
        """Get current connection status."""
        is_connected = self._process is not None and self._process.returncode is None
        
        status = HummingbirdStatus(
            is_connected=is_connected,
            config_file=str(self._current_config) if self._current_config else None,
        )
        
        if is_connected:
            status.public_ip = await self._get_public_ip()
            status.connected_at = datetime.now()  # Approximate
            if self._current_config:
                status.server_name = self._current_config.stem
        
        return status
    
    def get_config_files(self) -> list[Path]:
        """List all available config files."""
        if not self.config_dir.exists():
            return []
        return sorted(self.config_dir.glob("*.conf"))


# Alternative: WireGuard native control (without Hummingbird)
def _should_use_sudo() -> bool:
    """
    Determine if sudo should be used for WireGuard operations.
    
    Returns False if:
    - Running as root (uid 0)
    - sudo is not available
    - In Docker container (usually root)
    
    Returns True if:
    - Running as non-root user and sudo is available
    """
    import shutil
    import logging
    
    logger = logging.getLogger("airbl.hummingbird")
    
    # Check if running as root
    if os.geteuid() == 0:
        logger.debug("Running as root, sudo not needed")
        return False
    
    # Check if sudo is available
    sudo_path = shutil.which("sudo")
    if not sudo_path:
        logger.debug("sudo not found in PATH, running without sudo")
        return False
    
    logger.debug(f"Running as non-root user, will use sudo: {sudo_path}")
    return True


class WireGuardController:
    """
    Direct WireGuard control using manual wg/ip commands.
    
    Unlike wg-quick, this approach never calls sysctl at runtime,
    so it works with just NET_ADMIN capability (no privileged mode needed).
    The required sysctl values are set via docker-compose sysctls directive.
    
    Use this if Hummingbird is not available.
    """
    
    def __init__(self, use_sudo: Optional[bool] = None):
        """
        Initialize WireGuardController.
        
        Args:
            use_sudo: If None, auto-detects based on environment.
                     If True, uses sudo (will fail if not available).
                     If False, runs without sudo (requires root).
        """
        import logging
        logger = logging.getLogger("airbl.hummingbird")
        
        if use_sudo is None:
            self.use_sudo = _should_use_sudo()
            logger.info(f"WireGuardController initialized with auto-detected use_sudo={self.use_sudo}")
        else:
            self.use_sudo = use_sudo
            logger.info(f"WireGuardController initialized with use_sudo={self.use_sudo}")
        self._current_interface: Optional[str] = None
        self._temp_config_path: Optional[Path] = None  # Stores temp stripped config path
        self._fwmark: int = 51820  # WireGuard fwmark (matches wg-quick default)
    
    async def connect(self, config_file: Path, interface_name: str = "wg0", namespace = None) -> ConnectionResult:
        """
        Connect using manual wg/ip commands (Gluetun approach).
        
        Unlike wg-quick, this never calls sysctl so it works with just
        NET_ADMIN capability. The sysctl values are pre-set via docker-compose.
        
        Steps:
            1. Parse config to extract keys, address, endpoint, DNS
            2. Clean up any stale interface/routes
            3. Create WireGuard interface
            4. Apply config via wg setconf
            5. Add address, set MTU, bring interface up
            6. Set fwmark, routing rules, and routes
            7. Configure DNS via resolvconf
        
        Args:
            config_file: Path to config
            interface_name: Interface name to use
            namespace: DEPRECATED - ignored, kept for backward compatibility
        """
        # NOTE: namespace parameter is ignored - we always connect directly
            
        import logging
        import tempfile
        from .wireguard import parse_config_file
        
        logger = logging.getLogger("airbl.hummingbird")
        
        start_time = datetime.now()
        fwmark = str(self._fwmark)
        table = fwmark  # routing table ID matches fwmark
        
        try:
            # 1. Parse config file to get keys, address, endpoint, DNS
            wg_conf = parse_config_file(config_file)
            logger.debug(f"Parsed config {config_file.name}: endpoint={wg_conf.endpoint_ip}:{wg_conf.endpoint_port}, address={wg_conf.address}")
            
            # 2. Clean up any existing interface and stale routes
            if self._current_interface:
                logger.debug(f"Cleaning up existing interface {self._current_interface} before new connection")
                try:
                    await self.disconnect()
                except Exception as e:
                    logger.warning(f"Error cleaning up interface before connect: {e}")
            
            # Check if interface exists in the system (regardless of our state)
            try:
                check_cmd = []
                if self.use_sudo:
                    check_cmd.append("sudo")
                check_cmd.extend(["wg", "show", "interfaces"])
                check_process = await asyncio.create_subprocess_exec(
                    *check_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await check_process.communicate()
                interfaces = stdout.decode().strip()
                
                if interface_name in interfaces:
                    logger.info(f"Interface {interface_name} already exists, force removing")
                    await self._run_sudo(["ip", "link", "delete", interface_name])
                    await asyncio.sleep(0.5)
            except Exception as e:
                logger.debug(f"Could not check/cleanup interface (may not exist): {e}")
            
            # Clean up stale routes in fwmark table
            # This fixes "RTNETLINK answers: File exists" errors
            await self._cleanup_routing(table, logger)
            
            # 3. Create WireGuard interface
            logger.debug(f"Creating WireGuard interface {interface_name}")
            await self._run_sudo(["ip", "link", "add", interface_name, "type", "wireguard"])
            
            # 4. Apply config via wg setconf
            # Build a stripped config (wg setconf format: no Address/DNS, only keys + peers)
            stripped_conf = [
                "[Interface]",
                f"PrivateKey = {wg_conf.private_key}",
                "",
                "[Peer]",
                f"PublicKey = {wg_conf.public_key}",
                f"Endpoint = {wg_conf.endpoint_ip}:{wg_conf.endpoint_port}",
                f"AllowedIPs = {wg_conf.allowed_ips or '0.0.0.0/0'}",
                "PersistentKeepalive = 15",
            ]
            
            # Add preshared key if present in original config
            try:
                content = config_file.read_text()
                psk_match = re.search(r"PresharedKey\s*=\s*(.+)", content, re.IGNORECASE)
                if psk_match:
                    psk = psk_match.group(1).strip()
                    # Insert before Endpoint in [Peer] section
                    stripped_conf.insert(-2, f"PresharedKey = {psk}")
            except Exception:
                pass
            
            # Write stripped config to temp file
            temp_conf_path = Path(f"/tmp/{interface_name}_stripped.conf")
            temp_conf_path.write_text("\n".join(stripped_conf))
            self._temp_config_path = temp_conf_path
            
            try:
                await self._run_sudo(["wg", "setconf", interface_name, str(temp_conf_path)])
                logger.debug(f"Applied WireGuard config to {interface_name}")
            finally:
                # Clean up temp config immediately after applying
                if temp_conf_path.exists():
                    temp_conf_path.unlink()
                    self._temp_config_path = None
            
            # 5. Add address and bring interface up
            if wg_conf.address:
                # Ensure address has a prefix length
                addr = wg_conf.address.strip()
                if '/' not in addr:
                    addr = f"{addr}/32"
                await self._run_sudo(["ip", "-4", "address", "add", addr, "dev", interface_name])
                logger.debug(f"Added address {addr} to {interface_name}")
            
            # Set MTU and bring up
            await self._run_sudo(["ip", "link", "set", "mtu", "1420", "up", "dev", interface_name])
            logger.debug(f"Interface {interface_name} is UP with MTU 1420")
            
            # 6. Configure DNS via resolvconf (if available)
            if wg_conf.dns:
                dns_servers = [d.strip() for d in wg_conf.dns.split(',')]
                try:
                    # Build resolvconf input: one "nameserver" per line
                    dns_input = "\n".join(f"nameserver {d}" for d in dns_servers) + "\n"
                    resolvconf_cmd = []
                    if self.use_sudo:
                        resolvconf_cmd.append("sudo")
                    resolvconf_cmd.extend(["resolvconf", "-a", interface_name, "-m", "0", "-x"])
                    proc = await asyncio.create_subprocess_exec(
                        *resolvconf_cmd,
                        stdin=asyncio.subprocess.PIPE,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                    )
                    await proc.communicate(input=dns_input.encode())
                    if proc.returncode == 0:
                        logger.debug(f"Configured DNS via resolvconf: {dns_servers}")
                    else:
                        raise RuntimeError("resolvconf failed")
                except Exception as dns_err:
                    # Fallback: write /etc/resolv.conf directly
                    logger.debug(f"resolvconf not available ({dns_err}), writing /etc/resolv.conf directly")
                    resolv_content = "\n".join(f"nameserver {d}" for d in dns_servers) + "\n"
                    try:
                        write_cmd = ["sh", "-c", f"echo '{resolv_content}' > /etc/resolv.conf"]
                        await self._run_sudo(write_cmd)
                    except Exception as resolv_err:
                        logger.warning(f"Failed to configure DNS: {resolv_err}")
            
            # 7. Set fwmark and routing rules (replicates what wg-quick does)
            await self._run_sudo(["wg", "set", interface_name, "fwmark", fwmark])
            await self._run_sudo(["ip", "-4", "route", "add", "0.0.0.0/0", "dev", interface_name, "table", table])
            
            # Pin AirVPN internal DNS/address range through the tunnel BEFORE the broad RFC1918 bypasses
            # AirVPN uses 10.128.0.0/10 internally (DNS at 10.128.0.1, client addresses in 10.128-191.x.x)
            await self._run_sudo(["ip", "-4", "rule", "add", "to", "10.128.0.0/10", "table", table, "priority", "5"])
            
            # Local Subnet Bypass Rules (RFC1918)
            # Prevents asymmetric routing so the container Web UI doesn't drop when hit from the host LAN
            for subnet in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
                await self._run_sudo(["ip", "-4", "rule", "add", "to", subnet, "table", "main", "priority", "10"])
                
            await self._run_sudo(["ip", "-4", "rule", "add", "not", "fwmark", fwmark, "table", table])
            await self._run_sudo(["ip", "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0"])
            logger.debug(f"Set fwmark {fwmark}, local bypasses, and routing rules for table {table}")
            
            # NOTE: We intentionally skip sysctl -q net.ipv4.conf.all.src_valid_mark=1
            # It is already set via docker-compose sysctls directive, and skipping it
            # is what allows us to run without privileged mode.
            
            duration = (datetime.now() - start_time).total_seconds()
            self._current_interface = interface_name
            logger.info(f"Successfully connected to VPN using {config_file.name} via {interface_name} (manual wg/ip)")
            
            return ConnectionResult(
                success=True,
                server_name=config_file.stem,
                config_file=str(config_file),
                connect_time_seconds=duration,
            )
                
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.exception(f"Exception during VPN connection: {e}")
            
            # Best-effort cleanup on failure
            try:
                await self._run_sudo(["ip", "link", "delete", interface_name])
            except Exception:
                pass
            
            return ConnectionResult(
                success=False,
                config_file=str(config_file),
                connect_time_seconds=duration,
                error=str(e),
            )
    
    async def _cleanup_routing(self, table: str, logger):
        """
        Clean up stale routes and rules in the given routing table.
        Fixes "RTNETLINK answers: File exists" errors on reconnect.
        """
        try:
            # Flush all routes in the table
            await self._run_sudo(["ip", "route", "flush", "table", table])
        except Exception:
            pass
        
        # Clean up ip rules for this table (run multiple times to delete all)
        for _ in range(5):
            try:
                await self._run_sudo(["ip", "-4", "rule", "delete", "table", table])
            except Exception:
                break  # No more rules to delete
        
        # Also remove suppress_prefixlength rules
        for _ in range(3):
            try:
                await self._run_sudo(["ip", "-4", "rule", "delete", "table", "main", "suppress_prefixlength", "0"])
            except Exception:
                break
                
        # Remove RFC1918 bypass rules
        for subnet in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
            for _ in range(3):
                try:
                    await self._run_sudo(["ip", "-4", "rule", "delete", "to", subnet, "table", "main", "priority", "10"])
                except Exception:
                    break
        
        
        logger.debug(f"Cleaned up stale routes and rules in table {table}")
    
    async def _connect_namespace(self, config_file: Path, interface_name: str, namespace) -> ConnectionResult:
        """Connect to VPN inside a network namespace using manual configuration."""
        import logging
        from .wireguard import parse_config_file  # Avoid circular import
        
        logger = logging.getLogger("airbl.hummingbird")
        start_time = datetime.now()
        
        try:
            logger.info(f"Setting up VPN {config_file.stem} in namespace {namespace.name}")
            
            # 1. Parse config to get keys and address
            wg_conf = parse_config_file(config_file)
            
            # 2. Clean up any existing interface with the same name first
            try:
                cmd_del = ["ip", "link", "delete", "dev", interface_name]
                await self._run_sudo(cmd_del)
                logger.debug(f"Cleaned up existing interface {interface_name}")
            except Exception:
                pass  # Interface didn't exist, that's fine
            
            # 3. Create WireGuard Interface in HOST
            cmd_add = ["ip", "link", "add", "dev", interface_name, "type", "wireguard"]
            await self._run_sudo(cmd_add)
            
            # 3b. Set MTU to 1464 (User requested)
            await self._run_sudo(["ip", "link", "set", "dev", interface_name, "mtu", "1464"])

            # NOTE: Do NOT bring interface UP yet - it should only be UP after config and after moving

            # Check host routing to endpoint (Debug)
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    route_get = await self._run_sudo_output(["ip", "route", "get", wg_conf.endpoint_ip])
                    logger.debug(f"Host route to endpoint {wg_conf.endpoint_ip}:\n{route_get}")
                except Exception as e:
                    logger.warning(f"Failed to check route to endpoint: {e}")

            # 4. Create Stripped Config for wg setconf (Keys + Peers only, no Address/DNS)
            # wg setconf format is strict (no Interface Address)
            stripped_conf = [
                "[Interface]",
                f"PrivateKey = {wg_conf.private_key}",
                "ListenPort = 51820", # Force 51820 for debugging socket location
                "",
                "[Peer]",
                f"PublicKey = {wg_conf.public_key}",
                f"Endpoint = {wg_conf.endpoint_ip}:{wg_conf.endpoint_port}",
                f"AllowedIPs = {wg_conf.allowed_ips or '0.0.0.0/0'}",
                "PersistentKeepalive = 25",
            ]
            
            # Use a temp file that is definitely accessible to root in host
            temp_conf_path = Path(f"/tmp/{interface_name}_stripped.conf")
            temp_conf_path.write_text("\n".join(stripped_conf))
            
            try:
                # 5. Apply Config in HOST (This binds the socket in the Host Namespace)
                # IMPORTANT: This must be done BEFORE moving to the namespace so the output UDP socket
                # lives in the host (where it has internet access).
                cmd_conf = ["wg", "setconf", interface_name, str(temp_conf_path)]
                await self._run_sudo(cmd_conf)
                
                # Debug: Check WG status and Socket in Host
                if logger.isEnabledFor(logging.DEBUG):
                    wg_show = await self._run_sudo_output(["wg", "show", interface_name])
                    logger.debug(f"WG status in HOST before move:\n{wg_show}")
                    try:
                        ss_out = await self._run_sudo_output(["ss", "-ulpn", "sport = :51820"])
                        logger.debug(f"Socket status in HOST before move:\n{ss_out}")
                    except Exception as e:
                        logger.debug(f"Failed to run ss: {e}")
                
                # 6. Move to Namespace (interface is still DOWN)
                cmd_move = ["ip", "link", "set", interface_name, "netns", namespace.name]
                await self._run_sudo(cmd_move)
                
                # 7. Set Address inside NS
                if wg_conf.address:
                    await namespace.run(["ip", "address", "add", wg_conf.address, "dev", interface_name])
                
                # 8. Bring Up inside NS (first time interface is brought UP)
                await namespace.run(["ip", "link", "set", interface_name, "up"])
                
                # Debug: Check Socket in Host AGAIN (Did it survive?)
                if logger.isEnabledFor(logging.DEBUG):
                    try:
                        ss_out_after = await self._run_sudo_output(["ss", "-ulpn", "sport = :51820"])
                        logger.debug(f"Socket status in HOST AFTER move/up:\n{ss_out_after}")
                    except Exception:
                        pass
                    
                    # Check WG status from INSIDE the namespace
                    try:
                        wg_show_ns = await namespace.run(["wg", "show", interface_name])
                        logger.debug(f"WG status INSIDE namespace after up:\n{wg_show_ns}")
                    except Exception as e:
                        logger.debug(f"Failed to get wg show in namespace: {e}")
                
                # 9. Set Routes inside NS
                # Default route through wg interface
                await namespace.run(["ip", "route", "add", "default", "dev", interface_name])
                
                # Debug: Log namespace state
                if logger.isEnabledFor(logging.DEBUG):
                    ip_a = await namespace.run(["ip", "a"])
                    ip_r = await namespace.run(["ip", "route"])
                    logger.debug(f"Namespace {namespace.name} state:\nIPs:\n{ip_a}\nRoutes:\n{ip_r}")

            finally:
                # Cleanup temp config
                if temp_conf_path.exists():
                    temp_conf_path.unlink()
            
            # 9. Set up DNS
            # Create /etc/netns/<ns>/resolv.conf so ip netns exec uses it
            if wg_conf.dns:
                netns_dir = Path(f"/etc/netns/{namespace.name}")
                if not netns_dir.exists():
                    # We might need sudo to create this if running as non-root (but in Docker we are root)
                    # Ideally we use sudo if needed, but python's mkdir might fail permissions
                    # Let's try to run mkdir with sudo if needed
                    cmd_mkdir = ["mkdir", "-p", str(netns_dir)]
                    await self._run_sudo(cmd_mkdir)
                
                # Create resolv.conf content
                # Handle comma-separated DNS servers
                dns_servers = [d.strip() for d in wg_conf.dns.split(',')]
                
                # Add Quad9 and Cloudflare as fallbacks if not already present
                # Primary: 9.9.9.9 (Quad9), 1.1.1.1 (Cloudflare)
                # Secondary: 149.112.112.112 (Quad9), 1.0.0.1 (Cloudflare)
                fallbacks = ["9.9.9.9", "1.1.1.1", "149.112.112.112", "1.0.0.1"]
                for fb in fallbacks:
                    if fb not in dns_servers:
                        dns_servers.append(fb)
                
                resolv_content = "\n".join([f"nameserver {d}" for d in dns_servers])
                
                # Add options for faster failover
                resolv_content += "\noptions timeout:2 attempts:2 rotate"
                
                # Write to file (might need sudo)
                resolv_path = netns_dir / "resolv.conf"
                
                # Write using shell echo to handle permissions via sudo
                cmd_write = ["sh", "-c", f"echo '{resolv_content}' > {resolv_path}"]
                await self._run_sudo(cmd_write)
                
                logger.debug(f"Configured DNS for namespace {namespace.name}: {wg_conf.dns}")

            # Cleanup temp config
            if temp_conf_path.exists():
                temp_conf_path.unlink()
            
            # 10. Wait for Handshake (Verify Connectivity)
            # This is critical for AirVPN: traffic won't flow until handshake completes
            logger.debug(f"Waiting for VPN handshake in {namespace.name}...")
            handshake_complete = False
            handshake_start = datetime.now()
            
            # Start tcpdump in background to capture handshake traffic (first 5 packets)
            tcpdump_output = None
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    # Capture UDP traffic to/from the VPN endpoint
                    tcpdump_proc = await asyncio.create_subprocess_exec(
                        "timeout", "5", "tcpdump", "-i", "eth0", "-c", "10", "-n",
                        f"host {wg_conf.endpoint_ip} and udp",
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE
                    )
                except Exception as e:
                    logger.debug(f"Failed to start tcpdump: {e}")
                    tcpdump_proc = None
            else:
                tcpdump_proc = None
            
            while (datetime.now() - handshake_start).total_seconds() < 20:
                # Check handshake status
                # Output format: public_key    latest_handshake_epoch_seconds
                hs_output = await namespace.run(["wg", "show", interface_name, "latest-handshakes"])
                if hs_output.strip():
                    logger.debug(f"Handshake status: {hs_output.strip()}")
                    parts = hs_output.split()
                    if len(parts) >= 2:
                        last_hs = int(parts[1])
                        # Check if handshake happened recently (within last 30 seconds)
                        # Note: wg reports 0 if never moved
                        if last_hs > 0 and (datetime.now().timestamp() - last_hs) < 180:
                            handshake_complete = True
                            break
                else:
                    logger.debug("Handshake status: <empty>")
                    
                await asyncio.sleep(1.0)
            
            # Get tcpdump output
            if tcpdump_proc:
                try:
                    stdout, stderr = await asyncio.wait_for(tcpdump_proc.communicate(), timeout=2)
                    tcpdump_output = stdout.decode() + stderr.decode()
                    logger.debug(f"tcpdump output:\n{tcpdump_output}")
                except Exception as e:
                    logger.debug(f"Failed to get tcpdump output: {e}")
            
            if not handshake_complete:
                # Get final WG status before failing
                try:
                    final_wg = await namespace.run(["wg", "show", interface_name])
                    logger.debug(f"Final WG status before failure:\n{final_wg}")
                except Exception:
                    pass
                raise RuntimeError("VPN handshake timed out (no response from server)")

            # 11. Verify DNS Reachability (Optional but recommended)
            # Try to ping the DNS server (if it's a private IP like 10.128.0.1)
            # Or just assume it works if handshake worked
            if wg_conf.dns:
                primary_dns = dns_servers[0]
                # Only check if it's the internal AirVPN DNS
                if primary_dns.startswith("10."):
                    logger.debug(f"Verifying reachability of DNS {primary_dns}...")
                    try:
                        # Ping with short timeout (1s)
                        await namespace.run(["ping", "-c", "1", "-W", "2", primary_dns])
                        logger.debug(f"DNS {primary_dns} is reachable")
                    except Exception:
                        logger.warning(f"DNS {primary_dns} not reachable via ping, but proceeding regardless")

            duration = (datetime.now() - start_time).total_seconds()
            
            # Mark as connected (we don't track interface on host anymore, it's hidden in NS)
            self._current_interface = f"{interface_name}@{namespace.name}"
            
            logger.info(f"VPN setup complete in namespace {namespace.name} (handshake verified)")
            return ConnectionResult(
                success=True,
                server_name=wg_conf.server_name,
                config_file=str(config_file),
                connect_time_seconds=duration
            )
            
        except Exception as e:
            logger.error(f"Namespace connection failed: {e}")
            # Try to cleanup interface if it exists stuck in host or partially in NS?
            # If we fail, the namespace might be deleted by caller which cleans everything up automatically!
            # That's the beauty of namespaces.
            return ConnectionResult(
                success=False,
                config_file=str(config_file),
                connect_time_seconds=(datetime.now() - start_time).total_seconds(),
                error=str(e)
            )

    async def _run_sudo(self, cmd):
        """Helper to run command with sudo."""
        if self.use_sudo:
            cmd = ["sudo"] + cmd
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd} -> {stderr.decode()}")

    async def _run_sudo_output(self, cmd) -> str:
        """Helper to run command with sudo and return stdout."""
        if self.use_sudo:
            cmd = ["sudo"] + cmd
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        if process.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd} -> {stderr.decode()}")
        return stdout.decode().strip()
            
    async def disconnect(self, config_file: Path = None) -> bool:
        """
        Disconnect VPN using manual ip/wg commands.
        
        Mirrors wg-quick down: remove DNS, delete routing rules,
        flush routing table, delete interface.
        """
        import logging
        logger = logging.getLogger("airbl.hummingbird")
        
        table = str(self._fwmark)
        
        try:
            # Handle Namespace Interface (format: interface@namespace)
            if self._current_interface and "@" in self._current_interface:
                # We assume the caller destroys the namespace, which destroys the interface.
                # So here we just clear our state.
                logger.debug(f"Disconnecting namespace interface {self._current_interface} (caller should destroy NS)")
                self._current_interface = None
                return True
                
            # Always try to disconnect the interface, even if we don't have it tracked
            interface_to_disconnect = self._current_interface or "wg0"
            
            # First check if interface actually exists
            try:
                check_cmd = []
                if self.use_sudo:
                    check_cmd.append("sudo")
                check_cmd.extend(["wg", "show", "interfaces"])
                check_process = await asyncio.create_subprocess_exec(
                    *check_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, _ = await check_process.communicate()
                interfaces = stdout.decode().strip()
                
                if interface_to_disconnect not in interfaces:
                    logger.debug(f"Interface {interface_to_disconnect} does not exist, cleaning up routes only")
                    # Still clean up any stale routing rules
                    await self._cleanup_routing(table, logger)
                    self._current_interface = None
                    self._temp_config_path = None
                    return True
            except Exception as e:
                logger.debug(f"Could not check if interface exists: {e}")
            
            logger.debug(f"Disconnecting VPN interface: {interface_to_disconnect}")
            
            # 1. Remove DNS via resolvconf (best-effort)
            try:
                resolvconf_cmd = []
                if self.use_sudo:
                    resolvconf_cmd.append("sudo")
                resolvconf_cmd.extend(["resolvconf", "-d", interface_to_disconnect, "-f"])
                proc = await asyncio.create_subprocess_exec(
                    *resolvconf_cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                await proc.communicate()
            except Exception:
                pass  # resolvconf may not be available
            
            # 2. Clean up routing rules and table
            await self._cleanup_routing(table, logger)
            
            # 3. Delete the WireGuard interface
            try:
                await self._run_sudo(["ip", "link", "delete", "dev", interface_to_disconnect])
                logger.debug(f"Deleted interface {interface_to_disconnect}")
            except Exception as e:
                logger.warning(f"Failed to delete interface {interface_to_disconnect}: {e}")
            
            await asyncio.sleep(0.3)  # Brief settle time
            
            self._current_interface = None
            self._temp_config_path = None
            return True
        except Exception as e:
            logger.exception(f"Exception during VPN disconnection: {e}")
            # Best-effort force cleanup
            interface_to_disconnect = self._current_interface or "wg0"
            try:
                await self._run_sudo(["ip", "link", "delete", "dev", interface_to_disconnect])
            except Exception:
                pass
            self._current_interface = None
            self._temp_config_path = None
            return False


