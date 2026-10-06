"""
VPN Control Module.

Brings up an AirVPN WireGuard tunnel with plain wg/ip commands (WireGuardController)
for speedtests. (The module name is historical: the Hummingbird client wrapper is gone.)
"""

import asyncio
import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional
import re


@dataclass
class ConnectionResult:
    """Result of a VPN connection attempt."""
    success: bool
    server_name: Optional[str] = None
    config_file: Optional[str] = None
    public_ip: Optional[str] = None
    connect_time_seconds: float = 0.0
    error: Optional[str] = None


async def get_public_ip(timeout: float = 10) -> Optional[str]:
    """Current public IP via a few plain-text lookup services, or None."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=timeout) as client:
            for service in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
                try:
                    response = await client.get(service)
                    if response.status_code == 200:
                        return response.text.strip()
                except Exception:
                    continue
    except Exception:
        pass
    return None


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
    """
    
    def __init__(self, use_sudo: Optional[bool] = None):
        """
        Initialize WireGuardController.
        
        Args:
            use_sudo: If None, auto-detects based on environment.
                     If True, uses sudo (will fail if not available).
                     If False, runs without sudo (requires root).
        """
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
        self._resolv_backup: Optional[str] = None  # original /etc/resolv.conf if we overwrote it
        self._kill_switch_on: bool = False
    
    async def connect(self, config_file: Path, interface_name: str = "wg0") -> ConnectionResult:
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
        """
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
                interfaces = (await self._run_sudo_output(["wg", "show", "interfaces"])).split()
                
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
                # The tester always routes all IPv4 through the tunnel (route below is 0.0.0.0/0),
                # so the peer must accept it too; a split AllowedIPs would blackhole traffic.
                "AllowedIPs = 0.0.0.0/0",
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
            
            if wg_conf.allowed_ips and "0.0.0.0/0" not in wg_conf.allowed_ips:
                logger.info(f"{config_file.name} has split AllowedIPs ({wg_conf.allowed_ips}); "
                            "testing uses a full IPv4 tunnel instead")
            
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
            
            # 5. Add address and bring interface up.
            # IPv6-enabled AirVPN configs list "v4/32, v6/128"; the tunnel is IPv4-only
            # (routes, AllowedIPs, kill switch), so only the IPv4 entries are added.
            for addr in (a.strip() for a in (wg_conf.address or "").split(",")):
                if not addr:
                    continue
                if ":" in addr:
                    logger.debug(f"Skipping IPv6 address {addr} (IPv6 tunnel not supported)")
                    continue
                if '/' not in addr:
                    addr = f"{addr}/32"
                await self._run_sudo(["ip", "-4", "address", "add", addr, "dev", interface_name])
                logger.debug(f"Added address {addr} to {interface_name}")
            
            # Set MTU (from config when sane, else WireGuard's usual 1420) and bring up
            mtu = wg_conf.mtu if wg_conf.mtu and 1280 <= wg_conf.mtu <= 1500 else 1420
            await self._run_sudo(["ip", "link", "set", "mtu", str(mtu), "up", "dev", interface_name])
            logger.debug(f"Interface {interface_name} is UP with MTU {mtu}")
            
            # 6. Configure DNS via resolvconf (if available)
            dns_servers = [d.strip() for d in (wg_conf.dns or "").split(',')
                           if re.fullmatch(r"[0-9a-fA-F:.]+", d.strip())]
            if wg_conf.dns and not dns_servers:
                # Writing no nameserver at all would break every lookup; keep the current DNS
                logger.warning(f"{config_file.name}: no valid nameserver in DNS = {wg_conf.dns!r}; "
                               "keeping the current resolv.conf")
            if dns_servers:
                try:
                    # Build resolvconf input: one "nameserver" per line
                    dns_input = "\n".join(f"nameserver {d}" for d in dns_servers) + "\n"
                    await self._run_sudo(["resolvconf", "-a", interface_name, "-m", "0", "-x"],
                                         input_data=dns_input.encode())
                    logger.debug(f"Configured DNS via resolvconf: {dns_servers}")
                except Exception as dns_err:
                    # Fallback: write /etc/resolv.conf directly
                    logger.debug(f"resolvconf not available ({dns_err}), writing /etc/resolv.conf directly")
                    resolv_content = "\n".join(f"nameserver {d}" for d in dns_servers) + "\n"
                    try:
                        resolv = Path("/etc/resolv.conf")
                        if self._resolv_backup is None:
                            self._resolv_backup = resolv.read_text()  # restored on disconnect
                        resolv.write_text(resolv_content)
                    except Exception as resolv_err:
                        logger.warning(f"Failed to configure DNS: {resolv_err}")
            
            # 7. Set fwmark and routing rules (replicates what wg-quick does)
            await self._run_sudo(["wg", "set", interface_name, "fwmark", fwmark])
            await self._run_sudo(["ip", "-4", "route", "add", "0.0.0.0/0", "dev", interface_name, "table", table])
            # Fallback when wg0 vanishes (its route goes with it): drop instead of falling
            # through to the main table and measuring over the direct line.
            await self._run_sudo(["ip", "-4", "route", "add", "blackhole", "0.0.0.0/0", "table", table, "metric", "4096"])
            
            # Pin AirVPN internal DNS/address range through the tunnel BEFORE the broad RFC1918 bypasses
            # AirVPN uses 10.128.0.0/10 internally (DNS at 10.128.0.1, client addresses in 10.128-191.x.x)
            await self._run_sudo(["ip", "-4", "rule", "add", "to", "10.128.0.0/10", "table", table, "priority", "5"])
            
            # Local Subnet Bypass Rules (RFC1918)
            # Prevents asymmetric routing so the container Web UI doesn't drop when hit from the host LAN
            for subnet in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]:
                await self._run_sudo(["ip", "-4", "rule", "add", "to", subnet, "table", "main", "priority", "10"])
                
            # Automatic priorities can precede the dashboard's priority-1 exception.
            # Keep connected routes ahead of the VPN catch-all, but both after bypasses.
            await self._run_sudo(["ip", "-4", "rule", "add", "not", "fwmark", fwmark, "table", table, "priority", "20010"])
            await self._run_sudo(["ip", "-4", "rule", "add", "table", "main", "suppress_prefixlength", "0", "priority", "20000"])
            logger.debug(f"Set fwmark {fwmark}, local bypasses, and routing rules for table {table}")
            
            # NOTE: We intentionally skip sysctl -q net.ipv4.conf.all.src_valid_mark=1
            # It is already set via docker-compose sysctls directive, and skipping it
            # is what allows us to run without privileged mode.
            
            self._current_interface = interface_name
            
            # 8. Kill switch: block anything leaving outside the tunnel while connected
            await self._enable_kill_switch(interface_name, wg_conf.endpoint_ip, wg_conf.endpoint_port)
            
            # 9. Verify: a completed WireGuard handshake, then traffic leaving via AirVPN.
            # Interface/route setup alone doesn't prove the tunnel works.
            if not await self._wait_for_handshake(interface_name):
                raise RuntimeError(f"No WireGuard handshake within {self.HANDSHAKE_TIMEOUT}s "
                                   "(wrong key, endpoint unreachable, or UDP blocked)")
            public_ip = await self._verify_egress()
            
            duration = (datetime.now() - start_time).total_seconds()
            logger.info(f"Connected and verified via {interface_name} using {config_file.name} "
                        f"(egress {public_ip}, {duration:.1f}s)")
            
            return ConnectionResult(
                success=True,
                server_name=config_file.stem,
                config_file=str(config_file),
                public_ip=public_ip,
                connect_time_seconds=duration,
            )
                
        except Exception as e:
            duration = (datetime.now() - start_time).total_seconds()
            logger.exception(f"Exception during VPN connection: {e}")
            
            # Best-effort cleanup on failure: interface, routes/rules and DNS
            try:
                self._current_interface = interface_name
                await self.disconnect()
            except Exception:
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
    
    KILL_SWITCH_CHAIN = "AIRBL_KS"
    PRIVATE_V4 = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
    PRIVATE_V6 = ["fe80::/10", "fc00::/7"]
    KERNEL_FALLBACK_DEVICES = {"tunl0", "sit0", "ip6tnl0", "ip6gre0", "gre0", "gretap0",
                               "erspan0", "ip_vti0", "ip6_vti0"}

    @staticmethod
    def kill_switch_blocker() -> Optional[str]:
        """Reason the kill switch can't be used here, or None if it can."""
        if os.environ.get("AIRBL_KILL_SWITCH", "1").lower() in ("0", "false", "no", "off"):
            return "disabled via AIRBL_KILL_SWITCH"
        try:
            ifaces = os.listdir("/sys/class/net")
        except OSError:
            return "cannot list network interfaces"
        # A container's own network namespace only has lo/eth*/wg*, plus the kernel's
        # fallback tunnel devices that appear in every netns once their module is loaded.
        # Anything else (wlan0, docker0, br-*, veth*) means we share the host's network
        # (network_mode: host), where these rules would firewall the whole machine.
        # (Comparing /proc/self/ns/net with /proc/1/ns/net can't tell: in a container
        # PID 1 is the container's own init.)
        foreign = [i for i in ifaces
                   if not re.fullmatch(r"lo|eth\d+|wg\d+", i) and i not in WireGuardController.KERNEL_FALLBACK_DEVICES]
        if foreign:
            return f"host network namespace detected (interfaces: {', '.join(sorted(foreign)[:5])})"
        return None

    async def _iptables(self, binary: str, *args) -> bool:
        try:
            # Bounded lock wait: a held xtables lock must not hang connect
            await self._run_sudo([binary, "-w", "5", *args])
            return True
        except Exception:
            return False

    async def _enable_kill_switch(self, interface_name: str, endpoint_ip: str, endpoint_port: int):
        """Reject traffic leaving outside the tunnel while connected.

        Allowed: loopback, the tunnel itself, WireGuard's UDP to the endpoint, private
        networks (LAN, Docker, dashboard), and replies on dashboard connections.
        Only affects this container's network namespace.
        """
        logger = logging.getLogger("airbl.hummingbird")
        blocker = self.kill_switch_blocker()
        if blocker:
            logger.warning(f"VPN kill switch not enabled: {blocker}")
            return
        chain = self.KILL_SWITCH_CHAIN
        dash_port = os.environ.get("PORT", "5665")
        families = [("iptables", self.PRIVATE_V4, True)]
        if Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").exists() and \
                Path("/proc/sys/net/ipv6/conf/all/disable_ipv6").read_text().strip() == "0":
            families.append(("ip6tables", self.PRIVATE_V6, False))  # tunnel is IPv4-only: block v6 egress
        for binary, private_nets, is_v4 in families:
            await self._iptables(binary, "-N", chain)  # may already exist
            if not await self._iptables(binary, "-F", chain):
                raise RuntimeError(f"Kill switch: {binary} unavailable")
            rules = [
                ["-o", "lo", "-j", "RETURN"],
                ["-o", interface_name, "-j", "RETURN"],
            ]
            if is_v4:
                rules.append(["-p", "udp", "-d", endpoint_ip, "--dport", str(endpoint_port), "-j", "RETURN"])
            rules += [["-d", net, "-j", "RETURN"] for net in private_nets]
            rules += [
                # Dashboard replies to clients on public addresses (connections they opened)
                ["-p", "tcp", "--sport", dash_port, "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"],
                ["-j", "REJECT"],
            ]
            for rule in rules:
                if not await self._iptables(binary, "-A", chain, *rule):
                    raise RuntimeError(f"Kill switch: failed to add {binary} rule {' '.join(rule)}")
            if not await self._iptables(binary, "-C", "OUTPUT", "-j", chain):
                if not await self._iptables(binary, "-I", "OUTPUT", "1", "-j", chain):
                    raise RuntimeError(f"Kill switch: failed to hook {binary} OUTPUT")
        self._kill_switch_on = True
        logger.debug("VPN kill switch enabled")

    async def _disable_kill_switch(self):
        """Remove the kill switch chain (safe to call when it isn't installed)."""
        chain = self.KILL_SWITCH_CHAIN
        for binary in ("iptables", "ip6tables"):
            for _ in range(5):  # remove every jump (duplicates from a crashed run)
                if not await self._iptables(binary, "-D", "OUTPUT", "-j", chain):
                    break
            await self._iptables(binary, "-F", chain)
            await self._iptables(binary, "-X", chain)
        self._kill_switch_on = False

    HANDSHAKE_TIMEOUT = 15  # seconds; keepalive triggers the first handshake immediately

    async def _wait_for_handshake(self, interface_name: str) -> bool:
        """Poll `wg show <if> latest-handshakes` until the peer reports a handshake."""
        deadline = asyncio.get_event_loop().time() + self.HANDSHAKE_TIMEOUT
        while asyncio.get_event_loop().time() < deadline:
            try:
                out = await self._run_sudo_output(["wg", "show", interface_name, "latest-handshakes"])
                # "<peer-pubkey>\t<unix-time>"; 0 means no handshake yet
                if any(line.split()[-1] != "0" for line in out.strip().splitlines() if line.strip()):
                    return True
            except Exception:
                pass
            await asyncio.sleep(0.5)
        return False

    async def _verify_egress(self) -> str:
        """Confirm traffic exits through AirVPN; returns the public IP.

        Uses AirVPN's own IP API ("airvpn": true when the request came from an AirVPN exit).
        If that API is unreachable but the internet is, accept with a warning rather than
        failing every test because of one website.
        """
        import httpx
        logger = logging.getLogger("airbl.hummingbird")
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get("https://airvpn.org/api/whatismyip/")
                data = resp.json()
            if data.get("airvpn") is True:
                return data.get("ip")
            if data.get("airvpn") is False:
                raise RuntimeError(f"Traffic is not leaving via AirVPN (egress {data.get('ip')}); refusing to measure")
        except RuntimeError:
            raise
        except Exception as e:
            logger.debug(f"AirVPN IP API check failed: {e}")
        ip = await get_public_ip(timeout=10)
        if not ip:
            raise RuntimeError("Tunnel is up but no internet access through it")
        logger.warning(f"Could not confirm AirVPN egress (API unavailable); public IP {ip}")
        return ip

    async def _cleanup_routing(self, table: str, logger):
        """
        Clean up stale routes and rules in the given routing table.
        Fixes "RTNETLINK answers: File exists" errors on reconnect.
        """
        # Rules first, table last: flushing first would briefly send traffic matching
        # the rules into an empty table and on to the direct route.
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
        
        try:
            # Flush all routes in the table (VPN route and blackhole fallback)
            await self._run_sudo(["ip", "route", "flush", "table", table])
        except Exception:
            pass
        
        logger.debug(f"Cleaned up stale routes and rules in table {table}")
    
    CMD_TIMEOUT = 20  # seconds per wg/ip/iptables call

    async def _run_sudo_output(self, cmd, timeout: float = CMD_TIMEOUT, input_data: Optional[bytes] = None) -> str:
        """Run a command (via `sudo -n` when needed) and return stdout; raises on failure.

        `-n` makes sudo fail instead of waiting for a password; the timeout keeps a
        stuck command (e.g. a held lock) from hanging connect/disconnect forever.
        """
        if self.use_sudo:
            cmd = ["sudo", "-n"] + cmd
        process = await asyncio.create_subprocess_exec(
            *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            stdin=asyncio.subprocess.PIPE if input_data is not None else asyncio.subprocess.DEVNULL,
        )
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(input=input_data), timeout=timeout)
        except (asyncio.TimeoutError, asyncio.CancelledError) as e:
            try:
                process.kill()
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(process.wait(), timeout=5)  # reap
            except Exception:
                pass
            if isinstance(e, asyncio.CancelledError):
                raise
            raise RuntimeError(f"Command timed out after {timeout}s: {cmd}")
        if process.returncode != 0:
            raise RuntimeError(f"Command failed: {cmd} -> {stderr.decode()}")
        return stdout.decode().strip()

    async def _run_sudo(self, cmd, timeout: float = CMD_TIMEOUT, input_data: Optional[bytes] = None):
        """Run a command (via `sudo -n` when needed); raises on failure or timeout."""
        await self._run_sudo_output(cmd, timeout=timeout, input_data=input_data)
            
    async def disconnect(self, config_file: Path = None) -> bool:
        """
        Disconnect VPN using manual ip/wg commands.
        
        Mirrors wg-quick down: remove DNS, delete routing rules,
        flush routing table, delete interface.
        """
        logger = logging.getLogger("airbl.hummingbird")
        
        table = str(self._fwmark)
        
        try:
            # Always try to disconnect the interface, even if we don't have it tracked
            interface_to_disconnect = self._current_interface or "wg0"
            
            # First check if interface actually exists
            try:
                interfaces = (await self._run_sudo_output(["wg", "show", "interfaces"])).split()
                
                if interface_to_disconnect not in interfaces:
                    logger.debug(f"Interface {interface_to_disconnect} does not exist, cleaning up routes only")
                    # Still clean up any stale routing rules, DNS and the kill switch
                    if self._resolv_backup is not None:
                        try:
                            Path("/etc/resolv.conf").write_text(self._resolv_backup)
                            self._resolv_backup = None
                        except Exception as e:
                            logger.warning(f"Failed to restore /etc/resolv.conf: {e}")
                    await self._cleanup_routing(table, logger)
                    await self._disable_kill_switch()
                    self._current_interface = None
                    self._temp_config_path = None
                    return True
            except Exception as e:
                logger.debug(f"Could not check if interface exists: {e}")
            
            logger.debug(f"Disconnecting VPN interface: {interface_to_disconnect}")
            
            # 1. Remove DNS via resolvconf (best-effort)
            try:
                await self._run_sudo(["resolvconf", "-d", interface_to_disconnect, "-f"])
            except Exception:
                pass  # resolvconf may not be available
            
            # Restore /etc/resolv.conf if the direct-write fallback replaced it
            if self._resolv_backup is not None:
                try:
                    Path("/etc/resolv.conf").write_text(self._resolv_backup)
                    self._resolv_backup = None
                except Exception as e:
                    logger.warning(f"Failed to restore /etc/resolv.conf: {e}")
            
            # 2. Clean up routing rules and table
            await self._cleanup_routing(table, logger)
            
            # 3. Delete the WireGuard interface
            try:
                await self._run_sudo(["ip", "link", "delete", "dev", interface_to_disconnect])
                logger.debug(f"Deleted interface {interface_to_disconnect}")
            except Exception as e:
                logger.warning(f"Failed to delete interface {interface_to_disconnect}: {e}")
            
            await asyncio.sleep(0.3)  # Brief settle time
            
            # Last: lift the kill switch once nothing routes via the tunnel any more
            await self._disable_kill_switch()
            
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


