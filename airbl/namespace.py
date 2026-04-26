"""
Linux Network Namespace Management for VPN Isolation.

Allows creating isolated network stacks to run VPN connections avoiding
route conflicts and leaks.
"""

import asyncio
import logging
import uuid
import sys
import shutil
from typing import List, Optional
from pathlib import Path

logger = logging.getLogger("airbl.namespace")

class NetworkNamespace:
    """
    Context manager for a temporary Linux Network Namespace.
    
    Usage:
        async with NetworkNamespace() as ns:
            await ns.run(["ip", "a"])
            # Run commands inside namespace
    """
    
    def __init__(self, name_prefix: str = "airbl_ns", use_sudo: bool = True):
        self.name = f"{name_prefix}_{uuid.uuid4().hex[:6]}"
        self.use_sudo = use_sudo
        self.exists = False
        self._is_linux = sys.platform.startswith("linux")
        
    async def __aenter__(self):
        await self.create()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.delete()
        
    async def create(self):
        """Create the namespace and bring up headers."""
        if not self._is_linux:
            logger.warning("Network namespaces are only supported on Linux. Skipping creation.")
            return

        logger.debug(f"Creating network namespace: {self.name}")
        
        try:
            # Create netns
            await self._exec_cmd(["ip", "netns", "add", self.name])
            self.exists = True
            
            # Bring up loopback (lo) inside namespace
            await self.run(["ip", "link", "set", "lo", "up"])
            
            logger.info(f"Initialized network namespace: {self.name}")
            
        except Exception as e:
            logger.error(f"Failed to create namespace {self.name}: {e}")
            await self.delete() # Cleanup partial
            raise
            
    async def delete(self):
        """Delete the namespace."""
        if not self._is_linux or not self.exists:
            return
            
        logger.debug(f"Deleting network namespace: {self.name}")
        try:
            # Delete configuration directory if it exists (e.g. resolv.conf)
            netns_dir = Path(f"/etc/netns/{self.name}")
            if netns_dir.exists():
                # Try simple python removal first (works if we act as root)
                try:
                    shutil.rmtree(netns_dir)
                    logger.debug(f"Removed netns config: {netns_dir}")
                except Exception:
                    # Fallback to sudo if permission denied
                    if self.use_sudo:
                         await self._exec_cmd(["rm", "-rf", str(netns_dir)], check=False)

            await self._exec_cmd(["ip", "netns", "del", self.name])
            self.exists = False
        except Exception as e:
            logger.warning(f"Error deleting namespace {self.name}: {e}")

    async def run(self, cmd: List[str], check: bool = True) -> str:
        """
        Run a command INSIDE the namespace.
        Wraps command with `ip netns exec <name> ...`
        """
        if not self._is_linux:
            # Fallback: run on host if not Linux (development mode)
            # This means NO isolation on Mac/Windows
            return await self._exec_cmd(cmd, check=check)
            
        wrapped_cmd = ["ip", "netns", "exec", self.name] + cmd
        return await self._exec_cmd(wrapped_cmd, check=check)

    async def _exec_cmd(self, cmd: List[str], check: bool = True) -> str:
        """Helper to execute subprocess command."""
        final_cmd = cmd
        if self.use_sudo and shutil.which("sudo"):
            final_cmd = ["sudo"] + cmd
            
        process = await asyncio.create_subprocess_exec(
            *final_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        stdout, stderr = await process.communicate()
        
        if check and process.returncode != 0:
            err_msg = stderr.decode().strip()
            raise RuntimeError(f"Command failed ({process.returncode}): {' '.join(final_cmd)}\nError: {err_msg}")
            
        return stdout.decode().strip()
