"""
DNS Lookup Module for AirVPN Server Exit IPs.

Uses dig commands to query AirVPN DNS servers for server exit IPs.
"""

import asyncio
import logging
import re
from typing import Set

logger = logging.getLogger("airbl.dns_lookup")


async def lookup_server_exit_ips(server_name: str) -> Set[str]:
    """
    Lookup exit IPs for a server using dig commands.
    
    Queries both dns1.airvpn.org and dns2.airvpn.org for:
    dig ANY SERVERNAME_exit.airservers.org @dns1.airvpn.org +short
    dig ANY SERVERNAME_exit.airservers.org @dns2.airvpn.org +short
    
    Args:
        server_name: Server name (e.g., "adhil")
        
    Returns:
        Set of IPv4 addresses found
    """
    dns_servers = ["dns1.airvpn.org", "dns2.airvpn.org"]
    query_name = f"{server_name.lower()}_exit.airservers.org"
    all_ips = set()
    
    # IPv4 regex pattern
    ipv4_pattern = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
    
    async def query_dns(dns_server: str) -> Set[str]:
        """Query a single DNS server."""
        ips = set()
        try:
            # Run dig command: dig ANY SERVERNAME_exit.airservers.org @DNS_SERVER +short
            cmd = [
                "dig",
                "ANY",
                query_name,
                f"@{dns_server}",
                "+short"
            ]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                output = stdout.decode('utf-8').strip()
                # Parse output - dig +short returns one IP per line
                for line in output.split('\n'):
                    line = line.strip()
                    if line and ipv4_pattern.match(line):
                        ips.add(line)
            else:
                error = stderr.decode('utf-8').strip()
                logger.warning(f"dig query failed for {query_name} @{dns_server}: {error}")
        except FileNotFoundError:
            logger.error("dig command not found. Please install bind-utils or dnsutils.")
        except Exception as e:
            logger.warning(f"Error querying {query_name} @{dns_server}: {e}")
        
        return ips
    
    # Query both DNS servers concurrently
    results = await asyncio.gather(*[query_dns(server) for server in dns_servers])
    
    # Combine all IPs from both servers
    for ips in results:
        all_ips.update(ips)
    
    return all_ips


