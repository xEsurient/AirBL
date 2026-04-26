#!/bin/bash
set -e

# AirBL Docker Entrypoint
# Handles VPN setup and application startup

echo "==================================="
echo "  AirBL - AirVPN DroneBL Checker"
echo "==================================="
echo ""

# Check for required capabilities
check_capabilities() {
    if ! capsh --print | grep -q "cap_net_admin"; then
        echo "WARNING: Container may not have NET_ADMIN capability"
        echo "Run with: docker run --cap-add=NET_ADMIN"
    fi
}

# Setup WireGuard interface
setup_wireguard() {
    # Enable IP forwarding (may fail in read-only filesystem, that's OK)
    if [ -w /proc/sys/net/ipv4/ip_forward ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true
    else
        echo "Note: /proc/sys/net/ipv4/ip_forward is read-only (may need --privileged or sysctls)"
    fi
    
    # Set src_valid_mark for WireGuard routing (set via docker-compose sysctls,
    # but also set here as a fallback if /proc/sys is writable)
    if [ -w /proc/sys/net/ipv4/conf/all/src_valid_mark ]; then
        echo 1 > /proc/sys/net/ipv4/conf/all/src_valid_mark 2>/dev/null || true
    else
        echo "Note: /proc/sys/net/ipv4/conf/all/src_valid_mark is read-only (set via docker sysctls)"
    fi
    
    # Create WireGuard interface if not exists
    if ! ip link show wg0 &>/dev/null; then
        ip link add dev wg0 type wireguard 2>/dev/null || true
    fi
}

# Verify config directory
check_configs() {
    local config_dir="${AIRBL_CONFIG_DIR:-/app/conf}"
    local conf_count=$(find "$config_dir" -name "*.conf" 2>/dev/null | wc -l)
    
    echo "Config directory: $config_dir"
    echo "Config files found: $conf_count"
    
    if [ "$conf_count" -eq 0 ]; then
        echo ""
        echo "WARNING: No .conf files found in $config_dir"
        echo "Mount your config directory: -v /path/to/configs:/app/conf"
        echo ""
    fi
}

# Clean Python cache (remove old airnl references)
clean_python_cache() {
    find /app -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
    find /app -name "*.pyc" -delete 2>/dev/null || true
    find /app -name "*.pyo" -delete 2>/dev/null || true
}

# Setup Policy Routing so Web UI remains accessible
setup_policy_routing() {
    # Find the primary interface IP (dynamically detect the default interface)
    local default_iface=$(ip route show default | awk '/default/ {print $5}' | head -n 1)
    if [ -z "$default_iface" ]; then
        default_iface="eth0" # fallback to eth0
    fi
    local eth0_ip=$(ip -4 addr show "$default_iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
    
    if [ -n "$eth0_ip" ]; then
        echo "Setting up policy routing for container IP: $eth0_ip on $default_iface"
        # Ensure replies from the container IP go out the main table, bypassing WireGuard's table 51820
        ip rule add from "$eth0_ip" table main priority 100 2>/dev/null || true
    fi
}

# Initialize
echo "Initializing..."
check_capabilities
setup_wireguard
check_configs
clean_python_cache
setup_policy_routing

echo ""
echo "Starting AirBL..."
echo ""

# Handle different commands
case "$1" in
    web)
        shift
        # Run web server as module (now has proper __main__.py)
        exec python -m airbl.web "$@"
        ;;
    scan)
        shift
        exec python main.py scan "$@"
        ;;
    check)
        shift
        exec python main.py check "$@"
        ;;
    shell)
        exec /bin/bash
        ;;
    *)
        # Default: run the web server
        exec python -c "
import asyncio
from pathlib import Path
from airbl.web.app import run_server

config_dir = Path('${AIRBL_CONFIG_DIR:-/app/conf}')
port = int('${PORT:-5665}')
interval = int('${SCAN_INTERVAL:-120}')

print(f'Starting web server on port {port}')
print(f'Config directory: {config_dir}')
print(f'Scan interval: {interval} minutes')

asyncio.run(run_server(
    host='0.0.0.0',
    port=port,
    config_dir=config_dir,
    scan_interval_minutes=interval,
    auto_scan=True,
))
"
        ;;
esac

