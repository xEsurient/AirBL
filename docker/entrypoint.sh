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
    # No wg0 here: the tester creates its own interface per test (cleanup removes stale ones)
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
    local eth0_ip=$(ip -4 addr show "$default_iface" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -n 1 || true)
    
    if [ -n "$eth0_ip" ]; then
        local dash_port="${PORT:-5665}"
        echo "Setting up policy routing for dashboard replies: $eth0_ip tcp/$dash_port on $default_iface"
        # Keep dashboard replies ahead of VPN rules, after the kernel's priority-0 local rule.
        # Only replies from the dashboard port: a rule for every packet from this IP would let
        # any socket bound to it bypass the tunnel during tests.
        ip -4 rule del from "$eth0_ip" table main priority 1 2>/dev/null || true
        if ! ip -4 rule add from "$eth0_ip" ipproto tcp sport "$dash_port" table main priority 1 2>/dev/null; then
            echo "WARNING: kernel lacks ipproto/sport rule support; using broad source rule (source-bound sockets can bypass the VPN)"
            ip -4 rule add from "$eth0_ip" table main priority 1 \
                || echo "WARNING: could not add dashboard routing rule (NET_ADMIN missing?); dashboard may be unreachable during VPN tests"
        fi
    fi
}

# Remove VPN state left behind by a crash (kill switch chain, tunnel, policy rules)
cleanup_stale_vpn_state() {
    for ipt in iptables ip6tables; do
        command -v "$ipt" >/dev/null 2>&1 || continue
        while $ipt -w 5 -D OUTPUT -j AIRBL_KS 2>/dev/null; do :; done
        $ipt -w 5 -F AIRBL_KS 2>/dev/null || true
        $ipt -w 5 -X AIRBL_KS 2>/dev/null || true
    done
    ip link delete wg0 2>/dev/null || true
    while ip -4 rule del table 51820 2>/dev/null; do :; done
    while ip -4 rule del table main suppress_prefixlength 0 2>/dev/null; do :; done
    for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        while ip -4 rule del to "$net" table main priority 10 2>/dev/null; do :; done
    done
    ip -4 route flush table 51820 2>/dev/null || true
}

# Initialize
echo "Initializing..."
check_capabilities
setup_wireguard
check_configs
clean_python_cache
cleanup_stale_vpn_state
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
    shell)
        exec /bin/bash
        ;;
    "")
        exec python -m airbl.web
        ;;
    *)
        # Any other CLI command (scan, check, configs, ping, speedtest, status, --help, ...)
        exec python main.py "$@"
        ;;
esac
