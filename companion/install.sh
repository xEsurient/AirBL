#!/bin/bash
# Install / update / uninstall the AirBL companion as a macOS LaunchDaemon.
#   sudo ./install.sh            install or update (keeps an existing config)
#   sudo ./install.sh uninstall  stop it, take the tunnel down, remove it (keeps the config)
#
# The daemon runs as root, so everything it executes must be root-owned. Homebrew's folders
# (/opt/homebrew, /usr/local) belong to your user account: anything there could be replaced
# by any program running as you. So this copies wg, wg-quick, wireguard-go and bash into
# /opt/airbl-companion/bin (root-owned) and uses Apple's /usr/bin/python3.
# After `brew upgrade wireguard-tools`, run this again to refresh the copies.
set -euo pipefail
LABEL=org.airbl.companion
PREFIX=/opt/airbl-companion
PLIST=/Library/LaunchDaemons/$LABEL.plist
STATE=/var/db/airbl-companion
HERE="$(cd "$(dirname "$0")" && pwd)"
PY=/usr/bin/python3

[ "$(uname)" = Darwin ] || { echo "This installer is for macOS. On Linux, run airbl_companion.py serve from systemd."; exit 1; }
[ "$(id -u)" = 0 ] || { echo "Run with sudo."; exit 1; }

conf_name() {  # the WireGuard interface name from the config (default airbl)
    "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get("wireguard",{}).get("interface","airbl"))' \
        "$PREFIX/etc/config.json" 2>/dev/null || echo airbl
}

if [ "${1:-}" = uninstall ]; then
    IFACE=$(conf_name)
    launchctl bootout system "$PLIST" 2>/dev/null || true
    if [ -f "$STATE/$IFACE.conf" ]; then
        PATH="$PREFIX/bin:/usr/bin:/bin:/usr/sbin:/sbin" "$PREFIX/bin/wg-quick" down "$STATE/$IFACE.conf" 2>/dev/null || true
    fi
    rm -f "$PLIST" /usr/local/bin/airbl-companion
    rm -rf "${PREFIX:?}/bin" "${PREFIX:?}/lib"
    echo "Removed. Config kept in $PREFIX/etc (contains your WireGuard key; delete it if you no longer need it)."
    exit 0
fi

# Apple's python3 comes with the Xcode command line tools
if ! xcode-select -p >/dev/null 2>&1 || ! "$PY" -c 'import sys; sys.exit(sys.version_info < (3, 9))' 2>/dev/null; then
    echo "Apple's python3 (3.9+) is needed: run  xcode-select --install  and try again."; exit 1
fi

# Find the Homebrew tools (as installed by: brew install wireguard-tools bash)
BREW_PATH=/opt/homebrew/bin:/usr/local/bin
find_tool() { PATH="$BREW_PATH" command -v "$1" || true; }
WG=$(find_tool wg); WGQ=$(find_tool wg-quick); WGGO=$(find_tool wireguard-go); BASH4=$(find_tool bash)
for t in WG WGQ WGGO BASH4; do
    [ -n "${!t}" ] || { echo "Missing tools. Install them with:  brew install wireguard-tools bash"; exit 1; }
done

install -d -o root -g wheel -m 755 "$PREFIX" "$PREFIX/bin" "$PREFIX/lib"
install -d -o root -g wheel -m 700 "$PREFIX/etc" "$STATE"
for src in "$WG" "$WGGO" "$BASH4"; do
    real=$("$PY" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$src")
    install -o root -g wheel -m 755 "$real" "$PREFIX/bin/$(basename "$src")"
done
# Copied binaries must not load libraries from user-writable folders either. Homebrew's bash
# links readline, ncurses and gettext from /opt/homebrew: copy every such library (and what
# those load in turn) into the root-owned $PREFIX/lib/dylib, point the binaries at the copies,
# and re-sign them (Apple Silicon refuses to run modified binaries that aren't signed).
DYLIB="$PREFIX/lib/dylib"
rm -rf "$DYLIB"; install -d -o root -g wheel -m 755 "$DYLIB"
external_deps() {  # load paths of $1 outside the system and outside $PREFIX (not its own id)
    local own; own=$(otool -D "$1" 2>/dev/null | tail -n +2 | head -1)
    otool -L "$1" | tail -n +2 | awk '{print $1}' \
        | grep -vE "^(/usr/lib/|/System/|$PREFIX/)" | grep -vxF "${own:-//none//}" || true
}
queue=("$PREFIX/bin/wg" "$PREFIX/bin/wireguard-go" "$PREFIX/bin/bash")
modified=()
while [ ${#queue[@]} -gt 0 ]; do
    f="${queue[0]}"; queue=("${queue[@]:1}")
    for dep in $(external_deps "$f"); do
        case "$dep" in
            @*) echo "$f uses a relative library path ($dep); can't bundle it safely."; rm -rf "${PREFIX:?}/bin" "${DYLIB:?}"; exit 1 ;;
        esac
        dest="$DYLIB/$(basename "$dep")"
        if [ ! -f "$dest" ]; then
            real=$("$PY" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$dep")
            [ -f "$real" ] || { echo "Library $dep (needed by $f) not found"; rm -rf "${PREFIX:?}/bin" "${DYLIB:?}"; exit 1; }
            install -o root -g wheel -m 644 "$real" "$dest"
            install_name_tool -id "$dest" "$dest" 2>/dev/null
            queue+=("$dest"); modified+=("$dest")
        fi
        install_name_tool -change "$dep" "$dest" "$f" 2>/dev/null
        modified+=("$f")
    done
done
for f in $(printf '%s\n' "${modified[@]+"${modified[@]}"}" | sort -u); do
    codesign --force --sign - "$f" >/dev/null 2>&1 || { echo "codesign failed for $f"; rm -rf "${PREFIX:?}/bin" "${DYLIB:?}"; exit 1; }
done
[ ${#modified[@]} -gt 0 ] && echo "Bundled $(ls "$DYLIB" | wc -l | tr -d ' ') libraries into $DYLIB (root-owned copies)."
# Final check: everything the binaries load is the system's or one of the root-owned copies
for f in "$PREFIX/bin/wg" "$PREFIX/bin/wireguard-go" "$PREFIX/bin/bash" "$DYLIB"/*.dylib; do
    [ -e "$f" ] || continue
    if otool -L "$f" | tail -n +2 | awk '{print $1}' | grep -vE "^(/usr/lib/|/System/|$PREFIX/)" | grep -q .; then
        echo "$f still links outside /usr/lib, /System and $PREFIX:"; otool -L "$f" | tail -n +2
        echo "Refusing to run it as root. Please report this."
        rm -rf "${PREFIX:?}/bin" "${DYLIB:?}"; exit 1
    fi
done
"$PREFIX/bin/bash" -c '[ "${BASH_VERSINFO[0]}" -ge 4 ]' || { echo "bash 4 or newer is needed (brew install bash)"; exit 1; }
# wg-quick is a bash script: copy it and make it use the root-owned bash
{ echo "#!$PREFIX/bin/bash"; tail -n +2 "$("$PY" -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$WGQ")"; } \
    > "$PREFIX/bin/wg-quick.tmp"
install -o root -g wheel -m 755 "$PREFIX/bin/wg-quick.tmp" "$PREFIX/bin/wg-quick"; rm -f "$PREFIX/bin/wg-quick.tmp"
install -o root -g wheel -m 644 "$HERE/airbl_companion.py" "$PREFIX/lib/airbl_companion.py"

NEW_CONFIG=0
if [ ! -f "$PREFIX/etc/config.json" ]; then
    OLD=/usr/local/etc/airbl-companion/config.json  # layout of version 1.0
    if [ -f "$OLD" ]; then
        install -o root -g wheel -m 600 "$OLD" "$PREFIX/etc/config.json"
        echo "Moved your config from $OLD (you can delete the old folder)."
    else
        install -o root -g wheel -m 600 "$HERE/config.example.json" "$PREFIX/etc/config.json"
        KEY=$("$PY" -c 'import secrets; print(secrets.token_urlsafe(32))')
        sed -i '' "s/CHANGE-ME-long-random-string/$KEY/" "$PREFIX/etc/config.json"
        NEW_CONFIG=1
    fi
fi
chown root:wheel "$PREFIX/etc/config.json"; chmod 600 "$PREFIX/etc/config.json"
install -o root -g wheel -m 644 "$HERE/org.airbl.companion.plist" "$PLIST"
# Convenience command (only used by you with sudo; the daemon never runs it)
mkdir -p /usr/local/bin
cat > /usr/local/bin/airbl-companion <<EOF
#!/bin/sh
exec /usr/bin/python3 $PREFIX/lib/airbl_companion.py -c $PREFIX/etc/config.json "\$@"
EOF
chmod 755 /usr/local/bin/airbl-companion
rm -rf /usr/local/lib/airbl-companion  # version 1.0 layout

if [ $NEW_CONFIG = 1 ]; then
    echo "Installed. Now:"
    echo "  1. sudo nano $PREFIX/etc/config.json   (WireGuard key/address, allow_from = your AirBL host, qBittorrent)"
    echo "     The API key for AirBL's Settings page was generated: sudo grep api_key $PREFIX/etc/config.json"
    echo "  2. sudo airbl-companion check"
    echo "  3. Quit the WireGuard app's tunnel, then: sudo launchctl bootstrap system $PLIST"
elif launchctl print "system/$LABEL" >/dev/null 2>&1; then
    # It was running: restart it with the new version (the tunnel itself stays up)
    launchctl bootout system "$PLIST" 2>/dev/null || true
    sleep 1
    launchctl bootstrap system "$PLIST"
    echo "Updated and restarted. Log: /var/log/airbl-companion.log"
else
    # Not started yet (e.g. still setting up): don't start it behind your back
    echo "Updated. Start it when ready (after disconnecting the WireGuard app's tunnel):"
    echo "  sudo launchctl bootstrap system $PLIST"
fi
