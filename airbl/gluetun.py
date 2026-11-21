"""
Gluetun Servers.json Generator.

Downloads the official Gluetun servers.json, filters the AirVPN section
based on user performance thresholds, and generates a custom servers.json for Gluetun.
"""

import asyncio
import json
import os
import logging
import time
import weakref
from typing import Optional
from dataclasses import dataclass
from pathlib import Path

from .config import ControlTargetConfig, config_manager
from .scanner import speedtest_score
from .speedtest import SpeedTestResult
from .web.state import state

logger = logging.getLogger("airbl.gluetun")

WG_PUBKEY = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk="

# Country code -> region, covering every country AirVPN has (had) servers in plus neighbours,
# so no exported server ends up in region "Unknown".
REGION_MAP = {
    "US": "Americas", "CA": "Americas", "BR": "Americas", "MX": "Americas", "AR": "Americas",
    "CL": "Americas", "CO": "Americas", "PE": "Americas", "PA": "Americas", "CR": "Americas",
    "GB": "Europe", "UK": "Europe", "DE": "Europe", "NL": "Europe", "FR": "Europe", "CH": "Europe",
    "SE": "Europe", "ES": "Europe", "IT": "Europe", "RO": "Europe", "BG": "Europe", "AT": "Europe",
    "BE": "Europe", "CZ": "Europe", "DK": "Europe", "FI": "Europe", "HU": "Europe", "IE": "Europe",
    "LV": "Europe", "LT": "Europe", "LU": "Europe", "NO": "Europe", "PL": "Europe", "PT": "Europe",
    "RS": "Europe", "SK": "Europe", "UA": "Europe", "EE": "Europe", "IS": "Europe", "GR": "Europe",
    "HR": "Europe", "SI": "Europe", "CY": "Europe", "MT": "Europe", "MD": "Europe", "AL": "Europe",
    "BA": "Europe", "MK": "Europe", "ME": "Europe", "LI": "Europe", "MC": "Europe", "IM": "Europe",
    "AU": "Oceania", "NZ": "Oceania",
    "JP": "Asia", "SG": "Asia", "HK": "Asia", "IN": "Asia", "TW": "Asia", "TH": "Asia", "MY": "Asia",
    "KR": "Asia", "ID": "Asia", "PH": "Asia", "VN": "Asia", "KH": "Asia",
    "ZA": "Africa", "EG": "Africa", "NG": "Africa", "KE": "Africa",
    "IL": "Middle East", "AE": "Middle East", "TR": "Middle East", "SA": "Middle East", "QA": "Middle East",
}


async def _get_servers_for_gluetun_generation():
    """Get servers for generation. Prefers live scan state, falls back to DB."""
    if state.current_scan and state.current_scan.servers:
        return state.current_scan.servers
        
    if not state.db:
        return []
        
    logger.info("Falling back to DB for Gluetun generation.")
    
    # 1. Get last scan servers
    last_servers = await state.db.get_last_scan_servers()
    if not last_servers:
        return []
        
    # 2. Get entry pings
    entry_pings_raw = await state.db.get_last_scan_entry_pings()
    entry_pings = {}
    for ep in entry_pings_raw:
        name = ep["server_name"]
        if name not in entry_pings:
            entry_pings[name] = {}
        entry_pings[name][ep["entry_type"]] = ep
        
    # 3. Get recent speedtests
    recent_speedtests = await state.db.get_speedtest_history(limit=500)
    speedtest_map = {}
    newest_failed = set()  # newest test failed: the speed ranking must not use an older success
    seen = set()
    for st in recent_speedtests:
        name = st.get("vpn_server_name")
        if name and name not in seen:
            seen.add(name)
            if not st.get("is_success", 1):
                newest_failed.add(name)
        # Newest *successful* test: a failed one (download NULL) would fail the profile thresholds
        if name and name not in speedtest_map and st.get("is_success", 1):
            # The DB keeps Mbps and ping only: score them like the scan restore does
            res = SpeedTestResult(download_mbps=st.get("download_mbps") or 0.0,
                                  upload_mbps=st.get("upload_mbps") or 0.0, ping_ms=st.get("ping_ms") or 0.0)
            speedtest_map[name] = {**st, "score": res.score}
            if st.get("deviation_score") is None:
                speedtest_map[name].pop("deviation_score", None)
            
    # 4. Get server -> city mapping from configs and API fallback
    server_to_city = {}
    if hasattr(state, 'server_to_city_api'):
        server_to_city.update(state.server_to_city_api)
    try:
        from .wireguard import scan_config_directory
        configs = scan_config_directory(state.config_dir)
        for c in configs:
            server_to_city[c.server_name] = c.city
    except Exception as e:
        logger.debug(f"Failed to scan configs for city mapping: {e}")
            
    # 5. Construct mock ServerScanResult objects
    class MockPing:
        def __init__(self, ip, is_alive, avg_rtt_ms):
            self.ip = ip
            self.is_alive = is_alive
            self.avg_rtt_ms = avg_rtt_ms
            
    class MockServer:
        def __init__(self, name, is_clean, score, is_blocked=False):
            self.server_name = name
            self.is_clean = is_clean
            self.score = score
            self.speedtest_result = speedtest_map.get(name)
            self.speed_score = None if name in newest_failed else speedtest_score(self.speedtest_result)
            self.is_blocked = is_blocked
            
            self.country_code = state.servers_by_country.get(name, "Unknown")
            if self.country_code == "Unknown":
                self.country_code = state.servers_by_country.get(name.replace("AirVPN ", ""), "Unknown")
            self.country_name = state.all_countries.get(self.country_code, self.country_code)
            self.location = server_to_city.get(name, "Unknown")
            self.wg_pubkey = WG_PUBKEY
            self.entry1_ping = None
            self.entry3_ping = None
            
            pings = entry_pings.get(name, {})
            if "ENTRY1" in pings:
                ep = pings["ENTRY1"]
                self.entry1_ping = MockPing(ep.get("ip"), ep.get("is_alive"), ep.get("latency_ms"))
            if "ENTRY3" in pings:
                ep = pings["ENTRY3"]
                self.entry3_ping = MockPing(ep.get("ip"), ep.get("is_alive"), ep.get("latency_ms"))
                
    servers = []
    for s_raw in last_servers:
        name = s_raw["server_name"]
        from .database import row_is_clean
        is_clean = row_is_clean(s_raw)
        score = s_raw.get("score", 0)
        rep = s_raw.get("reputation")
        is_blocked = rep == "blocked" if rep else bool(s_raw.get("is_blocked"))
        servers.append(MockServer(name, is_clean, score, is_blocked=is_blocked))
        
    return servers


def _gluetun_name(server) -> str:
    """Server name as Gluetun knows it (no 'AirVPN ' prefix)."""
    return server.server_name.replace("AirVPN ", "").strip()


def _server_ips(server) -> set:
    """All known IPs of a server: entry IPs plus scanned exit IPs."""
    ips = set()
    for ping in (getattr(server, "entry1_ping", None), getattr(server, "entry3_ping", None),
                 getattr(server, "exit_ping", None)):
        if ping and ping.ip:
            ips.add(ping.ip)
    for scanned in getattr(server, "scanned_ips", None) or []:
        ips.add(scanned.ip)
    return ips


def _endpoint_ips(server, strategy: str) -> list:
    """Pick entry IPs to export according to the profile endpoint strategy."""
    entry1 = server.entry1_ping
    entry3 = server.entry3_ping
    e1_ok = bool(entry1 and entry1.is_alive and entry1.ip)
    e3_ok = bool(entry3 and entry3.is_alive and entry3.ip)

    if strategy == "ENTRY1":
        return [entry1.ip] if e1_ok else []
    if strategy == "ENTRY3":
        return [entry3.ip] if e3_ok else []
    if strategy == "PING_PRIORITY":
        candidates = [p for p, ok in ((entry1, e1_ok), (entry3, e3_ok)) if ok and p.avg_rtt_ms is not None]
        if not candidates:
            return []
        return [min(candidates, key=lambda p: p.avg_rtt_ms).ip]
    # ALL
    return [p.ip for p, ok in ((entry1, e1_ok), (entry3, e3_ok)) if ok]


def _filter_profile_servers(profile, servers) -> list:
    """Apply a profile's thresholds. Returns [(server, [endpoint ips])]."""
    strategy = getattr(profile, 'endpoint_strategy', 'ALL')
    allowed_countries = {c.upper() for c in profile.allowed_countries}
    allowed_cities = {c.lower() for c in profile.allowed_cities}

    result = []
    for server in servers:
        if profile.require_clean and not server.is_clean:
            continue
        if allowed_countries and server.country_code.upper() not in allowed_countries:
            continue
        if allowed_cities and server.location.lower() not in allowed_cities:
            continue

        speedtest = server.speedtest_result
        if not speedtest:
            if profile.min_download_mbps > 0 or profile.min_upload_mbps > 0:
                continue
        else:
            dl = speedtest.get("download_mbps") or 0
            ul = speedtest.get("upload_mbps") or 0
            if dl < profile.min_download_mbps or ul < profile.min_upload_mbps:
                continue

        ips = _endpoint_ips(server, strategy)
        if not ips:
            logger.debug(f"Skipping {server.server_name}: no alive endpoint for strategy {strategy}.")
            continue
        result.append((server, ips))
    return result


def _write_servers_json(profile, filtered) -> bool:
    """Write a Gluetun-compatible servers.json (same schema as Gluetun's own file)."""
    output_path = Path(profile.output_path)
    entries = []
    for server, ips in filtered:
        entries.append({
            "vpn": "wireguard",
            "country": server.country_name,
            "region": REGION_MAP.get(server.country_code.upper(), "Unknown"),
            "city": server.location,
            "server_name": _gluetun_name(server),
            "hostname": f"{server.country_code.lower()}.vpn.airdns.org",
            "wgpubkey": server.wg_pubkey or WG_PUBKEY,
            "ips": ips,
        })

    if not entries:
        # An empty-but-newer file would make Gluetun drop every AirVPN server.
        logger.warning(f"Profile '{profile.name}' matched no servers; keeping previous {output_path}.")
        return False

    # Schema versions must match Gluetun's built-in ones (top-level 1, airvpn 1),
    # otherwise Gluetun silently discards the file. "preferred" makes newer Gluetun
    # use this list even if its built-in list has a newer timestamp.
    provider_data = {
        "version": 1,
        "timestamp": int(time.time()),
        "preferred": True,
        "servers": entries,
    }
    # Newer Gluetun migrates /gluetun/servers.json once into /gluetun/servers/<provider>.json
    # and ignores servers.json afterwards; a file named airvpn.json gets that per-provider format.
    if output_path.name == "airvpn.json":
        custom_data = provider_data
    else:
        custom_data = {"version": 1, "airvpn": provider_data}

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = output_path.with_name(output_path.name + ".tmp")
        with open(temp_path, 'w', encoding='utf-8') as f:
            json.dump(custom_data, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        temp_path.replace(output_path)
        logger.info(f"Profile '{profile.name}': wrote {len(entries)} servers to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Error writing Gluetun servers.json for '{profile.name}': {e}")
        return False


# --- Control targets ----------------------------------------------------------------
# "primary" is the original control (GluetunConfig's own fields): clean servers only, ranked
# by score, names sorted, no dwell. "secondary" is GluetunConfig.secondary (a second Gluetun or
# the seedbox companion): may allow blocked servers, ranks by speed, sends names in rank order
# and keeps a minimum dwell between switches. Both are described by a TargetView, so the
# control code has no per-type branches.

@dataclass
class TargetView:
    key: str                 # "primary" | "secondary"
    cfg: object              # GluetunConfig / ControlTargetConfig: host, port, api_key, mode, profile
    label: str
    enabled: bool
    allow_blocked: bool
    rank_by: str             # "score" | "speed"
    top_n: int               # NOT_TOP4 / NOT_TOPN
    ordered_names: bool      # send names in rank order (preference) instead of sorted
    dwell_s: float           # minimum seconds between switches while the current server is allowed
    profile_fallback: bool   # no named profile -> first enabled profile (primary only)


def _view(target=None) -> TargetView:
    """TargetView for a key ("primary"/"secondary"), a config object, or None (primary)."""
    g = config_manager.config.gluetun
    if target is None or target == "primary":
        target = g
    elif target == "secondary":
        target = g.secondary
    if isinstance(target, TargetView):
        return target
    if isinstance(target, ControlTargetConfig):
        return TargetView(
            key="secondary", cfg=target, label=f"Gluetun control [{target.name}]",
            enabled=target.enabled and bool(target.control_server_host.strip()),
            allow_blocked=target.allow_blocked, rank_by=target.rank_by, top_n=target.top_n,
            ordered_names=True, dwell_s=target.min_dwell_minutes * 60.0, profile_fallback=False)
    return TargetView(
        key="primary", cfg=target, label="Gluetun control",
        enabled=target.force_update_enabled and target.force_update_mode != "DISABLED",
        allow_blocked=False, rank_by="score", top_n=4, ordered_names=False, dwell_s=0.0,
        profile_fallback=True)


class ProfileUnavailable(Exception):
    """The target names a profile that is not enabled (renamed, disabled or deleted)."""


def _control_profile(target):
    """Profile whose servers the target may use: the named one, else (primary only) the first
    enabled. Raises ProfileUnavailable when a named profile is not enabled: falling back to
    "no filter" would silently drop its thresholds and location limits."""
    v = _view(target)
    enabled = [p for p in config_manager.config.gluetun.profiles if p.enabled]
    name = v.cfg.control_profile
    if name:
        for p in enabled:
            if p.name == name:
                return p
        if not v.profile_fallback:
            raise ProfileUnavailable(f"profile '{name}' is not enabled")
    if not v.profile_fallback:
        return None
    return enabled[0] if enabled else None


def _control_candidates(target, servers) -> list:
    """[(server, ips)] the target may be moved to: the control profile's servers, or with no
    profile every scanned server that isn't disabled (the ranking applies the clean rule)."""
    v = _view(target)
    profile = _control_profile(v)
    if profile is not None:
        if v.allow_blocked and profile.require_clean:
            # A clean-only profile would hide every blocked server from a target that allows them
            profile = profile.model_copy(update={"require_clean": False})
        result = _filter_profile_servers(profile, servers)
        if v.allow_blocked:
            seedbox_off = {n.lower() for n in config_manager.config.performance.seedbox_disabled_servers}
            result = [(s, ips) for s, ips in result if s.server_name.lower() not in seedbox_off
                      and _gluetun_name(s).lower() not in seedbox_off]
        return result
    perf = config_manager.config.performance
    disabled = {n.lower() for n in perf.disabled_servers}
    if v.allow_blocked:
        disabled |= {n.lower() for n in perf.seedbox_disabled_servers}
    return [(s, []) for s in servers
            if s.server_name.lower() not in disabled and _gluetun_name(s).lower() not in disabled]


class _CtlState:
    """Per-target watchdog state: Gluetun needs time to reconnect after a push, and errors
    are logged once per outage."""
    def __init__(self):
        self.last_push_at = None     # any attempt (cooldown); monotonic() counts from boot
        self.last_switch_at = None   # last *successful* push (dwell), monotonic
        self.dwell_seeded = False    # secondary: last_switch_at taken from the companion once
        self.watchdog_error = None
        self.last_stay_logged = None  # watchdog logs "staying" once per server, not every minute


_ctl_state = {"primary": _CtlState(), "secondary": _CtlState()}
_ctl_locks: "weakref.WeakKeyDictionary" = weakref.WeakKeyDictionary()  # loop -> {key: Lock}

WATCHDOG_COOLDOWN_SECONDS = 180


def _target_lock(key: str) -> asyncio.Lock:
    """Serialises pushes per target (scan end, settings save, watchdog). Created per event loop."""
    locks = _ctl_locks.setdefault(asyncio.get_running_loop(), {})
    if key not in locks:
        locks[key] = asyncio.Lock()
    return locks[key]


def _target_key(cfg) -> str:
    return "secondary" if isinstance(cfg, ControlTargetConfig) else "primary"


def control_targets() -> list:
    """Enabled control targets as TargetViews."""
    return [v for v in (_view("primary"), _view("secondary")) if v.enabled]


def target_config(key: str):
    g = config_manager.config.gluetun
    return g.secondary if key == "secondary" else g


def _speed_key(s, by_upload: bool):
    st = s.speedtest_result or {}
    up, down = st.get("upload_mbps") or 0, st.get("download_mbps") or 0
    # Seeding: upload first. Ties on the score go to the better upload too.
    return (up, down) if by_upload else (s.speed_score, up)


def _rank(target, filtered) -> list:
    """Candidate servers in preference order for this target."""
    v = _view(target)
    # A target that allows listed servers ignores reputation entirely: "unknown" (e.g. a DroneBL
    # lookup failure) counts too. The primary (allow_blocked False) only ever gets clean servers.
    pool = [s for s, _ in filtered if s.is_clean or v.allow_blocked]
    if v.rank_by != "speed":
        # Primary: never a blocklisted server (pool is clean-only), whatever the profile allows
        return sorted(pool, key=lambda s: s.score or 0, reverse=True)
    # Untested and failed servers are never chosen by speed
    pool = [s for s in pool if getattr(s, "speed_score", None) is not None]
    # Baseline-relative scores and Ookla-only scores (no baseline, old DB rows) aren't
    # comparable: with a mix, rank by measured Mbps instead
    scales = {(s.speedtest_result or {}).get("deviation_score") is not None for s in pool}
    by_upload = len(scales) > 1
    return sorted(pool, key=lambda s: _speed_key(s, by_upload), reverse=True)


async def _servers_or_none():
    servers = await _get_servers_for_gluetun_generation()
    if not servers:
        logger.warning("Cannot generate Gluetun outputs: No scan results available yet.")
    return servers


async def push_target(target, servers=None) -> dict:
    """Push one target (e.g. after its settings changed) without touching the other."""
    v = _view(target)
    if not v.enabled:
        return {"applied": False, "reason": "control disabled"}
    servers = servers if servers is not None else await _servers_or_none()
    if not servers:
        return {"applied": False, "reason": "no scan results"}
    try:
        candidates = _control_candidates(v, servers)
    except ProfileUnavailable as e:
        logger.warning(f"{v.label}: {e}; not changing selection.")
        return {"applied": False, "reason": str(e)}
    return await update_gluetun_server_selection(candidates, target=v)


async def generate_gluetun_servers_json():
    """
    Generate a custom servers.json per enabled profile, then (optionally) point each enabled
    control target (local/remote Gluetun, or the companion) at its chosen servers via the API.
    """
    cfg = config_manager.config.gluetun
    active_profiles = [p for p in cfg.profiles if p.enabled]
    targets = control_targets()
    if not active_profiles and not targets:
        logger.debug("No active Gluetun profiles and control is off. Generation disabled.")
        return

    servers = await _servers_or_none()
    if not servers:
        return

    for profile in active_profiles:
        _write_servers_json(profile, _filter_profile_servers(profile, servers))

    for v in targets:
        try:
            await push_target(v, servers)
        except Exception as e:  # one unreachable target must not stop the other
            logger.error(f"{v.label}: update failed: {e}")


async def _seed_dwell_from_companion(v: TargetView, st: _CtlState) -> None:
    """After an AirBL restart the dwell would start from nothing: take the companion's own last
    switch time instead (once). Plain Gluetun has no such route; then the dwell starts at 0."""
    if st.dwell_seeded or st.last_switch_at is not None or not v.dwell_s:
        return
    extra = await get_companion_status(v.cfg)
    if extra is not None:
        st.dwell_seeded = True  # answered (with or without a switch time): don't ask again
    ts = (extra or {}).get("last_switch_at")
    if isinstance(ts, (int, float)) and 0 < ts <= time.time():
        st.last_switch_at = time.monotonic() - (time.time() - ts)


async def gluetun_watchdog_check(force: bool = False, target: str = "primary") -> dict:
    """
    Make sure the target is on a server its switch mode allows, between scans.

    Gluetun may reconnect on its own (restart, network drop) and pick any server from
    its list, so this re-applies the mode's targets when it drifted. It never pushes
    while a scan runs, while Gluetun is still connecting, or within the cooldown after a push.

    force (the Check Now button): ignore the cooldown, the dwell and (primary) the
    automatic-control switch.
    """
    v = _view(target)
    cfg = v.cfg
    st = _ctl_state[v.key]
    label = v.label.replace("control", "watchdog")
    if v.key == "secondary":
        if not v.enabled:
            return {"applied": False, "reason": "control disabled"}
    elif cfg.force_update_mode == "DISABLED" or not (cfg.force_update_enabled or force):
        return {"applied": False, "reason": "control disabled"}
    if state.is_scanning:
        return {"applied": False, "reason": "scan running"}  # the scan pushes when it finishes
    from .web.tasks import network_owner
    if network_owner():
        # A manual speedtest or baseline has the tunnel (and its DNS) up: names may not
        # resolve and the status would be misleading. Check again next time.
        return {"applied": False, "reason": f"VPN busy ({network_owner()})"}
    if not force and st.last_push_at is not None and time.monotonic() - st.last_push_at < WATCHDOG_COOLDOWN_SECONDS:
        return {"applied": False, "reason": "cooldown after a switch"}
    servers = await _get_servers_for_gluetun_generation()
    if not servers:
        return {"applied": False, "reason": "no scan results"}

    status = await get_gluetun_status(cfg)
    if status.get("error"):
        if status["error"] != st.watchdog_error:
            logger.warning(f"{label}: {status['error']}")
        st.watchdog_error = status["error"]
        return {"applied": False, "reason": status["error"]}
    if st.watchdog_error:
        logger.info(f"{label}: control server reachable again.")
        st.watchdog_error = None
    current = status.get("server_name") or status.get("ip") or (
        "one of " + ", ".join(status["selected_names"]) if status.get("selected_names") else None)
    if status.get("vpn_status") != "running" or not (status.get("ip") or status.get("selected_names")):
        return {"applied": False, "reason": "Gluetun not connected yet", "current": current}

    try:
        candidates = _control_candidates(v, servers)
    except ProfileUnavailable as e:
        return {"applied": False, "reason": str(e), "current": current}
    result = await update_gluetun_server_selection(candidates, status=status, quiet=True, target=v, force=force)
    return {**result, "current": current, "mode": cfg.force_update_mode}


async def watchdog_loop(key: str, ready=lambda: True, sleep=None) -> None:
    """Every watchdog_interval_seconds of this target, keep it on a server its mode allows.
    0 = off (the setting is re-read every minute); ready(): startup finished."""
    sleep = sleep or asyncio.sleep
    while True:
        cfg = target_config(key)
        interval = cfg.watchdog_interval_seconds
        await sleep(interval if interval > 0 else 60)
        if interval <= 0 or not ready() or (key == "secondary" and not _view(key).enabled):
            continue
        try:
            await gluetun_watchdog_check(target=key)
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception(f"Gluetun watchdog check failed ({key})")


def _judge_selection(v: "TargetView", mode: str, selected: list, targets: list, ranked: list,
                     st: "_CtlState", force: bool) -> Optional[str]:
    """Without a public IP, Gluetun's own server list decides: it's on one of those. Returns
    the reason to stay, or None to push a new list."""
    sel = {n.lower() for n in selected}
    if mode == "CLEAN_ONLY":
        servers = [_find_server_by_name(n) for n in sel]
        # Every server it may be on is known and not listed (a failed lookup is not a ban)
        if servers and all(s is not None and not s.is_blocked for s in servers):
            return "current server still clean"
        return None
    if sel <= {_gluetun_name(s).lower() for s in targets}:
        return "current server within target set"
    if (v.dwell_s and not force and st.last_switch_at is not None
            and sel <= {_gluetun_name(s).lower() for s in ranked}
            and v.dwell_s - (time.monotonic() - st.last_switch_at) > 0):
        return "minimum dwell"
    return None


def _is_current(s, current_ip, current_name) -> bool:
    return bool((current_ip and current_ip in _server_ips(s))
                or (current_name and current_name == _gluetun_name(s).lower()))


async def update_gluetun_server_selection(filtered, status: dict = None, quiet: bool = False,
                                          target=None, force: bool = False) -> dict:
    """
    Decide (per force_update_mode) whether the target should move, and if so push the
    target server names via PUT /v1/vpn/settings. Gluetun only reads servers.json at
    startup, so the API is the only way to change servers on a running instance.

    status: an already fetched Gluetun status (watchdog). quiet: log "staying" at debug
    level, and treat ALWAYS as "reset if outside the target set" so it doesn't push every minute.
    target: "primary"/"secondary", a config object or a TargetView (default primary).
    force: ignore the minimum dwell (Check Now).
    """
    v = _view(target)
    async with _target_lock(v.key):
        return await _update_selection(v, filtered, status, quiet, force)


async def _update_selection(v: TargetView, filtered, status, quiet, force) -> dict:
    cfg = v.cfg
    st = _ctl_state[v.key]
    label = v.label
    mode = cfg.force_update_mode

    def stay_log(msg):
        if quiet and msg == st.last_stay_logged:
            return
        st.last_stay_logged = msg
        (logger.debug if quiet else logger.info)(msg)

    ranked = _rank(v, filtered)
    if not ranked:
        what = ("servers with a speedtest" if v.rank_by == "speed"
                else "allowed servers" if v.allow_blocked else "clean servers")
        (logger.debug if quiet else logger.warning)(
            f"{label}: no {what} to choose from, not changing selection.")
        return {"applied": False, "reason": f"no {what} to choose from"}

    if mode == "NOT_BEST":
        targets = ranked[:1]
    elif mode in ("NOT_TOP4", "NOT_TOPN"):
        targets = ranked[:v.top_n]
    else:  # ALWAYS, ALLOWED, CLEAN_ONLY
        targets = ranked

    # The primary in ALWAYS mode pushes after every scan without asking; everything else
    # (and the secondary always: every switch drops its torrent peers) checks where it is first
    if mode != "ALWAYS" or quiet or v.key == "secondary":
        if status is None:
            status = await get_gluetun_status(cfg)
        if status.get("error"):
            logger.warning(f"{label}: {status['error']}; not changing selection.")
            return {"applied": False, "reason": status["error"]}
        current_ip = status.get("ip")
        # The status resolves the name via the scan or scan history; match on it too, since a
        # rebuilt scan keeps only one exit IP per server
        current_name = (status.get("server_name") or "").lower()
        if current_ip:
            in_targets = any(_is_current(s, current_ip, current_name) for s in targets)
            if mode == "CLEAN_ONLY":
                current = _find_server_by_ip(current_ip) or _find_server_by_name(current_name)
                # Stay unless there is evidence of a listing; a failed lookup is not a ban
                if in_targets or (current is not None and not current.is_blocked):
                    name = current.server_name if current is not None else status.get("server_name") or current_ip
                    stay_log(f"{label}: {name} is not listed, staying connected.")
                    return {"applied": False, "reason": "current server still clean"}
            elif in_targets:
                stay_log(f"{label}: current server is within target set ({mode}), staying connected.")
                return {"applied": False, "reason": "current server within target set"}
            if v.rank_by == "speed" and not force:
                # The current server has no speed result yet (scan still running, cancelled,
                # or results lost in a restart): unknown is not slower, so don't move away.
                # A failed test is evidence, though: then it may move.
                current = next((s for s, _ in filtered if _is_current(s, current_ip, current_name)), None)
                if (current is not None and getattr(current, "speed_score", None) is None
                        and not (current.speedtest_result or {}).get("error")
                        and (current.is_clean or v.allow_blocked)):
                    stay_log(f"{label}: {current.server_name} has no speed result yet; staying connected.")
                    return {"applied": False, "reason": "current server not re-tested yet"}
            if v.dwell_s and not force and any(_is_current(s, current_ip, current_name) for s in ranked):
                # Each switch drops every peer: while the current server is still an allowed
                # candidate, wait out the dwell before moving to a faster one
                await _seed_dwell_from_companion(v, st)
                if st.last_switch_at is not None:
                    left = v.dwell_s - (time.monotonic() - st.last_switch_at)
                    if left > 0:
                        stay_log(f"{label}: a faster server is available; staying for the minimum dwell "
                                 f"({left / 60:.0f} min left).")
                        return {"applied": False, "reason": "minimum dwell"}

        elif status.get("selected_names"):
            stay = _judge_selection(v, mode, status["selected_names"], targets, ranked, st, force)
            if stay:
                stay_log(f"{label}: Gluetun is on one of {', '.join(status['selected_names'])} "
                         f"(it doesn't report its public IP); {stay}.")
                return {"applied": False, "reason": stay}

    if v.ordered_names:
        names = list(dict.fromkeys(_gluetun_name(s) for s in targets))  # rank order = preference
    else:
        names = sorted({_gluetun_name(s) for s in targets})
    st.last_stay_logged = None
    if quiet:
        where = status.get("server_name") or status.get("ip") or (
            "one of " + ", ".join(status["selected_names"]) if status.get("selected_names") else "unknown")
        logger.info(f"{label.replace('control', 'watchdog')}: {where} doesn't fit {mode}; switching.")
    return await set_gluetun_server_names(cfg, names)


def _find_server_by_name(name: str):
    if not name or not state.current_scan or not state.current_scan.servers:
        return None
    for server in state.current_scan.servers:
        if _gluetun_name(server).lower() == name.lower():
            return server
    return None


def _find_server_by_ip(ip: str):
    if not state.current_scan or not state.current_scan.servers:
        return None
    for server in state.current_scan.servers:
        if ip in _server_ips(server):
            return server
    return None


def _base_url(cfg) -> str:
    host = cfg.control_server_host.strip()
    if host.startswith(("http://", "https://")):
        return host.rstrip("/")
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"  # bare IPv6
    return f"http://{host}:{cfg.control_server_port}"


def _headers(cfg) -> dict:
    return {"X-API-Key": cfg.api_key} if cfg.api_key else {}


def _http_error(resp) -> str:
    if resp.status_code == 401:
        return "Gluetun rejected the API key (401). Check the key and the role routes in Gluetun's auth config.toml."
    if resp.status_code == 403:
        return "Gluetun API key lacks access to this route (403). Add it to the role's routes."
    msg = f"Gluetun returned HTTP {resp.status_code}: {resp.text.strip()[:200]}"
    if resp.status_code == 400 and "server name" in resp.text and "no possible value" in resp.text:
        # Gluetun's stored list has servers without "server_name" (e.g. migrated from an old
        # AirBL servers.json), so it can't select by name. It never re-reads servers.json.
        msg += (" (Gluetun's AirVPN server list has no server names. Recreate the Gluetun container"
                " so it re-reads servers.json; if /gluetun is a persistent folder, delete"
                " servers/airvpn.json there first.)")
    elif resp.status_code == 400 and "server name" in resp.text and "is one of the choices" in resp.text:
        # Gluetun only knows the servers it loaded at startup; newly clean servers aren't among them.
        msg += (" (None of these servers were in Gluetun's list when it last started. Restart Gluetun so it"
                " loads AirBL's current servers.json, or let Gluetun use its full built-in AirVPN list.)")
    return msg


def _json_object(resp):
    """The response body as a dict, or None if it isn't a JSON object."""
    try:
        data = resp.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


async def get_gluetun_status(cfg) -> dict:
    """
    Get the current Gluetun public IP and, if it matches scanned data, the server.
    Gluetun reports the exit IP, so we match against exit IPs as well as entry IPs.
    """
    import httpx

    result = {"connected": False, "ip": None, "server_name": None, "country": None,
              "city": None, "vpn_status": None, "error": None, "selected_names": None, "note": None}
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=_headers(cfg)) as client:
            resp = await client.get(f"{_base_url(cfg)}/v1/vpn/status")
            if resp.status_code != 200:
                result["error"] = _http_error(resp)
                return result
            body = _json_object(resp)
            if body is None:
                result["error"] = f"Unexpected reply from {_base_url(cfg)}/v1/vpn/status (is this Gluetun's control server?)"
                return result
            result["vpn_status"] = body.get("status")

            resp = await client.get(f"{_base_url(cfg)}/v1/publicip/ip")
            if resp.status_code != 200:
                result["error"] = _http_error(resp)
                return result
            # Gluetun sends JSON without an application/json content-type.
            body = _json_object(resp)
            public_ip = body.get("public_ip") if body is not None else resp.text.strip()
            if not isinstance(public_ip, (str, type(None))):
                public_ip = None
            if not public_ip and result["vpn_status"] == "running":
                # Gluetun is connected but doesn't report its public IP (lookup off, or its IP
                # service rate-limited). It only ever connects to a server in its selection,
                # so that list still tells whether its server is acceptable.
                result["selected_names"] = await _gluetun_selected_names(client, cfg)
    except httpx.HTTPError as e:
        result["error"] = f"Could not reach Gluetun control server at {_base_url(cfg)}: {e.__class__.__name__}"
        return result

    if not public_ip:
        names = result["selected_names"]
        if names:
            result["connected"] = True
            if len(names) == 1:
                # One server in its list (AirBL pins it when there's no IP): that's where it is
                server = _find_server_by_name(names[0])
                result["server_name"] = names[0]
                result["country"] = server.country_code if server else state.servers_by_country.get(names[0])
                result["city"] = server.location if server else state.server_to_city_api.get(names[0])
                result["note"] = ("Gluetun doesn't report its public IP (check its PUBLICIP_* settings); "
                                  "it has only this server in its list")
            else:
                result["note"] = ("Gluetun doesn't report its public IP (check its PUBLICIP_* settings); "
                                  "AirBL judges its server list instead")
        return result  # VPN up but public IP not fetched yet

    result["connected"] = result["vpn_status"] == "running"
    result["ip"] = public_ip
    server = _find_server_by_ip(public_ip)
    if server is not None:
        result["server_name"] = _gluetun_name(server)
        result["country"] = server.country_code
        result["city"] = server.location
    elif state.db:
        # Not in the current scan (e.g. a disabled server): fall back to scan history
        try:
            name = await state.db.find_server_by_exit_ip(public_ip)
        except Exception as e:
            logger.debug(f"Gluetun status: exit IP history lookup failed: {e}")
            name = None
        if name:
            result["server_name"] = name.replace("AirVPN ", "").strip()
            result["country"] = state.servers_by_country.get(name) or state.servers_by_country.get(result["server_name"])
            result["city"] = state.server_to_city_api.get(name) or state.server_to_city_api.get(result["server_name"])
    return result


async def _gluetun_selected_names(client, cfg) -> Optional[list]:
    """Server names Gluetun may connect to (GET /v1/vpn/settings), or None if it selects by
    something else (countries, cities, ...) or the route isn't allowed for the key."""
    try:
        resp = await client.get(f"{_base_url(cfg)}/v1/vpn/settings")
    except Exception:
        return None
    body = _json_object(resp) if resp.status_code == 200 else None
    sel = ((body or {}).get("provider") or {}).get("server_selection") if body else None
    if not isinstance(sel, dict):
        return None
    names = sel.get("names")
    if not isinstance(names, list) or not names or not all(isinstance(n, str) for n in names):
        return None
    # Other filters would narrow the list further; then the names alone don't describe it
    if any(sel.get(k) for k in ("countries", "regions", "cities", "hostnames")):
        return None
    return [n.strip() for n in names if n.strip()][:50]


SWITCH_FOLLOW_UP_SECONDS = 45
_follow_ups: set = set()


def _follow_up_after_switch(cfg) -> None:
    """After a switch Gluetun reconnects and looks up its public IP again: check once a little
    later and log where it ended up (or that it still reports no IP)."""
    async def check():
        await asyncio.sleep(SWITCH_FOLLOW_UP_SECONDS)
        status = await get_gluetun_status(cfg)
        label = _view(cfg).label
        if status.get("error"):
            logger.info(f"{label}: after the switch: {status['error']}")
        elif status.get("ip"):
            where = status.get("server_name") or "a server not in the scan data"
            logger.info(f"{label}: after the switch Gluetun is on {where} (public IP {status['ip']}).")
        else:
            names = ", ".join(status.get("selected_names") or []) or "unknown"
            logger.info(f"{label}: after the switch Gluetun still doesn't report its public IP "
                        f"(on one of {names}); check its PUBLICIP_* settings.")
    try:
        task = asyncio.get_running_loop().create_task(check())
    except RuntimeError:
        return  # no running loop (sync caller)
    _follow_ups.add(task)
    task.add_done_callback(_follow_ups.discard)


async def set_gluetun_server_names(cfg, names: list) -> dict:
    """Restrict Gluetun to the given server names; Gluetun reconnects on change."""
    import httpx
    # The watchdog waits after any attempt, failed ones included; the dwell only after a success
    st = _ctl_state[_target_key(cfg)]
    st.last_push_at = time.monotonic()

    url = f"{_base_url(cfg)}/v1/vpn/settings"
    # Gluetun ANDs all filters, so names alone would still be limited by its own
    # SERVER_COUNTRIES/CITIES/... and a mismatch leaves no server (VPN stops).
    # Its settings override (gosettings.OverrideWithSlice) replaces any non-null list,
    # so sending [] clears those filters and the names alone decide.
    payload = {"provider": {"server_selection": {
        "names": names, "countries": [], "regions": [], "cities": [], "hostnames": [],
    }}}
    try:
        async with httpx.AsyncClient(timeout=15.0, headers=_headers(cfg)) as client:
            resp = await client.put(url, json=payload)
    except httpx.HTTPError as e:
        msg = f"Could not reach Gluetun control server at {_base_url(cfg)}: {e.__class__.__name__}"
        logger.error(msg)
        return {"applied": False, "reason": msg}

    if resp.status_code != 200:
        msg = _http_error(resp)
        logger.error(f"{_view(cfg).label}: server selection update failed: {msg}")
        return {"applied": False, "reason": msg}

    st.last_switch_at = time.monotonic()
    _follow_up_after_switch(cfg)
    logger.info(f"{_view(cfg).label}: server selection set to {len(names)} server(s): {', '.join(names)} ({resp.text.strip()})")
    return {"applied": True, "names": names, "outcome": resp.text.strip()}




async def get_companion_status(cfg) -> dict | None:
    """Extra status from the AirBL companion (GET /v1/companion/status), or None when the
    target is a plain Gluetun (no such route) or the call fails. Only known plain values are
    kept: the target is a remote host and its reply ends up in the browser."""
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5.0, headers=_headers(cfg)) as client:
            resp = await client.get(f"{_base_url(cfg)}/v1/companion/status")
    except httpx.HTTPError:
        return None
    if resp.status_code != 200:
        return None
    body = _json_object(resp)
    if body is None:
        return None
    out = {}
    for k in ("server", "entry_ip", "public_ip", "last_switch_result", "last_error", "version"):
        if isinstance(body.get(k), str):
            out[k] = body[k][:200]
    for k in ("handshake_age_s", "last_switch_at"):
        if isinstance(body.get(k), (int, float)) and not isinstance(body.get(k), bool):
            out[k] = body[k]
    if isinstance(body.get("tunnel_up"), bool):
        out["tunnel_up"] = body["tunnel_up"]
    q = body.get("qbit")
    if isinstance(q, dict):
        qo = {}
        if isinstance(q.get("connection_status"), str):
            qo["connection_status"] = q["connection_status"][:40]
        if isinstance(q.get("warnings"), list):
            qo["warnings"] = [str(w)[:200] for w in q["warnings"][:5]]
        for k in ("reannounce_pending", "start_pending"):
            if isinstance(q.get(k), int) and not isinstance(q.get(k), bool):
                qo[k] = q[k]
        out["qbit"] = qo
    return out
