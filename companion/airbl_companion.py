#!/usr/bin/env python3
"""
AirBL companion: a Gluetun-compatible control server for a WireGuard tunnel on macOS
(or Linux), so AirBL can steer a native seedbox (e.g. qBittorrent) onto the fastest
AirVPN server.

AirBL talks to it exactly like to Gluetun's control server:
  GET  /v1/vpn/status        {"status": "running" | "stopped"}
  GET  /v1/publicip/ip       {"public_ip": "..."}
  PUT  /v1/vpn/settings      {"provider": {"server_selection": {"names": [...]}}}
  PUT  /v1/vpn/status        {"status": "running" | "stopped"}
plus  GET /v1/companion/status and POST /v1/companion/switch (CLI, AirBL's status line).

Switching only changes the WireGuard peer's endpoint (all AirVPN servers share one
public key; the device key and tunnel address are per device), so the interface, its
address, routes and DNS stay up and qBittorrent keeps its listening socket. A full
wg-quick restart is the fallback. After a switch qBittorrent is told to reannounce,
and is restarted only if it stays unreachable.

Python 3.9+ standard library only (the macOS system python3 works). Needs wireguard-tools
(wg, wg-quick; Homebrew on macOS) and root. See README.md.
"""

import argparse
import copy
import hmac
import ipaddress
import json
import logging
import logging.handlers
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.cookiejar import CookieJar
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable, Dict, List, Optional, Tuple

VERSION = "1.2.1"
IS_DARWIN = sys.platform == "darwin"
AIRVPN_PUBKEY = "PyLCXAQT8KkM4T+dUsOQfn+Ub3pGxfGlxkIApuig+hk="

log = logging.getLogger("airbl-companion")

DEFAULT_CONFIG = {
    "api": {
        "listen": "0.0.0.0",
        "port": 8000,
        "api_key": "",
        "allow_from": [],          # source IPs allowed to call the API (empty = any); 127.0.0.1 always allowed
    },
    "wireguard": {
        "interface": "airbl",      # wg-quick interface name (macOS maps it to a utunN)
        "private_key": "",
        "preshared_key": "",
        "address": "",             # e.g. "10.150.1.2/32, fd7d:76ee:e68f:a993:1:2:3:4/128"
        "dns": "10.128.0.1",
        "server_public_key": AIRVPN_PUBKEY,
        "port": 1637,
        "entry": "ENTRY3",         # ENTRY1 | ENTRY3 (AirVPN's ip_v4_in1 / ip_v4_in3)
        "mtu": 1320,
        "keepalive": 15,
        "allowed_ips": "0.0.0.0/0, ::/0",
    },
    "airvpn_status_url": "https://airvpn.org/api/status/",
    "public_ip_url": "https://api.ipify.org",
    "state_dir": "/var/db/airbl-companion",
    "log_file": "/var/log/airbl-companion.log",
    "initial_servers": [],         # used at first start, before AirBL has sent anything
    "health": {
        "interval": 15,            # seconds between health checks
        "handshake_max_age": 180,  # older = tunnel considered dead
        "roam_timeout": 20,        # seconds to wait for a handshake after a switch
        "min_switch_interval": 600,  # AirBL requests sooner than this after a switch wait (unhealthy: never)
        "server_cooldown": 1800,   # a server that failed to connect is skipped this long
        "public_ip_interval": 600,
        "directory_refresh": 3600,
        "wake_grace": 45,          # after a wake / network change, let the tunnel re-handshake by itself
        "max_backoff": 600,        # when no server connects, retry after 30 s, 60 s, ... up to this
    },
    "qbittorrent": {
        "enabled": False,
        "url": "http://127.0.0.1:8080",
        "username": "",            # empty = "bypass authentication for clients on localhost"
        "password": "",
        "forwarded_port": 0,       # your AirVPN forwarded port (0 = don't check)
        "enforce_bind": False,     # set qBittorrent's bind address to the tunnel IP if it differs
        "pause_when_down": False,  # stop running torrents while the tunnel is down, resume after
        "verify_after": 600,       # seconds after a switch to check incoming connections
        "restart_if_unreachable": True,
        "app_path": "/Applications/qBittorrent.app",
        "process_name": "qbittorrent",
        "user": "",                # macOS user running qBittorrent (empty = console user)
        "restart_command": [],     # override, e.g. ["systemctl", "restart", "qbittorrent-nox"]
        # After a switch, trackers learn the new IP from a reannounce. qBittorrent's forced reannounce
        # ignores the tracker's minimum interval, so it is paced: small batches, few per tracker.
        "reannounce": {
            "batch_size": 8,           # torrents per batch
            "per_tracker": 2,          # at most this many from one tracker host per batch
            "interval": 20,            # seconds between batches
            "max_torrents": 200,       # most useful N only; the rest update at their normal announce (0 = all)
            "skip_idle_seeds": True,   # seeding with no leechers in the swarm: nobody is waiting
            "skip_if_qbit_does_it": True,  # tunnel restart + qBittorrent's own "reannounce when IP changed" on
            "resume_batch_size": 50,   # restarting torrents the companion stopped: per batch (same interval)
        },
    },
}


# --- config -----------------------------------------------------------------------------

def _merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _merge(out[k], v)
        else:
            out[k] = v
    return out


class ConfigError(ValueError):
    pass


def load_config(path: str) -> dict:
    with open(path) as f:
        cfg = _merge(DEFAULT_CONFIG, json.load(f))
    validate_config(cfg)
    return cfg


def validate_config(cfg: dict) -> None:
    wg = cfg["wireguard"]
    for key in ("private_key", "address"):
        if not wg.get(key):
            raise ConfigError(f"wireguard.{key} is required")
    if wg["entry"] not in ("ENTRY1", "ENTRY3"):
        raise ConfigError("wireguard.entry must be ENTRY1 or ENTRY3")
    if not str(wg["interface"]).replace("-", "").replace("_", "").isalnum() or len(wg["interface"]) > 15:
        raise ConfigError("wireguard.interface: letters, digits, - and _ only, at most 15 characters")
    if not cfg["api"].get("api_key"):
        raise ConfigError("api.api_key is required (AirBL sends it as X-API-Key)")
    if tunnel_ipv4(cfg) is None:
        raise ConfigError("wireguard.address needs an IPv4 address")
    for key in ("private_key", "preshared_key", "server_public_key"):
        if wg.get(key) and not _is_wg_key(wg[key]):
            raise ConfigError(f"wireguard.{key} is not a WireGuard key (44 characters of base64): "
                              "copy it from the AirVPN config generator")
    for entry in cfg["api"].get("allow_from") or []:
        try:
            ipaddress.ip_network(str(entry), strict=False)
        except ValueError:
            raise ConfigError(f"api.allow_from: {entry!r} is not an IP address or network (e.g. 192.168.1.0/24)")


def _is_wg_key(value: str) -> bool:
    import base64
    import binascii
    try:
        return len(value) == 44 and len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def source_allowed(src: str, allow: List[str]) -> bool:
    """Loopback always; otherwise the address must be in one of the allow_from entries
    (addresses or networks). IPv4-mapped IPv6 sources count as their IPv4 address."""
    try:
        ip = ipaddress.ip_address(src.split("%")[0])
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if ip.is_loopback or not allow:
        return True
    return any(ip in ipaddress.ip_network(str(a), strict=False) for a in allow)


def _has_ipv6_address(cfg: dict) -> bool:
    for part in str(cfg["wireguard"]["address"]).split(","):
        try:
            if ipaddress.ip_interface(part.strip()).version == 6:
                return True
        except ValueError:
            pass
    return False


def usable_dns(cfg: dict) -> str:
    """The configured DNS servers, minus IPv6 ones when the tunnel has no IPv6 address
    (IPv4-only setup): those would be unreachable and stall lookups."""
    servers = [d.strip() for d in str(cfg["wireguard"].get("dns") or "").split(",") if d.strip()]
    if not _has_ipv6_address(cfg):
        kept = []
        for d in servers:
            try:
                if ipaddress.ip_address(d).version == 6:
                    continue
            except ValueError:
                pass
            kept.append(d)
        servers = kept
    return ", ".join(servers)


def tunnel_ipv4(cfg: dict) -> Optional[str]:
    for part in str(cfg["wireguard"]["address"]).split(","):
        try:
            iface = ipaddress.ip_interface(part.strip())
        except ValueError:
            continue
        if iface.version == 4:
            return str(iface.ip)
    return None


# --- system commands --------------------------------------------------------------------

class Runner:
    """Runs commands; tests replace it. Never put secrets on a command line."""

    def run(self, cmd: List[str], timeout: float = 30) -> Tuple[int, str, str]:
        log.debug("run: %s", " ".join(cmd))
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError:
            return 127, "", f"{cmd[0]}: not found"
        except subprocess.TimeoutExpired:
            return 124, "", f"{cmd[0]}: timed out"
        except OSError as e:  # e.g. out of file descriptors: report, don't kill the worker
            return 126, "", f"{cmd[0]}: {e}"
        return p.returncode, p.stdout, p.stderr


class Tunnel:
    """The WireGuard interface, managed with wg / wg-quick (+ endpoint host routes on macOS)."""

    def __init__(self, cfg: dict, runner: Runner, darwin: bool = IS_DARWIN,
                 clock: Callable[[], float] = time.time):
        self.cfg = cfg
        self.clock = clock
        self.wg = cfg["wireguard"]
        self.runner = runner
        self.darwin = darwin
        self.name = self.wg["interface"]
        self.conf_path = os.path.join(cfg["state_dir"], f"{self.name}.conf")
        self.psk_path = os.path.join(cfg["state_dir"], "psk")
        self.routed: Dict[str, str] = {}  # endpoint ip -> gateway it is routed via (macOS)

    # Config file (rewritten on every switch, so a reboot / manual wg-quick up lands on the current server)
    def render(self, endpoint_ip: str, mask: bool = False) -> str:
        wg = self.wg
        key = "(hidden)" if mask else wg["private_key"]
        lines = ["[Interface]", f"PrivateKey = {key}", f"Address = {wg['address']}"]
        dns = usable_dns(self.cfg)
        if dns:
            lines.append(f"DNS = {dns}")
        if wg.get("mtu"):
            lines.append(f"MTU = {wg['mtu']}")
        lines += ["", "[Peer]", f"PublicKey = {wg['server_public_key']}"]
        if wg.get("preshared_key"):
            lines.append(f"PresharedKey = {'(hidden)' if mask else wg['preshared_key']}")
        lines += [f"Endpoint = {endpoint_ip}:{wg['port']}", f"AllowedIPs = {wg['allowed_ips']}"]
        if wg.get("keepalive"):
            lines.append(f"PersistentKeepalive = {wg['keepalive']}")
        return "\n".join(lines) + "\n"

    def write_conf(self, endpoint_ip: str) -> None:
        _write_private(self.conf_path, self.render(endpoint_ip))

    def real_iface(self) -> Optional[str]:
        """macOS: wg-quick records the utunN it got in /var/run/wireguard/<name>.name."""
        if not self.darwin:
            return self.name
        try:
            with open(f"/var/run/wireguard/{self.name}.name") as f:
                return f.read().strip() or None
        except OSError:
            return None

    def is_up(self) -> bool:
        iface = self.real_iface()
        if not iface:
            return False
        rc, _, _ = self.runner.run(["wg", "show", iface, "public-key"])
        return rc == 0

    def latest_handshake(self) -> Optional[int]:
        iface = self.real_iface()
        if not iface:
            return None
        rc, out, _ = self.runner.run(["wg", "show", iface, "latest-handshakes"])
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == self.wg["server_public_key"]:
                try:
                    return int(parts[1]) or None
                except ValueError:
                    return None
        return None

    def handshake_age(self) -> Optional[float]:
        ts = self.latest_handshake()
        return None if ts is None else max(0.0, self.clock() - ts)

    def endpoint(self) -> Optional[str]:
        iface = self.real_iface()
        if not iface:
            return None
        rc, out, _ = self.runner.run(["wg", "show", iface, "endpoints"])
        if rc != 0:
            return None
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0] == self.wg["server_public_key"] and parts[1] != "(none)":
                return parts[1].rsplit(":", 1)[0].strip("[]")
        return None

    def transfer(self) -> Tuple[int, int]:
        iface = self.real_iface()
        if not iface:
            return 0, 0
        rc, out, _ = self.runner.run(["wg", "show", iface, "transfer"])
        for line in out.splitlines() if rc == 0 else []:
            parts = line.split()
            if len(parts) == 3 and parts[0] == self.wg["server_public_key"]:
                return int(parts[1]), int(parts[2])
        return 0, 0

    def up(self, endpoint_ip: str) -> Tuple[bool, str]:
        self.write_conf(endpoint_ip)
        rc, out, err = self.runner.run(["wg-quick", "up", self.conf_path], timeout=60)
        if rc != 0:
            return False, (err or out).strip()[-300:]
        if self.darwin:
            self.routed[endpoint_ip] = self.default_gateway() or ""  # wg-quick added it
        return True, ""

    def down(self) -> Tuple[bool, str]:
        rc, out, err = self.runner.run(["wg-quick", "down", self.conf_path], timeout=60)
        self.routed.clear()
        return rc == 0, (err or out).strip()[-300:]

    def roam(self, endpoint_ip: str) -> Tuple[bool, str]:
        """Point the running interface at another server. Removing and re-adding the peer
        drops the old session, and the keepalive on the fresh peer starts a handshake at once."""
        iface = self.real_iface()
        if not iface:
            return False, "interface not up"
        old = self.endpoint()
        if self.darwin:
            ok, msg = self.route_endpoint(endpoint_ip)
            if not ok:
                return False, msg
        wg = self.wg
        pub = wg["server_public_key"]
        rc, out, err = self.runner.run(["wg", "set", iface, "peer", pub, "remove"])
        if rc != 0:
            return False, (err or out).strip()
        cmd = ["wg", "set", iface, "peer", pub, "endpoint", f"{endpoint_ip}:{wg['port']}",
               "allowed-ips", wg["allowed_ips"].replace(" ", "")]
        if wg.get("preshared_key"):
            _write_private(self.psk_path, wg["preshared_key"] + "\n")
            cmd += ["preshared-key", self.psk_path]
        if wg.get("keepalive"):
            cmd += ["persistent-keepalive", str(wg["keepalive"])]
        rc, out, err = self.runner.run(cmd)
        if rc != 0:
            return False, (err or out).strip()
        self.write_conf(endpoint_ip)
        if self.darwin and old and old != endpoint_ip:
            self.unroute_endpoint(old)
        return True, ""

    # macOS: the tunnel takes 0/1 + 128/1, so the endpoint needs a host route via the real gateway
    def default_gateway(self) -> Optional[str]:
        if self.darwin:
            rc, out, _ = self.runner.run(["route", "-n", "get", "default"])
            for line in out.splitlines() if rc == 0 else []:
                k, _, v = line.strip().partition(":")
                if k == "gateway":
                    return v.strip()
            return None
        rc, out, _ = self.runner.run(["ip", "route", "show", "default"])
        parts = out.split()
        return parts[parts.index("via") + 1] if rc == 0 and "via" in parts else None

    def route_endpoint(self, ip: str) -> Tuple[bool, str]:
        gw = self.default_gateway()
        if not gw:
            return False, "no default gateway (network down?)"
        self.runner.run(["route", "-q", "-n", "delete", "-inet", ip])
        rc, out, err = self.runner.run(["route", "-q", "-n", "add", "-inet", ip, "-gateway", gw])
        if rc != 0:
            return False, f"route add {ip} via {gw} failed: {(err or out).strip()}"
        self.routed[ip] = gw
        return True, ""

    def unroute_endpoint(self, ip: str) -> None:
        self.runner.run(["route", "-q", "-n", "delete", "-inet", ip])
        self.routed.pop(ip, None)

    def fix_routes_if_gateway_changed(self) -> bool:
        """Wi-Fi/Ethernet change or wake: re-point the endpoint route. True if it changed."""
        if not self.darwin:
            return False
        ep = self.endpoint()
        gw = self.default_gateway()
        if not ep or not gw or self.routed.get(ep) == gw:
            return False
        log.info("Default gateway is now %s; re-routing endpoint %s", gw, ep)
        self.route_endpoint(ep)
        return True

    def wireguard_app_connected(self) -> bool:
        """The WireGuard app (Network Extension) would fight over routes and DNS."""
        if not self.darwin:
            return False
        rc, out, _ = self.runner.run(["scutil", "--nc", "list"])
        return rc == 0 and any("(Connected)" in line and "com.wireguard" in line for line in out.splitlines())


def _write_private(path: str, content: str) -> None:
    d = os.path.dirname(path) or "."
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".tmp-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


# --- AirVPN server directory ----------------------------------------------------------------

def http_get(url: str, timeout: float = 15, headers: Optional[dict] = None) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "airbl-companion", **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


class Directory:
    """AirVPN server name -> entry IPs, from the public status API, cached on disk."""

    def __init__(self, cfg: dict, fetch: Callable[[str], bytes] = http_get):
        self.cfg = cfg
        self.fetch = fetch
        self.path = os.path.join(cfg["state_dir"], "servers.json")
        self.servers: Dict[str, dict] = {}
        self.loaded_at = 0.0
        self._lock = threading.Lock()

    def _parse(self, data: dict) -> Dict[str, dict]:
        out = {}
        for s in data.get("servers", []):
            if "server_best" in s or not s.get("public_name") or not s.get("ip_v4_in1"):
                continue
            out[s["public_name"].lower()] = {
                "name": s["public_name"], "ip_v4_in1": s.get("ip_v4_in1"), "ip_v4_in3": s.get("ip_v4_in3"),
                "country_code": (s.get("country_code") or "").upper(), "location": s.get("location"),
                "health": s.get("health"),
            }
        return out

    def refresh(self, force: bool = False) -> None:
        max_age = self.cfg["health"]["directory_refresh"]
        if not force and self.servers and time.time() - self.loaded_at < max_age:
            return
        try:
            data = json.loads(self.fetch(self.cfg["airvpn_status_url"]))
            servers = self._parse(data)
            if not servers:
                raise ValueError("no servers in the AirVPN status reply")
            with self._lock:
                self.servers, self.loaded_at = servers, time.time()
            _write_private(self.path, json.dumps(data))
            log.debug("AirVPN server list refreshed: %d servers", len(servers))
        except Exception as e:
            if not self.servers:
                self._load_disk()
            log.warning("AirVPN server list refresh failed (%s); using %s", e,
                        "the cached list" if self.servers else "nothing")
            self.loaded_at = time.time() - max_age + 300  # retry in 5 minutes

    def _load_disk(self) -> None:
        try:
            with open(self.path) as f:
                servers = self._parse(json.load(f))
            with self._lock:
                self.servers = servers
        except (OSError, ValueError):
            pass

    def lookup(self, name: str) -> Optional[dict]:
        with self._lock:
            return self.servers.get(str(name).replace("AirVPN ", "").strip().lower())

    def entry_ip(self, name: str) -> Optional[str]:
        s = self.lookup(name)
        if not s:
            return None
        if self.cfg["wireguard"]["entry"] == "ENTRY3":
            return s.get("ip_v4_in3") or s.get("ip_v4_in1")
        return s.get("ip_v4_in1")

    def name_for_ip(self, ip: str) -> Optional[str]:
        with self._lock:
            for s in self.servers.values():
                if ip in (s.get("ip_v4_in1"), s.get("ip_v4_in3")):
                    return s["name"]
        return None


# --- qBittorrent Web API ------------------------------------------------------------------

class QBitError(Exception):
    pass


class QBit:
    """Minimal qBittorrent Web API v2 client (cookie session, re-login on 403)."""

    def __init__(self, qcfg: dict, timeout: float = 10):
        self.cfg = qcfg
        self.base = qcfg["url"].rstrip("/")
        self.timeout = timeout
        self.jar = CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self._api = None

    def _call(self, method: str, path: str, data: Optional[dict] = None, retry: bool = True) -> bytes:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(self.base + path, data=body, method=method,
                                     headers={"Referer": self.base, "Origin": self.base})
        try:
            with self.opener.open(req, timeout=self.timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code in (401, 403) and retry and self.cfg.get("username"):
                self.login()
                return self._call(method, path, data, retry=False)
            if e.code == 404:
                self._api = None  # qBittorrent may have been upgraded (4.x pause -> 5.x stop)
            raise QBitError(f"qBittorrent {path}: HTTP {e.code}")
        except (urllib.error.URLError, OSError) as e:
            raise QBitError(f"qBittorrent not reachable at {self.base}: {getattr(e, 'reason', e)}")

    def login(self) -> None:
        out = self._call("POST", "/api/v2/auth/login",
                         {"username": self.cfg["username"], "password": self.cfg["password"]}, retry=False)
        if out.strip() != b"Ok.":
            raise QBitError("qBittorrent login failed (check username/password)")

    def _json(self, path: str):
        return json.loads(self._call("GET", path) or b"null")

    def api_version(self) -> Tuple[int, ...]:
        if self._api is None:
            raw = self._call("GET", "/api/v2/app/webapiVersion").decode().strip()
            self._api = tuple(int(x) for x in raw.split(".") if x.isdigit())
        return self._api

    def preferences(self) -> dict:
        return self._json("/api/v2/app/preferences")

    def set_preferences(self, prefs: dict) -> None:
        self._call("POST", "/api/v2/app/setPreferences", {"json": json.dumps(prefs)})

    def transfer_info(self) -> dict:
        return self._json("/api/v2/transfer/info")

    def torrents(self, filt: Optional[str] = None) -> list:
        q = "?filter=" + urllib.parse.quote(filt) if filt else ""
        return self._json("/api/v2/torrents/info" + q) or []

    def reannounce(self, hashes: List[str]) -> None:
        self._call("POST", "/api/v2/torrents/reannounce", {"hashes": "|".join(hashes)})

    def stop(self, hashes: List[str]) -> None:
        # qBittorrent 5 (Web API 2.11+) renamed pause/resume to stop/start
        path = "/api/v2/torrents/stop" if self.api_version() >= (2, 11) else "/api/v2/torrents/pause"
        self._call("POST", path, {"hashes": "|".join(hashes)})

    def start(self, hashes: List[str]) -> None:
        path = "/api/v2/torrents/start" if self.api_version() >= (2, 11) else "/api/v2/torrents/resume"
        self._call("POST", path, {"hashes": "|".join(hashes)})

    def running_hashes(self) -> List[str]:
        filt = "running" if self.api_version() >= (2, 11) else "resumed"
        return [t["hash"] for t in self.torrents(filt) if t.get("hash")]

    def shutdown(self) -> None:
        self._call("POST", "/api/v2/app/shutdown")

    def rebind(self, port: int, sleep: Callable[[float], None] = time.sleep) -> None:
        """Make libtorrent listen again (after the interface was recreated) by moving the
        listen port away and back."""
        self.set_preferences({"listen_port": port + 1 if port < 65535 else port - 1})
        sleep(2)
        self.set_preferences({"listen_port": port})


QBIT_SELF_REANNOUNCE = "'Reannounce to all trackers when IP or port changed'"
_SKIP_PREFIXES = ("stopped", "paused", "queued", "checking")
_SKIP_STATES = {"moving", "error", "missingFiles", "metaDL", "allocating", "unknown"}
_DOWNLOADING = {"downloading", "stalledDL", "forcedDL"}


def _tracker_host(t: dict) -> str:
    return urllib.parse.urlparse(t.get("tracker") or "").hostname or ""


def reannounce_order(torrents: list, rcfg: dict) -> List[Tuple[str, str]]:
    """[(hash, tracker host)] worth a forced reannounce, most useful first: downloads, then seeds
    by leechers waiting, then idle seeds (unless skipped), then torrents without a working tracker.
    Stopped, queued, checking and broken torrents are skipped (a start announces anyway)."""
    rows = []
    for t in torrents:
        h, st = t.get("hash"), t.get("state") or ""
        if not h or st in _SKIP_STATES or st.startswith(_SKIP_PREFIXES):
            continue
        host = _tracker_host(t)
        leech = int(t.get("num_incomplete") or 0)
        if not host:
            group = 3
        elif st in _DOWNLOADING:
            group = 0
        elif leech > 0:
            group = 1
        elif rcfg.get("skip_idle_seeds", True):
            continue
        else:
            group = 2
        rows.append((group, -leech, h, host))
    rows.sort(key=lambda r: (r[0], r[1]))
    if rcfg.get("max_torrents"):
        rows = rows[:rcfg["max_torrents"]]
    return [(h, host) for _, _, h, host in rows]


def resume_order(torrents: list, hashes: List[str]) -> List[Tuple[str, str]]:
    """The companion's own paused hashes, busiest swarms first (starting a torrent announces it)."""
    info = {t.get("hash"): t for t in torrents}
    ordered = sorted(hashes, key=lambda h: -int((info.get(h) or {}).get("num_incomplete") or 0))
    return [(h, _tracker_host(info.get(h) or {})) for h in ordered]


def take_batch(queue: List[Tuple[str, str]], batch_size: int, per_tracker: int) -> Tuple[List[str], list]:
    """Next batch in queue order, at most per_tracker per tracker host; the rest keep their order."""
    batch, rest, per_host = [], [], {}
    for h, host in queue:
        if len(batch) < batch_size and per_host.get(host, 0) < per_tracker:
            batch.append(h)
            per_host[host] = per_host.get(host, 0) + 1
        else:
            rest.append((h, host))
    return batch, rest


def qbit_preflight(cfg: dict, qbit: "QBit", apply: bool = True) -> List[str]:
    """Check (and with enforce_bind fix) the qBittorrent settings the setup relies on.
    apply=False (the `check` command): report only, never change qBittorrent. Fixing the bind
    address while another tunnel (e.g. the WireGuard app) is still in use would cut it off."""
    qcfg = cfg["qbittorrent"]
    warnings = []
    try:
        prefs = qbit.preferences()
    except QBitError as e:
        return [str(e)]
    tip = tunnel_ipv4(cfg)
    bound = prefs.get("current_interface_address") or ""
    if bound != tip:
        if qcfg.get("enforce_bind") and apply:
            try:
                qbit.set_preferences({"current_interface_address": tip})
                log.info("qBittorrent: bind address set to the tunnel IP %s", tip)
            except QBitError as e:
                warnings.append(f"could not set the bind address: {e}")
        else:
            fix = (" (the companion sets it when it starts, enforce_bind is on)" if qcfg.get("enforce_bind")
                   else ": torrents can leak outside the VPN when it is down")
            warnings.append(f"qBittorrent is bound to {bound or 'all addresses'}, not the tunnel IP {tip}{fix}")
    fport = qcfg.get("forwarded_port")
    if fport and prefs.get("listen_port") != fport:
        warnings.append(f"qBittorrent listens on {prefs.get('listen_port')}, not the AirVPN forwarded port {fport}")
    if prefs.get("upnp"):
        warnings.append("UPnP/NAT-PMP is on; it does nothing over AirVPN, turn it off")
    if prefs.get("reannounce_when_address_changed"):
        warnings.append(QBIT_SELF_REANNOUNCE + " is on: qBittorrent then "
                        "reannounces every torrent at once; turn it off and let the companion pace it")
    for w in warnings:
        log.warning("qBittorrent check: %s", w)
    return warnings


# --- the companion ------------------------------------------------------------------------

class Companion:
    def __init__(self, cfg: dict, runner: Optional[Runner] = None, fetch: Callable = http_get,
                 qbit: Optional[QBit] = None, darwin: bool = IS_DARWIN, clock: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep, monotonic: Callable[[], float] = time.monotonic):
        self.cfg = cfg
        self.h = cfg["health"]
        self.runner = runner or Runner()
        self.tunnel = Tunnel(cfg, self.runner, darwin=darwin, clock=clock)
        self.directory = Directory(cfg, fetch)
        self.fetch = fetch
        self.qcfg = cfg["qbittorrent"]
        self.qbit = qbit or (QBit(self.qcfg) if self.qcfg.get("enabled") else None)
        self.darwin = darwin
        self.clock = clock
        self.sleep = sleep
        self.monotonic = monotonic
        self.lock = threading.RLock()  # guards self.state, self.pending, self.jobs
        self.wake = threading.Event()
        self.stop_event = threading.Event()
        self.state_path = os.path.join(cfg["state_dir"], "state.json")
        self.state = {
            "desired": "running", "current": None, "entry_ip": None, "last_good": None,
            "last_list": [], "cooldowns": {}, "paused_hashes": [], "last_switch_at": 0.0,
            "last_switch_result": None,
        }
        self.pending: Optional[dict] = None   # {"names": [...], "force": bool, "reason": str}
        self.public_ip: Optional[str] = None
        self.public_ip_at = 0.0
        self.healthy = False
        self.last_error: Optional[str] = None
        self.qbit_status: dict = {}
        self.qbit_verify: Optional[dict] = None
        self.qbit_preflight_at = 0.0
        self.qbit_self_reannounce = False      # qBittorrent's own reannounce-on-address-change is on
        self.jobs: Dict[str, dict] = {}        # paced qBittorrent work: "reannounce", "start"
        self.last_tick_wall = None
        self.last_tick_mono = None
        self.switching = False       # a switch/recovery is in progress (status is not "running")
        self.ever_healthy = False    # the tunnel has been up since this start (pause only after that)
        self.resume_fast = False     # `resume` asked before a resume job existed
        self.grace_until = 0.0       # after a wake / network change: don't recover before this
        self.next_recover_at = 0.0   # backoff when no server connects
        self.backoff = 0.0
        self._load_state()

    # -- persistence
    def _load_state(self) -> None:
        try:
            with open(self.state_path) as f:
                saved = json.load(f)
            if isinstance(saved, dict):
                self.state.update({k: v for k, v in saved.items() if k in self.state})
        except (OSError, ValueError):
            pass

    def _save_state(self) -> None:
        with self.lock:
            data = json.dumps(self.state, indent=1)
        try:
            _write_private(self.state_path, data)
        except OSError as e:
            log.warning("Could not save state: %s", e)

    def _error(self, msg: Optional[str]) -> None:
        if msg and msg != self.last_error:
            log.warning(msg)
        self.last_error = msg

    # -- API side (any thread)
    def request_switch(self, names: List[str], force: bool = False, reason: str = "AirBL") -> Tuple[int, str]:
        """Gluetun-like reply for PUT /v1/vpn/settings."""
        self.directory.refresh()
        clean = [str(n).replace("AirVPN ", "").strip() for n in names if str(n).strip()]
        # AirVPN's spelling, deduplicated (names are compared and stored case-sensitively)
        known = list(dict.fromkeys(self.directory.lookup(n)["name"] for n in clean if self.directory.lookup(n)))
        unknown = [n for n in clean if not self.directory.lookup(n)]
        if not known:
            return 400, (f"unknown server(s): {', '.join(unknown) or '(none)'} "
                         "(not in the AirVPN server list the companion has)")
        if unknown:
            log.info("Ignoring unknown server name(s): %s", ", ".join(unknown))
        with self.lock:
            self.state["last_list"] = known
            current = (self.state.get("current") or "").lower()
            if not force and current in {n.lower() for n in known} and self.healthy and not self.switching:
                self.pending = None
                self._save_state()
                return 200, "settings left unchanged"
            self.pending = {"names": known, "force": force, "reason": reason}
            self._save_state()
        self.wake.set()
        return 200, "settings updated"

    def request_desired(self, desired: str) -> None:
        with self.lock:
            self.state["desired"] = desired
            self._save_state()
        self.wake.set()

    def status(self) -> dict:
        with self.lock:
            st = json.loads(json.dumps(self.state))  # deep copy: the worker keeps changing it
            pending = list(self.pending["names"]) if self.pending else None
            jobs = {k: len(j["queue"]) for k, j in self.jobs.items()}
        age = self.tunnel.handshake_age() if self.tunnel.real_iface() else None
        rx, tx = self.tunnel.transfer()
        return {
            "version": VERSION,
            "desired": st["desired"],
            "tunnel_up": self.healthy,
            "server": st["current"],
            "entry_ip": st["entry_ip"],
            "public_ip": self.public_ip,
            "handshake_age_s": round(age, 1) if age is not None else None,
            "rx_bytes": rx, "tx_bytes": tx,
            "last_switch_at": st["last_switch_at"] or None,
            "last_switch_result": st["last_switch_result"],
            "pending": pending,
            "last_list": st["last_list"],
            "cooldowns": {k: round(v - self.clock()) for k, v in st["cooldowns"].items() if v > self.clock()},
            "qbit": ({**self.qbit_status, **{f"{k}_pending": n for k, n in jobs.items()}} if self.qbit else None),
            "last_error": self.last_error,
        }

    def vpn_status(self) -> str:
        return ("running" if self.healthy and not self.switching and self.state["desired"] == "running"
                else "stopped")

    # -- worker thread
    def run_forever(self) -> None:
        log.info("airbl-companion %s started (interface %s)", VERSION, self.tunnel.name)
        self.startup()
        while not self.stop_event.is_set():
            try:
                self.tick()
            except Exception:
                log.exception("Health check failed")
            self.wake.wait(self._next_wait())
            self.wake.clear()

    def _next_wait(self) -> float:
        """Sleep until the next health check or the next paced qBittorrent batch, whichever is first."""
        wait = float(self.h["interval"])
        for job in self.jobs.values():
            wait = min(wait, max(0.5, job["next_at"] - self.clock()))
        return wait

    def startup(self) -> None:
        self.directory.refresh(force=True)
        if self.tunnel.is_up():
            ep = self.tunnel.endpoint()
            name = self.directory.name_for_ip(ep) if ep else None
            log.info("Adopting the running interface (endpoint %s%s)", ep, f" = {name}" if name else "")
            with self.lock:
                if name:
                    self.state["current"], self.state["entry_ip"] = name, ep
            age = self.tunnel.handshake_age()
            self.healthy = age is not None and age < self.h["handshake_max_age"]
            self.ever_healthy = self.healthy
            if self.darwin and ep:
                self.tunnel.routed[ep] = self.tunnel.default_gateway() or ""

    def tick(self) -> None:
        now = self.clock()
        mono = self.monotonic()
        if self.last_tick_wall is not None:
            # Wall clock jumped much further than the monotonic one: the Mac slept. Give the
            # tunnel time to re-handshake by itself (Wi-Fi may not even be back yet).
            if (now - self.last_tick_wall) - (mono - self.last_tick_mono) > 60:
                log.info("Wake from sleep detected; giving the tunnel %d s to reconnect", self.h["wake_grace"])
                self.grace_until = now + self.h["wake_grace"]
        self.last_tick_wall, self.last_tick_mono = now, mono

        self.directory.refresh()
        if self.state["desired"] == "stopped":
            if self.tunnel.is_up():
                log.info("Stopping the tunnel (requested)")
                self._qbit_pause()
                self.tunnel.down()
            self.healthy = False
            return
        if self.tunnel.wireguard_app_connected():
            self.healthy = False
            self._error("The WireGuard app has a tunnel connected; disconnect it (the companion manages the tunnel)")
            return
        if not self.tunnel.default_gateway():
            # No network outside the tunnel: no server can work, so none is blamed (no
            # cooldowns) and nothing is retried until it's back
            self.healthy = False
            self._error("No network (no default gateway); waiting for it to come back")
            self.grace_until = max(self.grace_until, now + self.h["wake_grace"])
            self.qbit_tick()
            return

        with self.lock:
            pending = self.pending
        if pending:
            wait = self.h["min_switch_interval"] - (now - (self.state["last_switch_at"] or 0))
            if pending["force"] or not self.healthy or wait <= 0:
                with self.lock:
                    if self.pending is pending:
                        self.pending = None
                self.switch(pending["names"], reason=pending["reason"])
            elif not pending.get("logged"):
                pending["logged"] = True
                log.info("Switch to %s deferred %.0f s (minimum time between switches)",
                         ", ".join(pending["names"]), wait)

        if not self.tunnel.is_up():
            self.healthy = False
            self._qbit_pause()
            self.recover("tunnel is down")
        else:
            if self.tunnel.fix_routes_if_gateway_changed():
                self.grace_until = max(self.grace_until, now + self.h["wake_grace"])
            age = self.tunnel.handshake_age()
            if age is None or age > self.h["handshake_max_age"]:
                self.healthy = False
                if now < self.grace_until:
                    log.debug("Handshake stale; within the reconnect grace period")
                else:
                    self._qbit_pause()
                    self.recover(f"no handshake for {'ever' if age is None else f'{age:.0f} s'}")
            elif not self.healthy:
                self.healthy = True
                self.ever_healthy = True
                self._error(None)
                self._qbit_resume()

        if self.healthy and now - self.public_ip_at > self.h["public_ip_interval"]:
            self.refresh_public_ip()
        if self.healthy and self.state.get("paused_hashes") and "start" not in self.jobs:
            self._qbit_resume()  # e.g. held from before a companion restart
        self.qbit_tick()

    # -- switching
    def _cooling(self, name: str) -> bool:
        return self.state["cooldowns"].get(name, 0) > self.clock()

    def _cool(self, name: str) -> None:
        with self.lock:
            self.state["cooldowns"][name] = self.clock() + self.h["server_cooldown"]

    def switch(self, names: List[str], reason: Optional[str] = "") -> bool:
        """Connect to the first name that works; fall back to the last good server.
        reason None: label by outcome (recovered / failover / start)."""
        pre_qbit = self._qbit_connection_status()
        prev = self.state.get("current")
        candidates = [n for n in names if not self._cooling(n)] or list(names)
        fallback = self.state.get("last_good")
        self.switching = True
        try:
            name, how = self._connect_any(candidates)
            if not name and fallback and fallback not in candidates:
                name, how = self._connect_any([fallback])
        finally:
            self.switching = False
        if name:
            if reason is None:
                reason = "recovered" if name == prev else ("failover" if prev else "start")
            elif name == fallback and name not in names:
                log.warning("No requested server connected; went back to %s", name)
                reason = "fallback"
            self._after_switch(name, how, reason, pre_qbit)
            return name in names
        self.healthy = False
        with self.lock:
            self.state["last_switch_result"] = f"failed: none of {', '.join(names)} connected"
        self._error(f"Switch failed: none of {', '.join(names)} connected" + (f" (was {prev})" if prev else ""))
        self._save_state()
        return False

    def _connect_any(self, names: List[str]) -> Tuple[Optional[str], str]:
        """In-place switches first, for every candidate: a dead first choice must not tear
        down a working interface. Only if none of them answers, restart the tunnel per
        candidate. A server that fails both ways cools down."""
        ips = {}
        for name in names:
            ips[name] = self.directory.entry_ip(name)
            if not ips[name]:
                log.warning("%s: no entry IP known", name)
        if self.tunnel.is_up():
            failed = []
            for name in names:
                if ips[name] and self._roam_to(name, ips[name]):
                    for f in failed:  # the network works (this one answered): those are dead
                        self._cool(f)
                    return name, "roam"
                failed.append(name)
        for name in names:
            if ips[name] and self._restart_to(name, ips[name]):
                return name, "restart"
            self._cool(name)
        return None, ""

    def _roam_to(self, name: str, ip: str) -> bool:
        start = int(self.clock())
        ok, msg = self.tunnel.roam(ip)
        if ok and self._wait_handshake(start):
            log.info("Switched to %s (%s) in place", name, ip)
            return True
        log.info("%s: in-place switch failed (%s)", name, msg or "no handshake")
        return False

    def _restart_to(self, name: str, ip: str) -> bool:
        self.tunnel.down()
        start = int(self.clock())
        ok, msg = self.tunnel.up(ip)
        if ok and self._wait_handshake(start):
            log.info("Connected to %s (%s) with a tunnel restart", name, ip)
            return True
        log.warning("%s: tunnel restart failed (%s)", name, msg or "no handshake")
        return False

    def _wait_handshake(self, since: int) -> bool:
        # Bounded by attempts, not the clock: a clock jump can't stall or skip the wait
        for attempt in range(int(self.h["roam_timeout"]) + 1):
            ts = self.tunnel.latest_handshake()
            if ts is not None and ts >= since - 1:
                return True
            if attempt < int(self.h["roam_timeout"]):
                self.sleep(1)
        return False

    def _after_switch(self, name: str, how: str, reason: str, pre_qbit: Optional[str]) -> None:
        now = self.clock()
        with self.lock:
            self.state.update({
                "current": name, "entry_ip": self.directory.entry_ip(name), "last_good": name,
                "last_switch_at": now,
                "last_switch_result": f"ok: {name} ({'in place' if how == 'roam' else 'tunnel restart'})"
                + (f", {reason}" if reason else ""),
            })
            self.state["cooldowns"].pop(name, None)
            self._save_state()
        self.healthy = True
        self.ever_healthy = True
        self.backoff, self.next_recover_at = 0.0, 0.0
        self._error(None)
        self.refresh_public_ip()
        self._qbit_after_switch(how, pre_qbit)
        self._qbit_resume()

    def recover(self, why: str) -> None:
        """Tunnel dead: the current server (in place, then a restart), then the names AirBL
        sent, then the initial servers. When nothing connects, retry with a growing backoff."""
        now = self.clock()
        if now < self.next_recover_at:
            return
        current = self.state.get("current")
        log.warning("Tunnel unhealthy (%s); recovering", why)
        order = ([current] if current else []) + [n for n in self.state.get("last_list", []) if n != current]
        order += [n for n in self.cfg.get("initial_servers", []) if n not in order]
        if not order:
            self._error("Tunnel down and no server known yet: waiting for AirBL to send one")
            return
        self.switch(order, reason=None)
        if not self.healthy:
            self.backoff = min(self.h["max_backoff"], max(30.0, self.backoff * 2))
            self.next_recover_at = self.clock() + self.backoff
            log.warning("No server connected; next attempt in %.0f s", self.backoff)

    def refresh_public_ip(self) -> None:
        self.public_ip_at = self.clock()
        try:
            ip = self.fetch(self.cfg["public_ip_url"]).decode().strip()
            ipaddress.ip_address(ip)
            if ip != self.public_ip:
                log.info("Public IP: %s", ip)
            self.public_ip = ip
        except Exception as e:
            log.info("Public IP check failed: %s", e)
            self.public_ip = None

    # -- qBittorrent
    def _qbit_connection_status(self) -> Optional[str]:
        if not self.qbit:
            return None
        try:
            return self.qbit.transfer_info().get("connection_status")
        except QBitError:
            return None

    def _qbit_after_switch(self, how: str, pre: Optional[str]) -> None:
        """Trackers still hand out the old IP: reannounce, paced. libtorrent reopens its listen
        socket on the bind IP by itself after a tunnel restart; a rebind is only an escalation."""
        if not self.qbit:
            return
        rcfg = self.qcfg["reannounce"]
        if how == "restart" and rcfg.get("skip_if_qbit_does_it") and self.qbit_self_reannounce:
            log.info("qBittorrent reannounces by itself after the tunnel restart; not queueing another wave")
        else:
            self._start_reannounce()
        self.qbit_verify = {"due": self.clock() + self.qcfg["verify_after"], "pre": pre, "stage": 0}

    def _start_reannounce(self) -> None:
        rcfg = self.qcfg["reannounce"]
        try:
            queue = reannounce_order(self.qbit.torrents(), rcfg)
        except QBitError as e:
            log.warning("qBittorrent reannounce: %s", e)
            return
        if not queue:
            self.jobs.pop("reannounce", None)
            return
        batches = -(-len(queue) // max(1, rcfg["batch_size"]))
        log.info("qBittorrent: reannouncing %d torrents in about %d batches (~%.0f min)", len(queue), batches,
                 (batches - 1) * rcfg["interval"] / 60)
        # A new switch replaces a running wave: every torrent needs the newest IP
        self.jobs["reannounce"] = {"queue": queue, "done": 0, "next_at": self.clock()}

    def run_jobs(self) -> None:
        """Send due batches (only while the tunnel is healthy)."""
        if not (self.qbit and self.healthy):
            return
        rcfg = self.qcfg["reannounce"]
        now = self.clock()
        for name in list(self.jobs):
            job = self.jobs[name]
            if now < job["next_at"]:
                continue
            if name == "start":  # only hashes the companion itself still holds stopped
                held = set(self.state.get("paused_hashes") or [])
                job["queue"] = [q for q in job["queue"] if q[0] in held]
            before = job["queue"]
            if name == "start":
                # Starting a torrent is a normal announce (what qBittorrent does for every torrent
                # at its own startup), not a forced one: only the batch size paces it
                size = 200 if job.get("fast") else rcfg.get("resume_batch_size", 50)
                per = size
            else:
                size, per = rcfg["batch_size"], rcfg["per_tracker"]
            batch, job["queue"] = take_batch(before, size, per)
            try:
                if batch:
                    if name == "reannounce":
                        self.qbit.reannounce(batch)
                    else:
                        self.qbit.start(batch)
                        self.state["paused_hashes"] = [h for h in self.state["paused_hashes"] if h not in batch]
                        self._save_state()
                    job["done"] += len(batch)
            except QBitError as e:
                log.warning("qBittorrent %s batch: %s", name, e)
                job["queue"] = [q for q in before if q[0] in set(batch)] + job["queue"]  # retry next time
            job["next_at"] = now + (2 if job.get("fast") else rcfg["interval"])
            if not job["queue"]:
                log.info("qBittorrent: %s done (%d torrents)", "reannounce" if name == "reannounce" else "resume",
                         job["done"])
                del self.jobs[name]

    def qbit_tick(self) -> None:
        if not self.qbit:
            return
        now = self.clock()
        if now - self.qbit_preflight_at > 3600:
            self.qbit_preflight_at = now
            self.qbit_preflight()
        try:
            self.qbit_status["connection_status"] = self.qbit.transfer_info().get("connection_status")
            self.qbit_status.pop("error", None)
        except QBitError as e:
            self.qbit_status["connection_status"] = None
            self.qbit_status["error"] = str(e)
        self.run_jobs()
        v = self.qbit_verify
        if not v or now < v["due"] or not self.healthy:
            return
        status = self.qbit_status.get("connection_status")
        if status == "connected":
            log.info("qBittorrent: incoming connections OK after the switch")
            self.qbit_verify = None
            return
        # "firewalled" only means no incoming connection yet: act on it only if it was
        # connected before the switch, or qBittorrent is fully disconnected
        bad = status == "disconnected" or status is None or v["pre"] == "connected"
        if bad and v["stage"] == 0:
            # Cheapest fix first: make libtorrent listen again (moves the port away and back)
            log.warning("qBittorrent still %s %d s after the switch; re-binding its listen port",
                        status, self.qcfg["verify_after"])
            v["stage"], v["due"] = 1, now + self.qcfg["verify_after"]
            try:
                port = self.qcfg.get("forwarded_port") or self.qbit.preferences().get("listen_port")
                if port:
                    self.qbit.rebind(int(port), sleep=self.sleep)
            except QBitError as e:
                log.warning("qBittorrent rebind: %s", e)
            return
        if bad and v["stage"] == 1 and self.qcfg.get("restart_if_unreachable"):
            log.warning("qBittorrent still %s after the rebind; restarting it", status)
            v["stage"], v["due"] = 2, now + self.qcfg["verify_after"]
            self.restart_qbit()
            return
        if bad:
            log.warning("qBittorrent is %s after the switch (rebind%s already tried)", status,
                        " and restart" if v["stage"] >= 2 else "")
        self.qbit_verify = None

    def qbit_preflight(self) -> List[str]:
        warnings = qbit_preflight(self.cfg, self.qbit)
        self.qbit_status["warnings"] = warnings
        self.qbit_self_reannounce = any(w.startswith(QBIT_SELF_REANNOUNCE) for w in warnings)
        return warnings

    def _qbit_pause(self) -> None:
        # Not before the tunnel has been up once since this start: at startup qBittorrent (bound
        # to the tunnel IP) can't leak anyway, and stopping everything there is only disruptive
        if not (self.qbit and self.qcfg.get("pause_when_down") and self.ever_healthy):
            return
        self.jobs.pop("start", None)  # stop resuming; the paused list is the source of truth
        try:
            held = set(self.state.get("paused_hashes") or [])
            new = [h for h in self.qbit.running_hashes() if h not in held]
            if new:
                self.qbit.stop(new)
                self.state["paused_hashes"] = list(held) + new
                self._save_state()
                log.info("qBittorrent: stopped %d running torrents while the tunnel is down", len(new))
        except QBitError as e:
            log.warning("qBittorrent pause: %s", e)

    def _qbit_resume(self) -> None:
        """Start the companion's own stopped torrents again, paced like the reannounce
        (each start announces). Torrents you stopped yourself stay stopped."""
        hashes = self.state.get("paused_hashes") or []
        if not (self.qbit and hashes) or "start" in self.jobs:
            return
        try:
            torrents = self.qbit.torrents()
        except QBitError:
            torrents = []
        self.jobs["start"] = {"queue": resume_order(torrents, hashes), "done": 0, "next_at": self.clock(),
                              "fast": getattr(self, "resume_fast", False)}
        self.resume_fast = False
        log.info("qBittorrent: resuming %d torrents in batches", len(hashes))

    def request_resume_now(self) -> int:
        """`airbl-companion resume`: restart every torrent the companion holds stopped, fast
        (200 per batch, every 2 s). Returns how many are held."""
        with self.lock:
            n = len(self.state.get("paused_hashes") or [])
            job = self.jobs.get("start")
            if job is not None:
                job["fast"] = True
                job["next_at"] = 0.0
            else:
                self.resume_fast = True
        self.wake.set()
        return n

    def restart_qbit(self) -> None:
        """Quit and relaunch qBittorrent. Its own startup announces every torrent, so no
        reannounce follows."""
        cmd = self.qcfg.get("restart_command")
        if cmd:
            rc, out, err = self.runner.run(list(cmd), timeout=120)
            if rc != 0:
                log.warning("qBittorrent restart command failed: %s", (err or out).strip())
            return
        if not self.darwin:
            log.warning("qBittorrent restart: set qbittorrent.restart_command on this platform")
            return
        try:
            self.qbit.shutdown()
        except QBitError as e:
            log.info("qBittorrent shutdown via API failed (%s); continuing", e)
        proc = self.qcfg["process_name"]
        for _ in range(60):
            if self.runner.run(["pgrep", "-x", proc])[0] != 0:
                break
            self.sleep(1)
        else:
            log.warning("qBittorrent did not quit within 60 s; not relaunching")
            return
        user = self.qcfg.get("user") or self.runner.run(["stat", "-f", "%Su", "/dev/console"])[1].strip()
        if not user or user == "root":
            log.warning("qBittorrent restart: no logged-in user to start it for")
            return
        uid = self.runner.run(["id", "-u", user])[1].strip()
        rc, out, err = self.runner.run(["launchctl", "asuser", uid, "sudo", "-u", user,
                                        "open", "-g", "-a", self.qcfg["app_path"]])
        if rc != 0:
            log.warning("qBittorrent relaunch failed: %s", (err or out).strip())
            return
        self.jobs.pop("reannounce", None)  # its startup announce supersedes a running wave
        self.qbit._api = None  # a different version may have started; also makes the probe real
        for _ in range(60):
            self.sleep(2)
            try:
                if self.qcfg.get("username"):
                    self.qbit.login()
                self.qbit.api_version()
                log.info("qBittorrent relaunched for %s", user)
                return
            except QBitError:
                continue
        log.warning("qBittorrent's Web API did not come back within 2 minutes")


# --- HTTP API -------------------------------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    companion: Companion = None  # set by make_server
    server_version = "airbl-companion"
    timeout = 10  # a client that stalls (slowloris) is dropped instead of holding a thread

    def log_message(self, fmt, *args):  # route to our logger, quietly
        log.debug("api %s: " + fmt, self.client_address[0], *args)

    def _send(self, code: int, body, content_type: str = "application/json") -> None:
        data = (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        api = self.companion.cfg["api"]
        if not source_allowed(self.client_address[0], api.get("allow_from") or []):
            self._send(403, {"error": "source address not allowed"})
            return False
        key = self.headers.get("X-API-Key") or ""
        if not hmac.compare_digest(key.encode(), api["api_key"].encode()):
            self._send(401, {"error": "invalid API key"})
            return False
        return True

    def _body(self) -> dict:
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            raise ValueError("bad Content-Length")
        if n < 0 or n > 65536:
            raise ValueError("body too large or negative length")
        raw = self.rfile.read(n) if n else b""
        body = json.loads(raw or b"{}")
        if not isinstance(body, dict):
            raise ValueError("expected a JSON object")
        return body

    def do_GET(self):
        if not self._authorized():
            return
        c = self.companion
        if self.path == "/v1/vpn/status":
            self._send(200, {"status": c.vpn_status()})
        elif self.path == "/v1/publicip/ip":
            self._send(200, {"public_ip": c.public_ip or ""} if c.healthy else {"public_ip": ""})
        elif self.path == "/v1/companion/status":
            self._send(200, c.status())
        else:
            self._send(404, {"error": "not found"})

    def do_PUT(self):
        if not self._authorized():
            return
        c = self.companion
        try:
            body = self._body()
        except ValueError as e:
            self._send(400, {"error": f"invalid JSON: {e}"})
            return
        if self.path == "/v1/vpn/settings":
            provider = body.get("provider")
            sel = (provider.get("server_selection") if isinstance(provider, dict) else None) or {}
            if not isinstance(sel, dict):
                sel = {}
            names = sel.get("names")
            if not isinstance(names, list) or not names:
                self._send(400, "provider.server_selection.names: a non-empty list of server names is required",
                           "text/plain")
                return
            code, msg = c.request_switch(names)
            self._send(code, msg, "text/plain")
        elif self.path == "/v1/vpn/status":
            st = body.get("status")
            if st not in ("running", "stopped"):
                self._send(400, {"error": 'status must be "running" or "stopped"'})
                return
            c.request_desired(st)
            self._send(200, {"outcome": st})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._authorized():
            return
        if self.path == "/v1/companion/resume":
            self._send(200, {"held": self.companion.request_resume_now()})
            return
        if self.path != "/v1/companion/switch":
            self._send(404, {"error": "not found"})
            return
        try:
            body = self._body()
        except ValueError as e:
            self._send(400, {"error": f"invalid JSON: {e}"})
            return
        names = body.get("names")
        if not isinstance(names, list) or not names:
            self._send(400, {"error": "names: a non-empty list is required"})
            return
        code, msg = self.companion.request_switch(names, force=True, reason="manual")
        self._send(code, {"result": msg})


class _Server(ThreadingHTTPServer):
    """Drops connections from sources outside allow_from before reading anything, and caps
    the number of concurrent requests, so a LAN client can't exhaust threads or descriptors."""
    daemon_threads = True
    max_clients = 16

    def __init__(self, addr, handler, companion: Companion):
        self.companion = companion
        self._slots = threading.BoundedSemaphore(self.max_clients)
        if ":" in addr[0]:
            self.address_family = socket.AF_INET6
        super().__init__(addr, handler)

    def verify_request(self, request, client_address) -> bool:
        return source_allowed(client_address[0], self.companion.cfg["api"].get("allow_from") or [])

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def make_server(companion: Companion, host: Optional[str] = None, port: Optional[int] = None) -> ThreadingHTTPServer:
    handler = type("BoundHandler", (Handler,), {"companion": companion})
    api = companion.cfg["api"]
    return _Server((host or api["listen"], port if port is not None else api["port"]), handler, companion)


# --- CLI ----------------------------------------------------------------------------------

def setup_logging(cfg: dict, verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
    root = logging.getLogger("airbl-companion")
    root.setLevel(level)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    if cfg.get("log_file"):
        try:
            fd = os.open(cfg["log_file"], os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
            os.chmod(cfg["log_file"], 0o600)  # server names and public IPs: root only
            fh = logging.handlers.RotatingFileHandler(cfg["log_file"], maxBytes=2_000_000, backupCount=3)
            fh.setFormatter(fmt)
            root.addHandler(fh)
        except OSError as e:
            root.warning("Log file %s not writable: %s", cfg["log_file"], e)


def _api_call(cfg: dict, method: str, path: str, body: Optional[dict] = None):
    host = cfg["api"]["listen"]
    host = "127.0.0.1" if host in ("0.0.0.0", "", "::") else host
    url = f"http://{host}:{cfg['api']['port']}{path}"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"X-API-Key": cfg["api"]["api_key"], "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            raw = resp.read()
    except urllib.error.HTTPError as e:
        raw = e.read()
    except urllib.error.URLError as e:
        raise SystemExit(f"The companion is not running or not reachable at {url}: {e.reason}")
    try:
        return json.loads(raw)
    except ValueError:
        return raw.decode()


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="airbl-companion", description=__doc__.split("\n\n")[0])
    p.add_argument("-c", "--config", default=os.environ.get("AIRBL_COMPANION_CONFIG",
                                                             "/opt/airbl-companion/etc/config.json"))
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the daemon (launchd runs this)")
    sub.add_parser("status", help="show the daemon's status")
    sw = sub.add_parser("switch", help="switch now, e.g. switch Achernar,Mirzam")
    sw.add_argument("names")
    sub.add_parser("up", help="bring the tunnel up (daemon)")
    sub.add_parser("down", help="take the tunnel down and keep it down (daemon)")
    sub.add_parser("check", help="check config, AirVPN name lookup and qBittorrent settings")
    sub.add_parser("resume", help="restart now all torrents the companion stopped (pause_when_down)")
    rd = sub.add_parser("render", help="print the WireGuard config for a server (keys hidden)")
    rd.add_argument("name")
    args = p.parse_args(argv)
    # The installer's root-owned copies of wg/wg-quick/wireguard-go come first (sudo's PATH
    # doesn't include them; the LaunchDaemon sets the same order)
    if os.path.isdir("/opt/airbl-companion/bin"):
        os.environ["PATH"] = "/opt/airbl-companion/bin:" + os.environ.get("PATH", "")

    try:
        cfg = load_config(args.config)
    except (OSError, ValueError) as e:
        print(f"Config {args.config}: {e}", file=sys.stderr)
        return 2

    if args.cmd == "serve":
        setup_logging(cfg, args.verbose)
        if os.geteuid() != 0:
            log.warning("Not running as root: wg-quick and route changes will fail")
        missing = [b for b in ("wg", "wg-quick") if not shutil.which(b)]
        if missing:
            log.error("Not found on PATH: %s (install wireguard-tools)", ", ".join(missing))
            return 1
        os.makedirs(cfg["state_dir"], mode=0o700, exist_ok=True)
        comp = Companion(cfg)
        try:
            srv = make_server(comp)
        except OSError as e:
            log.error("Can't listen on %s:%s (%s). Another program probably uses this port: set a free "
                      "api.port in the config (and the same port in AirBL's Second Control Target).",
                      cfg["api"]["listen"], cfg["api"]["port"], e.strerror or e)
            return 1
        threading.Thread(target=srv.serve_forever, name="api", daemon=True).start()
        log.info("API listening on %s:%s", cfg["api"]["listen"], cfg["api"]["port"])
        try:
            comp.run_forever()
        except KeyboardInterrupt:
            pass
        finally:
            srv.shutdown()
        return 0
    if args.cmd == "status":
        st = _api_call(cfg, "GET", "/v1/companion/status")
        if not isinstance(st, dict) or "version" not in st:
            # Something answered, but not the companion (e.g. another program on this port)
            print(f"Port {cfg['api']['port']} answered, but not as the companion ({str(st)[:80]!r}). Is another "
                  "program using it? Check: sudo lsof -nP -iTCP:%s -sTCP:LISTEN" % cfg["api"]["port"])
            return 1
        print(json.dumps(st, indent=2))
        return 0
    if args.cmd == "switch":
        names = [n.strip() for n in args.names.split(",") if n.strip()]
        print(json.dumps(_api_call(cfg, "POST", "/v1/companion/switch", {"names": names})))
        return 0
    if args.cmd == "resume":
        r = _api_call(cfg, "POST", "/v1/companion/resume", {})
        held = r.get("held") if isinstance(r, dict) else None
        print(f"Restarting {held} held torrents now (200 every 2 s)." if held else f"Nothing held ({r}).")
        return 0
    if args.cmd in ("up", "down"):
        st = "running" if args.cmd == "up" else "stopped"
        print(json.dumps(_api_call(cfg, "PUT", "/v1/vpn/status", {"status": st})))
        return 0
    if args.cmd == "render":
        d = Directory(cfg)
        d.refresh(force=True)
        ip = d.entry_ip(args.name)
        if not ip:
            print(f"Unknown server {args.name}", file=sys.stderr)
            return 1
        print(Tunnel(cfg, Runner()).render(ip, mask=True), end="")
        return 0
    if args.cmd == "check":
        setup_logging({**cfg, "log_file": ""}, args.verbose)
        ok = True
        d = Directory(cfg)
        d.refresh(force=True)
        print(f"AirVPN servers known: {len(d.servers)}")
        for b in ("wg", "wg-quick"):
            found = shutil.which(b)
            print(f"{b}: {found or 'NOT FOUND'}")
            ok &= bool(found)
        print(f"Tunnel IPv4 (bind qBittorrent to this): {tunnel_ipv4(cfg)}")
        if not _has_ipv6_address(cfg):
            allowed = cfg["wireguard"].get("allowed_ips", "")
            if "::/0" in allowed.replace(" ", ""):
                print("IPv4-only tunnel: IPv6 is routed into the tunnel and goes nowhere (no IPv6 while it runs). "
                      f"DNS used: {usable_dns(cfg)}")
            else:
                print("WARNING: no IPv6 address and ::/0 is not in allowed_ips: IPv6 traffic would bypass the "
                      "VPN. Add ::/0 to allowed_ips (or turn IPv6 off on the Mac).")
                ok = False
        if cfg["qbittorrent"]["enabled"]:
            q = QBit(cfg["qbittorrent"])
            try:
                if cfg["qbittorrent"]["username"]:
                    q.login()
                print(f"qBittorrent Web API {'.'.join(map(str, q.api_version()))}")
                warnings = qbit_preflight(cfg, q, apply=False)  # check never changes qBittorrent
                # A bind address the daemon will set itself is not a failure
                pending = [w for w in warnings if "the companion sets it when it starts" in w]
                warnings = [w for w in warnings if w not in pending]
                for w in pending:
                    print(f"qBittorrent: {w}")
                print("qBittorrent settings OK" if not warnings else "qBittorrent: " + "; ".join(warnings))
                ok &= not warnings
            except QBitError as e:
                print(f"qBittorrent: {e}")
                ok = False
        return 0 if ok else 1
    return 2


if __name__ == "__main__":
    sys.exit(main())
