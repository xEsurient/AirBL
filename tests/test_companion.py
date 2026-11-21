"""AirBL companion (companion/airbl_companion.py): tunnel switching with a simulated wg/wg-quick,
a fake qBittorrent Web API, and the Gluetun-compatible HTTP contract AirBL relies on."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs

import pytest

_COMPANION = Path(__file__).resolve().parents[1] / "companion"
if not (_COMPANION / "airbl_companion.py").exists():  # e.g. a deploy that ships tests/ only
    pytest.skip("companion/ not present", allow_module_level=True)
sys.path.insert(0, str(_COMPANION))
import airbl_companion as ac  # noqa: E402

PUB = ac.AIRVPN_PUBKEY
PRIV = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="  # format-valid fake keys
PSK = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
SERVERS = {  # name -> (entry1, entry3)
    "Achernar": ("198.51.100.1", "203.0.113.1"),
    "Mirzam": ("198.51.100.2", "203.0.113.2"),
    "Hamal": ("198.51.100.3", "203.0.113.3"),
    "Fuyue": ("198.51.100.4", "203.0.113.4"),
}
STATUS_JSON = json.dumps({"servers": [
    {"public_name": n, "ip_v4_in1": a, "ip_v4_in3": b, "country_code": "ch", "location": "Zurich", "health": "ok"}
    for n, (a, b) in SERVERS.items()] + [{"country_code": "ch", "server_best": "Achernar"}]}).encode()


class Clock:
    def __init__(self):
        self.t = 1_700_000_000.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakeWG(ac.Runner):
    """Simulates wg, wg-quick, route and scutil. `dead` entry IPs never complete a handshake;
    `no_roam` IPs only handshake after a full restart."""

    def __init__(self, clock, darwin=False):
        self.clock = clock
        self.darwin = darwin
        self.up = False
        self.endpoint = None
        self.handshake = 0
        self.dead = set()
        self.no_roam = set()
        self.calls = []
        self.routes = {}
        self.gateway = "192.168.1.1"
        self.app_connected = False
        self.quick_fail = False

    def _maybe_handshake(self, roam):
        if self.endpoint and self.endpoint not in self.dead and not (roam and self.endpoint in self.no_roam):
            self.handshake = int(self.clock())

    def run(self, cmd, timeout=30):
        self.calls.append(cmd)
        c = cmd[0]
        if c == "wg-quick":
            if cmd[1] == "up":
                if self.up or self.quick_fail:
                    return 1, "", "already exists" if self.up else "boom"
                conf = Path(cmd[2]).read_text()
                self.endpoint = [l.split("=", 1)[1].strip().rsplit(":", 1)[0] for l in conf.splitlines()
                                 if l.startswith("Endpoint")][0]
                self.up, self.handshake = True, 0
                if self.darwin:
                    self.routes[self.endpoint] = self.gateway
                self._maybe_handshake(roam=False)
                return 0, "", ""
            was = self.up
            self.up, self.endpoint, self.handshake = False, None, 0
            return (0, "", "") if was else (1, "", "not a WireGuard interface")
        if c == "wg":
            if not self.up:
                return 1, "", "Unable to access interface"
            if cmd[1] == "show":
                what = cmd[3]
                if what == "public-key":
                    return 0, "clientpub\n", ""
                if what == "latest-handshakes":
                    return 0, f"{PUB}\t{self.handshake}\n" if self.endpoint else "", ""
                if what == "endpoints":
                    return 0, f"{PUB}\t{self.endpoint}:1637\n" if self.endpoint else "", ""
                if what == "transfer":
                    return 0, f"{PUB}\t1000\t2000\n", ""
            if cmd[1] == "set":
                if cmd[5] == "remove":
                    self.endpoint, self.handshake = None, 0
                    return 0, "", ""
                ep = cmd[cmd.index("endpoint") + 1]
                self.endpoint = ep.rsplit(":", 1)[0]
                self._maybe_handshake(roam=True)
                return 0, "", ""
        if c == "route":
            if cmd[1:4] == ["-n", "get", "default"]:
                if self.gateway is None:
                    return 1, "", "route: writing to routing socket: not in table"
                return 0, f"   route to: default\n    gateway: {self.gateway}\n", ""
            if "add" in cmd:
                self.routes[cmd[cmd.index("-inet") + 1]] = cmd[cmd.index("-gateway") + 1]
            elif "delete" in cmd:
                self.routes.pop(cmd[cmd.index("-inet") + 1], None)
            return 0, "", ""
        if c == "ip":
            return 0, (f"default via {self.gateway} dev eth0\n" if self.gateway else ""), ""
        if c == "scutil":
            line = '* (Connected)  X VPN (com.wireguard.macos) "home"' if self.app_connected else ""
            return 0, line + "\n", ""
        return 0, "", ""


def make_cfg(tmp_path, **over):
    cfg = ac._merge(ac.DEFAULT_CONFIG, {
        "api": {"api_key": "k3y", "listen": "127.0.0.1", "port": 0},
        "wireguard": {"private_key": PRIV, "preshared_key": PSK, "address": "10.150.1.2/32, fd7d::2/128"},
        "state_dir": str(tmp_path / "state"), "log_file": "",
        "health": {"roam_timeout": 5, "min_switch_interval": 600, "server_cooldown": 1800},
    })
    return ac._merge(cfg, over)


def fetcher(ip="192.0.2.77"):
    def fetch(url, timeout=15, headers=None):
        if "airvpn" in url:
            return STATUS_JSON
        return ip.encode()
    return fetch


@pytest.fixture
def env(tmp_path):
    clock = Clock()

    def make(darwin=False, qbit=None, **over):
        wg = FakeWG(clock, darwin=darwin)
        cfg = make_cfg(tmp_path, **over)
        comp = ac.Companion(cfg, runner=wg, fetch=fetcher(), qbit=qbit, darwin=darwin,
                            clock=clock, sleep=clock.sleep, monotonic=clock)
        comp.startup()
        return comp, wg
    make.clock = clock
    return make


# --- config ------------------------------------------------------------------------------

def test_config_validation(tmp_path):
    cfg = make_cfg(tmp_path)
    ac.validate_config(cfg)
    assert ac.tunnel_ipv4(cfg) == "10.150.1.2"
    for bad in ({"wireguard": {"private_key": ""}}, {"api": {"api_key": ""}},
                {"wireguard": {"entry": "ENTRY2"}}, {"wireguard": {"interface": "x; rm -rf"}},
                {"wireguard": {"address": "fd7d::2/128"}},
                {"wireguard": {"private_key": "PrivateKey from the AirVPN config generator"}},
                {"wireguard": {"preshared_key": "short="}}, {"api": {"allow_from": ["not-an-ip"]}}):
        with pytest.raises(ac.ConfigError):
            ac.validate_config(ac._merge(cfg, bad))
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"api": {"api_key": "x"}, "wireguard": {"private_key": PRIV, "address": "10.0.0.2/32"}}))
    assert ac.load_config(str(p))["health"]["interval"] == 15  # defaults merged


def test_render_and_conf_file_private(env):
    comp, wg = env()
    text = comp.tunnel.render("203.0.113.1")
    assert "Endpoint = 203.0.113.1:1637" in text and f"PrivateKey = {PRIV}" in text
    assert f"PublicKey = {PUB}" in text and f"PresharedKey = {PSK}" in text
    masked = comp.tunnel.render("203.0.113.1", mask=True)
    assert PRIV not in masked and PSK not in masked
    comp.tunnel.write_conf("203.0.113.1")
    assert (Path(comp.tunnel.conf_path).stat().st_mode & 0o777) == 0o600


def test_directory_entry_and_disk_cache(tmp_path):
    cfg = make_cfg(tmp_path)
    d = ac.Directory(cfg, fetcher())
    d.refresh(force=True)
    assert d.entry_ip("Achernar") == "203.0.113.1" and d.entry_ip("AirVPN mirzam") == "203.0.113.2"
    assert d.name_for_ip("198.51.100.3") == "Hamal" and d.lookup("Nope") is None
    cfg["wireguard"]["entry"] = "ENTRY1"
    assert d.entry_ip("Achernar") == "198.51.100.1"

    def offline(url, timeout=15, headers=None):
        raise OSError("offline")
    d2 = ac.Directory(cfg, offline)
    d2.refresh(force=True)  # falls back to the list cached on disk
    assert d2.entry_ip("Fuyue") == "198.51.100.4"


# --- switching ---------------------------------------------------------------------------

def test_first_start_uses_initial_servers(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    assert wg.up and wg.endpoint == "203.0.113.2"
    assert comp.state["current"] == "Mirzam" and comp.healthy and comp.vpn_status() == "running"
    assert comp.public_ip == "192.0.2.77"


def test_no_server_known_waits(env):
    comp, wg = env()
    comp.tick()
    assert not wg.up and comp.vpn_status() == "stopped" and "waiting for AirBL" in comp.last_error


def test_switch_roams_in_place(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    up_calls = sum(1 for c in wg.calls if c[:2] == ["wg-quick", "up"])
    assert comp.request_switch(["Achernar", "Hamal"]) == (200, "settings updated")
    comp.state["last_switch_at"] = 0  # past the minimum interval
    comp.tick()
    assert wg.endpoint == "203.0.113.1" and comp.state["current"] == "Achernar"
    assert sum(1 for c in wg.calls if c[:2] == ["wg-quick", "up"]) == up_calls  # no restart
    assert "in place" in comp.state["last_switch_result"]
    assert "Endpoint = 203.0.113.1:1637" in Path(comp.tunnel.conf_path).read_text()  # reboot lands here
    roam = [c for c in wg.calls if c[:2] == ["wg", "set"] and "endpoint" in c][-1]
    assert PSK not in " ".join(roam) and "preshared-key" in roam  # key via file, never on the command line


def test_left_unchanged_when_current_listed(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    assert comp.request_switch(["Hamal", "Mirzam"]) == (200, "settings left unchanged")
    assert comp.pending is None and comp.state["last_list"] == ["Hamal", "Mirzam"]


def test_unknown_names(env):
    comp, wg = env()
    code, msg = comp.request_switch(["Nope"])
    assert code == 400 and "Nope" in msg and "no possible value" not in msg  # avoid AirBL's Gluetun hint
    assert comp.request_switch(["Nope", "AirVPN Hamal"])[0] == 200
    assert comp.pending["names"] == ["Hamal"]


def test_roam_fails_then_restart(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    wg.no_roam.add("203.0.113.1")
    comp.request_switch(["Achernar"], force=True)
    comp.tick()
    assert comp.state["current"] == "Achernar" and "tunnel restart" in comp.state["last_switch_result"]


def test_dead_server_cooldown_and_next(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    wg.dead.add("203.0.113.1")
    comp.request_switch(["Achernar", "Hamal"], force=True)
    comp.tick()
    assert comp.state["current"] == "Hamal"
    assert comp.state["cooldowns"]["Achernar"] > env.clock()


def test_all_fail_back_to_last_good(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    wg.dead |= {"203.0.113.1", "203.0.113.3"}
    comp.request_switch(["Achernar", "Hamal"], force=True)
    comp.tick()
    assert comp.state["current"] == "Mirzam" and wg.endpoint == "203.0.113.2" and comp.healthy


def test_min_switch_interval_defers(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()  # switched just now
    comp.request_switch(["Achernar"])
    comp.tick()
    assert comp.state["current"] == "Mirzam" and comp.pending is not None
    env.clock.t += 601
    wg.handshake = int(env.clock())
    comp.tick()
    assert comp.state["current"] == "Achernar" and comp.pending is None


def test_stale_handshake_recovers_then_fails_over(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    comp.state["last_list"] = ["Mirzam", "Fuyue"]
    wg.dead.add("203.0.113.2")      # Mirzam stops answering
    env.clock.t += 400               # handshake now 400 s old
    comp.tick()
    assert comp.state["current"] == "Fuyue" and comp.healthy
    assert "Mirzam" in comp.state["cooldowns"]


def test_tunnel_down_externally_is_restored(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    wg.up, wg.endpoint = False, None  # e.g. someone ran wg-quick down
    comp.tick()
    assert wg.up and comp.state["current"] == "Mirzam"


def test_desired_stopped_and_running(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    comp.request_desired("stopped")
    comp.tick()
    assert not wg.up and comp.vpn_status() == "stopped"
    comp.tick()
    assert not wg.up  # stays down
    comp.request_desired("running")
    comp.tick()
    assert wg.up and comp.healthy


def test_adopts_running_interface_after_restart(env, tmp_path):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    calls = len(wg.calls)
    comp2 = ac.Companion(comp.cfg, runner=wg, fetch=fetcher(), darwin=False, clock=env.clock, sleep=env.clock.sleep, monotonic=env.clock)
    comp2.startup()
    comp2.tick()
    assert comp2.state["current"] == "Mirzam" and comp2.healthy
    assert not any(c[0] == "wg-quick" for c in wg.calls[calls:])  # no restart of a working tunnel


def test_bad_first_candidate_does_not_restart_healthy_tunnel(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    n_quick = sum(1 for c in wg.calls if c[0] == "wg-quick")
    wg.dead.add("203.0.113.1")
    comp.request_switch(["Achernar", "Hamal"], force=True)
    comp.tick()
    assert comp.state["current"] == "Hamal" and "in place" in comp.state["last_switch_result"]
    assert sum(1 for c in wg.calls if c[0] == "wg-quick") == n_quick  # interface never recreated
    assert comp._cooling("Achernar")


def test_wake_grace_lets_tunnel_reconnect_by_itself(env):
    mono = {"t": 0.0}
    comp, wg = env(initial_servers=["Mirzam"])
    comp.monotonic = lambda: mono["t"]
    comp.tick()
    env.clock.t += 3600  # slept an hour: wall clock moved, monotonic didn't
    comp.tick()
    assert comp.state["current"] == "Mirzam" and not comp.state["cooldowns"]
    assert not any(c[:2] == ["wg", "set"] for c in wg.calls[-5:])  # no recovery attempt yet
    wg.handshake = int(env.clock())  # it re-handshook by itself
    env.clock.t += 15
    mono["t"] += 15
    comp.tick()
    assert comp.healthy and comp.state["current"] == "Mirzam"


def test_no_network_blames_no_server(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    wg.gateway = None  # Wi-Fi gone
    env.clock.t += 400
    calls = len(wg.calls)
    comp.tick()
    assert not comp.healthy and "No network" in comp.last_error and not comp.state["cooldowns"]
    assert not any(c[0] == "wg-quick" or c[:2] == ["wg", "set"] for c in wg.calls[calls:])
    assert comp.vpn_status() == "stopped"
    wg.gateway = "192.168.1.1"
    wg.handshake = int(env.clock())
    comp.tick()
    assert comp.healthy and comp.state["current"] == "Mirzam"


def test_backoff_when_nothing_connects(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    wg.dead |= {ip for _, ip in SERVERS.values()}
    comp.state["last_list"] = ["Mirzam", "Hamal"]
    env.clock.t += 400
    comp.tick()  # recovery fails -> backoff 30 s
    assert not comp.healthy and comp.backoff == 30
    attempts = len(wg.calls)
    env.clock.t += 15
    comp.tick()  # within the backoff: no new attempt
    assert not any(c[0] == "wg-quick" for c in wg.calls[attempts:])
    env.clock.t += 20
    comp.tick()  # backoff over: tries again, fails, doubles
    assert comp.backoff == 60
    wg.dead.clear()
    env.clock.t += 61
    comp.tick()
    assert comp.healthy and comp.backoff == 0


def test_no_unchanged_reply_mid_switch(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    comp.switching = True
    assert comp.vpn_status() == "stopped"
    assert comp.request_switch(["Mirzam"]) == (200, "settings updated")
    comp.switching = False
    assert comp.request_switch(["mirzam", "AirVPN Mirzam"]) == (200, "settings left unchanged")
    assert comp.state["last_list"] == ["Mirzam"]  # canonical spelling, deduplicated


def test_status_returns_copies(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    comp._cool("Hamal")
    st = comp.status()
    st["last_list"].append("X")
    assert "X" not in comp.state["last_list"] and st["cooldowns"]["Hamal"] > 0


# --- macOS specifics -------------------------------------------------------------------------

@pytest.fixture
def darwin_name(monkeypatch):
    real_open = open

    def fake_open(path, *a, **k):
        if str(path).startswith("/var/run/wireguard/"):
            import io
            return io.StringIO("utun7\n")
        return real_open(path, *a, **k)
    monkeypatch.setattr("builtins.open", fake_open)


def test_darwin_roam_moves_endpoint_route(env, darwin_name):
    comp, wg = env(darwin=True, initial_servers=["Mirzam"])
    comp.tick()
    assert wg.routes == {"203.0.113.2": "192.168.1.1"}
    comp.request_switch(["Achernar"], force=True)
    comp.tick()
    assert wg.routes == {"203.0.113.1": "192.168.1.1"}  # new endpoint routed, old one removed
    # Network change: the endpoint route follows the new gateway
    wg.gateway = "10.0.0.1"
    comp.tick()
    assert wg.routes["203.0.113.1"] == "10.0.0.1"


def test_darwin_wireguard_app_conflict(env, darwin_name):
    comp, wg = env(darwin=True, initial_servers=["Mirzam"])
    wg.app_connected = True
    comp.tick()
    assert not wg.up and "WireGuard app" in comp.last_error and comp.vpn_status() == "stopped"


# --- qBittorrent ---------------------------------------------------------------------------

class FakeQBitServer:
    def __init__(self, api="2.11.2", status="connected", prefs=None):
        self.api = api
        self.status = status
        self.prefs = {"listen_port": 51413, "current_interface_address": "10.150.1.2", "upnp": False, **(prefs or {})}
        self.calls = []
        self.torrents = [
            {"hash": "aaa", "state": "uploading", "tracker": "https://t1.example/announce", "num_incomplete": 5},
            {"hash": "bbb", "state": "stalledUP", "tracker": "https://t1.example/announce", "num_incomplete": 1},
        ]
        self.need_login = False
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _reply(self, code, body):
                data = body if isinstance(body, bytes) else json.dumps(body).encode()
                self.send_response(code)
                if self.path == "/api/v2/auth/login" and code == 200:
                    self.send_header("Set-Cookie", "SID=abc; path=/")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.calls.append(("GET", self.path, None))
                if outer.need_login and "SID=abc" not in (self.headers.get("Cookie") or ""):
                    return self._reply(403, b"Forbidden")
                p = self.path.split("?")[0]
                if p == "/api/v2/app/webapiVersion":
                    return self._reply(200, outer.api.encode())
                if p == "/api/v2/app/preferences":
                    return self._reply(200, outer.prefs)
                if p == "/api/v2/transfer/info":
                    return self._reply(200, {"connection_status": outer.status})
                if p == "/api/v2/torrents/info":
                    q = parse_qs(self.path.partition("?")[2])
                    rows = outer.torrents
                    if q.get("filter", [""])[0] in ("running", "resumed"):
                        rows = [t for t in rows if not t["state"].startswith(("stopped", "paused"))]
                    return self._reply(200, rows)
                return self._reply(404, b"")

            def do_POST(self):
                n = int(self.headers.get("Content-Length") or 0)
                form = {k: v[0] for k, v in parse_qs(self.rfile.read(n).decode()).items()}
                outer.calls.append(("POST", self.path, form))
                if self.path == "/api/v2/auth/login":
                    ok = form.get("username") == "admin" and form.get("password") == "pw"
                    return self._reply(200, b"Ok." if ok else b"Fails.")
                if outer.need_login and "SID=abc" not in (self.headers.get("Cookie") or ""):
                    return self._reply(403, b"Forbidden")
                if self.path == "/api/v2/app/setPreferences":
                    outer.prefs.update(json.loads(form["json"]))
                if self.path in ("/api/v2/torrents/stop", "/api/v2/torrents/start"):
                    hs = set(form["hashes"].split("|"))
                    for t in outer.torrents:
                        if t["hash"] in hs:
                            t["state"] = "stoppedUP" if self.path.endswith("stop") else "uploading"
                return self._reply(200, b"")

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.srv.server_address[1]}"

    def posts(self, path):
        return [c[2] for c in self.calls if c[0] == "POST" and c[1] == path]

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def qserver():
    s = FakeQBitServer()
    yield s
    s.close()


def _qcfg(url, **kw):
    return ac._merge(ac.DEFAULT_CONFIG["qbittorrent"], {"enabled": True, "url": url, **kw})


def test_qbit_login_retry_and_versioned_endpoints(qserver):
    qserver.need_login = True
    q = ac.QBit(_qcfg(qserver.url, username="admin", password="pw"))
    assert q.transfer_info()["connection_status"] == "connected"  # 403 -> login -> retry
    q.stop(["aaa"])
    assert qserver.posts("/api/v2/torrents/stop") == [{"hashes": "aaa"}]
    qserver.api = "2.8.3"
    q2 = ac.QBit(_qcfg(qserver.url, username="admin", password="pw"))
    q2.stop(["aaa"])
    assert qserver.posts("/api/v2/torrents/pause") == [{"hashes": "aaa"}]
    bad = ac.QBit(_qcfg(qserver.url, username="admin", password="wrong"))
    with pytest.raises(ac.QBitError):
        bad.login()


def test_qbit_unreachable_is_an_error():
    with pytest.raises(ac.QBitError):
        ac.QBit(_qcfg("http://127.0.0.1:9"), timeout=1).transfer_info()


def test_qbit_preflight(tmp_path, qserver):
    cfg = make_cfg(tmp_path, qbittorrent={"enabled": True, "url": qserver.url, "forwarded_port": 51413})
    q = ac.QBit(cfg["qbittorrent"])
    assert ac.qbit_preflight(cfg, q) == []
    qserver.prefs.update({"current_interface_address": "", "listen_port": 6881, "upnp": True})
    w = ac.qbit_preflight(cfg, q)
    assert len(w) == 3 and "leak" in w[0] and "51413" in w[1] and "UPnP" in w[2]
    cfg["qbittorrent"]["enforce_bind"] = True
    ac.qbit_preflight(cfg, q)
    assert qserver.prefs["current_interface_address"] == "10.150.1.2"


def _reannounced(qserver):
    return [h for f in qserver.posts("/api/v2/torrents/reannounce") for h in f["hashes"].split("|")]


def test_switch_reannounces_paced_without_port_toggle(env, qserver):
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"],
                   qbittorrent={"enabled": True, "url": qserver.url, "forwarded_port": 51413})
    comp.tick()  # first connect = tunnel restart: reannounce, but never touch the listen port
    assert sorted(_reannounced(qserver)) == ["aaa", "bbb"]
    assert qserver.posts("/api/v2/app/setPreferences") == []
    assert all(f["hashes"] != "all" for f in qserver.posts("/api/v2/torrents/reannounce"))
    comp.request_switch(["Achernar"], force=True)
    comp.tick()  # in place: another (paced) wave
    assert len(_reannounced(qserver)) == 4 and "reannounce" not in comp.jobs


def test_reannounce_order_and_skips():
    T = lambda h, st, tr="https://a.example/x", n=0: {"hash": h, "state": st, "tracker": tr, "num_incomplete": n}
    torrents = [
        T("idle", "stalledUP"), T("seed3", "uploading", n=3), T("seed9", "stalledUP", n=9),
        T("dl", "downloading"), T("notr", "uploading", tr="", n=50), T("stop", "stoppedUP", n=99),
        T("pause", "pausedUP", n=99), T("q", "queuedUP", n=99), T("chk", "checkingUP", n=99),
        T("err", "error", n=99), T("miss", "missingFiles", n=99), T("meta", "metaDL"), T("force", "forcedUP", n=1),
    ]
    rcfg = dict(ac.DEFAULT_CONFIG["qbittorrent"]["reannounce"], max_torrents=0)
    order = [h for h, _ in ac.reannounce_order(torrents, rcfg)]
    assert order == ["dl", "seed9", "seed3", "force", "notr"]  # idle seeds skipped by default
    rcfg["skip_idle_seeds"] = False
    order = [h for h, _ in ac.reannounce_order(torrents, rcfg)]
    assert order == ["dl", "seed9", "seed3", "force", "idle", "notr"]
    rcfg["max_torrents"] = 2
    assert [h for h, _ in ac.reannounce_order(torrents, rcfg)] == ["dl", "seed9"]


def test_take_batch_caps_per_tracker_and_size():
    queue = [(f"a{i}", "a.example") for i in range(5)] + [(f"b{i}", "b.example") for i in range(5)] + [("c0", "c")]
    batch, rest = ac.take_batch(queue, batch_size=4, per_tracker=2)
    assert batch == ["a0", "a1", "b0", "b1"]
    assert rest[0] == ("a2", "a.example") and len(rest) == 7  # order kept for the rest
    batch, rest = ac.take_batch(rest, batch_size=8, per_tracker=2)
    assert batch == ["a2", "a3", "b2", "b3", "c0"]


def test_large_wave_is_paced_over_time(env, qserver):
    qserver.torrents = [{"hash": f"h{i:03d}", "state": "uploading", "num_incomplete": 1,
                         "tracker": f"https://t{i % 2}.example/a"} for i in range(30)]
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"], qbittorrent={"enabled": True, "url": qserver.url})
    comp.tick()
    first = qserver.posts("/api/v2/torrents/reannounce")
    assert len(first) == 1 and len(first[0]["hashes"].split("|")) == 4  # 2 per tracker x 2 trackers
    assert comp.status()["qbit"]["reannounce_pending"] == 26
    comp.tick()  # no time passed: nothing more
    assert len(qserver.posts("/api/v2/torrents/reannounce")) == 1
    for _ in range(10):
        env.clock.t += 20
        wg.handshake = int(env.clock())
        comp.tick()
    assert sorted(_reannounced(qserver)) == sorted(t["hash"] for t in qserver.torrents)
    assert len(set(_reannounced(qserver))) == 30 and "reannounce" not in comp.jobs
    assert comp._next_wait() == comp.h["interval"]


def test_wave_waits_while_unhealthy_and_new_switch_restarts_it(env, qserver):
    qserver.torrents = [{"hash": f"h{i}", "state": "uploading", "num_incomplete": 1,
                         "tracker": "https://t.example/a"} for i in range(10)]
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"], qbittorrent={"enabled": True, "url": qserver.url})
    comp.tick()
    assert len(_reannounced(qserver)) == 2
    comp.healthy = False
    env.clock.t += 20
    comp.run_jobs()
    assert len(_reannounced(qserver)) == 2  # paused while unhealthy
    comp.healthy = True
    comp.request_switch(["Achernar"], force=True)
    comp.tick()  # new wave from the top
    assert comp.jobs["reannounce"]["done"] == 2 and len(comp.jobs["reannounce"]["queue"]) == 8


def test_restart_skips_wave_when_qbit_reannounces_itself(env, qserver):
    qserver.prefs["reannounce_when_address_changed"] = True
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"], qbittorrent={"enabled": True, "url": qserver.url})
    comp.qbit_preflight()
    assert comp.qbit_self_reannounce and any("Reannounce to all trackers" in w for w in comp.qbit_status["warnings"])
    comp.tick()  # tunnel restart: qBittorrent does it, so no second wave
    assert _reannounced(qserver) == []
    comp.request_switch(["Achernar"], force=True)
    comp.tick()  # in place: qBittorrent can't see that, so the companion reannounces
    assert sorted(_reannounced(qserver)) == ["aaa", "bbb"]


def test_verify_escalates_rebind_then_restart(env, qserver):
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"],
                   qbittorrent={"enabled": True, "url": qserver.url, "forwarded_port": 51413,
                                "restart_command": ["fake-restart"]})
    comp.tick()
    comp.request_switch(["Achernar"], force=True)
    comp.tick()  # pre-switch status was "connected"
    qserver.status = "firewalled"
    reannounces = len(qserver.posts("/api/v2/torrents/reannounce"))

    def later():
        env.clock.t += 601
        wg.handshake = int(env.clock())
        comp.tick()
    later()  # stage 1: rebind only
    ports = [json.loads(f["json"])["listen_port"] for f in qserver.posts("/api/v2/app/setPreferences")]
    assert ports == [51414, 51413] and ["fake-restart"] not in wg.calls
    later()  # stage 2: restart
    assert sum(1 for c in wg.calls if c == ["fake-restart"]) == 1
    later()  # give up, no second restart
    assert sum(1 for c in wg.calls if c == ["fake-restart"]) == 1 and comp.qbit_verify is None
    assert len(qserver.posts("/api/v2/torrents/reannounce")) == reannounces  # no extra waves


def test_verify_ok_after_rebind_stops_escalation(env, qserver):
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"],
                   qbittorrent={"enabled": True, "url": qserver.url, "restart_command": ["fake-restart"]})
    comp.tick()
    comp.request_switch(["Achernar"], force=True)
    comp.tick()
    qserver.status = "disconnected"
    env.clock.t += 601
    wg.handshake = int(env.clock())
    comp.tick()
    qserver.status = "connected"
    env.clock.t += 601
    wg.handshake = int(env.clock())
    comp.tick()
    assert comp.qbit_verify is None and ["fake-restart"] not in wg.calls


def test_darwin_relaunch_probes_api_without_reannounce(env, qserver, darwin_name):
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(darwin=True, qbit=q, initial_servers=["Mirzam"],
                   qbittorrent={"enabled": True, "url": qserver.url, "user": "alice"})
    real_run = wg.run

    def run(cmd, timeout=30):
        if cmd[0] == "pgrep":
            wg.calls.append(cmd)
            return 1, "", ""  # quit at once
        if cmd[0] == "id":
            return 0, "501\n", ""
        return real_run(cmd, timeout)
    wg.run = run
    comp.tick()
    comp.jobs["reannounce"] = {"queue": [("zzz", "t")], "done": 0, "next_at": 1e18}
    before = len(qserver.posts("/api/v2/torrents/reannounce"))
    comp.restart_qbit()
    assert qserver.posts("/api/v2/app/shutdown") == [{}]
    assert ["launchctl", "asuser", "501", "sudo", "-u", "alice", "open", "-g", "-a",
            "/Applications/qBittorrent.app"] in wg.calls
    assert len(qserver.posts("/api/v2/torrents/reannounce")) == before and "reannounce" not in comp.jobs


def test_firewalled_without_prior_connection_is_not_restarted(env, qserver):
    qserver.status = "firewalled"
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"],
                   qbittorrent={"enabled": True, "url": qserver.url, "restart_command": ["fake-restart"]})
    comp.tick()
    env.clock.t += 601
    wg.handshake = int(env.clock())
    comp.tick()
    assert ["fake-restart"] not in wg.calls and qserver.posts("/api/v2/app/setPreferences") == []


def test_pause_when_down_resumes_only_own_paced(env, qserver):
    qserver.torrents += [{"hash": f"x{i:03d}", "state": "uploading", "tracker": f"https://t{i % 3}.example/a",
                          "num_incomplete": i} for i in range(120)]
    qserver.torrents.append({"hash": "mine", "state": "stoppedUP", "tracker": "https://t2.example/a",
                             "num_incomplete": 0})  # stopped by the user: never touched
    q = ac.QBit(_qcfg(qserver.url))
    comp, wg = env(qbit=q, initial_servers=["Mirzam"],
                   qbittorrent={"enabled": True, "url": qserver.url, "pause_when_down": True})
    comp.tick()  # first start: the tunnel was never up, so nothing is stopped
    assert qserver.posts("/api/v2/torrents/stop") == [] and comp.state["paused_hashes"] == []
    # The tunnel dies: running torrents are stopped (the user's own stopped one is left alone)
    wg.dead.add("203.0.113.2")
    comp.state["last_list"] = ["Mirzam"]
    env.clock.t += 400
    comp.tick()
    held = comp.state["paused_hashes"]
    assert len(held) == 122 and "mine" not in held
    # Back: resumed 50 per batch (busiest swarms first), only the companion's own
    wg.dead.clear()
    env.clock.t += 2000
    comp.tick()
    first = qserver.posts("/api/v2/torrents/start")[0]["hashes"].split("|")
    assert len(first) == 50 and first[0] == "x119"
    assert len(comp.state["paused_hashes"]) == 72
    # The companion restarts mid-resume and adopts the healthy tunnel: the rest still resumes
    comp2 = ac.Companion(comp.cfg, runner=wg, fetch=fetcher(), qbit=q, darwin=False,
                         clock=env.clock, sleep=env.clock.sleep, monotonic=env.clock)
    comp2.startup()
    assert comp2.healthy and len(comp2.state["paused_hashes"]) == 72
    wg.handshake = int(env.clock())
    comp2.tick()
    assert len(comp2.state["paused_hashes"]) == 22
    # `airbl-companion resume`: the rest at once (200 per batch)
    assert comp2.request_resume_now() == 22
    env.clock.t += 2
    wg.handshake = int(env.clock())
    comp2.tick()
    assert comp2.state["paused_hashes"] == [] and "start" not in comp2.jobs
    starts = sum((f["hashes"].split("|") for f in qserver.posts("/api/v2/torrents/start")), [])
    assert "mine" not in starts and len(set(starts)) == 122
    assert qserver.torrents[-1]["state"] == "stoppedUP"


# --- HTTP API (the Gluetun contract) ----------------------------------------------------------

@pytest.fixture
def api(env):
    comp, wg = env(initial_servers=["Mirzam"])
    comp.tick()
    srv = ac.make_server(comp, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True).start()
    yield comp, wg, f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _req(url, method="GET", body=None, key="k3y"):
    import urllib.request
    import urllib.error
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(url, data=data, method=method, headers={"X-API-Key": key} if key else {})
    try:
        with urllib.request.urlopen(r, timeout=5) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def test_api_auth_and_routes(api):
    comp, wg, url = api
    assert _req(url + "/v1/vpn/status", key="wrong")[0] == 401
    assert _req(url + "/v1/vpn/status", key=None)[0] == 401
    assert json.loads(_req(url + "/v1/vpn/status")[1]) == {"status": "running"}
    assert json.loads(_req(url + "/v1/publicip/ip")[1]) == {"public_ip": "192.0.2.77"}
    st = json.loads(_req(url + "/v1/companion/status")[1])
    assert st["server"] == "Mirzam" and st["tunnel_up"] is True and PRIV not in json.dumps(st)
    assert _req(url + "/v1/vpn/settings", "PUT", {"provider": {}})[0] == 400
    code, text = _req(url + "/v1/vpn/settings", "PUT", {"provider": {"server_selection": {"names": ["Hamal"]}}})
    assert (code, text) == (200, "settings updated") and comp.pending["names"] == ["Hamal"]
    assert _req(url + "/v1/vpn/status", "PUT", {"status": "paused"})[0] == 400
    assert _req(url + "/v1/vpn/status", "PUT", {"status": "stopped"})[0] == 200
    assert comp.state["desired"] == "stopped"
    assert _req(url + "/v1/nope")[0] == 404


def test_source_allowed():
    allow = ["192.168.1.10", "10.0.0.0/8"]
    assert ac.source_allowed("192.168.1.10", allow) and ac.source_allowed("10.2.3.4", allow)
    assert ac.source_allowed("::ffff:192.168.1.10", allow)  # IPv4-mapped (listening on ::)
    assert ac.source_allowed("127.0.0.1", allow) and ac.source_allowed("::1", allow)
    assert not ac.source_allowed("192.168.1.11", allow) and not ac.source_allowed("junk", allow)
    assert ac.source_allowed("192.168.1.11", [])  # empty = any


def test_api_rejects_bad_bodies(api):
    import http.client
    comp, wg, url = api
    host, port = url.rsplit("//", 1)[1].split(":")
    for body, length in ((b"[1,2]", "5"), (b"{}", "-1"), (b"{}", "abc"), (b'{"provider": []}', "16")):
        c = http.client.HTTPConnection(host, int(port), timeout=5)
        c.putrequest("PUT", "/v1/vpn/settings")
        c.putheader("X-API-Key", "k3y")
        c.putheader("Content-Length", length)
        c.endheaders()
        c.send(body)
        assert c.getresponse().status == 400
        c.close()


def test_api_drops_disallowed_source_before_parsing(api):
    comp, wg, url = api
    srv_ok = comp.cfg["api"].get("allow_from")
    comp.cfg["api"]["allow_from"] = ["192.0.2.1"]
    try:
        # loopback is always allowed; verify_request itself rejects others
        assert _req(url + "/v1/vpn/status")[0] == 200
        server = ac._Server(("127.0.0.1", 0), ac.Handler, comp)
        assert server.verify_request(None, ("198.51.100.9", 1234)) is False
        assert server.verify_request(None, ("127.0.0.1", 1234)) is True
        server.server_close()
    finally:
        comp.cfg["api"]["allow_from"] = srv_ok


def test_api_connection_cap(api):
    comp, wg, url = api
    server = ac._Server(("127.0.0.1", 0), ac.Handler, comp)
    closed = []
    server.shutdown_request = lambda req: closed.append(req)
    for _ in range(server.max_clients):
        assert server._slots.acquire(blocking=False)
    server.process_request("sock", ("127.0.0.1", 1))  # over the cap: dropped, no thread
    assert closed == ["sock"]
    server.server_close()


def test_qbit_404_resets_api_version(qserver):
    q = ac.QBit(_qcfg(qserver.url))
    q._api = (2, 8)
    with pytest.raises(ac.QBitError):
        q._call("GET", "/api/v2/nope")
    assert q._api is None


async def test_airbl_client_drives_the_companion(api, env, fresh_config):
    """AirBL's own Gluetun client code against the companion: status, public IP and a switch."""
    from airbl import gluetun
    comp, wg, url = api
    port = int(url.rsplit(":", 1)[1])
    target = fresh_config.gluetun.secondary
    target.control_server_host, target.control_server_port, target.api_key = "127.0.0.1", port, "k3y"
    status = await gluetun.get_gluetun_status(target)
    assert status["error"] is None and status["vpn_status"] == "running" and status["ip"] == "192.0.2.77"
    r = await gluetun.set_gluetun_server_names(target, ["Hamal", "Achernar"])
    assert r["applied"] and r["outcome"] == "settings updated"
    assert comp.pending["names"] == ["Hamal", "Achernar"]  # order kept = preference
    comp.tick()
    assert comp.state["current"] == "Mirzam"  # deferred: the fixture switched just now
    env.clock.t += 601
    comp.tick()
    assert comp.state["current"] == "Hamal"
    extra = await gluetun.get_companion_status(target)
    assert extra["server"] == "Hamal" and extra["tunnel_up"] is True
    target.api_key = "bad"
    assert "401" in (await gluetun.get_gluetun_status(target))["error"]



def test_ipv4_only_drops_ipv6_dns(tmp_path):
    cfg = make_cfg(tmp_path, wireguard={"address": "10.150.1.2/32", "dns": "10.128.0.1, fd7d:76ee:e68f:a993::1"})
    assert ac.usable_dns(cfg) == "10.128.0.1"
    text = ac.Tunnel(cfg, ac.Runner(), darwin=False).render("203.0.113.1")
    assert "DNS = 10.128.0.1\n" in text and "fd7d" not in text and "AllowedIPs = 0.0.0.0/0, ::/0" in text
    dual = make_cfg(tmp_path, wireguard={"address": "10.150.1.2/32, fd7d::2/128", "dns": "10.128.0.1, fd7d:76ee:e68f:a993::1"})
    assert ac.usable_dns(dual) == "10.128.0.1, fd7d:76ee:e68f:a993::1"



def test_check_preflight_is_read_only(tmp_path, qserver):
    qserver.prefs["current_interface_address"] = "10.136.0.1"  # e.g. the WireGuard app's tunnel
    cfg = make_cfg(tmp_path, qbittorrent={"enabled": True, "url": qserver.url, "enforce_bind": True})
    q = ac.QBit(cfg["qbittorrent"])
    w = ac.qbit_preflight(cfg, q, apply=False)
    assert qserver.prefs["current_interface_address"] == "10.136.0.1"  # untouched
    assert qserver.posts("/api/v2/app/setPreferences") == []
    assert "sets it when it starts" in w[0]
    ac.qbit_preflight(cfg, q)  # the daemon (apply=True) fixes it
    assert qserver.prefs["current_interface_address"] == "10.150.1.2"


def test_serve_reports_busy_port(tmp_path, monkeypatch, capsys):
    import socket
    busy = socket.socket(); busy.bind(("127.0.0.1", 0)); busy.listen(1)
    port = busy.getsockname()[1]
    cfg = make_cfg(tmp_path, api={"api_key": "k3y", "listen": "127.0.0.1", "port": port})
    p = tmp_path / "c.json"; p.write_text(json.dumps(cfg))
    monkeypatch.setattr(ac.shutil, "which", lambda b: "/usr/bin/" + b)
    monkeypatch.setattr(ac.Companion, "startup", lambda self: None)
    monkeypatch.setattr(ac.Directory, "refresh", lambda self, force=False: None)
    assert ac.main(["-c", str(p), "serve"]) == 1
    busy.close()


def test_status_says_when_something_else_answers(tmp_path, monkeypatch, capsys):
    cfg = make_cfg(tmp_path)
    p = tmp_path / "c.json"; p.write_text(json.dumps(cfg))
    monkeypatch.setattr(ac, "_api_call", lambda *a, **k: "Not found")
    assert ac.main(["-c", str(p), "status"]) == 1
    assert "not as the companion" in capsys.readouterr().out
