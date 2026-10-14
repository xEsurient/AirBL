"""Shared test setup for AirBL.

airbl.config builds global `settings`/`config_manager` objects at import time from
env vars, so the env must be set here before any airbl import.
"""

import os
import sys
import tempfile
from pathlib import Path

_TMP_ROOT = Path(tempfile.mkdtemp(prefix="airbl-tests-"))
os.environ["AIRBL_CONFIG_DIR"] = str(_TMP_ROOT / "conf")
os.environ["AIRBL_CACHE_DIR"] = str(_TMP_ROOT / "data")
os.environ["AIRBL_KILL_SWITCH"] = "0"
os.environ.pop("AIRBL_CONFIG_FILE", None)
os.environ.pop("AIRBL_DB_PATH", None)
(_TMP_ROOT / "conf").mkdir(parents=True, exist_ok=True)
(_TMP_ROOT / "data").mkdir(parents=True, exist_ok=True)

# Make the package importable without installing it
_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import pytest  # noqa: E402

from airbl import config as config_mod  # noqa: E402
from airbl.config import AirBLConfig, config_manager  # noqa: E402

# airbl.web.app calls setup_debug_logging() at import, which replaces sys.stdout and
# the root logger level. Neutralise it before anything imports the app module.
import airbl.web.state as _state_mod  # noqa: E402

_state_mod.setup_debug_logging = lambda: None

from airbl.dronebl import DroneBLResult  # noqa: E402
from airbl.pinger import PingResult  # noqa: E402
from airbl.scanner import ScannedIP, ServerScanResult, ScanSummary  # noqa: E402

TMP_ROOT = _TMP_ROOT

# Obviously fake 44-char base64 keys (never real key material)
FAKE_PRIV = "A" * 43 + "="
FAKE_PUB = "B" * 43 + "="
FAKE_PSK = "C" * 43 + "="


@pytest.fixture
def fresh_config(monkeypatch, tmp_path):
    """Reset config_manager.config to defaults; save() writes into tmp_path only."""
    original = config_manager.config
    config_manager.config = AirBLConfig()
    config_manager.config.scan.confgen_dir = str(tmp_path / "confgen")
    saves = []

    def fake_save():
        saves.append(config_manager.config.model_dump(mode="json"))
        return True

    monkeypatch.setattr(config_manager, "save", fake_save)
    # Some code paths read `state.server_performance_history`; keep it isolated too
    yield config_manager.config
    config_manager.config = original


def _conf_text(endpoint_ip: str, port: int = 1637) -> str:
    return (
        "[Interface]\n"
        f"Address = 10.128.0.2/32, fd7d:76ee:e68f:a993::2/128\n"
        f"PrivateKey = {FAKE_PRIV}\n"
        "MTU = 1320\n"
        "DNS = 10.128.0.1, fd7d:76ee:e68f:a993::1\n\n"
        "[Peer]\n"
        f"PublicKey = {FAKE_PUB}\n"
        f"PresharedKey = {FAKE_PSK}\n"
        f"Endpoint = {endpoint_ip}:{port}\n"
        "AllowedIPs = 0.0.0.0/0, ::/0\n"
        "PersistentKeepalive = 15\n"
    )


SAMPLE_CONFS = {
    "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf": "192.0.2.10",
    "AirVPN_CH-Zurich_Achernar_UDP-1637-Entry3.conf": "192.0.2.11",
    "AirVPN_DE-Frankfurt_Ran_UDP-1637-Entry3.conf": "198.51.100.20",
    "AirVPN_DE-Frankfurt_Taurus_UDP-1637-Entry3.conf": "198.51.100.21",
    "AirVPN_NL-Amsterdam_Alchiba_UDP-1637-Entry3.conf": "203.0.113.30",
}


@pytest.fixture
def sample_conf_dir(tmp_path):
    """Directory of synthetic AirVPN WireGuard configs with fake keys."""
    d = tmp_path / "conf"
    d.mkdir()
    for name, ip in SAMPLE_CONFS.items():
        (d / name).write_text(_conf_text(ip))
    return d


_COUNTRY_NAMES = {"CH": "Switzerland", "DE": "Germany", "NL": "Netherlands", "SE": "Sweden"}


@pytest.fixture
def fake_server():
    """Factory: fake_server(name, reputation="clean"|"blocked"|"unknown", **overrides)."""
    counter = {"n": 0}

    def make(name="Toliman", reputation="clean", country_code="CH", location="Zurich",
             latency_ms=20.0, load_percent=10, speedtest=None, **kw):
        counter["n"] += 1
        ip = kw.pop("ip", f"192.0.2.{100 + counter['n']}")
        ping = PingResult(ip=ip, is_alive=True, avg_rtt_ms=latency_ms, packet_loss=0.0, method="icmp")
        if reputation == "clean":
            dbl = DroneBLResult(ip=ip, is_listed=False)
        elif reputation == "blocked":
            dbl = DroneBLResult(ip=ip, is_listed=True, listing_code=19, listing_reason="Abused VPN Service")
        elif reputation == "unknown":
            dbl = DroneBLResult(ip=ip, is_listed=False, error="timeout")
        else:
            raise ValueError(reputation)
        sip = ScannedIP(ip=ip, server_name=name, country_code=country_code,
                        country_name=_COUNTRY_NAMES.get(country_code, country_code), location=location,
                        is_from_dns=True, dronebl=dbl, ping=ping, is_responsive=True)
        params = dict(
            server_name=name, country_code=country_code,
            country_name=_COUNTRY_NAMES.get(country_code, country_code), location=location,
            load_percent=load_percent, users=5, bandwidth_current=100, bandwidth_max=1000,
            scanned_ips=[sip], speedtest_result=speedtest, exit_ping=ping,
        )
        params.update(kw)
        return ServerScanResult(**params)

    return make


@pytest.fixture
def make_summary():
    def make(servers, **kw):
        from datetime import datetime
        return ScanSummary(servers=list(servers),
                           countries_scanned=sorted({s.country_code for s in servers}),
                           completed_at=kw.pop("completed_at", datetime.now()), **kw)
    return make


_STATE_FIELDS = (
    "current_scan", "live_scan", "is_scanning", "is_paused", "scan_cancelled",
    "scan_task", "port_discovery_results", "db", "current_scan_id", "baseline_speedtest",
    "scan_history", "ban_history", "server_performance_history", "websocket_clients",
    "_last_scan_servers", "_last_scan_entry_pings", "scan_progress", "next_scan_at",
    "settings_updated_event", "all_countries", "servers_by_country", "server_to_city_api",
)


@pytest.fixture(autouse=True)
def reset_web_state():
    """Restore web.state fields that tests touch, so tests don't leak into each other."""
    import copy
    st = _state_mod.state
    saved = {}
    for f in _STATE_FIELDS:
        if hasattr(st, f):
            val = getattr(st, f)
            try:
                saved[f] = copy.copy(val)
            except Exception:
                saved[f] = val
    had_override = hasattr(st, "_config_dir_override")
    override = getattr(st, "_config_dir_override", None)
    # Defaults for a clean start
    st.current_scan = None
    st.live_scan = None
    st.is_scanning = False
    st.is_paused = False
    st.scan_cancelled = False
    st.scan_task = None
    st.port_discovery_results = {}
    st.db = None
    st.websocket_clients = []
    st.baseline_speedtest = None
    st._last_scan_servers = []
    st._last_scan_entry_pings = []
    yield st
    for f, v in saved.items():
        setattr(st, f, v)
    if had_override:
        st._config_dir_override = override
    elif hasattr(st, "_config_dir_override"):
        del st._config_dir_override


class _FakeWS:
    """Captures broadcast_update() messages (broadcast only sends to state.websocket_clients)."""

    def __init__(self):
        self.messages = []

    async def send_json(self, message):
        self.messages.append(message)

    def types(self):
        return [m["type"] for m in self.messages]

    def of(self, type_):
        return [m["data"] for m in self.messages if m["type"] == type_]


@pytest.fixture
def broadcasts():
    """Fake websocket client registered on web.state; collects every broadcast."""
    ws = _FakeWS()
    _state_mod.state.websocket_clients.append(ws)
    return ws
