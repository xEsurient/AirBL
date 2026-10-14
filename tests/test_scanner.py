"""Scanner result model: reputation, notes, score, dedupe, to_dict contract."""

from pathlib import Path

import pytest

from airbl import scanner as scanner_mod
from airbl.dronebl import DroneBLResult
from airbl.pinger import PingResult
from airbl.scanner import EnhancedScanner, ScannedIP, ServerScanResult


def _ip(ip="192.0.2.1", listed=False, error=None, responsive=True, latency=20.0, code=19):
    dbl = None if error == "none" else DroneBLResult(
        ip=ip, is_listed=listed, listing_code=code if listed else None,
        listing_reason="Abused VPN Service" if listed else None, error=error)
    ping = PingResult(ip=ip, is_alive=responsive, avg_rtt_ms=latency if responsive else None,
                      method="icmp", icmp_avg_ms=latency, tcp_avg_ms=None)
    return ScannedIP(ip=ip, server_name="S", country_code="CH", country_name="Switzerland",
                     location="Zurich", dronebl=dbl, ping=ping, is_responsive=responsive)


def _srv(ips, **kw):
    params = dict(server_name="S", country_code="CH", country_name="Switzerland", location="Zurich",
                  load_percent=10, users=1, bandwidth_current=1, bandwidth_max=10, scanned_ips=ips)
    params.update(kw)
    return ServerScanResult(**params)


# --- reputation ----------------------------------------------------------------

def test_clean_blocked_unknown(fake_server):
    clean = fake_server(reputation="clean")
    assert (clean.reputation, clean.is_clean, clean.reputation_note) == ("clean", True, None)
    blocked = fake_server(reputation="blocked")
    assert (blocked.reputation, blocked.is_clean, blocked.is_blocked) == ("blocked", False, True)
    assert blocked.reputation_note is None and blocked.score == 0.0
    unknown = fake_server(reputation="unknown")
    assert unknown.reputation == "unknown" and not unknown.is_clean and not unknown.is_blocked
    assert unknown.reputation_note == "DroneBL lookup failed for 1/1 exit IP(s): timeout"


def test_is_clean_only_when_all_ips_verified():
    s = _srv([_ip("192.0.2.1"), _ip("192.0.2.2", error="DNS timeout")])
    assert s.reputation == "unknown" and not s.is_clean
    assert "1/2" in s.reputation_note and "DNS timeout" in s.reputation_note
    s2 = _srv([_ip("192.0.2.1"), _ip("192.0.2.2", error="none")])
    assert s2.reputation == "unknown" and "not checked" in s2.reputation_note
    assert _srv([_ip("192.0.2.1"), _ip("192.0.2.2", responsive=False)]).is_clean


def test_blocked_wins_over_unknown():
    s = _srv([_ip("192.0.2.1", listed=True), _ip("192.0.2.2", error="x")])
    assert s.reputation == "blocked" and s.is_blocked


def test_notes_for_empty_results():
    assert _srv([]).reputation_note == "No exit IPs found (DNS returned no records)"
    assert _srv([], dns_error="dig timed out").reputation_note == "DNS lookup failed: dig timed out"
    assert _srv([], scan_error="boom").reputation_note == "Scan failed: boom"
    assert _srv([]).reputation == "unknown" and _srv([]).score == 0.0


# --- score ----------------------------------------------------------------------

@pytest.mark.parametrize("speedtest,expected", [
    ({"error": "x", "deviation_score": 90}, 0.0),
    ({"deviation_score": 150}, 100.0),
    ({"deviation_score": 80.5}, 80.5),
    ({"deviation_score": -5}, 0.0),
    ({"score": 7.5}, 75.0),
    ({"score": 12}, 100.0),
    ({"download_mbps": 100}, 0.0),
])
def test_score_with_speedtest(speedtest, expected):
    assert _srv([_ip()], speedtest_result=speedtest).score == pytest.approx(expected)


@pytest.mark.parametrize("latency,load,expected", [
    (20.0, 10, 88.0),      # 100 - 10 - 2
    (0.0001, 0, 100.0),
    (300.0, 50, 0.0),      # capped at 0
])
def test_score_from_ping_and_load(latency, load, expected):
    assert _srv([_ip(latency=latency)], load_percent=load).score == pytest.approx(expected, abs=0.01)


def test_unknown_load_uses_mid_penalty():
    s = _srv([_ip(latency=20.0)], load_percent=0, load_known=False)
    assert s.score == pytest.approx(80.0)  # 100 - 10 - 50/5
    assert _srv([_ip(latency=20.0)], load_percent=0).score == pytest.approx(90.0)


def test_score_falls_back_to_entry_pings():
    s = _srv([_ip(responsive=False)], load_percent=0,
             entry1_ping=PingResult(ip="198.51.100.1", is_alive=True, avg_rtt_ms=30.0),
             entry3_ping=PingResult(ip="198.51.100.3", is_alive=True, avg_rtt_ms=10.0))
    assert s.score == pytest.approx(95.0)


def test_score_without_ping_and_zero_load_is_unranked_but_positive():
    assert _srv([_ip(responsive=False)], load_percent=0).score == pytest.approx(1.0)


def test_score_without_ping_stays_positive_with_load():
    assert _srv([_ip(responsive=False)], load_percent=30).score > 0


def test_score_always_within_0_100(fake_server):
    for st in (None, {"deviation_score": 10_000}, {"score": -3}, {"deviation_score": None, "score": None}):
        for lat in (0.0001, 50.0, 10_000.0):
            sc = _srv([_ip(latency=lat)], speedtest_result=st, load_percent=100).score
            assert 0.0 <= sc <= 100.0


# --- ScannedIP ------------------------------------------------------------------

@pytest.mark.parametrize("kw,status,color", [
    (dict(listed=True), "BLOCKED", "red"),
    (dict(listed=True, responsive=False), "BLOCKED", "red"),
    (dict(error="DNS timeout"), "UNKNOWN", "yellow"),
    (dict(error="none"), "UNKNOWN", "yellow"),
    (dict(responsive=False), "OFFLINE", "dim"),
    (dict(), "OK", "green"),
])
def test_scanned_ip_status(kw, status, color):
    ip = _ip(**kw)
    assert ip.status == status and ip.status_color == color


def test_scanned_ip_to_dict_contract():
    d = _ip(listed=True, code=19).to_dict()
    for key in ("ip", "is_blocked", "reputation_verified", "status", "latency_ms", "method", "icmp_ms",
                "tcp_ms", "dronebl_reason", "dronebl_code", "dronebl_checked_at", "dronebl_error"):
        assert key in d
    assert d["is_blocked"] is True and d["dronebl_code"] == 19 and d["method"] == "icmp"
    assert isinstance(d["dronebl_checked_at"], str)
    clean = _ip().to_dict()
    assert clean["dronebl_code"] is None and clean["dronebl_reason"] is None
    unchecked = _ip(error="none").to_dict()
    assert unchecked["dronebl_checked_at"] is None and unchecked["dronebl_error"] == "Not checked"


def test_server_to_dict_contract(fake_server):
    s = fake_server(reputation="blocked", entry3_ping=PingResult(ip="198.51.100.3", is_alive=True,
                                                                 avg_rtt_ms=12.34, method="tcp", tcp_avg_ms=12.34))
    d = s.to_dict()
    for key in ("exit_ips", "reputation", "reputation_note", "is_blocked", "is_clean", "score",
                "exit_ping", "entry1_ping", "entry3_ping", "best_ip", "speedtest", "scanned_at"):
        assert key in d
    assert d["reputation"] == "blocked" and d["is_blocked"] is True
    ip0 = d["exit_ips"][0]
    for key in ("dronebl_code", "dronebl_checked_at", "method", "icmp_ms", "tcp_ms", "is_blocked"):
        assert key in ip0
    assert d["entry3_ping"]["method"] == "tcp" and d["entry3_ping"]["tcp_ms"] == 12.3
    assert d["entry3_ping"]["latency_ms"] == 12.3
    assert d["entry1_ping"] is None
    import json
    json.dumps(d)  # serialisable


# --- scanner: dedupe and failure handling ------------------------------------------

def _write_conf(d: Path, name: str, ip: str):
    d.joinpath(name).write_text(f"[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = {ip}:1637\n")


def test_one_result_per_server(tmp_path, fresh_config):
    _write_conf(tmp_path, "AirVPN_CH-Zurich_Toliman_UDP-47107-Entry1.conf", "192.0.2.1")
    _write_conf(tmp_path, "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf", "192.0.2.3")
    _write_conf(tmp_path, "AirVPN_CH-Zurich_Toliman_UDP-51820-Entry1.conf", "192.0.2.1")
    _write_conf(tmp_path, "AirVPN_CH-Zurich_Achernar_UDP-47107-Entry1.conf", "192.0.2.9")
    _write_conf(tmp_path, "AirVPN_CH-Zurich_Achernar_UDP-51820-Entry3.conf", "192.0.2.8")
    sc = EnhancedScanner(config_dir=tmp_path, us_near_europe_only=False)
    res = sc.get_servers_for_country("CH")
    by = {c.server_name: c for c, _ in res}
    assert sorted(by) == ["Achernar", "Toliman"]
    assert (by["Toliman"].port, by["Toliman"].entry_number) == (1637, 3)


def test_server_filter_and_exclude(sample_conf_dir, fresh_config):
    sc = EnhancedScanner(config_dir=sample_conf_dir, server_filter={"toliman", "Achernar"},
                         server_exclude={"ACHERNAR"}, us_near_europe_only=False)
    assert [c.server_name for c, _ in sc.get_servers_for_country("CH")] == ["Toliman"]
    assert sc.get_servers_for_country("DE") == []


async def test_scan_all_keeps_failed_server_as_unknown(sample_conf_dir, fresh_config, monkeypatch):
    async def no_api():
        raise RuntimeError("offline")

    async def fake_lookup(name):
        if name == "Toliman":
            raise RuntimeError("kaboom")
        if name == "Ran":
            return set(), "dig timed out"
        return {"203.0.113.50"}, None

    async def fake_ping_batch(ips, concurrency=None, progress_callback=None):
        return [PingResult(ip=i, is_alive=True, avg_rtt_ms=10.0) for i in ips]

    async def fake_dronebl(ips, concurrency=None, progress_callback=None):
        return [DroneBLResult(ip=i, is_listed=False) for i in ips]

    monkeypatch.setattr(scanner_mod, "get_airvpn_status", no_api)
    monkeypatch.setattr(scanner_mod, "lookup_exit_ips", fake_lookup)
    monkeypatch.setattr(scanner_mod, "ping_batch", fake_ping_batch)
    monkeypatch.setattr(scanner_mod, "check_dronebl_batch", fake_dronebl)

    sc = EnhancedScanner(config_dir=sample_conf_dir, us_near_europe_only=False)
    summary = await sc.scan_all()
    by = {s.server_name: s for s in summary.servers}
    assert len(summary.servers) == 5 == len(by)
    assert by["Toliman"].reputation == "unknown" and by["Toliman"].reputation_note == "Scan failed: kaboom"
    assert by["Ran"].reputation_note == "DNS lookup failed: dig timed out"
    assert by["Achernar"].is_clean and by["Achernar"].load_known is False
    assert summary.unknown_servers_count == 2 and summary.clean_servers_count == 3
    assert summary.countries_scanned == ["CH", "DE", "NL"]


async def test_region_config_scans_every_api_server(monkeypatch, tmp_path, fresh_config):
    """Only a region config (AirVPN_Europe_...): its keys + the API list give one config per server."""
    from airbl.airvpn import AirVPNServer, AirVPNStatus
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "AirVPN_Europe_UDP-1637-Entry3.conf").write_text(
        "[Interface]\nPrivateKey = " + "A" * 43 + "=\nAddress = 10.128.0.2/32\n"
        "[Peer]\nPublicKey = " + "B" * 43 + "=\nEndpoint = europe3.vpn.airdns.org:1637\n")

    def srv(name, cc, city, in1, in3):
        return AirVPNServer(public_name=name, country_name=cc, country_code=cc.lower(), location=city,
                            continent="Europe", bandwidth_current=1, bandwidth_max=10, users=1,
                            load_percent=5, ip_v4_in1=in1, ip_v4_in3=in3)

    async def fake_api():
        return AirVPNStatus(servers=[srv("Toliman", "CH", "Zurich", "192.0.2.1", "192.0.2.3"),
                                     srv("Alchiba", "NL", "Amsterdam", "192.0.2.5", "192.0.2.7")],
                            countries=[])

    async def fake_lookup(name, *a, **k):
        return {"203.0.113.50"}, None

    async def fake_ping_batch(ips, concurrency=None, progress_callback=None):
        return [PingResult(ip=i, is_alive=True, avg_rtt_ms=10.0) for i in ips]

    async def fake_dronebl(ips, concurrency=None, progress_callback=None):
        return [DroneBLResult(ip=i, is_listed=False) for i in ips]

    monkeypatch.setattr(scanner_mod, "get_airvpn_status", fake_api)
    monkeypatch.setattr(scanner_mod, "lookup_exit_ips", fake_lookup)
    monkeypatch.setattr(scanner_mod, "ping_batch", fake_ping_batch)
    monkeypatch.setattr(scanner_mod, "check_dronebl_batch", fake_dronebl)

    sc = EnhancedScanner(config_dir=conf, country_filter={"CH"}, us_near_europe_only=False)
    updates = [u async for u in sc.scan_iter()]
    assert [u.server.server_name for u in updates] == ["Toliman"]
    s = updates[-1].server
    assert s.is_clean and s.config_file.name == "CH-Zurich_Toliman-1637-E3.conf"
    assert s.config_file.parent == Path(fresh_config.scan.confgen_dir)
