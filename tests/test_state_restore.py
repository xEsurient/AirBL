"""Rebuilding the last completed scan from the DB after a restart (no network)."""

import pytest
from fastapi.testclient import TestClient

import airbl.airvpn as airvpn
from airbl.config import settings
from airbl.database import DatabaseManager
from airbl.web.state import state


@pytest.fixture
async def db(tmp_path):
    d = DatabaseManager(tmp_path / "restore.db")
    await d.init()
    yield d
    await d.close()


def _row(name, reputation, blocked=False, ip="192.0.2.50", ping=15.0):
    return {"server_name": name, "reputation": reputation, "is_blocked": blocked, "load_percent": 33,
            "users": 7, "responsive_count": 1, "score": 80.0,
            "exit_ping": {"ip": ip, "latency_ms": ping} if ip else None}


async def _populate(db):
    sid = await db.add_scan_result({})
    for r in (_row("Toliman", "clean"), _row("Ran", "blocked", True), _row("Taurus", "unknown"),
              _row("Achernar", "unknown", ip=None), _row("Alchiba", None, False)):
        await db.add_server_scan_result(sid, r)
    await db.add_entry_ping(sid, "Toliman", "ENTRY1", "10.0.0.1", 25.0, True)
    await db.add_entry_ping(sid, "Toliman", "ENTRY3", "10.0.0.3", 18.0, True)
    await db.update_scan_result(sid, {"total_servers": 5, "clean_servers": 2, "blocked_servers": 1})
    await db.add_speedtest_result({"server_name": "Ookla Zurich", "download_mbps": 250.0, "upload_mbps": 60.0,
                                   "ping_ms": 9.0, "vpn_server_name": "Toliman", "vpn_country_code": "CH",
                                   "vpn_port": 1637, "vpn_entry": "Entry 3"}, scan_id=sid)
    await db.add_speedtest_result({"error": "Failed to connect", "vpn_server_name": "Ran"}, scan_id=sid)
    # A later cancelled scan must be ignored
    later = await db.add_scan_result({})
    await db.add_server_scan_result(later, _row("Partial", "clean"))
    await db.set_scan_status(later, "cancelled")
    return sid


async def _restore(db, conf_dir):
    state.db = db
    state.config_dir = conf_dir
    state._last_scan_servers = await db.get_last_scan_servers()
    state._last_scan_entry_pings = await db.get_last_scan_entry_pings()
    return await state._restore_last_scan()


async def test_restore_preserves_reputation(db, sample_conf_dir, fresh_config):
    await _populate(db)
    summary = await _restore(db, sample_conf_dir)
    assert summary is not None and summary.restored is True
    by = {s.server_name: s for s in summary.servers}
    assert set(by) == {"Toliman", "Ran", "Taurus", "Achernar", "Alchiba"}
    assert by["Toliman"].reputation == "clean"
    assert by["Ran"].reputation == "blocked"
    assert by["Taurus"].reputation == "unknown" and len(by["Taurus"].scanned_ips) == 1
    assert by["Achernar"].reputation == "unknown" and by["Achernar"].scanned_ips == []
    assert by["Alchiba"].reputation == "clean"  # legacy row without reputation, not blocked
    assert summary.clean_servers_count == 2 and summary.blocked_servers_count == 1
    assert summary.unknown_servers_count == 2


async def test_restore_details(db, sample_conf_dir, fresh_config):
    await _populate(db)
    summary = await _restore(db, sample_conf_dir)
    t = next(s for s in summary.servers if s.server_name == "Toliman")
    assert t.country_code == "CH" and t.location == "Zurich" and t.country_name
    assert t.config_file == sample_conf_dir / "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf"
    assert t.wg_pubkey  # from the (fake) config
    assert t.exit_ping.ip == "192.0.2.50" and t.exit_ping.avg_rtt_ms == 15.0
    assert t.entry1_ping.avg_rtt_ms == 25.0 and t.entry3_ping.ip == "10.0.0.3"
    assert t.load_percent == 33 and t.users == 7
    st = t.speedtest_result
    assert st["download_mbps"] == 250.0 and st["restored"] is True and st["vpn_port"] == 1637
    r = next(s for s in summary.servers if s.server_name == "Ran")
    assert r.speedtest_result["error"] == "Failed to connect"
    assert summary.countries_scanned == ["CH", "DE", "NL"]
    # Restored results are usable by the exports
    assert {s.server_name for s in summary.clean_servers} == {"Toliman", "Alchiba"}


async def test_restore_none_without_complete_scan(db, sample_conf_dir):
    sid = await db.add_scan_result({})
    await db.add_server_scan_result(sid, _row("Toliman", "clean"))
    await db.set_scan_status(sid, "cancelled")
    assert await _restore(db, sample_conf_dir) is None


async def test_startup_restores_without_network(monkeypatch, tmp_path, sample_conf_dir, fresh_config):
    # Seed a DB where startup() will look for it
    monkeypatch.setattr(settings, "cache_dir", tmp_path)
    seed = DatabaseManager(tmp_path / "airbl.db")
    await seed.init()
    await _populate(seed)
    await seed.close()

    async def no_api():
        raise RuntimeError("network disabled in tests")

    monkeypatch.setattr(airvpn, "get_airvpn_status", no_api)
    state.config_dir = sample_conf_dir
    state.current_scan = None
    try:
        await state.startup()
        assert state.current_scan is not None and state.current_scan.restored
        assert {s.server_name for s in state.current_scan.clean_servers} == {"Toliman", "Alchiba"}
        assert state.ban_history == {"Ran": 1}
        assert "CH" in state.countries_with_configs and "Toliman" in state.servers_with_configs

        from airbl.web.app import create_app
        client = TestClient(create_app())
        status = client.get("/api/status").json()
        assert status["results_restored"] is True and status["has_results"] is True
        export = client.get("/api/export/gluetun")
        assert export.status_code == 200
        assert set(export.text.split("=", 1)[1].split(",")) == {"Toliman", "Alchiba"}
    finally:
        if state.db:
            await state.db.close()


async def test_startup_with_region_config_uses_api_list(monkeypatch, tmp_path, fresh_config):
    from airbl.airvpn import AirVPNServer, AirVPNStatus
    from airbl.confgen import configs_from_api
    monkeypatch.setattr(settings, "cache_dir", tmp_path)
    conf = tmp_path / "conf"
    conf.mkdir()
    (conf / "AirVPN_Europe_UDP-1637-Entry3.conf").write_text(
        "[Interface]\nPrivateKey = " + "A" * 43 + "=\nAddress = 10.128.0.2/32\n"
        "[Peer]\nEndpoint = europe3.vpn.airdns.org:1637\n")
    servers = [AirVPNServer(public_name="Ran", country_name="United States", country_code="us",
                            location="Dallas-Texas", continent="America", bandwidth_current=1,
                            bandwidth_max=10, users=1, load_percent=5, ip_v4_in1="192.0.2.5")]

    async def fake_api():
        return AirVPNStatus(servers=servers, countries=[])

    monkeypatch.setattr(airvpn, "get_airvpn_status", fake_api)
    state.config_dir = conf
    state.current_scan = None
    try:
        await state.startup()
        assert state.region_configs is True
        assert "US" in state.countries_with_configs and "Ran" in state.servers_with_configs
        assert "Dallas Texas" in state.cities_by_country["US"]
        # After a scan generated them, restore/speedtests find the generated configs
        assert state.server_configs() == []
        configs_from_api(servers, conf)
        assert [c.server_name for c in state.server_configs()] == ["Ran"]
    finally:
        state.region_configs = False
        if state.db:
            await state.db.close()
