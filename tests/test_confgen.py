"""confgen: exact config matching, generated config contents, identity cache."""

import os
from pathlib import Path

import pytest

from airbl import confgen
from airbl import config as config_mod
from airbl.confgen import ClientIdentity, get_client_identity, get_or_generate_config
from airbl.wireguard import parse_config_content

FAKE_PRIV = "A" * 43 + "="
FAKE_PUB = "B" * 43 + "="
FAKE_PSK = "C" * 43 + "="
IDENT = ClientIdentity(private_key=FAKE_PRIV, address="10.128.0.9/32", preshared_key=FAKE_PSK)


def _conf(ip, address="10.128.0.2/32"):
    return f"[Interface]\nPrivateKey = {FAKE_PRIV}\nAddress = {address}\n[Peer]\nPublicKey = {FAKE_PUB}\nEndpoint = {ip}:1637\n"


@pytest.fixture
def conf_dir(tmp_path, monkeypatch, fresh_config):
    d = tmp_path / "userconf"
    d.mkdir()
    for name in (
        "AirVPN_DE-Frankfurt_Alathfar_UDP-1637-Entry3.conf",
        "AirVPN_DE-Frankfurt_Centaurus_UDP-1637-Entry3.conf",
        "AirVPN_CA-Toronto-Ontario_Markab_UDP-1637-Entry3.conf",
        "AirVPN_US-Dallas-Texas_Ran_UDP-1637-Entry3.conf",
        "AirVPN_CH-Zurich_Toliman_UDP-47107-Entry1.conf",
    ):
        (d / name).write_text(_conf("192.0.2.1"))
    monkeypatch.setattr(config_mod.settings, "config_dir", d)
    monkeypatch.setattr(confgen, "_cached_identity", None)
    monkeypatch.setattr(confgen, "_cached_identity_key", None)
    return d


def _gen(name, port=1637, entry=3, cc="XX", city="Somewhere", ip="198.51.100.9"):
    return get_or_generate_config(server_name=name, country_code=cc, city=city, endpoint_ip=ip,
                                  server_pubkey=FAKE_PUB, port=port, entry_number=entry, identity=IDENT)


def test_exact_match_returns_user_file(conf_dir):
    p = _gen("Ran", cc="US", city="Dallas Texas")
    assert p.parent == conf_dir and p.name == "AirVPN_US-Dallas-Texas_Ran_UDP-1637-Entry3.conf"
    # "AirVPN " prefix and case are normalised
    assert _gen("AirVPN ran").name == p.name


@pytest.mark.parametrize("name", ["Taurus", "Arkab", "Frank", "Alat"])
def test_substring_names_do_not_match(conf_dir, fresh_config, name):
    p = _gen(name)
    assert p.parent == Path(fresh_config.scan.confgen_dir)
    assert p.name.startswith(f"XX-Somewhere_{name}-1637-E3")


def test_ran_does_not_match_frankfurt_files(conf_dir, fresh_config):
    (conf_dir / "AirVPN_US-Dallas-Texas_Ran_UDP-1637-Entry3.conf").unlink()
    p = _gen("Ran")
    assert p.parent == Path(fresh_config.scan.confgen_dir)


def test_port_and_entry_must_match(conf_dir, fresh_config):
    assert _gen("Toliman", port=47107, entry=1).parent == conf_dir
    assert _gen("Toliman", port=1637, entry=1).parent == Path(fresh_config.scan.confgen_dir)
    assert _gen("Toliman", port=47107, entry=3).parent == Path(fresh_config.scan.confgen_dir)


@pytest.mark.parametrize("pref,expected", [(1000, 1280), (9000, 1500), (1400, 1400), (0, 1320)])
def test_generated_mtu_is_clamped(conf_dir, fresh_config, pref, expected):
    fresh_config.scan.preferred_mtu = pref
    parsed = parse_config_content(_gen("Nobody").read_text())
    assert parsed["mtu"] == expected


def test_generated_config_contents(conf_dir):
    p = _gen("Nobody", port=51820, entry=1, cc="CA", city="Toronto Ontario", ip="203.0.113.4")
    assert p.name == "CA-Toronto-Ontario_Nobody-51820-E1.conf"
    parsed = parse_config_content(p.read_text())
    assert parsed["endpoint_ip"] == "203.0.113.4" and parsed["endpoint_port"] == 51820
    assert parsed["address"] == "10.128.0.9/32"
    assert parsed["public_key"] == FAKE_PUB
    assert parsed["preshared_key"] == FAKE_PSK
    # Generated filename round-trips through parse_filename
    from airbl.wireguard import parse_filename
    meta = parse_filename(p.name)
    assert (meta["server_name"], meta["port"], meta["entry_number"], meta["city"]) == ("Nobody", 51820, 1, "Toronto Ontario")


def test_generated_config_is_always_regenerated(conf_dir, fresh_config):
    fresh_config.scan.preferred_mtu = 1300
    p = _gen("Nobody", ip="203.0.113.1")
    p.write_text("[Interface]\nMTU = 1500\n[Peer]\nEndpoint = 1.1.1.1:1637\n")  # stale file
    fresh_config.scan.preferred_mtu = 1400
    p2 = _gen("Nobody", ip="203.0.113.2")
    assert p2 == p
    parsed = parse_config_content(p.read_text())
    assert parsed["endpoint_ip"] == "203.0.113.2" and parsed["mtu"] == 1400


def test_identity_cache_invalidated_on_dir_change(conf_dir, tmp_path, monkeypatch):
    assert get_client_identity().address == "10.128.0.2/32"
    other = tmp_path / "other"
    other.mkdir()
    (other / "AirVPN_CH-Zurich_X_UDP-1637-Entry3.conf").write_text(_conf("192.0.2.2", address="10.99.0.1/32"))
    monkeypatch.setattr(config_mod.settings, "config_dir", other)
    assert get_client_identity().address == "10.99.0.1/32"


def test_identity_cache_invalidated_on_file_edit(conf_dir):
    assert get_client_identity().address == "10.128.0.2/32"
    first = sorted(conf_dir.glob("*.conf"))[0]
    first.write_text(_conf("192.0.2.1", address="10.55.0.1/32"))
    st = first.stat()
    os.utime(first, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000_000))
    assert get_client_identity().address == "10.55.0.1/32"


def test_identity_cached_when_unchanged(conf_dir, monkeypatch):
    first = get_client_identity()
    calls = []
    monkeypatch.setattr(confgen, "extract_client_identity", lambda d: calls.append(d))
    assert get_client_identity() is first
    assert calls == []


def test_identity_fallback_to_profile_and_error(tmp_path, monkeypatch, fresh_config):
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(config_mod.settings, "config_dir", empty)
    monkeypatch.setattr(confgen, "_cached_identity", None)
    monkeypatch.setattr(confgen, "_cached_identity_key", None)
    fresh_config.wireguard.profiles[0].private_key = ""
    with pytest.raises(ValueError):
        get_client_identity()
    assert confgen.has_client_identity() is False
    fresh_config.wireguard.profiles[0].private_key = FAKE_PRIV
    ident = get_client_identity()
    assert ident.address == "10.128.0.2/10"


def _api_server(name, cc, city, in1, in3=None):
    from airbl.airvpn import AirVPNServer
    return AirVPNServer(public_name=name, country_name=cc, country_code=cc.lower(), location=city,
                        continent="Europe", bandwidth_current=1, bandwidth_max=10, users=1,
                        load_percent=5, ip_v4_in1=in1, ip_v4_in3=in3)


def test_configs_from_api_uses_region_config_keys(tmp_path, fresh_config):
    d = tmp_path / "region"
    d.mkdir()
    (d / "AirVPN_Europe_UDP-443-Entry3.conf").write_text(
        f"[Interface]\nPrivateKey = {FAKE_PRIV}\nAddress = 10.128.0.7/32\n"
        f"[Peer]\nPublicKey = {FAKE_PUB}\nPresharedKey = {FAKE_PSK}\nEndpoint = europe3.vpn.airdns.org:443\n")
    servers = [
        _api_server("Toliman", "CH", "Zurich", "192.0.2.1", "192.0.2.3"),
        _api_server("Ran", "US", "Dallas-Texas", "192.0.2.5"),  # no Entry 3
        _api_server("Two Words", "DE", "Berlin", "192.0.2.9"),  # unparseable name, skipped
    ]
    configs = {c.server_name: c for c in confgen.configs_from_api(servers, d)}
    assert set(configs) == {"Toliman", "Ran"}
    t, r = configs["Toliman"], configs["Ran"]
    assert (t.country_code, t.city, t.endpoint_ip, t.endpoint_port, t.entry_number) == ("CH", "Zurich", "192.0.2.3", 443, 3)
    assert (r.city, r.endpoint_ip, r.entry_number) == ("Dallas Texas", "192.0.2.5", 1)
    assert t.file_path.parent == Path(fresh_config.scan.confgen_dir)
    assert (t.private_key, t.public_key, t.preshared_key, t.address) == (FAKE_PRIV, FAKE_PUB, FAKE_PSK, "10.128.0.7/32")
    # No keys: nothing generated
    empty = tmp_path / "empty"
    empty.mkdir()
    assert confgen.configs_from_api(servers, empty) == []
