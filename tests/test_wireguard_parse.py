"""WireGuard config parsing: content, filenames, US filter, and the real docker/conf set."""

import ipaddress
from pathlib import Path

import pytest

from airbl.wireguard import (
    city_region,
    city_regions_for,
    get_scannable_configs,
    is_us_city_near_europe,
    parse_config_content,
    parse_config_file,
    parse_filename,
    scan_config_directory,
)

FAKE_PRIV = "A" * 43 + "="
FAKE_PUB = "B" * 43 + "="
FAKE_PSK = "C" * 43 + "="

REAL_CONF_DIR = Path(__file__).resolve().parent.parent / "docker" / "conf"


# --- parse_config_content ---------------------------------------------------

def test_full_config_with_comments_and_inline_comments():
    content = f"""
# AirVPN config  Endpoint = 9.9.9.9:1
; another comment style
[Interface]
Address = 10.128.0.2/32, fd7d::2/128   # inline comment
PrivateKey = {FAKE_PRIV}
MTU = 1320 ; inline
DNS = 10.128.0.1

[Peer]
PublicKey = {FAKE_PUB}
PresharedKey = {FAKE_PSK}
Endpoint = 192.0.2.10:1637  # entry 3
AllowedIPs = 0.0.0.0/0, ::/0
"""
    r = parse_config_content(content)
    assert r["endpoint_ip"] == "192.0.2.10"
    assert r["endpoint_port"] == 1637
    assert r["address"] == "10.128.0.2/32, fd7d::2/128"
    assert r["mtu"] == 1320
    assert r["dns"] == "10.128.0.1"
    assert r["allowed_ips"] == "0.0.0.0/0, ::/0"
    assert r["public_key"] == FAKE_PUB
    assert r["preshared_key"] == FAKE_PSK
    assert r["private_key"] == FAKE_PRIV


def test_keys_are_section_aware():
    content = """
[Interface]
PublicKey = interface-pubkey-should-be-ignored
Endpoint = 1.1.1.1:1
[Peer]
Address = 10.0.0.9/32
Endpoint = 192.0.2.5:47107
"""
    r = parse_config_content(content)
    assert "public_key" not in r
    assert "address" not in r
    assert (r["endpoint_ip"], r["endpoint_port"]) == ("192.0.2.5", 47107)


def test_first_peer_wins():
    content = """
[Interface]
Address = 10.0.0.2/32
[Peer]
PublicKey = first
Endpoint = 192.0.2.1:1637
[Peer]
PublicKey = second
PresharedKey = second-psk
Endpoint = 192.0.2.2:51820
"""
    r = parse_config_content(content)
    assert r["public_key"] == "first"
    assert r["endpoint_ip"] == "192.0.2.1"
    assert "preshared_key" not in r  # only in the 2nd peer


def test_unknown_section_ignored():
    r = parse_config_content("[Foo]\nEndpoint = 192.0.2.1:1\n[Peer]\nEndpoint = 192.0.2.2:2\n")
    assert r["endpoint_ip"] == "192.0.2.2"


def test_bracketed_ipv6_endpoint():
    r = parse_config_content("[Peer]\nEndpoint = [2001:db8::1]:1637\n")
    assert r["endpoint_ip"] == "2001:db8::1"
    assert r["endpoint_port"] == 1637


def test_bad_endpoint_and_mtu_are_skipped():
    r = parse_config_content("[Interface]\nMTU = abc\n[Peer]\nEndpoint = nonsense\n")
    assert "mtu" not in r and "endpoint_ip" not in r


def test_headerless_snippet_and_case_insensitive_keys():
    r = parse_config_content("endpoint = 192.0.2.7:443\nmtu=1400\n")
    assert r["endpoint_ip"] == "192.0.2.7"
    assert r["mtu"] == 1400


def test_first_occurrence_wins_within_section():
    r = parse_config_content("[Interface]\nMTU = 1300\nMTU = 1400\n")
    assert r["mtu"] == 1300


# --- parse_filename ---------------------------------------------------------

def test_parse_standard_filename():
    m = parse_filename("AirVPN_AT-Vienna_Alderamin_UDP-1637-Entry3.conf")
    assert m == {
        "country_code": "AT", "country_name": "Austria", "city": "Vienna",
        "server_name": "Alderamin", "protocol": "UDP", "port": 1637, "entry_number": 3,
    }


@pytest.mark.parametrize("fname,cc,city,server", [
    ("AirVPN_CA-Toronto-Ontario_Agena_UDP-1637-Entry3.conf", "CA", "Toronto Ontario", "Agena"),
    ("AirVPN_US-Raleigh-NorthCarolina_Foo_UDP-47107-Entry1.conf", "US", "Raleigh NorthCarolina", "Foo"),
    ("AirVPN_US-Atlanta-Georgia_Musca_UDP-1637-Entry3.conf", "US", "Atlanta Georgia", "Musca"),
    ("AirVPN_GB-London_Alathfar_UDP-51820-Entry1.conf", "GB", "London", "Alathfar"),
])
def test_parse_multiword_city(fname, cc, city, server):
    m = parse_filename(fname)
    assert (m["country_code"], m["city"], m["server_name"]) == (cc, city, server)


def test_parse_filename_without_entry_defaults_to_1():
    m = parse_filename("AirVPN_DE-Frankfurt_Ran_UDP-1637.conf")
    assert m["entry_number"] == 1 and m["port"] == 1637


def test_parse_confgen_filename():
    m = parse_filename("CA-Toronto-Ontario_Agena-47107-E1.conf")
    assert m["country_code"] == "CA"
    assert m["city"] == "Toronto Ontario"
    assert m["server_name"] == "Agena"
    assert m["port"] == 47107 and m["entry_number"] == 1
    assert m["protocol"] == "UDP"


def test_parse_filename_garbage_raises():
    with pytest.raises(ValueError):
        parse_filename("wg0.conf")


# --- US filter ------------------------------------------------------------------

@pytest.mark.parametrize("city,expected", [
    ("New York", True), ("NewYorkCity", True), ("Atlanta Georgia", True), ("Chicago Illinois", True),
    ("Dallas Texas", True), ("Los Angeles", False), ("LosAngeles", False), ("Miami", False),
    ("Raleigh NorthCarolina", False), ("Albany", False), ("Sydney", False),
])
def test_us_city_whole_word_matching(city, expected):
    assert is_us_city_near_europe(city) is expected


# --- City regions (dashboard grouping) -------------------------------------------

@pytest.mark.parametrize("cc,city,expected", [
    ("US", "NewYorkCity", "East"), ("US", "Atlanta-Georgia", "East"), ("US", "Miami", "East"),
    ("US", "Raleigh-NorthCarolina", "East"), ("US", "Chicago-Illinois", "Central"),
    ("US", "Dallas Texas", "Central"), ("US", "Denver-Colorado", "Mountain"), ("US", "LosAngeles", "West"),
    ("US", "Phoenix-Arizona", "Mountain"), ("US", "SanJose-California", "West"),
    ("US", "Fremont-California", "West"), ("US", "Seattle-Washington", "West"), ("US", "Las Vegas", "West"),
    ("US", "Salt Lake City", "Mountain"),
    ("US", "Albany", None), ("us", "Miami", "East"),
    # Unknown cities group by their state/province (how new AirVPN servers are named)
    ("US", "Omaha-Nebraska", "Central"), ("US", "Columbus-Ohio", "East"), ("US", "Detroit-Michigan", "East"),
    ("US", "Portland-Maine", "East"), ("US", "Portland-Oregon", "West"), ("US", "Boise-Idaho", "Mountain"),
    ("US", "Ashburn-Virginia", "East"), ("US", "Charleston-WestVirginia", "East"),
    ("US", "Washington-DC", "East"), ("US", "Spokane Washington", "West"), ("US", "Anytown Wyoming", "Mountain"),
    ("US", "KansasCity-Missouri", "Central"), ("CA", "Halifax-NovaScotia", "East"), ("CA", "Winnipeg", "Central"),
    ("CA", "Toronto-Ontario", "East"), ("CA", "Montreal", "East"), ("CA", "Vancouver", "West"),
    ("DE", "Frankfurt", None), ("", "Miami", None),
])
def test_city_region(cc, city, expected):
    assert city_region(cc, city) == expected


def test_city_regions_for_skips_ungrouped():
    got = city_regions_for({"us": {"Miami", "Albany"}, "DE": {"Berlin"}, "CA": ["Vancouver"]})
    assert got == {"US": {"Miami": "East"}, "CA": {"Vancouver": "West"}}


def _write(d: Path, name: str, ip: str = "192.0.2.1"):
    (d / name).write_text(f"[Interface]\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = {ip}:1637\n")


@pytest.fixture
def us_dir(tmp_path):
    for n in ("AirVPN_US-LosAngeles_Maia_UDP-1637-Entry3.conf",
              "AirVPN_US-Miami_Aladfar_UDP-1637-Entry3.conf",
              "AirVPN_US-Raleigh-NorthCarolina_Foo_UDP-1637-Entry3.conf",
              "AirVPN_US-Atlanta-Georgia_Musca_UDP-1637-Entry3.conf",
              "AirVPN_US-NewYorkCity_Bar_UDP-1637-Entry3.conf",
              "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf"):
        _write(tmp_path, n)
    return tmp_path


def test_us_filter_is_off_by_default(us_dir, fresh_config):
    assert fresh_config.regions.us_near_europe_only is False
    configs = scan_config_directory(us_dir)
    assert len(configs) == 6
    assert all(c.should_scan for c in configs)
    assert len(get_scannable_configs(configs)) == 6


def test_us_filter_opt_in(us_dir, fresh_config):
    fresh_config.regions.us_near_europe_only = True
    configs = scan_config_directory(us_dir)
    kept = sorted(c.server_name for c in get_scannable_configs(configs))
    assert kept == ["Bar", "Musca", "Toliman"]
    la = next(c for c in configs if c.server_name == "Maia")
    assert la.should_scan is False
    # Explicit argument overrides the setting
    assert len(get_scannable_configs(configs, us_near_europe_only=False)) == 6


def test_subnet_computed():
    from airbl.wireguard import WireGuardConfig
    c = WireGuardConfig(file_path=Path("x.conf"), filename="x.conf", country_code="CH", country_name="Switzerland",
                        city="Zurich", server_name="X", protocol="UDP", port=1637, entry_number=3,
                        endpoint_ip="192.0.2.77", endpoint_port=1637)
    assert c.subnet == "192.0.2.0/24"


# --- real configs (non-secret fields only) ---------------------------------------

def _public_summary(path: Path) -> dict:
    """Parse a real config and return only non-secret fields."""
    c = parse_config_file(path)
    return {
        "endpoint_ip": c.endpoint_ip,
        "endpoint_port": c.endpoint_port,
        "has_address": bool(c.address),
        "has_pubkey": bool(c.public_key),
        "port": c.port,
        "entry": c.entry_number,
        "cc": c.country_code,
    }


@pytest.mark.skipif(not REAL_CONF_DIR.is_dir(), reason="docker/conf not present")
def test_every_real_config_parses():
    files = sorted(REAL_CONF_DIR.glob("*.conf"))
    if not files:
        pytest.skip("no .conf files in docker/conf")
    bad = []
    for f in files:
        try:
            s = _public_summary(f)
        except Exception as e:  # report only the filename and exception type
            bad.append(f"{f.name}: {type(e).__name__}")
            continue
        try:
            ipaddress.ip_address(s["endpoint_ip"])
            ok = (isinstance(s["endpoint_port"], int) and s["endpoint_port"] > 0
                  and s["has_address"] and s["has_pubkey"]
                  and s["endpoint_port"] == s["port"] and len(s["cc"]) in (2, 3))
        except ValueError:
            ok = False
        if not ok:
            bad.append(f.name)
    assert bad == []
    # scan_config_directory must not drop any of them
    assert len(scan_config_directory(REAL_CONF_DIR)) == len(files)


def test_no_configs_message_names_skipped_region_config(tmp_path, fresh_config):
    from airbl.wireguard import no_configs_message, scan_config_directory, unparsed_config_files
    region = tmp_path / "AirVPN_Europe_UDP-1637-Entry3.conf"
    region.write_text("[Peer]\nEndpoint = europe3.vpn.airdns.org:1637\n")
    (tmp_path / "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf").write_text("[Peer]\nEndpoint = 192.0.2.1:1637\n")
    assert unparsed_config_files(tmp_path) == ["AirVPN_Europe_UDP-1637-Entry3.conf"]
    assert [c.server_name for c in scan_config_directory(tmp_path)] == ["Toliman"]
    (tmp_path / "AirVPN_CH-Zurich_Toliman_UDP-1637-Entry3.conf").unlink()
    # No keys in the region file
    assert "have no PrivateKey" in no_configs_message(tmp_path)
    # Keys present, but the server list couldn't be loaded
    region.write_text("[Interface]\nPrivateKey = " + "A" * 43 + "=\nAddress = 10.128.0.2/32\n" + region.read_text())
    msg = no_configs_message(tmp_path, api_failed=True)
    assert "AirVPN_Europe_UDP-1637-Entry3.conf" in msg and "server list" in msg
    assert "region config" in no_configs_message(tmp_path / "missing")
