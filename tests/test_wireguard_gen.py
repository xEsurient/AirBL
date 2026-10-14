"""WireGuard profile export: modes, filters, wg0, manifests, AllowedIPs, pubkeys."""

import pytest

from airbl import confgen
from airbl import wireguard_gen as wg
from airbl.config import WireGuardProfileConfig
from airbl.confgen import ClientIdentity
from airbl.gluetun import WG_PUBKEY
from airbl.pinger import PingResult
from airbl.web.state import state
from airbl.wireguard import parse_config_content

FAKE_PRIV = "A" * 43 + "="


@pytest.fixture
def identity(monkeypatch):
    """Client identity used by _build_conf (IPv4-only by default)."""
    box = {"id": ClientIdentity(private_key=FAKE_PRIV, address="10.128.0.2/32")}
    monkeypatch.setattr(confgen, "get_client_identity", lambda: box["id"])
    return box


@pytest.fixture
def srv(fake_server):
    n = {"i": 0}

    def mk(name, rep="clean", cc="CH", city="Zurich", latency=20.0, e1=True, e3=True, pubkey=""):
        n["i"] += 1
        i = n["i"]
        return fake_server(
            name=name, reputation=rep, country_code=cc, location=city, latency_ms=latency,
            entry1_ping=PingResult(ip=f"198.51.100.{i}", is_alive=e1, avg_rtt_ms=5.0) if e1 is not None else None,
            entry3_ping=PingResult(ip=f"203.0.113.{i}", is_alive=e3, avg_rtt_ms=5.0) if e3 is not None else None,
            wg_pubkey=pubkey,
        )
    return mk


@pytest.fixture
def run(fresh_config, make_summary, identity, tmp_path):
    out = tmp_path / "wg"

    def go(servers, profiles=None, **profile_kw):
        state.current_scan = make_summary(servers)
        if profiles is None:
            params = dict(name="P1", enabled=True, private_key=FAKE_PRIV, output_dir=str(out))
            params.update(profile_kw)
            profiles = [WireGuardProfileConfig(**params)]
        fresh_config.wireguard.profiles = profiles
        return profiles

    go.out = out
    return go


async def _gen(run, servers, **kw):
    run(servers, **kw)
    await wg.generate_wireguard_configs()
    return sorted(p.name for p in run.out.glob("*.conf")) if run.out.exists() else []


def _endpoint(path):
    return parse_config_content(path.read_text())["endpoint_ip"]


# --- modes --------------------------------------------------------------------------------

@pytest.fixture
def mix(srv):
    return [
        srv("Alpha", latency=10.0),                       # best clean CH
        srv("Beta", latency=40.0),                        # 2nd clean CH
        srv("Gamma", cc="CH", city="Geneva", latency=30.0),
        srv("Delta", cc="DE", city="Frankfurt", latency=20.0),
        srv("Bad", rep="blocked", latency=1.0),
        srv("Unk", rep="unknown", latency=1.0),
    ]


async def test_mode_clean(run, mix):
    assert await _gen(run, mix, mode="clean") == ["Alpha.conf", "Beta.conf", "Delta.conf", "Gamma.conf"]


async def test_mode_custom_includes_blocked(run, mix):
    assert await _gen(run, mix, mode="custom") == [
        "Alpha.conf", "Bad.conf", "Beta.conf", "Delta.conf", "Gamma.conf", "Unk.conf"]


async def test_mode_fastest_clean(run, mix):
    assert await _gen(run, mix, mode="fastest_clean") == ["Alpha.conf"]


async def test_mode_fastest_single_file(run, mix):
    assert await _gen(run, mix, mode="fastest") == ["Alpha.conf"]


async def test_mode_fastest_clean_with_country_filter(run, mix):
    assert await _gen(run, mix, mode="fastest_clean", countries=["de"]) == ["Delta.conf"]


async def test_mode_countries(run, mix):
    assert await _gen(run, mix, mode="countries") == ["CH.conf", "DE.conf"]
    ch = _endpoint(run.out / "CH.conf")
    alpha = next(s for s in mix if s.server_name == "Alpha")
    assert ch == alpha.entry3_ping.ip


async def test_mode_cities(run, mix):
    assert await _gen(run, mix, mode="cities") == ["CH-Geneva.conf", "CH-Zurich.conf", "DE-Frankfurt.conf"]
    gamma = next(s for s in mix if s.server_name == "Gamma")
    assert _endpoint(run.out / "CH-Geneva.conf") == gamma.entry3_ping.ip


async def test_city_filter(run, mix):
    assert await _gen(run, mix, mode="clean", cities=["geneva"]) == ["Gamma.conf"]


async def test_countries_mode_skips_server_without_entry(run, srv):
    a = srv("Alpha", latency=10.0, e3=False)  # best, but entry 3 dead
    b = srv("Beta", latency=40.0)
    assert await _gen(run, [a, b], mode="countries") == ["CH.conf"]
    assert _endpoint(run.out / "CH.conf") == b.entry3_ping.ip


async def test_entry1_selection(run, srv):
    a = srv("Alpha")
    await _gen(run, [a], mode="clean", entry_ip="ENTRY1", port=47107)
    parsed = parse_config_content((run.out / "Alpha.conf").read_text())
    assert parsed["endpoint_ip"] == a.entry1_ping.ip and parsed["endpoint_port"] == 47107


async def test_profile_without_private_key_skipped(run, mix):
    assert await _gen(run, mix, mode="clean", private_key="") == []


async def test_disabled_profile_skipped(run, mix):
    assert await _gen(run, mix, mode="clean", enabled=False) == []


# --- wg0 ------------------------------------------------------------------------------------

async def test_wg0_never_blocked_in_custom(run, srv):
    bad = srv("Bad", rep="blocked", latency=1.0)
    good = srv("Good", latency=50.0)
    await _gen(run, [bad, good], mode="custom", auto_update_wg0=True)
    assert _endpoint(run.out / "wg0.conf") == good.entry3_ping.ip


async def test_wg0_not_written_when_only_blocked(run, srv):
    names = await _gen(run, [srv("Bad", rep="blocked")], mode="custom", auto_update_wg0=True)
    assert names == ["Bad.conf"]


async def test_wg0_may_be_blocked_in_fastest(run, srv):
    bad = srv("Bad", rep="blocked")
    names = await _gen(run, [bad], mode="fastest", auto_update_wg0=True)
    assert names == ["Bad.conf", "wg0.conf"]
    assert _endpoint(run.out / "wg0.conf") == bad.entry3_ping.ip


async def test_wg0_best_clean(run, mix):
    await _gen(run, mix, mode="clean", auto_update_wg0=True)
    alpha = next(s for s in mix if s.server_name == "Alpha")
    assert _endpoint(run.out / "wg0.conf") == alpha.entry3_ping.ip


# --- manifests / stale cleanup -------------------------------------------------------------

async def test_stale_cleanup_per_profile(run, srv, tmp_path):
    out = run.out
    a, b = srv("Alpha", latency=10.0), srv("Beta", latency=30.0)
    d = srv("Delta", cc="DE", city="Frankfurt")
    p1 = WireGuardProfileConfig(name="P1", enabled=True, private_key=FAKE_PRIV, output_dir=str(out), mode="clean",
                                auto_update_wg0=True)
    p2 = WireGuardProfileConfig(name="Second / profile", enabled=True, private_key=FAKE_PRIV, output_dir=str(out),
                                mode="countries")
    p3 = WireGuardProfileConfig(name="P3", enabled=True, private_key=FAKE_PRIV, output_dir=str(out),
                                mode="custom", countries=["DE"])
    out.mkdir(parents=True)
    (out / "mine.conf").write_text("user file")
    run([a, b, d], profiles=[p1, p2, p3])
    await wg.generate_wireguard_configs()
    assert sorted(p.name for p in out.glob("*.conf")) == [
        "Alpha.conf", "Beta.conf", "CH.conf", "DE.conf", "Delta.conf", "mine.conf", "wg0.conf"]
    assert (out / ".airbl-generated-P1").exists() and (out / ".airbl-generated-Second_profile").exists()

    # Beta and Delta become blocked: P1 drops Beta and Delta, but Delta is still P3's (custom)
    b.scanned_ips[0].dronebl.is_listed = True
    d.scanned_ips[0].dronebl.is_listed = True
    await wg.generate_wireguard_configs()
    names = sorted(p.name for p in out.glob("*.conf"))
    assert names == ["Alpha.conf", "CH.conf", "Delta.conf", "mine.conf", "wg0.conf"]

    # Alpha becomes blocked too: P1 and P2 drop their files; wg0 and the user file stay
    a.scanned_ips[0].dronebl.is_listed = True
    await wg.generate_wireguard_configs()
    names = sorted(p.name for p in out.glob("*.conf"))
    assert "mine.conf" in names and "wg0.conf" in names
    assert "Alpha.conf" not in names  # P1's own stale file removed
    assert "CH.conf" not in names     # no clean CH server left for P2


async def test_stale_cleanup_ignores_suspicious_manifest_entries(run, srv, tmp_path):
    out = run.out
    out.mkdir(parents=True)
    victim = tmp_path / "outside.conf"
    victim.write_text("x")
    (out / "notes.txt").write_text("keep")
    (out / ".airbl-generated-P1").write_text("../outside.conf\nnotes.txt\nwg0.conf\n")
    (out / "wg0.conf").write_text("keep")
    await _gen(run, [srv("Alpha")], mode="clean")
    assert victim.exists() and (out / "notes.txt").exists() and (out / "wg0.conf").exists()


# --- AllowedIPs / pubkey ----------------------------------------------------------------

@pytest.mark.parametrize("layer,address,expected", [
    ("Both", "10.0.0.2/32", "0.0.0.0/0"),
    ("Both", "10.0.0.2/32, fd00::2/128", "0.0.0.0/0, ::/0"),
    ("IPv4", "10.0.0.2/32, fd00::2/128", "0.0.0.0/0"),
    ("IPv6", "10.0.0.2/32, fd00::2/128", "10.128.0.1/32, ::/0"),
    ("IPv6", "10.0.0.2/32", "0.0.0.0/0"),
])
def test_allowed_ips(layer, address, expected):
    assert wg._allowed_ips(layer, address) == expected


@pytest.mark.parametrize("address,expected", [
    ("10.0.0.2/32", "0.0.0.0/0"),
    ("10.0.0.2/32,fd00::2/128", "0.0.0.0/0, ::/0"),
])
async def test_allowed_ips_in_file(run, srv, identity, address, expected):
    identity["id"] = ClientIdentity(private_key=FAKE_PRIV, address=address)
    await _gen(run, [srv("Alpha")], mode="clean", ip_layer_exit="Both")
    parsed = parse_config_content((run.out / "Alpha.conf").read_text())
    assert parsed["allowed_ips"] == expected and parsed["address"] == address


async def test_no_identity_falls_back(run, srv, monkeypatch):
    def raise_():
        raise ValueError("none")

    monkeypatch.setattr(confgen, "get_client_identity", raise_)
    await _gen(run, [srv("Alpha")], mode="clean")
    assert parse_config_content((run.out / "Alpha.conf").read_text())["address"] == "10.128.0.2/10"


@pytest.mark.parametrize("profile_key,server_key,expected", [
    ("PROFILEKEY=", "SERVERKEY=", "PROFILEKEY="),
    ("  ", "SERVERKEY=", "SERVERKEY="),
    ("", "", WG_PUBKEY),
])
async def test_pubkey_precedence(run, srv, profile_key, server_key, expected):
    await _gen(run, [srv("Alpha", pubkey=server_key)], mode="clean", public_key=profile_key)
    assert parse_config_content((run.out / "Alpha.conf").read_text())["public_key"] == expected


async def test_conf_contents(run, srv):
    await _gen(run, [srv("Alpha")], mode="clean", mtu=1400, keepalive=15, port=51820)
    text = (run.out / "Alpha.conf").read_text()
    parsed = parse_config_content(text)
    assert parsed["mtu"] == 1400 and parsed["endpoint_port"] == 51820 and parsed["dns"] == "10.128.0.1"
    assert "PersistentKeepalive = 15" in text


async def test_no_scan_results_is_noop(fresh_config, tmp_path):
    state.current_scan = None
    fresh_config.wireguard.profiles = [WireGuardProfileConfig(enabled=True, private_key=FAKE_PRIV,
                                                              output_dir=str(tmp_path / "o"))]
    await wg.generate_wireguard_configs()
    assert not (tmp_path / "o").exists()
