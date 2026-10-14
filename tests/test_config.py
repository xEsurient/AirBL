"""SettingsManager layering, salvage, backups and env parsing."""

import json
from pathlib import Path

import pytest

from airbl.config import Settings, SettingsManager


@pytest.fixture
def mgr_factory(tmp_path):
    """Build SettingsManagers on an isolated conf/data dir pair."""
    conf = tmp_path / "conf"
    data = tmp_path / "data"
    conf.mkdir()

    def make(base=None, user=None):
        if base is not None:
            (conf / "airbl-config.json").write_text(json.dumps(base))
        if user is not None:
            data.mkdir(exist_ok=True)
            (data / "airbl-settings.json").write_text(user if isinstance(user, str) else json.dumps(user))
        s = Settings(_env_file=None, config_dir=conf, cache_dir=data)
        return SettingsManager(s)

    make.conf = conf
    make.data = data
    return make


def _user_file(mgr) -> dict:
    return json.loads(mgr.user_settings_path.read_text())


def test_defaults_without_files(mgr_factory):
    cfg = mgr_factory().load()
    assert cfg.scan.scan_interval_minutes == 120
    assert cfg.regions.us_near_europe_only is False


def test_user_layer_overrides_base_and_merges_sections(mgr_factory):
    m = mgr_factory(
        base={"scan": {"scan_interval_minutes": 60, "speedtest_enabled": False}, "regions": {"countries": ["CH"]}},
        user={"scan": {"scan_interval_minutes": 30}},
    )
    cfg = m.load()
    assert cfg.scan.scan_interval_minutes == 30          # user wins
    assert cfg.scan.speedtest_enabled is False           # base value in same section kept
    assert cfg.regions.countries == ["CH"]               # untouched base section kept


def test_invalid_value_salvage_keeps_other_values(mgr_factory):
    m = mgr_factory(user={
        "scan": {"scan_interval_minutes": "not-a-number", "speedtest_enabled": False, "preferred_port": 47107},
        "regions": {"countries": ["DE", "CH"]},
        "servers": "not-a-list",
    })
    cfg = m.load()
    assert cfg.scan.scan_interval_minutes == 120  # dropped -> default
    assert cfg.scan.speedtest_enabled is False
    assert cfg.scan.preferred_port == 47107
    assert cfg.regions.countries == ["DE", "CH"]
    assert cfg.servers == []
    copies = list(mgr_factory.data.glob("airbl-settings.json.invalid-*"))
    assert len(copies) == 1
    # The copy is the original, untouched file
    assert json.loads(copies[0].read_text())["scan"]["scan_interval_minutes"] == "not-a-number"


def test_unreadable_user_file_is_preserved(mgr_factory):
    m = mgr_factory(base={"scan": {"scan_interval_minutes": 45}}, user="{broken json")
    cfg = m.load()
    assert cfg.scan.scan_interval_minutes == 45
    assert list(mgr_factory.data.glob("airbl-settings.json.unreadable-*"))


def test_save_writes_bak_of_previous_version(mgr_factory):
    m = mgr_factory()
    m.load()
    m.config.scan.scan_interval_minutes = 10
    assert m.save()
    assert not m.user_settings_path.with_name("airbl-settings.json.bak").exists()
    m.config.scan.scan_interval_minutes = 20
    assert m.save()
    bak = m.user_settings_path.with_name("airbl-settings.json.bak")
    assert json.loads(bak.read_text())["scan"]["scan_interval_minutes"] == 10
    assert _user_file(m)["scan"]["scan_interval_minutes"] == 20
    assert not m.user_settings_path.with_suffix(".tmp").exists()


def test_save_is_diff_only_and_later_base_edits_apply(mgr_factory):
    m = mgr_factory(base={"scan": {"scan_interval_minutes": 60}})
    m.load()
    m.config.scan.speedtest_enabled = False
    assert m.save()
    assert _user_file(m) == {"scan": {"speedtest_enabled": False}}

    # Owner edits the base file later: the change applies
    (mgr_factory.conf / "airbl-config.json").write_text(json.dumps({"scan": {"scan_interval_minutes": 30}}))
    m2 = mgr_factory()
    cfg = m2.load()
    assert cfg.scan.scan_interval_minutes == 30
    assert cfg.scan.speedtest_enabled is False


def test_value_reset_to_base_drops_out_of_user_file(mgr_factory):
    m = mgr_factory(base={"scan": {"scan_interval_minutes": 60}})
    m.load()
    m.config.scan.scan_interval_minutes = 15
    m.save()
    assert _user_file(m)["scan"]["scan_interval_minutes"] == 15
    m.config.scan.scan_interval_minutes = 60
    m.save()
    assert "scan" not in _user_file(m)
    # ... so a later base edit applies again
    (mgr_factory.conf / "airbl-config.json").write_text(json.dumps({"scan": {"scan_interval_minutes": 90}}))
    assert mgr_factory().load().scan.scan_interval_minutes == 90


def test_deleted_free_form_map_keys_stay_deleted(mgr_factory):
    m = mgr_factory(base={
        "cities": {"CH": ["Zurich"], "DE": ["Berlin"]},
        "scan": {"discovery_results": {"1637_ENTRY3": {"tests": 1}, "47107_ENTRY1": {"tests": 2}}},
    })
    m.load()
    del m.config.cities["DE"]
    del m.config.scan.discovery_results["47107_ENTRY1"]
    m.save()
    cfg = mgr_factory().load()
    assert cfg.cities == {"CH": ["Zurich"]}
    assert cfg.scan.discovery_results == {"1637_ENTRY3": {"tests": 1}}


def test_airbl_config_file_env_selects_base(monkeypatch, tmp_path):
    base = tmp_path / "elsewhere" / "custom.json"
    base.parent.mkdir()
    base.write_text(json.dumps({"scan": {"scan_interval_minutes": 77}}))
    monkeypatch.setenv("AIRBL_CONFIG_FILE", str(base))
    s = Settings(_env_file=None, config_dir=tmp_path / "conf", cache_dir=tmp_path / "data")
    assert s.config_file == base
    m = SettingsManager(s)
    assert m.base_config_path == base
    assert m.load().scan.scan_interval_minutes == 77


def test_default_base_path_without_env(monkeypatch, tmp_path):
    monkeypatch.delenv("AIRBL_CONFIG_FILE", raising=False)
    s = Settings(_env_file=None, config_dir=tmp_path / "conf", cache_dir=tmp_path / "data")
    assert SettingsManager(s).base_config_path == tmp_path / "conf" / "airbl-config.json"


@pytest.mark.parametrize("var", ["DNS_SERVERS", "AIRBL_DNS_SERVERS"])
def test_dns_servers_env_parsing(monkeypatch, tmp_path, var):
    monkeypatch.delenv("DNS_SERVERS", raising=False)
    monkeypatch.delenv("AIRBL_DNS_SERVERS", raising=False)
    monkeypatch.setenv(var, " 1.1.1.1, bogus ,, 2606:4700:4700::1111,9.9.9.9 ")
    s = Settings(_env_file=None, cache_dir=tmp_path / "data")
    assert s.dns_server_list == ["1.1.1.1", "2606:4700:4700::1111", "9.9.9.9"]


def test_dns_servers_empty_means_system_resolver(monkeypatch, tmp_path):
    monkeypatch.delenv("DNS_SERVERS", raising=False)
    monkeypatch.delenv("AIRBL_DNS_SERVERS", raising=False)
    s = Settings(_env_file=None, cache_dir=tmp_path / "data")
    assert s.dns_server_list == []


def test_settings_db_path_default(tmp_path):
    s = Settings(_env_file=None, cache_dir=tmp_path / "d")
    assert s.db_path == tmp_path / "d" / "airbl.db"
    assert (tmp_path / "d").is_dir()
