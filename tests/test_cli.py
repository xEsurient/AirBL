"""CLI entry points (no network: only --help/--version and the offline `configs` command)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from airbl.cli import cli

ROOT = Path(__file__).resolve().parent.parent


def test_main_py_help(tmp_path):
    env = dict(os.environ)
    env.update(AIRBL_CONFIG_DIR=str(tmp_path / "conf"), AIRBL_CACHE_DIR=str(tmp_path / "data"),
               AIRBL_KILL_SWITCH="0", PYTHONDONTWRITEBYTECODE="1")
    env.pop("AIRBL_CONFIG_FILE", None)
    r = subprocess.run([sys.executable, "main.py", "--help"], cwd=ROOT, env=env,
                       capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr[-2000:]
    for cmd in ("scan", "configs", "check", "ping", "speedtest", "web", "status"):
        assert cmd in r.stdout


def test_cli_group_help_and_version():
    from airbl.cli import cli, main  # noqa: F401  (main is the console-script target)
    runner = CliRunner()
    r = runner.invoke(cli, ["--help"])
    assert r.exit_code == 0 and "AirBL" in r.output
    r = runner.invoke(cli, ["--version"])
    assert r.exit_code == 0 and "1.0.0" in r.output


def test_subcommand_help():
    from airbl.cli import cli
    runner = CliRunner()
    for cmd in ("scan", "configs", "speedtest", "web"):
        r = runner.invoke(cli, [cmd, "--help"])
        assert r.exit_code == 0, (cmd, r.output)
    assert "--speedtest" in runner.invoke(cli, ["scan", "--help"]).output


def test_configs_command_lists_sample_dir(sample_conf_dir, fresh_config):
    from airbl.cli import cli
    r = CliRunner().invoke(cli, ["configs", "-c", str(sample_conf_dir)], terminal_width=200)
    assert r.exit_code == 0, r.output
    assert "WireGuard Configs (5)" in r.output
    for name in ("Toliman", "Achernar", "Ran", "Taurus", "Alchiba"):
        assert name in r.output


def test_configs_command_empty_dir(tmp_path):
    from airbl.cli import cli
    r = CliRunner().invoke(cli, ["configs", "-c", str(tmp_path)])
    assert r.exit_code == 0 and "No .conf files" in r.output


def test_scan_rejects_missing_dir(tmp_path):
    from airbl.cli import cli
    r = CliRunner().invoke(cli, ["scan", "-c", str(tmp_path / "missing")])
    assert r.exit_code != 0


@pytest.mark.parametrize("result, code, text", [
    (dict(is_listed=True, listing_code=19, listing_reason="Abused VPN Service"), 1, "BLOCKED"),
    (dict(is_listed=False, error="DNS timeout"), 2, "UNVERIFIED"),
    (dict(is_listed=False), 0, "CLEAN"),
])
def test_check_exit_codes(monkeypatch, result, code, text):
    # A failed lookup used to print "CLEAN" and exit 0
    import airbl.dronebl as dronebl

    async def fake_batch(ips):
        return [dronebl.DroneBLResult(ip=ips[0], **result)]

    monkeypatch.setattr(dronebl, "check_dronebl_batch", fake_batch)
    r = CliRunner().invoke(cli, ["check", "192.0.2.1"])
    assert r.exit_code == code and text in r.output
    if code == 2:
        assert "CLEAN" not in r.output


def test_web_keeps_saved_interval_and_auto_scan(monkeypatch, tmp_path):
    # --interval 120 / --auto-scan used to override the saved settings on every start
    import airbl.web.app as webapp
    seen = {}

    async def fake_run_server(**kw):
        seen.update(kw)

    monkeypatch.setattr(webapp, "run_server", fake_run_server)
    r = CliRunner().invoke(cli, ["web", "-c", str(tmp_path)])
    assert r.exit_code == 0, r.output
    assert seen["scan_interval_minutes"] is None and seen["auto_scan"] is None
    CliRunner().invoke(cli, ["web", "-c", str(tmp_path), "-i", "30", "--no-auto-scan"])
    assert seen["scan_interval_minutes"] == 30 and seen["auto_scan"] is False


def test_status_api_failure_exits_1(monkeypatch):
    import airbl.cli as cli_mod

    async def boom():
        raise RuntimeError("API down")

    monkeypatch.setattr(cli_mod, "get_airvpn_status", boom)
    r = CliRunner().invoke(cli, ["status"])
    assert r.exit_code == 1 and "API down" in r.output


def test_scan_without_configs_exits_1(tmp_path):
    r = CliRunner().invoke(cli, ["scan", "-c", str(tmp_path)])
    assert r.exit_code == 1


def test_cli_speedtests_refuse_while_web_app_runs(monkeypatch):
    import airbl.cli as cli_mod
    monkeypatch.setattr(cli_mod, "_web_app_running", lambda: True)

    def no_controller(**kw):
        raise AssertionError("must not touch the tunnel")

    monkeypatch.setattr(cli_mod, "WireGuardController", no_controller)
    import asyncio
    summary = type("S", (), {"clean_servers": [object()]})()
    assert asyncio.run(cli_mod.run_speedtests(summary)) is False
