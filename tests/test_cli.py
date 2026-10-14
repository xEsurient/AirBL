"""CLI entry points (no network: only --help/--version and the offline `configs` command)."""

import os
import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

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
