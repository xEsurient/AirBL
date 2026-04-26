#!/usr/bin/env python3
"""
AirBL - AirVPN DroneBL Checker

Main CLI entry point with comprehensive scanning workflow.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich import box
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from airbl.config import settings
from airbl.airvpn import get_airvpn_status
from airbl.scanner import EnhancedScanner, ScanSummary
from airbl.wireguard import scan_config_directory, get_scannable_configs, WireGuardConfig
from airbl.speedtest import run_speedtest_for_country, get_speedtest_server_id
from airbl.hummingbird import WireGuardController


console = Console()


def flag_emoji(country_code: str) -> str:
    """Convert country code to flag emoji."""
    if len(country_code) != 2:
        return "🏳️"
    try:
        return "".join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in country_code)
    except Exception:
        return "🏳️"


@click.group()
@click.version_option(version="1.0.0", prog_name="AirBL")
def cli():
    """
    🌐 AirBL - AirVPN DroneBL Checker
    
    Scan AirVPN servers against DroneBL blocklist,
    check ping latency, run speedtests, and find the best clean servers.
    
    \b
    Workflow:
    1. Parse .conf files from conf/ directory
    2. Full /24 subnet ping scan
    3. DroneBL check all responsive IPs
    4. Optional: Connect & speedtest clean servers
    """
    pass


@cli.command()
@click.option(
    "--config-dir", "-c",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="./conf",
    help="Directory containing WireGuard .conf files",
)
@click.option(
    "--speedtest/--no-speedtest",
    default=False,
    help="Run speedtest on clean servers",
)
@click.option(
    "--output", "-o",
    type=click.Choice(["table", "json"]),
    default="table",
    help="Output format",
)
def scan(config_dir: Path, speedtest: bool, output: str):
    """
    Run comprehensive DroneBL scan.
    
    Scans all servers from .conf files:
    
    \b
    1. Extracts IPs from config files
    2. Does full /24 subnet ping scan
    3. Checks responsive IPs against DroneBL
    4. Optionally runs speedtest on clean servers
    
    \b
    Examples:
        airbl scan
        airbl scan --config-dir /path/to/configs
        airbl scan --speedtest
        airbl scan -o json
    """
    asyncio.run(_scan_async(config_dir, speedtest, output))


async def _scan_async(config_dir: Path, run_speedtest: bool, output: str):
    """Async scan implementation."""
    
    console.print(Panel(
        Text("AirBL - AirVPN DroneBL Checker", style="bold cyan", justify="center"),
        border_style="cyan",
        box=box.DOUBLE,
    ))
    console.print()
    
    # Check config directory
    if not config_dir.exists():
        console.print(f"[red]Error: Config directory not found: {config_dir}[/]")
        console.print("[dim]Create the directory and add your AirVPN .conf files[/]")
        return
    
    configs = scan_config_directory(config_dir)
    scannable = get_scannable_configs(configs)
    
    if not configs:
        console.print(f"[red]Error: No .conf files found in {config_dir}[/]")
        return
    
    console.print(f"[green]✓[/] Found {len(configs)} config files")
    console.print(f"[green]✓[/] {len(scannable)} servers to scan (after US filter)")
    
    # Show countries
    countries = set(c.country_code for c in scannable)
    console.print(f"[dim]Countries: {', '.join(sorted(countries))}[/]")
    console.print()
    
    # Run scan with progress
    scanner = EnhancedScanner(config_dir=config_dir)
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
    ) as progress:
        main_task = progress.add_task(
            "Scanning servers...",
            total=len(scannable),
            status="Starting",
        )
        
        async def update_progress(server: str, phase: str, current: int, total: int):
            progress.update(main_task, completed=current, status=f"{server} - {phase}")
        
        summary = await scanner.scan_all(progress_callback=update_progress)
        progress.update(main_task, completed=len(scannable), status="Complete")
    
    console.print()
    
    # Display results
    if output == "json":
        import json
        console.print_json(json.dumps(summary.to_dict(), indent=2))
    else:
        display_results(summary)
    
    # Run speedtests if requested
    if run_speedtest and summary.clean_servers:
        console.print()
        console.print("[bold cyan]Running speedtests on clean servers...[/]")
        await run_speedtests(summary)
        console.print()
        display_results(summary)  # Refresh display with speedtest results


def display_results(summary: ScanSummary):
    """Display scan results in tables."""
    
    # Stats panel
    stats = Text()
    stats.append("📊 Scan Statistics\n\n", style="bold cyan")
    stats.append(f"Servers Scanned: {summary.total_servers}\n")
    stats.append(f"Clean Servers: ", style="dim")
    stats.append(f"{len(summary.clean_servers)}\n", style="green bold")
    stats.append(f"Blocked Servers: ", style="dim")
    stats.append(f"{len(summary.blocked_servers)}\n", style="red bold" if summary.blocked_servers else "green")
    stats.append(f"IPs Checked: {summary.total_ips_scanned}\n")
    stats.append(f"Blocked IPs: {summary.total_blocked}\n")
    
    console.print(Panel(stats, border_style="cyan"))
    console.print()
    
    # Results by country
    by_country = summary.servers_by_country()
    
    for country_code in sorted(by_country.keys()):
        servers = by_country[country_code]
        if not servers:
            continue
        
        country_name = servers[0].country_name
        clean_count = len([s for s in servers if s.is_clean])
        blocked_count = len(servers) - clean_count
        
        table = Table(
            title=f"{flag_emoji(country_code)} {country_name} ({clean_count} clean, {blocked_count} blocked)",
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            border_style="blue" if clean_count > 0 else "red",
        )
        
        table.add_column("Server", style="bold")
        table.add_column("Location")
        table.add_column("Status", justify="center")
        table.add_column("Ping", justify="right")
        table.add_column("Load", justify="right")
        table.add_column("IPs", justify="center")
        table.add_column("Blocked", justify="center")
        table.add_column("Score", justify="right")
        
        if any(s.speedtest_result for s in servers):
            table.add_column("Download", justify="right")
            table.add_column("Upload", justify="right")
        
        for server in servers:
            # Status
            if server.is_clean:
                status = Text("✅ OK", style="green")
            else:
                status = Text("🚫 BLOCKED", style="red")
            
            # Ping
            best = server.best_ip
            if best and best.latency_ms:
                ping_style = "green" if best.latency_ms < 50 else "yellow" if best.latency_ms < 150 else "red"
                ping = Text(f"{best.latency_ms:.0f}ms", style=ping_style)
            else:
                ping = Text("N/A", style="dim")
            
            # Load
            load_style = "green" if server.load_percent < 50 else "yellow" if server.load_percent < 80 else "red"
            load = Text(f"{server.load_percent}%", style=load_style)
            
            # Blocked IPs
            if server.blocked_count > 0:
                blocked = Text(str(server.blocked_count), style="red bold")
            else:
                blocked = Text("0", style="green")
            
            row = [
                server.server_name,
                server.location,
                status,
                ping,
                load,
                str(server.responsive_count),
                blocked,
                f"{server.score:.1f}",
            ]
            
            # Speedtest columns
            if any(s.speedtest_result for s in servers):
                if server.speedtest_result:
                    row.append(f"{server.speedtest_result['download_mbps']:.1f}")
                    row.append(f"{server.speedtest_result['upload_mbps']:.1f}")
                else:
                    row.extend(["-", "-"])
            
            table.add_row(*row)
        
        console.print(table)
        console.print()


async def run_speedtests(summary: ScanSummary):
    """Run speedtests on clean servers."""
    
    clean_servers = summary.clean_servers
    if not clean_servers:
        console.print("[yellow]No clean servers to speedtest[/]")
        return
    
    # Auto-detect if sudo is needed (None = auto-detect)
    controller = WireGuardController(use_sudo=None)
    
    for i, server in enumerate(clean_servers):
        if not server.config_file:
            continue
        
        console.print(f"[dim]({i+1}/{len(clean_servers)})[/] Testing {server.server_name}...")
        
        try:
            # Connect to VPN
            result = await controller.connect(server.config_file)
            
            if not result.success:
                console.print(f"  [red]Failed to connect: {result.error}[/]")
                continue
            
            # Wait for connection
            await asyncio.sleep(3)
            
            # Run speedtest
            speedtest = await run_speedtest_for_country(server.country_code)
            
            if speedtest.is_success:
                server.speedtest_result = speedtest.to_dict()
                console.print(
                    f"  [green]↓ {speedtest.download_mbps:.1f} Mbps[/] | "
                    f"[cyan]↑ {speedtest.upload_mbps:.1f} Mbps[/] | "
                    f"[dim]ping {speedtest.ping_ms:.0f}ms[/]"
                )
            else:
                console.print(f"  [red]Speedtest failed: {speedtest.error}[/]")
            
            # Disconnect
            await controller.disconnect(server.config_file)
            
        except Exception as e:
            console.print(f"  [red]Error: {e}[/]")
            await controller.disconnect(server.config_file)


@cli.command()
@click.option(
    "--config-dir", "-c",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="./conf",
    help="Directory containing WireGuard .conf files",
)
def configs(config_dir: Path):
    """
    List parsed WireGuard configs.
    
    Shows all .conf files with extracted information.
    """
    configs = scan_config_directory(config_dir)
    
    if not configs:
        console.print(f"[yellow]No .conf files found in {config_dir}[/]")
        return
    
    table = Table(
        title=f"WireGuard Configs ({len(configs)})",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
    )
    
    table.add_column("Server")
    table.add_column("Country")
    table.add_column("City")
    table.add_column("Endpoint IP")
    table.add_column("Subnet")
    table.add_column("Scannable", justify="center")
    
    for config in configs:
        scannable = "✅" if config.should_scan else "❌ (US filter)"
        
        table.add_row(
            config.server_name,
            f"{flag_emoji(config.country_code)} {config.country_code}",
            config.city,
            config.endpoint_ip,
            config.subnet or "N/A",
            scannable,
        )
    
    console.print(table)


@cli.command()
@click.argument("ip")
def check(ip: str):
    """
    Check a single IP against DroneBL.
    """
    from airbl.dronebl import check_dronebl_sync
    
    console.print(f"[dim]Checking {ip} against DroneBL...[/]")
    
    result = check_dronebl_sync(ip)
    
    if result.is_listed:
        console.print(f"[red]🚫 BLOCKED[/] - {ip}")
        console.print(f"   Code: {result.listing_code}")
        console.print(f"   Reason: {result.listing_reason}")
    else:
        console.print(f"[green]✅ CLEAN[/] - {ip}")
    
    console.print(f"   Lookup time: {result.lookup_time_ms:.1f}ms")


@cli.command()
@click.argument("ip")
def ping(ip: str):
    """
    Ping a single IP address.
    """
    from airbl.pinger import ping_ip
    
    console.print(f"[dim]Pinging {ip}...[/]")
    
    result = asyncio.run(ping_ip(ip))
    
    if result.is_alive:
        console.print(f"[green]✅ ALIVE[/] - {ip}")
        console.print(f"   RTT: {result.min_rtt_ms:.1f} / {result.avg_rtt_ms:.1f} / {result.max_rtt_ms:.1f} ms")
        console.print(f"   Packet loss: {result.packet_loss:.0f}%")
    else:
        console.print(f"[red]❌ UNREACHABLE[/] - {ip}")


@cli.command()
@click.option("--country", "-c", help="Country code for server selection")
@click.option("--server-id", "-s", type=int, help="Specific speedtest server ID")
def speedtest(country: str, server_id: int):
    """
    Run a speed test.
    
    Uses speedtest-cli with --secure and country-specific server.
    """
    from airbl.speedtest import run_speedtest, run_speedtest_for_country
    
    console.print("[bold cyan]🚀 Running Speed Test...[/]")
    
    if server_id:
        result = asyncio.run(run_speedtest(server_id=server_id))
    elif country:
        result = asyncio.run(run_speedtest_for_country(country))
        console.print(f"[dim]Using server for {country.upper()}[/]")
    else:
        result = asyncio.run(run_speedtest())
    
    if result.is_success:
        console.print(f"[green]✓[/] Download: [bold]{result.download_mbps:.1f} Mbps[/]")
        console.print(f"[green]✓[/] Upload: [bold]{result.upload_mbps:.1f} Mbps[/]")
        console.print(f"[green]✓[/] Ping: [bold]{result.ping_ms:.0f} ms[/]")
        if result.server_location:
            console.print(f"[dim]Server: {result.server_name} ({result.server_location})[/]")
        if result.client_ip:
            console.print(f"[dim]Your IP: {result.client_ip}[/]")
    else:
        console.print(f"[red]✗[/] Error: {result.error}")


@cli.command()
@click.option(
    "--host", "-h",
    default="0.0.0.0",
    help="Host to bind to",
)
@click.option(
    "--port", "-p",
    default=5665,
    type=int,
    help="Port to listen on",
)
@click.option(
    "--config-dir", "-c",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="./conf",
    help="Config directory",
)
@click.option(
    "--interval", "-i",
    default=120,
    type=int,
    help="Scan interval in minutes",
)
@click.option(
    "--auto-scan/--no-auto-scan",
    default=True,
    help="Start scanning automatically",
)
def web(host: str, port: int, config_dir: Path, interval: int, auto_scan: bool):
    """
    Start the web GUI server.
    
    Provides a real-time dashboard for monitoring scan results.
    """
    from airbl.web.app import run_server
    
    console.print("[bold cyan]🌐 Starting AirBL Web Server[/]")
    console.print(f"[dim]URL: http://{host}:{port}[/]")
    console.print(f"[dim]Config: {config_dir}[/]")
    console.print(f"[dim]Scan interval: {interval} minutes[/]")
    console.print()
    
    asyncio.run(run_server(
        host=host,
        port=port,
        config_dir=config_dir,
        scan_interval_minutes=interval,
        auto_scan=auto_scan,
    ))


@cli.command()
def status():
    """
    Show AirVPN network status summary.
    """
    status_data = asyncio.run(get_airvpn_status())
    
    text = Text()
    text.append("🌐 AirVPN Network Status\n\n", style="bold cyan")
    text.append(f"Total Servers: {len(status_data.servers)}\n")
    text.append(f"Total Users: {status_data.total_users:,}\n")
    
    console.print(Panel(text, border_style="blue"))


def main():
    """Main entry point."""
    cli()


if __name__ == "__main__":
    main()
