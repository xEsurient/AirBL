"""
Rich Terminal UI Module.

Beautiful terminal interface for displaying scan results.
"""

import asyncio
from datetime import datetime
from typing import Optional

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.live import Live
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.style import Style
from rich import box

from .scanner import ScanSummary, ServerScanResult, ScannedIP
from .config import settings


console = Console()


def create_server_table(
    summary: ScanSummary,
    sort_by: str = "latency",  # "latency", "load", "blocked", "country"
    filter_country: str = None,
    show_blocked_only: bool = False,
) -> Table:
    """
    Create a rich table displaying server scan results.
    
    Args:
        summary: Scan summary to display
        sort_by: Sort criteria
        filter_country: Filter by country code
        show_blocked_only: Only show servers with blocked IPs
        
    Returns:
        Rich Table object
    """
    table = Table(
        title="🌐 AirVPN DroneBL Scan Results",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="blue",
        row_styles=["", "dim"],
    )
    
    # Define columns
    table.add_column("Server", style="bold white", no_wrap=True)
    table.add_column("Country", style="white")
    table.add_column("Location", style="dim")
    table.add_column("Load", justify="right")
    table.add_column("Users", justify="right", style="dim")
    table.add_column("Ping", justify="right")
    table.add_column("IPs", justify="center")
    table.add_column("Blocked", justify="center")
    table.add_column("Status", justify="center")
    
    # Prepare data
    servers = summary.servers
    
    # Filter by country
    if filter_country:
        servers = [s for s in servers if s.server.country_code.lower() == filter_country.lower()]
    
    # Filter blocked only
    if show_blocked_only:
        servers = [s for s in servers if s.blocked_count > 0]
    
    # Sort
    if sort_by == "latency":
        def get_latency(s: ServerScanResult) -> float:
            best = s.best_ip
            if best and best.latency_ms:
                return best.latency_ms
            return 9999.0
        servers = sorted(servers, key=get_latency)
    elif sort_by == "load":
        servers = sorted(servers, key=lambda s: s.server.load_percent)
    elif sort_by == "blocked":
        servers = sorted(servers, key=lambda s: s.blocked_count, reverse=True)
    elif sort_by == "country":
        servers = sorted(servers, key=lambda s: (s.server.country_name, s.server.public_name))
    
    # Add rows
    for result in servers:
        server = result.server
        best_ip = result.best_ip
        
        # Load color
        if server.load_percent < 50:
            load_style = "green"
        elif server.load_percent < 80:
            load_style = "yellow"
        else:
            load_style = "red"
        
        # Ping display
        if best_ip and best_ip.latency_ms:
            latency = best_ip.latency_ms
            if latency < 50:
                ping_style = "green"
            elif latency < 150:
                ping_style = "yellow"
            else:
                ping_style = "red"
            ping_text = Text(f"{latency:.0f}ms", style=ping_style)
        else:
            ping_text = Text("N/A", style="dim")
        
        # Status
        if result.blocked_count > 0:
            status_text = Text("⚠️ PARTIAL", style="yellow")
            if result.blocked_count == result.responsive_count:
                status_text = Text("🚫 BLOCKED", style="red")
        elif result.responsive_count > 0:
            status_text = Text("✅ OK", style="green")
        else:
            status_text = Text("❌ OFFLINE", style="red")
        
        # Blocked column
        if result.blocked_count > 0:
            blocked_text = Text(str(result.blocked_count), style="red bold")
        else:
            blocked_text = Text("0", style="green")
        
        table.add_row(
            server.public_name,
            f"{flag_emoji(server.country_code)} {server.country_code.upper()}",
            server.location,
            Text(f"{server.load_percent}%", style=load_style),
            str(server.users),
            ping_text,
            str(result.responsive_count),
            blocked_text,
            status_text,
        )
    
    return table


def create_blocked_details_table(summary: ScanSummary) -> Table:
    """Create detailed table of blocked IPs."""
    table = Table(
        title="🚫 Blocked IPs Details",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold red",
        border_style="red",
    )
    
    table.add_column("Server", style="bold")
    table.add_column("IP Address", style="cyan")
    table.add_column("DroneBL Code", justify="center")
    table.add_column("Reason", style="yellow")
    table.add_column("Ping", justify="right")
    
    for result in summary.servers:
        for ip in result.blocked_ips:
            if ip.dronebl:
                table.add_row(
                    result.server.public_name,
                    ip.ip,
                    str(ip.dronebl.listing_code or "?"),
                    ip.dronebl.listing_reason or "Unknown",
                    ip.ping.latency_display if ip.ping else "N/A",
                )
    
    return table


def create_country_summary_table(summary: ScanSummary) -> Table:
    """Create summary table grouped by country."""
    table = Table(
        title="🌍 Country Summary",
        box=box.ROUNDED,
        show_header=True,
        header_style="bold magenta",
        border_style="magenta",
    )
    
    table.add_column("Country", style="bold white")
    table.add_column("Servers", justify="right")
    table.add_column("Best Server", style="cyan")
    table.add_column("Best Ping", justify="right")
    table.add_column("Avg Load", justify="right")
    table.add_column("Blocked IPs", justify="right")
    
    best_per_country = summary.best_server_per_country()
    by_country = summary.servers_by_country()
    
    # Sort by best ping
    countries = sorted(
        by_country.keys(),
        key=lambda c: (
            best_per_country[c].best_ip.latency_ms 
            if best_per_country.get(c) and best_per_country[c].best_ip and best_per_country[c].best_ip.latency_ms
            else 9999
        )
    )
    
    for country_code in countries:
        servers = by_country[country_code]
        best = best_per_country.get(country_code)
        
        if not servers:
            continue
        
        country_name = servers[0].server.country_name
        total_blocked = sum(s.blocked_count for s in servers)
        avg_load = sum(s.server.load_percent for s in servers) / len(servers)
        
        # Best ping
        if best and best.best_ip and best.best_ip.latency_ms:
            latency = best.best_ip.latency_ms
            if latency < 50:
                ping_style = "green"
            elif latency < 150:
                ping_style = "yellow"
            else:
                ping_style = "red"
            ping_text = Text(f"{latency:.0f}ms", style=ping_style)
            best_server = best.server.public_name
        else:
            ping_text = Text("N/A", style="dim")
            best_server = "N/A"
        
        # Load color
        if avg_load < 50:
            load_style = "green"
        elif avg_load < 80:
            load_style = "yellow"
        else:
            load_style = "red"
        
        # Blocked
        if total_blocked > 0:
            blocked_text = Text(str(total_blocked), style="red bold")
        else:
            blocked_text = Text("0", style="green")
        
        table.add_row(
            f"{flag_emoji(country_code)} {country_name}",
            str(len(servers)),
            best_server,
            ping_text,
            Text(f"{avg_load:.0f}%", style=load_style),
            blocked_text,
        )
    
    return table


def create_stats_panel(summary: ScanSummary) -> Panel:
    """Create statistics panel."""
    stats_text = Text()
    
    stats_text.append("📊 Scan Statistics\n\n", style="bold cyan")
    
    stats_text.append("Servers Scanned: ", style="dim")
    stats_text.append(f"{summary.total_servers}\n", style="bold white")
    
    stats_text.append("Total IPs Checked: ", style="dim")
    stats_text.append(f"{summary.total_ips_scanned}\n", style="bold white")
    
    stats_text.append("Responsive IPs: ", style="dim")
    stats_text.append(f"{summary.total_responsive}\n", style="bold green")
    
    stats_text.append("Blocked IPs: ", style="dim")
    if summary.total_blocked > 0:
        stats_text.append(f"{summary.total_blocked}\n", style="bold red")
    else:
        stats_text.append(f"{summary.total_blocked}\n", style="bold green")
    
    if summary.completed_at:
        duration = (summary.completed_at - summary.started_at).total_seconds()
        stats_text.append("\nScan Duration: ", style="dim")
        stats_text.append(f"{duration:.1f}s\n", style="bold white")
    
    stats_text.append("Last Updated: ", style="dim")
    stats_text.append(datetime.now().strftime("%H:%M:%S"), style="bold white")
    
    return Panel(stats_text, border_style="cyan", box=box.ROUNDED)


def flag_emoji(country_code: str) -> str:
    """Convert country code to flag emoji."""
    if len(country_code) != 2:
        return "🏳️"
    
    # Convert to regional indicator symbols
    try:
        return "".join(chr(0x1F1E6 + ord(c.upper()) - ord('A')) for c in country_code)
    except Exception:
        return "🏳️"


def display_scan_results(
    summary: ScanSummary,
    sort_by: str = "latency",
    filter_country: str = None,
    show_blocked_only: bool = False,
    show_details: bool = False,
):
    """
    Display scan results in terminal.
    
    Args:
        summary: Scan summary to display
        sort_by: Sort criteria
        filter_country: Filter by country
        show_blocked_only: Only show blocked
        show_details: Show detailed blocked IPs
    """
    console.clear()
    
    # Header
    console.print(Panel(
        Text("AirBL - AirVPN DroneBL Checker", style="bold white", justify="center"),
        border_style="blue",
        box=box.DOUBLE,
    ))
    console.print()
    
    # Stats
    console.print(create_stats_panel(summary))
    console.print()
    
    # Main server table
    console.print(create_server_table(
        summary,
        sort_by=sort_by,
        filter_country=filter_country,
        show_blocked_only=show_blocked_only,
    ))
    console.print()
    
    # Country summary
    console.print(create_country_summary_table(summary))
    console.print()
    
    # Blocked details
    if show_details and summary.total_blocked > 0:
        console.print(create_blocked_details_table(summary))
        console.print()
    
    # Footer
    console.print(
        Text(
            "Press Ctrl+C to exit | R to refresh | S to change sort | F to filter",
            style="dim",
            justify="center",
        )
    )


def create_scan_progress() -> Progress:
    """Create progress bar for scanning."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        TaskProgressColumn(),
        TextColumn("[dim]{task.fields[status]}"),
        console=console,
    )


async def display_live_scan(
    scanner,
    status,
    country_filter: list[str] = None,
    server_filter: list[str] = None,
):
    """
    Display live progress during scan.
    """
    progress = create_scan_progress()
    
    servers = status.servers
    if country_filter:
        country_filter = [c.lower() for c in country_filter]
        servers = [s for s in servers if s.country_code.lower() in country_filter]
    if server_filter:
        server_filter = [s.lower() for s in server_filter]
        servers = [s for s in servers if s.public_name.lower() in server_filter]
    
    with progress:
        main_task = progress.add_task(
            "[cyan]Scanning servers...",
            total=len(servers),
            status="Starting",
        )
        
        current_task = None
        
        def update_progress(server_name: str, phase: str, current: int, total: int):
            nonlocal current_task
            
            progress.update(
                main_task,
                description=f"[cyan]Scanning {server_name}",
                status=phase,
            )
            
            if current_task is not None:
                progress.remove_task(current_task)
            
            current_task = progress.add_task(
                f"[dim]{phase}",
                total=total,
                completed=current,
                status="",
            )
            
            if current >= total:
                progress.advance(main_task)
        
        summary = await scanner.scan_all(
            status=status,
            country_filter=country_filter,
            server_filter=server_filter,
            progress_callback=update_progress,
        )
        
        progress.update(main_task, status="Complete!")
    
    return summary

