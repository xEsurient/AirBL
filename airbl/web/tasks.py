"""
Background tasks for AirBL Web UI.
"""

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
import copy
import random
from typing import Optional
import logging
from collections import defaultdict, deque
import statistics

from .state import state
from .websockets import broadcast_update
from ..config import config_manager, settings
from ..scanner import EnhancedScanner, ScanSummary
from ..speedtest import run_speedtest_for_country, SpeedTestResult
from ..hummingbird import WireGuardController
from ..wireguard import scan_config_directory, get_scannable_configs
from ..airvpn import get_airvpn_status
from ..gluetun import generate_gluetun_servers_json

logger = logging.getLogger("airbl.web.tasks")


# --- VPN / routing ownership ---
# Every job that brings the VPN up or depends on direct (non-VPN) routing must hold
# this lock: scans (incl. their baseline, batch speedtests and discovery), manual
# speedtests and standalone baseline tests. They share wg0 and routing table 51820.
_network_lock = asyncio.Lock()
_network_owner: Optional[str] = None


def network_owner() -> Optional[str]:
    """Name of the job currently holding the VPN/routing lock, or None."""
    return _network_owner if _network_lock.locked() else None


@asynccontextmanager
async def network_job(name: str):
    """Hold the VPN/routing lock for the duration of a job; tells the UI if it has to wait."""
    global _network_owner
    if _network_lock.locked():
        logger.info(f"{name} waiting for '{_network_owner}' to release the VPN")
        await broadcast_update("network_job_waiting", {"job": name, "owner": _network_owner})
    async with _network_lock:
        _network_owner = name
        try:
            yield
        finally:
            _network_owner = None


def _reject_if_not_via_vpn(res, egress_ip: Optional[str]):
    """Mark a speedtest failed if Ookla saw a different public IP than the verified VPN exit.

    Catches any measurement that leaked onto the direct line (tunnel dropped mid-test,
    source-bound socket, ...) so it is never stored as a VPN server's result.
    """
    if res.is_success and egress_ip and res.external_ip and res.external_ip != egress_ip:
        res.error = f"Measured outside the VPN (speedtest saw {res.external_ip}, VPN exit is {egress_ip})"
        logger.warning(f"Discarding speedtest: {res.error}")
    return res


def calculate_next_scan_time(scan_cfg, last_scan_time=None) -> datetime:
    """Calculate the next scheduled scan time based on configuration."""
    now = datetime.now()
    if last_scan_time is None:
        last_scan_time = now
        
    mode = getattr(scan_cfg, 'scan_mode', 'interval')
    if mode == "interval":
        # Note: If last_scan_time is now (startup), it will wait the full interval
        return last_scan_time + timedelta(minutes=scan_cfg.scan_interval_minutes)
    else:
        scheduled_time = getattr(scan_cfg, 'scan_schedule_time', "20:00")
        scheduled_days = getattr(scan_cfg, 'scan_schedule_days', ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"])
        
        try:
            sched_h, sched_m = map(int, str(scheduled_time).split(':'))
            if not (0 <= sched_h < 24 and 0 <= sched_m < 60):
                raise ValueError(scheduled_time)
        except ValueError:
            logger.warning(f"Invalid scan_schedule_time {scheduled_time!r}; using 20:00")
            sched_h, sched_m = 20, 0
            
        days_map = {"Mon": 0, "Tue": 1, "Wed": 2, "Thu": 3, "Fri": 4, "Sat": 5, "Sun": 6}
        target_days = [days_map.get(d, 0) for d in scheduled_days]
        if not target_days:
            target_days = list(range(7))
            
        for offset in range(8):
            test_date = now + timedelta(days=offset)
            if test_date.weekday() in target_days:
                target_datetime = test_date.replace(hour=sched_h, minute=sched_m, second=0, microsecond=0)
                # If it's today but the time has already passed, skip to next match
                if target_datetime > now:
                    return target_datetime
                    
        return now + timedelta(days=1)


async def _check_and_disable_underperforming_server(server_name: str, speedtest_result: dict):
    """
    Check if server consistently underperforms and auto-disable if needed.
    """
    # Skip if speedtest failed
    # to_dict() always has an "error" key (None on success), so test its value
    if not speedtest_result or speedtest_result.get("error"):
        return
    
    download = speedtest_result.get("download_mbps", 0)
    upload = speedtest_result.get("upload_mbps", 0)
    
    threshold_dl = config_manager.config.performance.threshold_download
    threshold_ul = config_manager.config.performance.threshold_upload
    
    # Store history (persistently via SettingsManager for now/backward compat, 
    # but runtime update happens in state.server_performance_history)
    if server_name not in state.server_performance_history:
        state.server_performance_history[server_name] = []
        
    state.server_performance_history[server_name].append({
        "download": download,
        "upload": upload,
        "timestamp": datetime.now().isoformat()
    })
    
    # Keep last N checks
    # Use check_count * 2 to keep some context
    max_history = config_manager.config.performance.check_count * 2
    if len(state.server_performance_history[server_name]) > max_history:
        state.server_performance_history[server_name] = state.server_performance_history[server_name][-max_history:]
    
    # Check if underperforming for N consecutive times
    check_count = config_manager.config.performance.check_count
    history = state.server_performance_history[server_name]
    
    if len(history) >= check_count:
        recent = history[-check_count:]
        consistently_bad = all(
            entry["download"] < threshold_dl or entry["upload"] < threshold_ul
            for entry in recent
        )
        
        if consistently_bad and server_name not in state.disabled_servers:
            logger.warning(f"Auto-disabling {server_name}: consistently underperforming (last {check_count} checks below threshold)")
            
            # Update config via SettingsManager
            current_disabled = set(config_manager.config.performance.disabled_servers)
            current_disabled.add(server_name)
            
            # Update history in config too 
            # (Note: this is inefficient for every check, but matches previous logic behavior of saving state)
            # In next phase with SQLite, this part vanishes.
            
            config_manager.config.performance.disabled_servers = sorted(list(current_disabled))
            config_manager.config.performance.history = state.server_performance_history
            config_manager.save()
            
            await broadcast_update("server_disabled", {
                "server": server_name,
                "reason": "underperformance"
            })


def _average_speedtest_results(results: list[SpeedTestResult], server_name: str) -> SpeedTestResult:
    """Calculate average from multiple speedtest results."""
    if not results:
        return SpeedTestResult(
            download_mbps=0.0,
            upload_mbps=0.0,
            ping_ms=0.0,
            server_name=server_name,
            error="No results to average",
        )
    
    # Simple arithmetic mean
    avg_download = statistics.mean([r.download_mbps for r in results])
    avg_upload = statistics.mean([r.upload_mbps for r in results])
    avg_ping = statistics.mean([r.ping_ms for r in results])
    
    # Use metadata from the last result
    last = results[-1]
    
    return SpeedTestResult(
        server_id=last.server_id,
        server_name=last.server_name,
        server_location=last.server_location,
        server_country=last.server_country,
        client_ip=last.client_ip,
        external_ip=last.external_ip,
        tested_at=last.tested_at,
        download_mbps=avg_download,
        upload_mbps=avg_upload,
        ping_ms=avg_ping,
    )


async def run_baseline_speedtest():
    """Standalone baseline speedtest (API). Waits for the VPN to be free: a baseline
    measured while another job has the tunnel up would really be a VPN measurement."""
    async with network_job("baseline speedtest"):
        await _run_baseline_speedtest()


async def _run_baseline_speedtest():
    """
    Run a speedtest without VPN to establish baseline performance.
    This is used to calculate deviation scores for VPN-connected speedtests.
    Caller must hold the network lock.
    """
    from ..speedtest import run_speedtest
    
    logger.info("Running baseline speedtest (no VPN)")
    await broadcast_update("baseline_speedtest_started", {})
    
    try:
        result = await run_speedtest(timeout=120)
        if not result.is_success:
            # One retry: a transient Ookla/network failure shouldn't leave the scan
            # without a baseline (all deviation scores depend on it)
            logger.warning(f"Baseline speedtest failed ({result.error}); retrying once")
            await asyncio.sleep(5)
            result = await run_speedtest(timeout=120)
        
        if result.is_success:
            baseline = {
                "download_mbps": result.download_mbps,
                "upload_mbps": result.upload_mbps,
                "ping_ms": result.ping_ms,
                "server_name": result.server_name,
                "server_location": result.server_location,
                "tested_at": result.tested_at.isoformat() if result.tested_at else None,
            }
            state.save_baseline(baseline)
            logger.info(f"Baseline speedtest complete: ↓{result.download_mbps:.1f} ↑{result.upload_mbps:.1f} Mbps")
            await broadcast_update("baseline_speedtest_complete", {"baseline": baseline})
        else:
            error_msg = result.error or "Unknown error"
            logger.error(f"Baseline speedtest failed: {error_msg}")
            await broadcast_update("baseline_speedtest_error", {"error": error_msg})
    except Exception as e:
        logger.error(f"Baseline speedtest error: {e}")
        await broadcast_update("baseline_speedtest_error", {"error": str(e)})


def _idle_progress() -> dict:
    return {"phase": "idle", "current": 0, "total": 0, "server": "", "country": "", "next": ""}


async def _generate_outputs():
    """Gluetun servers.json and WireGuard configs from the last completed scan."""
    try:
        await generate_gluetun_servers_json()
    except Exception as e:
        logger.error(f"Failed to generate Gluetun servers.json: {e}")
    try:
        from ..wireguard_gen import generate_wireguard_configs
        await generate_wireguard_configs()
    except Exception as e:
        logger.error(f"Failed to generate WireGuard configs: {e}")


async def run_scan_task():
    """Background task to run a full scan."""
    state.is_scanning = True
    state.is_paused = False
    state.scan_cancelled = False
    state.live_scan = None
    scan_id = None
    status = "cancelled"  # DB status unless the scan phase completes (or fails)
    
    try:
        # Own the VPN/routing for the whole cycle (scan, baseline, speedtests, discovery)
        async with network_job("scan"):
            # Calculate next scan time using config
            scan_cfg = config_manager.config.scan
            state.next_scan_at = calculate_next_scan_time(scan_cfg, datetime.now())
        
            await broadcast_update("scan_started", {
                "next_scan_at": state.next_scan_at.astimezone().isoformat()
            })
        
            logger.info("Starting scheduled scan task")
        
            # Initialize scanner with disabled servers exclusion
            # We need to pass the excluded servers from config
            excluded = set(config_manager.config.performance.disabled_servers)
        
            # Pass country filter from enabled countries settings
            country_filter = state.enabled_countries if state.enabled_countries else None
        
            # Pass city filter if enabled
            city_filter = state.enabled_cities if state.enabled_cities else None

            scanner = EnhancedScanner(
                config_dir=state.config_dir,
                server_exclude=excluded,
                country_filter=country_filter,
                country_exclude=set(config_manager.config.regions.excluded_countries),
                city_filter=city_filter,
                # Settings > Server Selection; empty means all servers
                server_filter=state.enabled_servers or None,
            )
        
            # Create scan entry in DB at start to get ID (status 'running' until it completes)
            if state.db:
                try:
                    scan_id = await state.db.add_scan_result({
                        "total_servers": 0,
                        "clean_servers": 0,
                        "blocked_servers": 0,
                        "disabled_servers": len(excluded)
                    })
                    logger.info(f"Scan started with DB ID: {scan_id}")
                except Exception as e:
                    logger.error(f"Failed to create scan entry in DB: {e}")
            state.current_scan_id = scan_id
        
            # Generator based scanning for real-time updates
            async for update in scanner.scan_iter():
                if state.scan_cancelled:
                    logger.info("Scan cancelled manually")
                    break
                
                # Handle pause
                while state.is_paused and not state.scan_cancelled:
                    await asyncio.sleep(1)
            
                if state.scan_cancelled:
                    break
            
                # Build into live_scan; current_scan keeps the last completed scan until this one finishes
                state.live_scan = update.summary
            
                # Broadcast update
                if update.server:
                    # Individual server update
                    await broadcast_update("server_complete", {
                        "server": update.server.to_dict(),
                        "summary": update.summary.to_dict()
                    })
                
                    # Persist the server row and its entry pings (AUTO entry mode), one commit per server
                    if state.db and scan_id:
                        try:
                            srv = update.server
                            await state.db.add_server_scan_result(scan_id, srv.to_dict(), commit=False)
                            for entry_type, ping in (("ENTRY1", srv.entry1_ping), ("ENTRY3", srv.entry3_ping)):
                                if ping:
                                    await state.db.add_entry_ping(
                                        scan_id, srv.server_name, entry_type, ping.ip,
                                        ping.avg_rtt_ms, ping.is_alive, commit=False,
                                    )
                            await state.db.commit()
                        except Exception as e:
                            logger.error(f"Failed to persist server result to DB: {e}")
            
                # Update progress
                state.scan_progress = {
                    "phase": "scanning",
                    "current": update.summary.total_servers,
                    "total": update.total_expected if hasattr(update, 'total_expected') else 0, # total_expected might need to be added to scanner
                    # Just use scanned count for now
                    "server": update.server.server_name if update.server else "...",
                    "country": update.server.country_code if update.server else "...",
                    "next": ""
                }
                await broadcast_update("progress_update", {"progress": state.scan_progress})

            if state.scan_cancelled or state.live_scan is None:
                if not state.scan_cancelled:
                    status = "failed"
                    logger.warning("Scan produced no results")
                return

            # Scan complete: promote it to the results everything else reads
            state.current_scan, state.live_scan = state.live_scan, None
            summary = state.current_scan
            logger.info(f"Scan completed. Found {summary.clean_servers_count} clean servers.")

            # Ban frequency tracking (unknown, i.e. lookup failed, is not a ban)
            for server in summary.servers:
                if server.is_blocked:
                    state.ban_history[server.server_name] = state.ban_history.get(server.server_name, 0) + 1
        
            await broadcast_update("scan_complete", {
                "summary": summary.to_dict(),
                "next_scan_at": state.next_scan_at.astimezone().isoformat() if state.next_scan_at else None
            })
        
            # Save history to memory (and log)
            state.scan_history.append({
                "timestamp": datetime.now().isoformat(),
                "total_servers": summary.total_servers,
                "clean_servers": summary.clean_servers_count,
                "blocked_servers": summary.blocked_servers_count,
                "disabled_servers": len(config_manager.config.performance.disabled_servers),
            })
            # Keep only last 50 entries in memory
            if len(state.scan_history) > 50:
                state.scan_history = state.scan_history[-50:]

            # Update DB with final summary and mark the scan complete
            status = "complete"
            if state.db and scan_id:
                try:
                    # Same keys as the in-memory history entry (to_dict uses *_count names)
                    await state.db.update_scan_result(scan_id, state.scan_history[-1], status="complete")
                    logger.info(f"Updated scan result ID {scan_id} with final stats")
                except Exception as e:
                    logger.error(f"Failed to update scan in DB: {e}")

            # Run speedtests on clean servers if enabled (only if not cancelled)
            if not state.scan_cancelled and state.speedtest_enabled:
                # Force baseline speedtest refresh for every new scan cycle
                # This ensures we have an up-to-date baseline for comparison
                logger.info("Running baseline speedtest (no VPN) before VPN tests")
                await _run_baseline_speedtest()  # already inside the scan's network lock
            
                await _run_batch_speedtests()

            # Once per completed cycle, after speedtests so the outputs include them
            if not state.scan_cancelled:
                await _generate_outputs()
        
    except asyncio.CancelledError:
        await broadcast_update("scan_cancelled", {})
    except Exception as e:
        if status != "complete":
            status = "failed"
        logger.error(f"Scan task error: {e}", exc_info=True)
        await broadcast_update("scan_error", {"error": str(e)})
    finally:
        # A stopped or failed scan never replaces the last completed one
        state.live_scan = None
        state.current_scan_id = None
        if state.db and scan_id and status != "complete":
            try:
                await state.db.set_scan_status(scan_id, status)
            except Exception as e:
                logger.error(f"Failed to set scan status in DB: {e}")

        # A restart may already have started a newer scan task; leave its state alone
        if state.scan_task in (None, asyncio.current_task()):
            state.is_scanning = False
            state.is_paused = False
            state.scan_cancelled = False
            state.scan_task = None
            # Count the interval from the end of the cycle, so a long cycle can't cause back-to-back scans
            state.next_scan_at = calculate_next_scan_time(config_manager.config.scan, datetime.now())
            state.scan_progress = _idle_progress()
            await broadcast_update("progress_update", {
                "progress": state.scan_progress,
                "next_scan_at": state.next_scan_at.astimezone().isoformat(),
            })


async def _run_batch_speedtests():
    """Helper to run batch speedtests after scan."""
    # Logic extracted from app.py run_scan_task to keep it clean
    logger = logging.getLogger("airbl.web.scan")
    
    # Get all clean servers with config files
    clean_servers = [s for s in state.current_scan.servers if s.is_clean and s.config_file]
    
    # Apply city filter if set
    if state.enabled_cities:
        # ... city filtering logic ...
        # Simplified for brevity as logic mirrors app.py, 
        # but in real extraction we should copy the logic.
        # Let's copy the logic fully to be safe.
         
        original_count = len(clean_servers)
        configs = scan_config_directory(state.config_dir)
        scannable_configs = get_scannable_configs(configs)
        config_to_city = {}
        for config in scannable_configs:
            config_to_city[str(config.file_path)] = config.city.lower()
        
        filtered_servers = []
        for server in clean_servers:
            server_city = config_to_city.get(str(server.config_file), "").lower()
            country = server.country_code.upper()
            if country in state.enabled_cities:
                allowed_cities = {c.lower() for c in state.enabled_cities[country]}
                if server_city not in allowed_cities:
                    continue
            filtered_servers.append(server)
        
        clean_servers = filtered_servers
    
    if clean_servers:
        total_speedtests = len(clean_servers)
        logger.info(f"Starting speedtests for {total_speedtests} clean servers")
        
        state.scan_progress = {
            "phase": "speedtesting",
            "current": 0,
            "total": total_speedtests,
            "server": "",
            "country": "",
            "next": ""
        }
        await broadcast_update("speedtest_queue", {
            "count": total_speedtests,
            "total": total_speedtests,
            "current": 0,
            "message": f"Queueing speedtests for {total_speedtests} clean servers..."
        })
        
        # Group servers by country
        servers_by_country = defaultdict(list)
        for server in clean_servers:
            servers_by_country[server.country_code].append(server)
        
        controller = WireGuardController(use_sudo=None)
        
        # Consts — TESTS_PER_SERVER uses the same user-configured value as discovery
        TESTS_PER_SERVER = _speedtest_count()
        INTER_TEST_DELAY = 10
        VPN_STABILIZATION_WAIT = 30
        POST_SERVER_WAIT = config_manager.config.scan.post_server_wait
        
        # --- Run Discovery Phase (before standard speedtests) ---
        try:
            await _run_discovery_phase(clean_servers, controller)
        except Exception as e:
            logger.error(f"Discovery phase failed: {e}")
        
        # Restore progress to speedtest phase after discovery
        state.scan_progress = {
            "phase": "speedtesting",
            "current": 0,
            "total": total_speedtests,
            "server": "",
            "country": "",
            "next": "Starting server speedtests..."
        }
        await broadcast_update("progress_update", {"progress": state.scan_progress})
        
        server_index = 0
        
        try:
            for country_code, country_servers in servers_by_country.items():
                if state.scan_cancelled: break
                
                # Check Pause
                while state.is_paused and not state.scan_cancelled:
                    await asyncio.sleep(0.5)
                if state.scan_cancelled: break
                
                for server in country_servers:
                    if state.scan_cancelled: break
                    
                    # Check Pause
                    while state.is_paused and not state.scan_cancelled:
                        await asyncio.sleep(0.5)
                    if state.scan_cancelled: break
                    
                    server_index += 1
                    
                    # Resolve config based on preferred port/entry settings
                    config_override = await _resolve_server_config(server)
                    
                    # Run single server test
                    await _run_single_server_speedtest(
                        server, server_index, total_speedtests, 
                        controller, TESTS_PER_SERVER, INTER_TEST_DELAY, VPN_STABILIZATION_WAIT,
                        config_override=config_override, scan_id=state.current_scan_id,
                    )
                    
                    # Post-server wait
                    if server_index < total_speedtests and not state.scan_cancelled:
                        await _smart_wait(POST_SERVER_WAIT)
                        
        finally:
            try:
                await controller.disconnect()
            except:
                pass
                
        # Completion broadcast (ban history and output generation happen in run_scan_task)
        if not state.scan_cancelled:
            await broadcast_update("speedtest_all_complete", {
                "summary": state.current_scan.to_dict(),
                "progress": state.scan_progress
            })


# --- Port & entry discovery ---------------------------------------------------
DISCOVERY_MIN_SUCCESS = 3     # successful tests a combo needs before it can be chosen
DISCOVERY_HISTORY_CAP = 30    # per-combo test history kept (persisted with the results)
DISCOVERY_STABILIZE = 10      # seconds after a verified connect before testing


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(value: str) -> datetime:
    """Parse a stored timestamp; old naive values were local time."""
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.astimezone()


def _speedtest_count() -> int:
    """Tests per server for normal speedtests (separate from discovery's tests per combo)."""
    cfg = config_manager.config.scan
    return cfg.speedtest_test_count or cfg.discovery_test_count


async def _wait_if_paused():
    while state.is_paused and not state.scan_cancelled:
        await asyncio.sleep(0.5)


def reset_discovery(start: bool) -> None:
    """Clear discovery results; optionally start a new period now. Caller saves config."""
    cfg = config_manager.config.scan
    cfg.discovery_results = {}
    cfg.discovery_scan_count = 0
    cfg.discovery_started_at = _utcnow_iso() if start else None
    if start:
        cfg.port_discovery_enabled = True
    state.port_discovery_results = {}


def _combo_record(existing: Optional[dict], port: int, entry: int) -> dict:
    """Combo record with running sums over successful tests only.
    Older records (averages that included failures as zeros) convert exactly:
    sum over all tests == sum over successes, because failures added 0."""
    r = dict(existing or {})
    if "dl_sum" not in r:
        tests = r.get("tests", 0)
        r["dl_sum"] = r.get("download_mbps", 0) * tests
        r["ul_sum"] = r.get("upload_mbps", 0) * tests
        r["ping_sum"] = r.get("ping_ms", 0) * tests
    r.setdefault("tests", 0)
    r.setdefault("success_tests", 0)
    for k in ("rel_dl_sum", "rel_ul_sum", "rel_ping_sum", "rel_n"):
        r.setdefault(k, 0)
    r.setdefault("history", [])
    r["port"], r["entry"] = port, entry
    return r


def _refresh_combo_stats(r: dict) -> None:
    ok = r["success_tests"]
    r["download_mbps"] = round(r["dl_sum"] / ok, 2) if ok else 0.0
    r["upload_mbps"] = round(r["ul_sum"] / ok, 2) if ok else 0.0
    r["ping_ms"] = round(r["ping_sum"] / ok, 2) if ok else 0.0
    r["success_rate"] = round(ok / max(1, r["tests"]), 2)
    if r["rel_n"]:
        r["relative_score"] = round(
            (0.5 * r["rel_dl_sum"] + 0.3 * r["rel_ul_sum"] + 0.2 * r["rel_ping_sum"]) / r["rel_n"], 3)
    r["history"] = r["history"][-DISCOVERY_HISTORY_CAP:]


def _persist_discovery() -> None:
    config_manager.config.scan.discovery_results = copy.deepcopy(state.port_discovery_results)
    config_manager.save()


async def _resolve_server_config(server):
    """
    Config to use for a server's speedtest, from the Preferred Port / Entry settings
    (which discovery updates when it finishes). Returns a Path, or None to use
    server.config_file.
    """
    scan_cfg = config_manager.config.scan
    # preferred_* is the single source of truth; discovery_auto_* is only a label
    target_port = scan_cfg.preferred_port
    target_entry_str = scan_cfg.preferred_entry_ip

    if target_entry_str == "AUTO":
        entry_number = 3
        if state.db:
            try:
                best_entry = await state.db.get_best_entry_for_server(server.server_name)
                entry_number = 1 if best_entry == "ENTRY1" else 3
            except Exception as e:
                logger.debug(f"AUTO entry lookup failed for {server.server_name}: {e}")
    else:
        entry_number = 1 if target_entry_str == "ENTRY1" else 3

    pings = {1: server.entry1_ping, 3: server.entry3_ping}
    entry_ping = pings.get(entry_number)
    if not entry_ping or not entry_ping.is_alive:
        # Keep the preferred port; try the other entry before giving up
        other = 3 if entry_number == 1 else 1
        alt = pings.get(other)
        if alt and alt.is_alive:
            logger.info(f"{server.server_name}: Entry {entry_number} not responding, using Entry {other} on port {target_port}")
            entry_number, entry_ping = other, alt
        else:
            return None

    if server.config_file:
        try:
            from ..wireguard import parse_filename
            meta = parse_filename(server.config_file.name)
            if int(meta.get("port")) == int(target_port) and int(meta.get("entry_number")) == entry_number:
                return None  # Already the right config
        except Exception:
            pass

    if not server.wg_pubkey:
        return None

    try:
        from ..confgen import get_or_generate_config
        config_path = get_or_generate_config(
            server_name=server.server_name,
            country_code=server.country_code,
            city=server.location,
            endpoint_ip=entry_ping.ip,
            server_pubkey=server.wg_pubkey,
            port=target_port,
            entry_number=entry_number,
        )
        logger.debug(f"Config override for {server.server_name}: {config_path.name}")
        return config_path
    except Exception as e:
        logger.warning(f"Failed to resolve config for {server.server_name}: {e}")
        return None


async def _run_discovery_phase(clean_servers, controller):
    """
    Port/entry discovery, run inside a scan's speedtest phase while the period is active.

    Each scan tests every port x entry combo on ONE server (rotating through the top 3
    clean servers), in random order, all from the same generated config template.
    Per combo it keeps sums over successful tests only. Per scan it also records how each
    combo did relative to the others on that server, so scans on different servers or at
    different times of day stay comparable. After discovery_duration_days the next scan
    finalizes.
    """
    scan_cfg = config_manager.config.scan
    if not scan_cfg.port_discovery_enabled:
        return

    if scan_cfg.discovery_started_at:
        try:
            started = _parse_ts(scan_cfg.discovery_started_at)
        except ValueError:
            started = datetime.now(timezone.utc)
            scan_cfg.discovery_started_at = started.isoformat()
        elapsed_days = (datetime.now(timezone.utc) - started).total_seconds() / 86400
        if elapsed_days >= scan_cfg.discovery_duration_days:
            await _finalize_discovery()
            return
        logger.info(f"Discovery active: {scan_cfg.discovery_duration_days - elapsed_days:.1f} days remaining")
    else:
        reset_discovery(start=True)
        config_manager.save()
        logger.info(f"Discovery started; runs for {scan_cfg.discovery_duration_days} days")

    candidates = sorted(
        [s for s in clean_servers if s.wg_pubkey and (s.entry1_ping or s.entry3_ping)],
        key=lambda s: s.score or 0, reverse=True,
    )[:3]
    if not candidates:
        logger.warning("Discovery: no eligible servers with pubkey and entry pings")
        return
    target = candidates[scan_cfg.discovery_scan_count % len(candidates)]
    scan_cfg.discovery_scan_count += 1

    try:
        from ..confgen import generate_config, get_client_identity
        identity = get_client_identity()
    except ValueError as e:
        logger.error(f"Discovery: cannot run: {e}")
        return

    entries = []
    for num, ping in ((1, target.entry1_ping), (3, target.entry3_ping)):
        if scan_cfg.discovery_entry_filter in ("ALL", f"ENTRY{num}") and ping and ping.is_alive:
            entries.append((num, ping.ip))
    combos = []
    for port in scan_cfg.available_ports:
        for num, ip in entries:
            # Every combo from the same template (same MTU), freshly generated
            path = generate_config(
                server_name=target.server_name, country_code=target.country_code, city=target.location,
                endpoint_ip=ip, server_pubkey=target.wg_pubkey, port=port, entry_number=num, identity=identity,
            )
            combos.append((path, port, num))
    if not combos:
        logger.warning(f"Discovery: no testable combos on {target.server_name}")
        return
    random.shuffle(combos)  # no fixed order, so no time-of-day bias towards the first combo

    tests_per_combo = scan_cfg.discovery_test_count
    total = len(combos)
    state.scan_progress = {
        "phase": "discovery", "current": 0, "total": total,
        "server": target.server_name, "country": target.country_code,
        "next": f"Discovery: {total} combos on {target.server_name}",
    }
    await broadcast_update("discovery_started", {"server": target.server_name, "combos": total,
                                                 "tests_per_combo": tests_per_combo})
    await broadcast_update("progress_update", {"progress": state.scan_progress})

    this_scan: dict[str, list] = {}  # combo_key -> successful SpeedTestResults this scan
    for idx, (config_path, port, entry_num) in enumerate(combos, 1):
        await _wait_if_paused()
        if state.scan_cancelled:
            break
        key = f"{port}_E{entry_num}"
        rec = _combo_record(state.port_discovery_results.get(key), port, entry_num)
        state.scan_progress.update(current=idx, next=f"Discovery: {key} on {target.server_name} ({idx}/{total})")
        await broadcast_update("progress_update", {"progress": state.scan_progress})
        logger.info(f"Discovery [{idx}/{total}]: {target.server_name} {key}")

        try:
            result = await controller.connect(config_path)
            if not result.success:
                logger.info(f"Discovery {key}: connect failed ({result.error}); retrying once")
                await asyncio.sleep(5)
                result = await controller.connect(config_path)
            if not result.success:
                # One failed attempt, not N: the speedtests never ran
                rec["tests"] += 1
                rec["history"].append({"tested_at": _utcnow_iso(), "server": target.server_name,
                                       "error": f"Connect failed: {result.error}"})
            else:
                await asyncio.sleep(DISCOVERY_STABILIZE)
                for test_num in range(1, tests_per_combo + 1):
                    await _wait_if_paused()
                    if state.scan_cancelled:
                        break
                    state.scan_progress["next"] = f"Discovery: {key} on {target.server_name} test {test_num}/{tests_per_combo}"
                    await broadcast_update("progress_update", {"progress": state.scan_progress})
                    res = await run_speedtest_for_country(target.country_code, secure=True)
                    _reject_if_not_via_vpn(res, result.public_ip)
                    rec["tests"] += 1
                    entry = {"tested_at": res.tested_at.astimezone(timezone.utc).isoformat() if res.tested_at else _utcnow_iso(),
                             "server": target.server_name}
                    if res.is_success:
                        # Only successful, verified-via-VPN tests feed the averages
                        rec["success_tests"] += 1
                        rec["dl_sum"] += res.download_mbps
                        rec["ul_sum"] += res.upload_mbps
                        rec["ping_sum"] += res.ping_ms
                        this_scan.setdefault(key, []).append(res)
                        entry.update(download_mbps=round(res.download_mbps, 2), upload_mbps=round(res.upload_mbps, 2),
                                     ping_ms=round(res.ping_ms, 1))
                    else:
                        entry["error"] = res.error or "failed"
                    rec["history"].append(entry)
                    if test_num < tests_per_combo:
                        await asyncio.sleep(10)
        finally:
            try:
                await controller.disconnect(config_path)
            except Exception:
                pass

        _refresh_combo_stats(rec)
        state.port_discovery_results[key] = rec
        logger.info(f"Discovery {key}: avg ↓{rec['download_mbps']:.1f} ↑{rec['upload_mbps']:.1f} "
                    f"ping {rec['ping_ms']:.1f}ms ({rec['success_tests']}/{rec['tests']} ok)")
        await broadcast_update("discovery_combo_complete", {"combo": key, "results": rec})
        _persist_discovery()

    # Relative comparison within this scan (same server, same time window)
    means = {k: (statistics.mean(r.download_mbps for r in v), statistics.mean(r.upload_mbps for r in v),
                 statistics.mean(r.ping_ms for r in v)) for k, v in this_scan.items()}
    if len(means) >= 2:
        avg_dl = statistics.mean(m[0] for m in means.values()) or 1
        avg_ul = statistics.mean(m[1] for m in means.values()) or 1
        avg_inv_ping = statistics.mean(1 / max(m[2], 0.1) for m in means.values())
        for k, (dl, ul, ping) in means.items():
            rec = state.port_discovery_results[k]
            rec["rel_dl_sum"] += dl / avg_dl
            rec["rel_ul_sum"] += ul / avg_ul
            rec["rel_ping_sum"] += (1 / max(ping, 0.1)) / avg_inv_ping
            rec["rel_n"] += 1
            _refresh_combo_stats(rec)
        _persist_discovery()

    await broadcast_update("discovery_scan_complete", {"server": target.server_name,
                                                       "results": state.port_discovery_results})
    # Cool down before the regular speedtests start
    if not state.scan_cancelled:
        await _smart_wait(scan_cfg.post_server_wait)


async def _finalize_discovery():
    """
    Called on the first scan after the discovery period ends. Picks the best combo
    (relative score x success rate) among combos with enough successful tests, applies
    it to Preferred Port/Entry (an "AUTO" entry choice is kept), and stops discovery.
    """
    scan_cfg = config_manager.config.scan
    allowed_entries = {1, 3} if scan_cfg.discovery_entry_filter == "ALL" else {int(scan_cfg.discovery_entry_filter[-1])}
    results = {
        k: _combo_record(v, v.get("port"), v.get("entry"))
        for k, v in state.port_discovery_results.items()
        if v.get("port") in scan_cfg.available_ports and v.get("entry") in allowed_entries
    }
    for r in results.values():
        _refresh_combo_stats(r)
    qualified = {k: r for k, r in results.items() if r["success_tests"] >= DISCOVERY_MIN_SUCCESS}

    scan_cfg.port_discovery_enabled = False
    scan_cfg.discovery_started_at = None
    scan_cfg.discovery_finished_at = _utcnow_iso()

    if not qualified:
        scan_cfg.discovery_auto_port = None
        scan_cfg.discovery_auto_entry = None
        scan_cfg.discovery_outcome = (f"inconclusive: no combo reached {DISCOVERY_MIN_SUCCESS} successful tests; "
                                      "kept current settings")
        config_manager.save()
        logger.warning(f"Discovery finished: {scan_cfg.discovery_outcome}")
        await broadcast_update("discovery_finalized", {"outcome": scan_cfg.discovery_outcome, "results": results})
        return

    def score(r):
        rel = r.get("relative_score", 1.0)  # 1.0 = neutral when only one combo was comparable
        return rel * r["success_rate"]

    best_key = max(qualified, key=lambda k: score(qualified[k]))
    best = qualified[best_key]
    scan_cfg.discovery_auto_port = best["port"]
    scan_cfg.discovery_auto_entry = f"ENTRY{best['entry']}"
    scan_cfg.preferred_port = best["port"]
    if scan_cfg.preferred_entry_ip != "AUTO":  # respect an explicit AUTO choice
        scan_cfg.preferred_entry_ip = f"ENTRY{best['entry']}"
    scan_cfg.discovery_outcome = f"{best['port']}/ENTRY{best['entry']}"
    config_manager.save()

    logger.info(f"Discovery complete: best port={best['port']} entry=E{best['entry']} "
                f"(↓{best['download_mbps']:.1f} ↑{best['upload_mbps']:.1f} ping={best['ping_ms']:.1f}ms, "
                f"{best['success_tests']}/{best['tests']} ok, relative {best.get('relative_score', 1.0):.2f})")
    await broadcast_update("discovery_finalized", {
        "best_port": best["port"], "best_entry": best["entry"], "outcome": scan_cfg.discovery_outcome,
        "results": results,
    })


def _should_skip_server(server_name: str) -> bool:
    """
    Pre-check: should we skip this server based on performance history?
    Returns True if the server is disabled or consistently underperforming.
    """
    perf_cfg = config_manager.config.performance
    
    # Check if explicitly disabled
    if server_name in perf_cfg.disabled_servers:
        return True
    
    # Check performance history
    history = state.server_performance_history.get(server_name, [])
    if len(history) >= perf_cfg.check_count:
        recent = history[-perf_cfg.check_count:]
        all_below = all(
            r.get("download", r.get("download_mbps", 0)) < perf_cfg.threshold_download or
            r.get("upload", r.get("upload_mbps", 0)) < perf_cfg.threshold_upload
            for r in recent
        )
        if all_below:
            logger.debug(f"Skipping {server_name}: consistently below threshold")
            return True
    
    return False


async def _run_single_server_speedtest(server, index, total, controller, tests_per_server, inter_test_delay, vpn_wait, config_override=None, scan_id=None):
    """Refactored single server speedtest runner using direct wg/ip commands (no namespaces).

    scan_id links the stored result to a scan (None for manual tests).
    Returns None on success, otherwise a short reason (used for manual-run feedback).
    """
    # Pre-check: skip if underperforming
    if _should_skip_server(server.server_name):
        logger.info(f"Skipping speedtest for {server.server_name} (below threshold / disabled)")
        return "Skipped: server is disabled or below performance thresholds"

    # Update progress
    state.scan_progress["current"] = index
    state.scan_progress["server"] = server.server_name
    state.scan_progress["country"] = server.country_code
    state.scan_progress["next"] = "Connecting VPN..."
    await broadcast_update("progress_update", {"progress": state.scan_progress})
    
    # Determine which config file to use
    conf_file = config_override or server.config_file
    
    try:
        # 1. Connect VPN directly (no namespace)
        if not conf_file:
            await _report_speedtest_error(server, "No config file available")
            return "No config file available"

        logger.debug(f"Connecting to VPN for {server.server_name}")
        result = await controller.connect(conf_file)
        
        if not result.success:
             await _report_speedtest_error(server, f"Failed to connect: {result.error}")
             return f"Failed to connect: {result.error}"
             
        # 2. Wait for VPN to stabilize
        state.scan_progress["next"] = "Stabilizing VPN..."
        await broadcast_update("progress_update", {"progress": state.scan_progress})
        await asyncio.sleep(vpn_wait)
        
        # 3. Run Tests (no namespace - runs directly in container)
        results = []
        last_error = None
        for i in range(1, tests_per_server + 1):
            if state.scan_cancelled: return "Cancelled"
            state.scan_progress["next"] = f"Test {i}/{tests_per_server}"
            await broadcast_update("progress_update", {"progress": state.scan_progress})
            
            await broadcast_update("speedtest_started", {
                "server": server.server_name,
                "country": server.country_code,
                "current": index,
                "total": total,
                "test_number": i,
                "next": state.scan_progress.get("next", f"Test {i}/{tests_per_server}")
            })
            
            # Run speedtest directly (no namespace parameter)
            res = await run_speedtest_for_country(
                server.country_code, 
                secure=True
            )
            _reject_if_not_via_vpn(res, result.public_ip)
            
            if res.is_success:
                results.append(res)
            else:
                last_error = res.error
            
            if i < tests_per_server:
                await asyncio.sleep(inter_test_delay)
                
        # Averaging and Reporting
        if not results:
            msg = f"All {tests_per_server} speedtest run(s) failed" + (f": {last_error}" if last_error else "")
            await _report_speedtest_error(server, msg)
            return msg
        if results:
            avg = _average_speedtest_results(results, server.server_name)
            dct = avg.to_dict()
            dct["vpn_server_name"] = server.server_name
            dct["vpn_country_code"] = server.country_code
            
            # Include port/entry info from the config filename for comparison testing
            try:
                from ..wireguard import parse_filename
                conf_name = conf_file.name if hasattr(conf_file, 'name') else str(conf_file).split('/')[-1]
                meta = parse_filename(conf_name)
                dct["vpn_port"] = meta["port"]
                dct["vpn_entry"] = f"Entry {meta['entry_number']}"
            except Exception:
                pass
            
            # Calculate deviation if baseline exists
            if state.baseline_speedtest:
                baseline_down = state.baseline_speedtest.get("download_mbps", 0)
                baseline_up = state.baseline_speedtest.get("upload_mbps", 0)
                
                if baseline_down > 0:
                    # Deviation score = percentage of baseline speed retained
                    # e.g., 100 = same as baseline, 50 = half speed, 150 = 50% faster
                    down_ratio = (dct.get("download_mbps", 0) / baseline_down) * 100
                    up_ratio = (dct.get("upload_mbps", 0) / baseline_up) * 100 if baseline_up > 0 else 100
                    
                    # Get weights from config
                    cfg = config_manager.config.scoring
                    down_weight = cfg.deviation_download_weight
                    up_weight = cfg.deviation_upload_weight
                    
                    # Weighted average of download and upload ratios
                    deviation_score = (down_ratio * down_weight) + (up_ratio * up_weight)
                    dct["deviation_score"] = round(deviation_score, 1)
                    
                    logger.debug(f"Deviation score for {server.server_name}: {deviation_score:.1f}% "
                                f"(down: {down_ratio:.1f}%, up: {up_ratio:.1f}%)")
            
            server.speedtest_result = dct
            
            # Update summary in state
            if state.current_scan:
                for s in state.current_scan.servers:
                    if s.server_name == server.server_name:
                        s.speedtest_result = dct
                        break
            
            await _check_and_disable_underperforming_server(server.server_name, dct)
            
            # Persist to SQLite
            if state.db:
                try:
                    await state.db.add_speedtest_result(dct, scan_id=scan_id)
                except Exception as e:
                    logger.error(f"Failed to save speedtest to DB: {e}")
            
            await broadcast_update("speedtest_complete", {
                 "server": server.to_dict() if hasattr(server, 'to_dict') else {"server_name": server.server_name},
                 "summary": state.current_scan.to_dict() if state.current_scan else None
            })
            return None

    finally:
        # Always disconnect VPN after test (cleanup for next server)
        try:
            await controller.disconnect(conf_file)
        except Exception as e:
            logger.warning(f"Failed to disconnect VPN: {e}")


async def _report_speedtest_error(server, msg):
    await broadcast_update("speedtest_error", {"server": server.server_name, "error": msg})
    if state.current_scan:
        for s in state.current_scan.servers:
            if s.server_name == server.server_name:
                s.speedtest_result = {"error": msg}


async def _smart_wait(duration):
    """Wait with progress updates and cancellation check."""
    elapsed = 0
    interval = 1
    while elapsed < duration and not state.scan_cancelled:
        if state.is_paused:
            await asyncio.sleep(1)
            continue
            
        await asyncio.sleep(interval)
        elapsed += interval
        
        remaining = duration - elapsed
        if remaining % 5 == 0:
            state.scan_progress["next"] = f"Waiting {remaining}s..."
            await broadcast_update("progress_update", {"progress": state.scan_progress})


async def run_speedtest_task(server, current: int = None, total: int = None, controller=None):
    """
    Manual single server speedtest task.
    Creates its own WireGuard controller if none provided.
    """
    ctrl = controller or WireGuardController(use_sudo=None)
    error = "Speedtest crashed (see logs)"
    try:
        # Queue behind any other VPN job (another manual test or a baseline)
        async with network_job(f"speedtest {server.server_name}"):
            # Own progress dict: a manual test must not leave the scan progress dirty
            saved_progress = state.scan_progress
            state.scan_progress = {"phase": "speedtesting", "current": 0, "total": total or 1,
                                   "server": "", "country": "", "next": ""}
            try:
                error = await _run_single_server_speedtest(
                    server,
                    current or 1,
                    total or 1,
                    ctrl,
                    tests_per_server=_speedtest_count(),
                    inter_test_delay=10,
                    vpn_wait=30,
                    # Same port/entry as scan speedtests, so results are comparable
                    config_override=await _resolve_server_config(server),
                    scan_id=None,  # manual results don't belong to any scan
                )
            finally:
                # Restore while still holding the lock, so a waiting scan's progress isn't overwritten
                state.scan_progress = saved_progress if state.is_scanning else _idle_progress()
                if not state.is_scanning:
                    await broadcast_update("progress_update", {"progress": state.scan_progress})
    finally:
        # Always tell the UI how a manual run ended (success, failure or skip)
        result = server.speedtest_result if not error else None
        await broadcast_update("speedtest_manual_done", {
            "server": server.server_name,
            "ok": error is None,
            "error": error,
            "download_mbps": result.get("download_mbps") if result else None,
            "upload_mbps": result.get("upload_mbps") if result else None,
            "ping_ms": result.get("ping_ms") if result else None,
        })
        if not controller:
            try:
                await ctrl.disconnect()
            except Exception:
                pass

