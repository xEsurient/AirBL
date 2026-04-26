"""
Background tasks for AirBL Web UI.
"""

import asyncio
from datetime import datetime, timedelta
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


async def _check_and_disable_underperforming_server(server_name: str, speedtest_result: dict):
    """
    Check if server consistently underperforms and auto-disable if needed.
    """
    # Skip if speedtest failed
    if not speedtest_result or "error" in speedtest_result:
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
            server_id=0,
            server_name=server_name,
            server_country="Unknown",
            timestamp=datetime.now().isoformat(),
            error="No results to average"
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
        server_country=last.server_country,
        tested_at=last.tested_at,
        download_mbps=avg_download,
        upload_mbps=avg_upload,
        ping_ms=avg_ping,
    )


async def run_baseline_speedtest():
    """
    Run a speedtest without VPN to establish baseline performance.
    This is used to calculate deviation scores for VPN-connected speedtests.
    """
    from ..speedtest import run_speedtest
    
    logger.info("Running baseline speedtest (no VPN)")
    await broadcast_update("baseline_speedtest_started", {})
    
    try:
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
            state.baseline_speedtest = baseline
            logger.info(f"Baseline speedtest complete: ↓{result.download_mbps:.1f} ↑{result.upload_mbps:.1f} Mbps")
            await broadcast_update("baseline_speedtest_complete", {"baseline": baseline})
        else:
            error_msg = result.error or "Unknown error"
            logger.error(f"Baseline speedtest failed: {error_msg}")
            await broadcast_update("baseline_speedtest_error", {"error": error_msg})
    except Exception as e:
        logger.error(f"Baseline speedtest error: {e}")
        await broadcast_update("baseline_speedtest_error", {"error": str(e)})


async def run_scan_task():
    """Background task to run a full scan."""
    state.is_scanning = True
    state.is_paused = False
    state.scan_cancelled = False
    
    try:
        # Calculate next scan time
        interval = state.scan_interval_minutes
        state.next_scan_at = datetime.now() + timedelta(minutes=interval)
        
        await broadcast_update("scan_started", {
            "next_scan_at": state.next_scan_at.isoformat()
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
            city_filter=city_filter
        )
        
        # Create scan entry in DB at start to get ID
        if state.db:
            try:
                state.current_scan_id = await state.db.add_scan_result({
                    "total_servers": 0,
                    "clean_servers": 0,
                    "blocked_servers": 0,
                    "disabled_servers": len(excluded)
                })
                logger.info(f"Scan started with DB ID: {state.current_scan_id}")
            except Exception as e:
                logger.error(f"Failed to create scan entry in DB: {e}")
                state.current_scan_id = None
        
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
            
            # update.summary is ScanSummary object
            # update.server is the server that just finished (optional)
            
            # Update global state
            state.current_scan = update.summary
            
            # Broadcast update
            if update.server:
                # Individual server update
                await broadcast_update("server_complete", {
                    "server": update.server.to_dict(),
                    "summary": update.summary.to_dict()
                })
                
                # Persist individual server result to DB
                if state.db and getattr(state, "current_scan_id", None):
                    try:
                        await state.db.add_server_scan_result(
                            state.current_scan_id, 
                            update.server.to_dict()
                        )
                    except Exception as e:
                        logger.error(f"Failed to persist server result to DB: {e}")
                    
                    # Persist entry ping history for AUTO mode
                    try:
                        srv = update.server
                        if srv.entry1_ping:
                            await state.db.add_entry_ping(
                                state.current_scan_id, srv.server_name,
                                "ENTRY1", srv.entry1_ping.ip,
                                srv.entry1_ping.avg_rtt_ms,
                                srv.entry1_ping.is_alive
                            )
                        if srv.entry3_ping:
                            await state.db.add_entry_ping(
                                state.current_scan_id, srv.server_name,
                                "ENTRY3", srv.entry3_ping.ip,
                                srv.entry3_ping.avg_rtt_ms,
                                srv.entry3_ping.is_alive
                            )
                    except Exception as e:
                        logger.error(f"Failed to persist entry ping to DB: {e}")
            
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

        # Scan Complete Handling
        if not state.scan_cancelled and state.current_scan:
            logger.info(f"Scan completed. Found {state.current_scan.clean_servers_count} clean servers.")
            
            await broadcast_update("scan_complete", {
                "summary": state.current_scan.to_dict(),
                "next_scan_at": state.next_scan_at.isoformat() if state.next_scan_at else None
            })
            
            # Save history to memory (and log)
            state.scan_history.append({
                "timestamp": datetime.now().isoformat(),
                "total_servers": state.current_scan.total_servers,
                "clean_servers": state.current_scan.clean_servers_count,
                "blocked_servers": state.current_scan.blocked_servers_count,
                 # "disabled_servers": len(state.disabled_servers), 
                 # use config directly
                "disabled_servers": len(config_manager.config.performance.disabled_servers),
            })
            # Keep only last 50 entries in memory
            if len(state.scan_history) > 50:
                state.scan_history = state.scan_history[-50:]

            # Update DB with final summary
            if state.db and getattr(state, "current_scan_id", None):
                try:
                    await state.db.update_scan_result(
                        state.current_scan_id, 
                        state.current_scan.to_dict()
                    )
                    logger.info(f"Updated scan result ID {state.current_scan_id} with final stats")
                except Exception as e:
                    logger.error(f"Failed to update scan in DB: {e}")

        
        # Run speedtests on clean servers if enabled (only if not cancelled)
        if not state.scan_cancelled and state.speedtest_enabled and state.current_scan:
            # Force baseline speedtest refresh for every new scan cycle
            # This ensures we have an up-to-date baseline for comparison
            logger.info("Running baseline speedtest (no VPN) before VPN tests")
            await run_baseline_speedtest()
            
            await _run_batch_speedtests()
        
    except asyncio.CancelledError:
        await broadcast_update("scan_cancelled", {})
    except Exception as e:
        logger.error(f"Scan task error: {e}", exc_info=True)
        await broadcast_update("scan_error", {"error": str(e)})
    finally:
        # Only set is_scanning to False after everything is complete (including speedtests)
        state.is_scanning = False
        state.is_paused = False
        state.scan_cancelled = False
        state.scan_task = None
        
        # Reset progress to idle
        state.scan_progress = {"phase": "idle", "current": 0, "total": 0, "server": "", "country": "", "next": ""}
        await broadcast_update("progress_update", {"progress": state.scan_progress})


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
        TESTS_PER_SERVER = config_manager.config.scan.discovery_test_count
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
                        config_override=config_override
                    )
                    
                    # Post-server wait
                    if server_index < total_speedtests and not state.scan_cancelled:
                        await _smart_wait(POST_SERVER_WAIT)
                        
        finally:
            try:
                await controller.disconnect()
            except:
                pass
                
        # Completion broadcast logic
        if not state.scan_cancelled:
             # Update ban frequency tracking
             if state.current_scan and state.current_scan.servers:
                 for server in state.current_scan.servers:
                     if not server.is_clean:
                         name = server.server_name
                         state.ban_history[name] = state.ban_history.get(name, 0) + 1

             # Generate custom Gluetun servers.json
             try:
                 await generate_gluetun_servers_json()
             except Exception as e:
                 logger.error(f"Failed to generate Gluetun servers.json: {e}")

             # Generate WireGuard configs
             try:
                 from ..wireguard_gen import generate_wireguard_configs
                 await generate_wireguard_configs()
             except Exception as e:
                 logger.error(f"Failed to generate WireGuard configs: {e}")

             await broadcast_update("speedtest_all_complete", {
                "summary": state.current_scan.to_dict(),
                "progress": state.scan_progress
            })


async def _resolve_server_config(server):
    """
    Resolve the correct WireGuard config file for a server based on
    preferred port, entry IP settings (including AUTO mode).
    
    Returns a Path to the config file to use, or None to use server.config_file.
    """
    scan_cfg = config_manager.config.scan
    target_port = scan_cfg.discovery_auto_port or scan_cfg.preferred_port
    target_entry_str = scan_cfg.discovery_auto_entry or scan_cfg.preferred_entry_ip
    
    # Determine entry number
    if target_entry_str == "AUTO":
        # Use DB-backed historical latency analysis
        if state.db:
            try:
                best_entry = await state.db.get_best_entry_for_server(server.server_name)
                entry_number = 1 if best_entry == "ENTRY1" else 3
            except Exception as e:
                logger.debug(f"AUTO entry lookup failed for {server.server_name}: {e}")
                entry_number = 3  # Default fallback
        else:
            entry_number = 3
    elif target_entry_str == "ENTRY1":
        entry_number = 1
    else:
        entry_number = 3  # Default to ENTRY3
    
    # Get the entry IP
    if entry_number == 1:
        entry_ping = server.entry1_ping
    else:
        entry_ping = server.entry3_ping
    
    if not entry_ping or not entry_ping.is_alive:
        # Fallback to original config file
        return None
    
    endpoint_ip = entry_ping.ip
    
    # Check if the current server.config_file already matches
    if server.config_file:
        try:
            from ..wireguard import parse_filename, parse_config_content
            meta = parse_filename(server.config_file.name)
            if meta.get("port") == target_port and meta.get("entry_number") == entry_number:
                return None  # Already the right config
        except Exception:
            pass
    
    # Need a different config — use confgen
    if not server.wg_pubkey:
        return None
    
    try:
        from ..confgen import get_or_generate_config
        config_path = get_or_generate_config(
            server_name=server.server_name,
            country_code=server.country_code,
            city=server.location,
            endpoint_ip=endpoint_ip,
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
    Run port/entry discovery if enabled and still within the discovery period.
    
    Tests ALL port×entry combos on the top-scored clean server each scan.
    Runs for discovery_duration_days, then auto-selects the best combo.
    """
    scan_cfg = config_manager.config.scan
    
    if not scan_cfg.port_discovery_enabled:
        return
    
    # Check if discovery period is active
    if scan_cfg.discovery_started_at:
        started = datetime.fromisoformat(scan_cfg.discovery_started_at)
        elapsed_days = (datetime.now() - started).total_seconds() / 86400
        
        if elapsed_days >= scan_cfg.discovery_duration_days:
            # Discovery period is over — finalize results
            await _finalize_discovery()
            return
        
        days_remaining = scan_cfg.discovery_duration_days - elapsed_days
        logger.info(f"Discovery active: {days_remaining:.1f} days remaining")
    else:
        # First run — set the start time
        scan_cfg.discovery_started_at = datetime.now().isoformat()
        config_manager.save()
        logger.info(f"Discovery started — will run for {scan_cfg.discovery_duration_days} days")
    
    # Pick the top-scored clean server for discovery
    scored_servers = sorted(
        [s for s in clean_servers if s.wg_pubkey and (s.entry1_ping or s.entry3_ping)],
        key=lambda s: s.score,
        reverse=True
    )
    
    if not scored_servers:
        logger.warning("Discovery: no eligible servers with pubkey and entry pings")
        return
    
    target = scored_servers[0]
    logger.info(f"Discovery: testing combos on {target.server_name} ({target.country_code})")
    
    # Get entry IPs
    entry1_ip = target.entry1_ping.ip if target.entry1_ping and target.entry1_ping.is_alive else None
    entry3_ip = target.entry3_ping.ip if target.entry3_ping and target.entry3_ping.is_alive else None
    
    try:
        from ..confgen import generate_all_combos, get_client_identity
        identity = get_client_identity()
    except ValueError as e:
        logger.error(f"Discovery: cannot run — {e}")
        return
    
    combos = generate_all_combos(
        server_name=target.server_name,
        country_code=target.country_code,
        city=target.location,
        entry1_ip=entry1_ip,
        entry3_ip=entry3_ip,
        server_pubkey=target.wg_pubkey,
        ports=scan_cfg.available_ports,
        entry_filter=scan_cfg.discovery_entry_filter,
        identity=identity,
    )
    
    if not combos:
        logger.warning("Discovery: no valid combos generated")
        return
    
    total_combos = len(combos)
    POST_SERVER_WAIT = scan_cfg.post_server_wait
    VPN_STABILIZATION_WAIT = 30
    INTER_TEST_DELAY = 10
    tests_per_combo = scan_cfg.discovery_test_count
    
    state.scan_progress = {
        "phase": "discovery",
        "current": 0,
        "total": total_combos,
        "server": target.server_name,
        "country": target.country_code,
        "next": f"Discovery: testing {total_combos} combos on {target.server_name}"
    }
    await broadcast_update("discovery_started", {
        "server": target.server_name,
        "combos": total_combos,
        "tests_per_combo": tests_per_combo,
    })
    await broadcast_update("progress_update", {"progress": state.scan_progress})
    
    for combo_idx, (config_path, port, entry_num) in enumerate(combos, 1):
        if state.scan_cancelled:
            break
        
        combo_key = f"{port}_E{entry_num}"
        logger.info(f"Discovery [{combo_idx}/{total_combos}]: port={port} entry=E{entry_num}")
        
        state.scan_progress["current"] = combo_idx
        state.scan_progress["next"] = f"Discovery: {combo_key} ({combo_idx}/{total_combos})"
        await broadcast_update("progress_update", {"progress": state.scan_progress})
        
        try:
            # Connect with this combo's config
            result = await controller.connect(config_path)
            if not result.success:
                logger.warning(f"Discovery: failed to connect with {combo_key}: {result.error}")
                continue
            
            # Stabilize
            await asyncio.sleep(VPN_STABILIZATION_WAIT)
            
            # Run speedtests
            combo_results = []
            for test_num in range(1, tests_per_combo + 1):
                if state.scan_cancelled:
                    break
                
                state.scan_progress["next"] = f"Discovery: {combo_key} test {test_num}/{tests_per_combo}"
                await broadcast_update("progress_update", {"progress": state.scan_progress})
                
                res = await run_speedtest_for_country(
                    target.country_code,
                    secure=True
                )
                
                if res.is_success:
                    combo_results.append(res)
                
                if test_num < tests_per_combo:
                    await asyncio.sleep(INTER_TEST_DELAY)
            
            # Average results for this combo
            if combo_results:
                avg = _average_speedtest_results(combo_results, f"DISCOVERY_{combo_key}")
                
                # Update or accumulate discovery results
                existing = state.port_discovery_results.get(combo_key, {
                    "download_mbps": 0, "upload_mbps": 0, "ping_ms": 0, "tests": 0, "history": []
                })
                prev_tests = existing["tests"]
                new_tests = prev_tests + len(combo_results)
                
                # Running weighted average
                state.port_discovery_results[combo_key] = {
                    "download_mbps": round(
                        (existing["download_mbps"] * prev_tests + avg.download_mbps * len(combo_results)) / new_tests, 2
                    ),
                    "upload_mbps": round(
                        (existing["upload_mbps"] * prev_tests + avg.upload_mbps * len(combo_results)) / new_tests, 2
                    ),
                    "ping_ms": round(
                        (existing["ping_ms"] * prev_tests + (avg.ping_ms or 0) * len(combo_results)) / new_tests, 2
                    ),
                    "tests": new_tests,
                    "port": port,
                    "entry": entry_num,
                    "history": existing.get("history", []) + [res.to_dict() for res in combo_results]
                }
                
                logger.info(
                    f"Discovery {combo_key}: ↓{avg.download_mbps:.1f} ↑{avg.upload_mbps:.1f} "
                    f"ping={avg.ping_ms:.1f}ms (total tests: {new_tests})"
                )
                
                await broadcast_update("discovery_combo_complete", {
                    "combo": combo_key,
                    "results": state.port_discovery_results[combo_key],
                })
                
                # Persist to config for survival across restarts (strip bulky history)
                config_manager.config.scan.discovery_results = {
                    k: {kk: vv for kk, vv in v.items() if kk != "history"}
                    for k, v in state.port_discovery_results.items()
                }
                config_manager.save()
        
        finally:
            try:
                await controller.disconnect(config_path)
            except Exception:
                pass
        
        # Wait between combos
        if combo_idx < total_combos and not state.scan_cancelled:
            await _smart_wait(POST_SERVER_WAIT)
    
    await broadcast_update("discovery_scan_complete", {
        "results": state.port_discovery_results,
    })


async def _finalize_discovery():
    """
    Called when discovery period expires.
    Picks the best port/entry combo and updates config.
    """
    scan_cfg = config_manager.config.scan
    results = state.port_discovery_results
    
    if not results:
        logger.warning("Discovery period ended but no results collected")
        scan_cfg.port_discovery_enabled = False
        config_manager.save()
        return
    
    # Find best combo by download speed (primary), then upload (secondary)
    best_key = max(
        results.keys(),
        key=lambda k: (results[k].get("download_mbps", 0), results[k].get("upload_mbps", 0))
    )
    best = results[best_key]
    
    scan_cfg.discovery_auto_port = best["port"]
    scan_cfg.discovery_auto_entry = f"ENTRY{best['entry']}"
    scan_cfg.preferred_port = best["port"]
    scan_cfg.preferred_entry_ip = f"ENTRY{best['entry']}"
    scan_cfg.port_discovery_enabled = False
    state.port_discovery_complete = True
    
    config_manager.save()
    
    logger.info(
        f"Discovery complete! Best combo: port={best['port']} entry=E{best['entry']} "
        f"(↓{best['download_mbps']:.1f} ↑{best['upload_mbps']:.1f} ping={best['ping_ms']:.1f}ms "
        f"from {best['tests']} tests)"
    )
    
    await broadcast_update("discovery_finalized", {
        "best_port": best["port"],
        "best_entry": best["entry"],
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
            r.get("download_mbps", 0) < perf_cfg.threshold_download or
            r.get("upload_mbps", 0) < perf_cfg.threshold_upload
            for r in recent
        )
        if all_below:
            logger.debug(f"Skipping {server_name}: consistently below threshold")
            return True
    
    return False


async def _run_single_server_speedtest(server, index, total, controller, tests_per_server, inter_test_delay, vpn_wait, config_override=None):
    """Refactored single server speedtest runner using direct wg/ip commands (no namespaces)."""
    # Pre-check: skip if underperforming
    if _should_skip_server(server.server_name):
        logger.info(f"Skipping speedtest for {server.server_name} (below threshold / disabled)")
        return

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
            return

        logger.debug(f"Connecting to VPN for {server.server_name}")
        result = await controller.connect(conf_file)
        
        if not result.success:
             await _report_speedtest_error(server, f"Failed to connect: {result.error}")
             return
             
        # 2. Wait for VPN to stabilize
        state.scan_progress["next"] = "Stabilizing VPN..."
        await broadcast_update("progress_update", {"progress": state.scan_progress})
        await asyncio.sleep(vpn_wait)
        
        # 3. Run Tests (no namespace - runs directly in container)
        results = []
        for i in range(1, tests_per_server + 1):
            if state.scan_cancelled: return
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
            
            if res.is_success:
                results.append(res)
            
            if i < tests_per_server:
                await asyncio.sleep(inter_test_delay)
                
        # Averaging and Reporting
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
                    # Use current_scan_id if available (set in run_scan_task)
                    scan_id = getattr(state, "current_scan_id", None)
                    await state.db.add_speedtest_result(dct, scan_id=scan_id)
                except Exception as e:
                    logger.error(f"Failed to save speedtest to DB: {e}")
            
            await broadcast_update("speedtest_complete", {
                 "server": server.to_dict() if hasattr(server, 'to_dict') else {"server_name": server.server_name},
                 "summary": state.current_scan.to_dict() if state.current_scan else None
            })

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
    try:
        await _run_single_server_speedtest(
            server,
            current or 1,
            total or 1,
            ctrl,
            tests_per_server=config_manager.config.scan.discovery_test_count,
            inter_test_delay=10,
            vpn_wait=30
        )
    finally:
        if not controller:
            try:
                await ctrl.disconnect()
            except Exception:
                pass

