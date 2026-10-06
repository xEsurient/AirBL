import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import uvicorn

from .state import state, setup_debug_logging
from .tasks import run_scan_task
from .routes import api, pages
from .websockets import websocket_handler
from typing import Optional
from fastapi import WebSocket

# Setup basic logging
setup_debug_logging()
logger = logging.getLogger("airbl.web")

async def _shutdown():
    # Don't leave a tunnel, kill switch or routes behind on stop/restart
    task = getattr(state, "scan_task", None)
    if task and not task.done():
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=20)
        except BaseException:
            pass
    try:
        from ..hummingbird import WireGuardController
        await asyncio.wait_for(WireGuardController(use_sudo=None).disconnect(), timeout=20)
    except BaseException as e:
        logger.warning(f"VPN cleanup on shutdown failed: {e}")
    if hasattr(state, 'db') and state.db:
        await state.db.close()
    logger.info("Application shutdown complete.")


@asynccontextmanager
async def _lifespan(app: FastAPI):
    await state.startup()
    logger.info(f"Application started. Config dir: {state.config_dir}")
    try:
        yield
    finally:
        await _shutdown()


def create_app(config_dir: Path = None) -> FastAPI:
    if config_dir:
        state.config_dir = config_dir

    app = FastAPI(title="AirVPN DroneBL Scanner", lifespan=_lifespan)

    @app.middleware("http")
    async def _revalidate(request, call_next):
        # Pages and static files are revalidated on every load (cheap 304 via
        # ETag); without this, browsers kept stale JS after a deploy.
        response = await call_next(request)
        path = request.url.path
        if not path.startswith(("/api", "/ws")):
            response.headers.setdefault("Cache-Control", "no-cache")
        return response

    # Mount static files
    static_dir = Path(__file__).parent.parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # Include routers
    app.include_router(api.router, prefix="/api")
    app.include_router(pages.router)
    
    # WebSocket route for real-time updates
    @app.websocket("/ws")
    async def ws_route(websocket: WebSocket):
        await websocket_handler(websocket)

    return app

async def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    config_dir: Path = None,
    scan_interval_minutes: Optional[int] = None,
    auto_scan: Optional[bool] = None,
):
    """
    Run the web server with auto-scanning.

    scan_interval_minutes / auto_scan override the saved settings for this run only
    when given (None keeps what was saved in the UI).
    """
    if config_dir:
        state.config_dir = config_dir
    if scan_interval_minutes is not None:
        state.scan_interval_minutes = scan_interval_minutes
        logger.info(f"Scan interval overridden to {state.scan_interval_minutes} min (env/CLI)")
    if auto_scan is not None:
        state.auto_scan_enabled = auto_scan
        logger.info(f"Auto-scan overridden to {auto_scan} (env/CLI)")
    
    app = create_app(config_dir)
    
    # Configure uvicorn (access_log disabled to reduce noise from polling endpoints)
    config = uvicorn.Config(
        app, 
        host=host, 
        port=port, 
        log_level="info",
        access_log=False,
        timeout_keep_alive=75,
        limit_concurrency=1000,
        backlog=2048,
    )
    server = uvicorn.Server(config)
    
    # Always start the scan timer loop so it respects dynamic settings changes.
    async def auto_scan_loop():
        from datetime import datetime
        from .tasks import calculate_next_scan_time
        
        # Wait for startup to initialize the event
        while state.settings_updated_event is None:
            await asyncio.sleep(1)
            
        logger.info("Auto-scan loop started")
        
        while True:
            try:
                if not state.auto_scan_enabled or state.is_scanning:
                    state.settings_updated_event.clear()
                    try:
                        await asyncio.wait_for(
                            state.settings_updated_event.wait(), timeout=60
                        )
                    except asyncio.TimeoutError:
                        pass
                    continue

                from ..config import config_manager
                scan_cfg = config_manager.config.scan
                
                now = datetime.now()
                if state.next_scan_at is None:
                    state.next_scan_at = calculate_next_scan_time(scan_cfg, now)
                    
                # How long until next scan?
                sleep_duration = (state.next_scan_at - datetime.now()).total_seconds()
                
                if sleep_duration <= 0:
                    logger.info("Scheduled scan time reached, launching scan")
                    state.is_scanning = True  # before the task runs, so Start can't add a second scan
                    task = asyncio.create_task(run_scan_task())
                    state.scan_task = task
                    try:
                        await task
                    except asyncio.CancelledError:
                        # Stop cancels the scan task we await; that must not end
                        # this loop (CancelledError isn't an Exception subclass).
                        if getattr(asyncio.current_task(), "cancelling", lambda: 0)():
                            raise  # the loop itself is being cancelled (shutdown)
                        logger.info("Scheduled scan was stopped; scheduler continues")
                    continue
                    
                logger.info(
                    f"Sleeping {sleep_duration:.0f}s until next scan at "
                    f"{state.next_scan_at.strftime('%Y-%m-%d %H:%M')}"
                )
                
                # Clear event right before waiting — NOT at the top of the loop
                state.settings_updated_event.clear()
                try:
                    await asyncio.wait_for(
                        state.settings_updated_event.wait(), timeout=sleep_duration
                    )
                    # Event fired (settings changed). Recalculate.
                    logger.info("Settings changed, recalculating next scan time")
                    state.next_scan_at = calculate_next_scan_time(
                        config_manager.config.scan, datetime.now()
                    )
                except asyncio.TimeoutError:
                    pass  # Timer expired naturally, loop will fire the scan

            except Exception:
                logger.exception("Error in auto-scan loop, retrying in 60s")
                await asyncio.sleep(60)
    
    def _loop_done(t: asyncio.Task):
        if not t.cancelled() and t.exception():
            logger.error("Auto-scan loop stopped unexpectedly", exc_info=t.exception())

    # Keep a reference (unreferenced tasks can be garbage-collected) and log if it dies
    state.auto_scan_loop_task = asyncio.create_task(auto_scan_loop())
    state.auto_scan_loop_task.add_done_callback(_loop_done)
    
    await server.serve()
