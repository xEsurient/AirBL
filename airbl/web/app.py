import asyncio
import logging
from pathlib import Path
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
import uvicorn

from .state import state, setup_debug_logging
from .tasks import run_scan_task
from .routes import api, pages
from .websockets import websocket_handler
from ..config import SettingsManager, Settings
from fastapi import WebSocket

# Setup basic logging
setup_debug_logging()
logger = logging.getLogger("airbl.web")

def create_app(config_dir: Path = None) -> FastAPI:
    if config_dir:
        state.config_dir = config_dir
        # Initialize SettingsManager with the config directory
        state.config_manager = SettingsManager(Settings(config_dir=config_dir))

    app = FastAPI(title="AirVPN DroneBL Scanner")

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

    @app.on_event("startup")
    async def startup_event():
        await state.startup()
        logger.info(f"Application started. Config dir: {state.config_dir}")

    return app

async def run_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    config_dir: Path = None,
    scan_interval_minutes: int = 120,
    auto_scan: bool = True,
):
    """
    Run the web server with auto-scanning.
    """
    if config_dir:
        state.config_dir = config_dir
    state.scan_interval_minutes = scan_interval_minutes
    state.auto_scan_enabled = auto_scan
    
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
    # The loop sleeps for the configured interval before checking, so no scan fires on boot.
    async def auto_scan_loop():
        while True:
            await asyncio.sleep(state.scan_interval_minutes * 60)
            if state.auto_scan_enabled and not state.is_scanning:
                await run_scan_task()
    
    asyncio.create_task(auto_scan_loop())
    
    await server.serve()
