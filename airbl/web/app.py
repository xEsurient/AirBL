import asyncio
import logging
import os
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI
from fastapi.responses import JSONResponse
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

SCHEDULER_MAX_WAIT = 300  # seconds; see auto_scan_loop

# Host names a DNS-rebinding page can't use: rebinding needs a public domain the attacker
# controls, so IP literals, single-label names and LAN-only suffixes are safe by default.
_LAN_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localdomain", ".home", ".intranet")


AUTH_COOKIE = "airbl_auth"
_OPEN_PATHS = {"/healthz"}  # Docker healthcheck


def _auth_token() -> str:
    return os.getenv("AIRBL_AUTH_TOKEN", "").strip()


def _session_value(token: str) -> str:
    """Cookie value for a logged-in browser: derived from the token, so changing the token
    logs everyone out, and the token itself never sits in a cookie."""
    import hashlib
    import hmac
    return hmac.new(token.encode(), b"airbl-session-v1", hashlib.sha256).hexdigest()


def _request_authorized(headers, cookies) -> tuple:
    """(ok, set_cookie) for the optional AIRBL_AUTH_TOKEN. Accepts HTTP Basic (any user name,
    the token as password: the browser's own login prompt), Bearer / X-AirBL-Token (scripts),
    or the session cookie set after a browser login (also used by the WebSocket)."""
    import base64
    import binascii
    import hmac
    token = _auth_token()
    if not token:
        return True, False
    if hmac.compare_digest(cookies.get(AUTH_COOKIE, ""), _session_value(token)):
        return True, False
    given = headers.get("x-airbl-token", "")
    auth = headers.get("authorization", "")
    scheme, _, value = auth.partition(" ")
    if scheme.lower() == "bearer":
        given = value.strip()
    elif scheme.lower() == "basic":
        try:
            given = base64.b64decode(value.strip()).decode("utf-8", "replace").partition(":")[2]
        except (binascii.Error, ValueError):
            given = ""
    if given and hmac.compare_digest(given.encode(), token.encode()):
        return True, scheme.lower() == "basic"  # browser login: remember it in a cookie
    return False, False


def _host_allowed(host_header: str) -> bool:
    """Is the Host header (as the browser used it) one this dashboard should answer?
    Extra names (e.g. a reverse proxy's public name) go in AIRBL_ALLOWED_HOSTS (comma list)."""
    import ipaddress
    host = (host_header or "").strip().lower()
    if not host:
        return True  # HTTP/1.0 or a raw client: no browser, no rebinding
    if host.startswith("["):
        host = host[1:host.find("]")] if "]" in host else host[1:]
    elif host.count(":") == 1:
        host = host.split(":")[0]
    host = host.rstrip(".")
    extra = {h.strip().lower().rstrip(".") for h in os.getenv("AIRBL_ALLOWED_HOSTS", "").split(",") if h.strip()}
    if host in extra or host == "localhost" or "." not in host or host.endswith(_LAN_SUFFIXES):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _origin_allowed(origin: str, headers) -> bool:
    """Same-origin check for write requests: the Origin's host:port must be the Host the
    browser used (or X-Forwarded-Host behind a proxy), or listed in AIRBL_ALLOWED_ORIGINS."""
    extra = {o.strip().rstrip("/").lower() for o in os.getenv("AIRBL_ALLOWED_ORIGINS", "").split(",") if o.strip()}
    if origin.rstrip("/").lower() in extra:
        return True
    netloc = urlsplit(origin).netloc.lower()
    if not netloc:  # "null" (sandboxed frames, file://)
        return False
    hosts = {headers.get("host", "").lower()}
    hosts |= {h.strip().lower() for h in headers.get("x-forwarded-host", "").split(",") if h.strip()}
    return netloc in hosts


async def _shutdown():
    # Stop the loops first, so none of them starts a scan or a Gluetun check while the
    # tunnel is torn down and the DB is closed
    loops = [getattr(state, "auto_scan_loop_task", None), getattr(state, "gluetun_watchdog_task", None),
             getattr(state, "gluetun_watchdog_task_secondary", None), *api._background_tasks]
    loops = [t for t in loops if t and not t.done()]
    for t in loops:
        t.cancel()
    if loops:
        await asyncio.wait(loops, timeout=10)

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

    @app.middleware("http")
    async def _login(request, call_next):
        # Optional AIRBL_AUTH_TOKEN (runs after the host check below: middleware added later
        # runs first, so this is registered before _known_host)
        if request.url.path in _OPEN_PATHS:
            return await call_next(request)
        ok, set_cookie = _request_authorized(request.headers, request.cookies)
        if not ok:
            return JSONResponse({"error": "Login required"}, status_code=401,
                                headers={"WWW-Authenticate": 'Basic realm="AirBL", charset="UTF-8"'})
        response = await call_next(request)
        if set_cookie:
            response.set_cookie(AUTH_COOKIE, _session_value(_auth_token()), httponly=True, samesite="strict",
                                secure=request.url.scheme == "https", max_age=30 * 86400)
        return response

    @app.middleware("http")
    async def _known_host(request, call_next):
        # DNS rebinding: a page on evil.example can point its name at this host and then
        # read the API as "same origin" (Origin and Host would both be evil.example)
        host = request.headers.get("host", "")
        if not _host_allowed(host):
            logger.warning(f"Blocked request for unknown host name {host!r} (add it to AIRBL_ALLOWED_HOSTS)")
            return JSONResponse({"error": "Unknown host name. If this is how you reach AirBL, "
                                          "add it to AIRBL_ALLOWED_HOSTS."}, status_code=403)
        return await call_next(request)

    @app.middleware("http")
    async def _same_origin_writes(request, call_next):
        # No login, so a web page open in a LAN browser could otherwise POST here
        # (form or text/plain requests need no CORS preflight). Browsers always send
        # Origin on POSTs; scripts and curl send none and are allowed.
        if request.method not in ("GET", "HEAD", "OPTIONS") and request.url.path.startswith("/api"):
            origin = request.headers.get("origin")
            if origin is not None and not _origin_allowed(origin, request.headers):
                logger.warning(f"Blocked cross-site {request.method} {request.url.path} from {origin}")
                return JSONResponse({"error": "Cross-site request blocked"}, status_code=403)
        return await call_next(request)

    # Mount static files
    static_dir = Path(__file__).parent.parent / "static"
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        """Liveness for Docker's healthcheck; open even with AIRBL_AUTH_TOKEN, reveals nothing."""
        return {"ok": True}

    if _auth_token() and len(_auth_token()) < 16:
        logger.warning("AIRBL_AUTH_TOKEN is shorter than 16 characters; use a long random token")

    # Include routers
    app.include_router(api.router, prefix="/api")
    app.include_router(pages.router)
    
    # WebSocket route for real-time updates
    @app.websocket("/ws")
    async def ws_route(websocket: WebSocket):
        # Middleware doesn't see WebSockets: same host and origin rules here
        origin = websocket.headers.get("origin")
        if not _host_allowed(websocket.headers.get("host", "")) or (
                origin is not None and not _origin_allowed(origin, websocket.headers)) or (
                not _request_authorized(websocket.headers, websocket.cookies)[0]):
            await websocket.close(code=1008)
            return
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
        from .tasks import next_scan_from_last

        # Wait for startup to initialize the event
        while state.settings_updated_event is None:
            await asyncio.sleep(1)
            
        logger.info("Auto-scan loop started")
        last_logged_target = None
        
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

                if state.next_scan_at is None:
                    state.next_scan_at = next_scan_from_last(scan_cfg)
                    
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
                    
                if state.next_scan_at != last_logged_target:
                    last_logged_target = state.next_scan_at
                    logger.info(
                        f"Sleeping {sleep_duration:.0f}s until next scan at "
                        f"{state.next_scan_at.strftime('%Y-%m-%d %H:%M')}"
                    )
                
                # Clear event right before waiting — NOT at the top of the loop
                state.settings_updated_event.clear()
                try:
                    # Wake at least every 5 minutes and recompute from the wall clock: one long
                    # timeout counts monotonic seconds, so a DST change or a clock fix after boot
                    # (Pi without RTC) would shift the scan by up to an hour
                    await asyncio.wait_for(
                        state.settings_updated_event.wait(), timeout=min(sleep_duration, SCHEDULER_MAX_WAIT)
                    )
                    # Event fired (settings changed). Recalculate.
                    logger.info("Settings changed, recalculating next scan time")
                    state.next_scan_at = next_scan_from_last(config_manager.config.scan)
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
    
    # One watchdog per control target, so a slow or unreachable second target never delays
    # the main Gluetun's checks
    from ..gluetun import watchdog_loop
    for key, attr in (("primary", "gluetun_watchdog_task"), ("secondary", "gluetun_watchdog_task_secondary")):
        task = asyncio.create_task(watchdog_loop(key, ready=lambda: state.db is not None))
        task.add_done_callback(
            lambda t, key=key: not t.cancelled() and t.exception()
            and logger.error(f"Gluetun watchdog ({key}) stopped unexpectedly", exc_info=t.exception()))
        setattr(state, attr, task)

    await server.serve()
