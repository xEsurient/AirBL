from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pathlib import Path

router = APIRouter()

# Setup templates
# Assuming this file is in airbl/web/routes/
# Templates are in airbl/web/templates/
BASE_DIR = Path(__file__).resolve().parent.parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))

@router.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the main dashboard."""
    return templates.TemplateResponse(request=request, name="index.html")

@router.get("/metrics", response_class=HTMLResponse)
async def metrics_page(request: Request):
    """Serve the advanced metrics page."""
    return templates.TemplateResponse(request=request, name="metrics.html")


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    """Serve the settings page."""
    return templates.TemplateResponse(request=request, name="settings.html")

@router.get("/debug", response_class=HTMLResponse)
async def debug_page(request: Request):
    """Serve the debug page."""
    return templates.TemplateResponse(request=request, name="debug.html")

@router.get("/servers", response_class=HTMLResponse)
async def servers_page(request: Request):
    """Serve the servers listing page."""
    return templates.TemplateResponse(request=request, name="servers.html")
