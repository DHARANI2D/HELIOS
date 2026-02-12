from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from app.api.endpoints import router as api_router
import sys
import os

# Get base path for PyInstaller compatibility
def get_base_path():
    """Get base path for resources, works with PyInstaller"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return sys._MEIPASS
    else:
        # Running in normal Python environment
        # Move up two levels from app/main.py to reach project root
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

BASE_PATH = get_base_path()
print(f"DEBUG: BASE_PATH: {BASE_PATH}")
print(f"DEBUG: sys.frozen: {getattr(sys, 'frozen', False)}")

app = FastAPI(title="Dynamic Email Sandbox Analysis System (DESAS)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def log_requests(request: Request, call_next):
    print(f"DEBUG: Incoming request: {request.method} {request.url.path}")
    response = await call_next(request)
    print(f"DEBUG: Response status: {response.status_code}")
    return response

# Mount Static Files
static_dir = os.path.join(BASE_PATH, "app", "static")
if not os.path.exists(static_dir):
    # Fallback for different build structures
    static_dir = os.path.join(BASE_PATH, "static")
    
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")
    print(f"DEBUG: Mounted static files from {static_dir}")
else:
    print(f"ERROR: Static directory not found: {static_dir}")

# Templates
template_dir = os.path.join(BASE_PATH, "app", "templates")
if not os.path.exists(template_dir):
    # Fallback for different build structures
    template_dir = os.path.join(BASE_PATH, "templates")

if os.path.exists(template_dir):
    templates = Jinja2Templates(directory=template_dir)
    print(f"DEBUG: Loaded templates from {template_dir}")
else:
    # Final fallback to current directory
    templates = Jinja2Templates(directory="templates")
    print(f"WARNING: Template directory not found, using 'templates' fallback")

# Include API Router
app.include_router(api_router, prefix="/api")

from app.core.config import settings
from app.core.whitelist_manager import get_whitelist, add_to_whitelist, remove_from_whitelist
from app.core.settings_manager import save_settings, get_dynamic_settings, AppSettings
from pydantic import BaseModel

class WhitelistRequest(BaseModel):
    domain: str

@app.get("/health")
async def health_check():
    return {"status": "ok", "app": "DESAS", "version": settings.VERSION}

@app.get("/settings", response_class=HTMLResponse)
async def view_settings(request: Request):
    print("DEBUG: Hit /settings route")
    return templates.TemplateResponse("settings.html", {
        "request": request,
        "settings": get_dynamic_settings().model_dump(),
        "whitelist": get_whitelist(),
        "defaults": {
            "VIRUSTOTAL_API_KEY": settings.VIRUSTOTAL_API_KEY,
            "MXTOOLBOX_API_KEY": settings.MXTOOLBOX_API_KEY,
            "ABUSEIPDB_API_KEY": settings.ABUSEIPDB_API_KEY
        }
    })

@app.api_route("/", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request
    })

@app.api_route("/whitelist", methods=["GET", "HEAD"], response_class=HTMLResponse)
async def view_whitelist(request: Request):
    from fastapi.responses import RedirectResponse
    return RedirectResponse(url="/settings")

@app.post("/api/whitelist")
async def api_add_whitelist(item: WhitelistRequest):
    updated_list = add_to_whitelist(item.domain)
    return {"status": "success", "whitelist": updated_list}

@app.delete("/api/whitelist")
async def api_remove_whitelist(item: WhitelistRequest):
    updated_list = remove_from_whitelist(item.domain)
    return {"status": "success", "whitelist": updated_list}

@app.post("/api/settings")
async def api_update_settings(item: AppSettings):
    success = save_settings(item.model_dump())
    if success:
        return {"status": "success"}
    return {"status": "error", "message": "Failed to save settings"}
