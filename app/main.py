from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from app.api.endpoints import router as api_router

app = FastAPI(title="Dynamic Email Sandbox Analysis System (DESAS)")

# Mount Static Files
app.mount("/static", StaticFiles(directory="app/static"), name="static")

# Templates
templates = Jinja2Templates(directory="app/templates")

# Include API Router
app.include_router(api_router, prefix="/api")

from app.core.config import settings
from app.core.whitelist_manager import get_whitelist, add_to_whitelist, remove_from_whitelist
from pydantic import BaseModel

class WhitelistRequest(BaseModel):
    domain: str

@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request
    })

@app.get("/whitelist", response_class=HTMLResponse)
async def view_whitelist(request: Request):
    return templates.TemplateResponse("whitelist.html", {
        "request": request,
        "whitelist": get_whitelist()
    })

@app.post("/api/whitelist")
async def api_add_whitelist(item: WhitelistRequest):
    updated_list = add_to_whitelist(item.domain)
    return {"status": "success", "whitelist": updated_list}

@app.delete("/api/whitelist")
async def api_remove_whitelist(item: WhitelistRequest):
    updated_list = remove_from_whitelist(item.domain)
    return {"status": "success", "whitelist": updated_list}
