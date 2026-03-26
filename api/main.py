from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
import os

from api.database import init_db
from api.routers import scans, reports

app = FastAPI(
    title="VulnAnalyzer API",
    description="API REST para VulnAnalyzer - Análisis de Vulnerabilidades",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router)
app.include_router(reports.router)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(BASE_DIR)
web_static = os.path.join(PROJECT_ROOT, "web", "static")
web_templates = os.path.join(PROJECT_ROOT, "web", "templates")

if os.path.exists(web_static):
    app.mount("/static", StaticFiles(directory=web_static), name="static")

templates = Jinja2Templates(directory=web_templates)


@app.on_event("startup")
def startup_event():
    init_db()


@app.get("/", tags=["web"])
def root():
    from fastapi.responses import RedirectResponse

    return RedirectResponse(url="/web/dashboard")


@app.get("/web/dashboard", tags=["web"])
def dashboard(request: Request):
    return templates.TemplateResponse(name="dashboard.html", request=request)


@app.get("/web/scans", tags=["web"])
def scans_page(request: Request):
    return templates.TemplateResponse(name="scan_list.html", request=request)


@app.get("/web/scans/{scan_id}", tags=["web"])
def scan_detail_page(request: Request, scan_id: int):
    return templates.TemplateResponse(
        name="scan_detail.html", request=request, context={"scan_id": scan_id}
    )


@app.get("/web/reports/{scan_id}", tags=["web"])
def report_page(request: Request, scan_id: int):
    return templates.TemplateResponse(
        name="report.html", request=request, context={"scan_id": scan_id}
    )


@app.get("/web/scan/new", tags=["web"])
def new_scan_page(request: Request):
    return templates.TemplateResponse(name="scan_new.html", request=request)


@app.get("/health", tags=["health"])
def health_check():
    return {"status": "healthy", "service": "vulnanalyzer-api"}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
