from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from sqlalchemy.orm import Session
from datetime import datetime
import tempfile
import json
import os

from api.database import get_db
from api.models import Scan
from api.schemas import ScanDetail, ReportResponse

router = APIRouter(prefix="/api/reports", tags=["reports"])


def get_report_template_path():
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base_dir, "web", "templates")


def get_report_service():
    from services.report_service import ReportService
    return ReportService()


@router.get("/{scan_id}", response_model=ReportResponse)
def get_report_data(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_service = get_report_service()
    summary = report_service.generate_summary(scan.results or {})

    return ReportResponse(
        scan=ScanDetail(
            id=scan.id,
            target=scan.target,
            scan_type=scan.scan_type,
            status=scan.status,
            created_at=scan.created_at,
            completed_at=scan.completed_at,
            total_vulnerabilities=scan.total_vulnerabilities,
            critical_count=scan.critical_count,
            high_count=scan.high_count,
            medium_count=scan.medium_count,
            low_count=scan.low_count,
            info_count=scan.info_count,
            results=scan.results,
            error_message=scan.error_message,
        ),
        summary=summary,
        generated_at=datetime.now(),
    )


@router.get("/{scan_id}/html")
def get_report_html(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.results:
        raise HTTPException(status_code=400, detail="Scan has no results")

    report_service = get_report_service()
    html_content = report_service.generate_html_from_data(
        data={"scan_results": scan.results},
        title=f"Vulnerability Report - {scan.target}",
        context={"scan": scan},
    )

    return HTMLResponse(content=html_content)


@router.get("/{scan_id}/preview")
def get_report_preview(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.results:
        raise HTTPException(status_code=400, detail="Scan has no results")

    report_service = get_report_service()
    summary = report_service.generate_summary(scan.results or {})

    template_path = get_report_template_path()
    from jinja2 import Environment, FileSystemLoader
    env = Environment(loader=FileSystemLoader(template_path))
    template = env.get_template("reports/view.html")

    html_content = template.render(
        scan=scan,
        summary=summary,
        title=f"Vulnerability Report - {scan.target}",
    )

    return HTMLResponse(content=html_content)


@router.get("/{scan_id}/download/{format}")
def download_report(scan_id: int, format: str, db: Session = Depends(get_db)):
    if format not in ["html", "json"]:
        raise HTTPException(status_code=400, detail="Invalid format. Use 'html' or 'json'")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    report_data = {
        "id": scan.id,
        "title": f"Vulnerability Report - {scan.target}",
        "timestamp": scan.created_at.isoformat() if scan.created_at else datetime.now().isoformat(),
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "total_vulnerabilities": scan.total_vulnerabilities,
        "severity_counts": {
            "critical": scan.critical_count,
            "high": scan.high_count,
            "medium": scan.medium_count,
            "low": scan.low_count,
            "info": scan.info_count,
        },
        "results": scan.results,
    }

    if format == "json":
        temp_file = tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False, dir="/tmp"
        )
        json.dump(report_data, temp_file, indent=4)
        temp_file.close()

        return FileResponse(
            temp_file.name,
            media_type="application/json",
            filename=f"scan_{scan_id}_report.json",
        )

    report_service = get_report_service()
    html_content = report_service.generate_html_from_data(
        data={"scan_results": scan.results},
        title=f"Vulnerability Report - {scan.target}",
        context={"scan": scan},
    )

    return HTMLResponse(content=html_content)
