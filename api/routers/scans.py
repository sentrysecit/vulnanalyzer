from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import List, Optional
from datetime import datetime
import json
import threading

from api.database import get_db, SessionLocal
from api.models import Scan, ScanStatus as DBScanStatus, ScanType as DBScanType
from api.schemas import (
    ScanCreate,
    ScanResponse,
    ScanDetail,
    ScanListResponse,
    StatsResponse,
    VulnerabilitySummary,
)

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.get("", response_model=ScanListResponse)
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status: Optional[str] = None,
    scan_type: Optional[str] = None,
    target: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Scan)

    if status:
        query = query.filter(Scan.status == status)
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type)
    if target:
        query = query.filter(Scan.target.like(f"%{target}%"))

    total = query.count()
    scans = (
        query.order_by(desc(Scan.created_at))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )

    return ScanListResponse(
        scans=[ScanResponse.model_validate(s) for s in scans],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    total_scans = db.query(Scan).count()
    targets = db.query(Scan.target).distinct().all()
    total_targets = len(targets)

    all_scans = db.query(Scan).all()
    total_vulns = sum(s.total_vulnerabilities for s in all_scans)
    critical = sum(s.critical_count for s in all_scans)
    high = sum(s.high_count for s in all_scans)
    medium = sum(s.medium_count for s in all_scans)
    low = sum(s.low_count for s in all_scans)
    info = sum(s.info_count for s in all_scans)

    recent_scans = db.query(Scan).order_by(desc(Scan.created_at)).limit(5).all()

    target_vulns = {}
    for scan in all_scans:
        if scan.total_vulnerabilities > 0:
            if scan.target not in target_vulns:
                target_vulns[scan.target] = 0
            target_vulns[scan.target] += scan.total_vulnerabilities

    top_vulnerable = sorted(
        [{"target": t, "vulnerabilities": v} for t, v in target_vulns.items()],
        key=lambda x: x["vulnerabilities"],
        reverse=True,
    )[:10]

    return StatsResponse(
        total_scans=total_scans,
        total_targets=total_targets,
        total_vulnerabilities=total_vulns,
        vulnerabilities_by_severity=VulnerabilitySummary(
            critical=critical, high=high, medium=medium, low=low, info=info
        ),
        recent_scans=[ScanResponse.model_validate(s) for s in recent_scans],
        top_vulnerable_targets=top_vulnerable,
    )


@router.post("", response_model=ScanResponse)
def create_scan(scan_data: ScanCreate, db: Session = Depends(get_db)):
    scan = Scan(
        target=scan_data.target,
        scan_type=scan_data.scan_type.value,
        status=DBScanStatus.PENDING.value,
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    thread = threading.Thread(
        target=_execute_scan_background, args=(scan.id, scan.target, scan.scan_type)
    )
    thread.daemon = True
    thread.start()

    return ScanResponse.model_validate(scan)


def _execute_scan_background(scan_id: int, target: str, scan_type: str):
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            return

        scan.status = DBScanStatus.RUNNING.value
        db.commit()

        try:
            from core.scanner import VulnerabilityScanner

            scanner = VulnerabilityScanner(target, scan_type=scan_type)
            results = scanner.run()

            scan.results_json = json.dumps(results)
            summary = _calculate_summary(results)
            os_info = _extract_os_info(results)
            ad_info = _extract_ad_info(results)
            scan.status = DBScanStatus.COMPLETED.value
            scan.total_vulnerabilities = summary["total"]
            scan.critical_count = summary["critical"]
            scan.high_count = summary["high"]
            scan.medium_count = summary["medium"]
            scan.low_count = summary["low"]
            scan.info_count = summary["info"]
            scan.os_name = os_info.get("name")
            scan.os_family = os_info.get("family")
            scan.os_accuracy = os_info.get("accuracy")
            scan.is_domain_controller = ad_info.get("is_domain_controller", False)
            scan.domain_name = ad_info.get("domain_name")
            scan.ad_vulnerabilities = ad_info.get("ad_vulnerabilities", 0)
            scan.completed_at = datetime.now()

        except Exception as e:
            scan.status = DBScanStatus.FAILED.value
            scan.error_message = str(e)
            scan.completed_at = datetime.now()

        db.commit()

    finally:
        db.close()


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return ScanDetail(
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
        os_name=scan.os_name,
        os_family=scan.os_family,
        os_accuracy=scan.os_accuracy,
        is_domain_controller=scan.is_domain_controller,
        domain_name=scan.domain_name,
        ad_vulnerabilities=scan.ad_vulnerabilities,
        results=scan.results,
        error_message=scan.error_message,
    )


@router.delete("/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}


@router.patch("/{scan_id}/status")
def update_scan_status(
    scan_id: int,
    status: str,
    results: Optional[dict] = None,
    error_message: Optional[str] = None,
    db: Session = Depends(get_db),
):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    scan.status = status

    if results:
        scan.results_json = json.dumps(results)
        summary = _calculate_summary(results)
        os_info = _extract_os_info(results)
        scan.total_vulnerabilities = summary["total"]
        scan.critical_count = summary["critical"]
        scan.high_count = summary["high"]
        scan.medium_count = summary["medium"]
        scan.low_count = summary["low"]
        scan.info_count = summary["info"]
        scan.os_name = os_info.get("name")
        scan.os_family = os_info.get("family")
        scan.os_accuracy = os_info.get("accuracy")

    if error_message:
        scan.error_message = error_message

    if status in ["completed", "failed"]:
        scan.completed_at = datetime.now()

    db.commit()
    db.refresh(scan)
    return ScanResponse.model_validate(scan)


def _calculate_summary(results: dict) -> dict:
    summary = {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

    for host, host_data in results.items():
        vulns = host_data.get("vulnerabilities", [])
        for vuln in vulns:
            severity = vuln.get("severity", "info").lower()
            summary["total"] += 1
            if severity in summary:
                summary[severity] += 1

    return summary


def _extract_os_info(results: dict) -> dict:
    for host, host_data in results.items():
        os_family = host_data.get("os_family")
        if os_family and os_family != "Unknown":
            return {
                "name": host_data.get("os_name"),
                "family": os_family,
                "accuracy": host_data.get("os_accuracy"),
            }
    return {"name": None, "family": None, "accuracy": None}


def _extract_ad_info(results: dict) -> dict:
    for host, host_data in results.items():
        ad_data = host_data.get("ad")
        if ad_data:
            ad_vulns = ad_data.get("vulnerabilities", [])
            return {
                "is_domain_controller": ad_data.get("is_domain_controller", False),
                "domain_name": ad_data.get("domain"),
                "ad_vulnerabilities": len(ad_vulns),
            }
    return {"is_domain_controller": False, "domain_name": None, "ad_vulnerabilities": 0}
