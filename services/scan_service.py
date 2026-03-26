import json
from datetime import datetime
from sqlalchemy.orm import Session

from api.database import SessionLocal
from api.models import Scan
from core.scanner import VulnerabilityScanner


class ScanService:
    def __init__(self):
        pass

    def create_scan(self, target: str, scan_type: str = "full") -> int:
        db = SessionLocal()
        try:
            scan = Scan(target=target, scan_type=scan_type, status="pending")
            db.add(scan)
            db.commit()
            db.refresh(scan)
            return scan.id
        finally:
            db.close()

    def get_scan(self, scan_id: int) -> dict:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return None

            return {
                "id": scan.id,
                "target": scan.target,
                "scan_type": scan.scan_type,
                "status": scan.status,
                "created_at": scan.created_at,
                "completed_at": scan.completed_at,
                "results": scan.results,
                "total_vulnerabilities": scan.total_vulnerabilities,
                "critical_count": scan.critical_count,
                "high_count": scan.high_count,
                "medium_count": scan.medium_count,
                "low_count": scan.low_count,
                "info_count": scan.info_count,
                "error_message": scan.error_message,
            }
        finally:
            db.close()

    def update_scan_status(
        self, scan_id: int, status: str, results: dict = None, error: str = None
    ):
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return False

            scan.status = status

            if results:
                scan.results_json = json.dumps(results)
                summary = self._calculate_summary(results)
                scan.total_vulnerabilities = summary["total"]
                scan.critical_count = summary["critical"]
                scan.high_count = summary["high"]
                scan.medium_count = summary["medium"]
                scan.low_count = summary["low"]
                scan.info_count = summary["info"]

            if error:
                scan.error_message = error

            if status in ["completed", "failed"]:
                scan.completed_at = datetime.now()

            db.commit()
            return True
        finally:
            db.close()

    def execute_scan(self, scan_id: int):
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return False

            scan.status = "running"
            db.commit()

            try:
                scanner = VulnerabilityScanner()
                results = scanner.scan(scan.target, scan_type=scan.scan_type)

                scan.results_json = json.dumps(results)
                summary = self._calculate_summary(results)
                scan.status = "completed"
                scan.total_vulnerabilities = summary["total"]
                scan.critical_count = summary["critical"]
                scan.high_count = summary["high"]
                scan.medium_count = summary["medium"]
                scan.low_count = summary["low"]
                scan.info_count = summary["info"]
                scan.completed_at = datetime.now()

            except Exception as e:
                scan.status = "failed"
                scan.error_message = str(e)
                scan.completed_at = datetime.now()

            db.commit()
            return True
        finally:
            db.close()

    def list_scans(self, page: int = 1, per_page: int = 20, status: str = None) -> dict:
        db = SessionLocal()
        try:
            query = db.query(Scan)

            if status:
                query = query.filter(Scan.status == status)

            total = query.count()
            scans = (
                query.order_by(Scan.created_at.desc())
                .offset((page - 1) * per_page)
                .limit(per_page)
                .all()
            )

            return {
                "scans": [
                    {
                        "id": s.id,
                        "target": s.target,
                        "scan_type": s.scan_type,
                        "status": s.status,
                        "created_at": s.created_at,
                        "total_vulnerabilities": s.total_vulnerabilities,
                        "critical_count": s.critical_count,
                        "high_count": s.high_count,
                        "medium_count": s.medium_count,
                        "low_count": s.low_count,
                        "info_count": s.info_count,
                    }
                    for s in scans
                ],
                "total": total,
                "page": page,
                "per_page": per_page,
            }
        finally:
            db.close()

    def delete_scan(self, scan_id: int) -> bool:
        db = SessionLocal()
        try:
            scan = db.query(Scan).filter(Scan.id == scan_id).first()
            if not scan:
                return False
            db.delete(scan)
            db.commit()
            return True
        finally:
            db.close()

    def _calculate_summary(self, results: dict) -> dict:
        summary = {
            "total": 0,
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
        }

        for host, host_data in results.items():
            vulns = host_data.get("vulnerabilities", [])
            for vuln in vulns:
                severity = vuln.get("severity", "info").lower()
                summary["total"] += 1
                if severity in summary:
                    summary[severity] += 1

        return summary
