from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import Optional, List
import threading

from api.database import get_db, SessionLocal
from api.models import Vulnerability, Scan, SubdomainEnum
from api.schemas import (
    CVESearchRequest,
    CVEDetailResponse,
    ExploitResponse,
    VulnerabilityResponse,
    VulnerabilityStatsResponse,
)


router = APIRouter(prefix="/api/vulns", tags=["vulnerabilities"])


@router.get("/scan/{scan_id}", response_model=List[VulnerabilityResponse])
def get_scan_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vulns = db.query(Vulnerability).filter(
        Vulnerability.scan_id == scan_id
    ).all()

    return [VulnerabilityResponse.model_validate(v) for v in vulns]


@router.get("/enum/{enum_id}", response_model=List[VulnerabilityResponse])
def get_enum_vulnerabilities(enum_id: int, db: Session = Depends(get_db)):
    enum = db.query(SubdomainEnum).filter(SubdomainEnum.id == enum_id).first()
    if not enum:
        raise HTTPException(status_code=404, detail="Enumeration not found")

    vulns = db.query(Vulnerability).filter(
        Vulnerability.enum_id == enum_id
    ).all()

    return [VulnerabilityResponse.model_validate(v) for v in vulns]


@router.get("/host/{host}", response_model=List[VulnerabilityResponse])
def get_host_vulnerabilities(
    host: str,
    db: Session = Depends(get_db),
    limit: int = Query(100, ge=1, le=500),
):
    vulns = db.query(Vulnerability).filter(
        Vulnerability.host == host
    ).order_by(
        desc(Vulnerability.cvss_score)
    ).limit(limit).all()

    return [VulnerabilityResponse.model_validate(v) for v in vulns]


@router.get("/stats", response_model=VulnerabilityStatsResponse)
def get_vulnerability_stats(db: Session = Depends(get_db)):
    total = db.query(Vulnerability).count()
    critical = db.query(Vulnerability).filter(
        Vulnerability.cvss_score >= 9.0
    ).count()
    high = db.query(Vulnerability).filter(
        func.cast(Vulnerability.cvss_score, type_=float) >= 7.0,
        Vulnerability.cvss_score < 9.0,
    ).count()
    medium = db.query(Vulnerability).filter(
        func.cast(Vulnerability.cvss_score, type_=float) >= 4.0,
        Vulnerability.cvss_score < 7.0,
    ).count()
    low = db.query(Vulnerability).filter(
        func.cast(Vulnerability.cvss_score, type_=float) < 4.0,
        Vulnerability.cvss_score > 0,
    ).count()
    exploited = db.query(Vulnerability).filter(
        Vulnerability.is_exploited == True
    ).count()
    with_exploit = db.query(Vulnerability).filter(
        Vulnerability.exploit_available == True
    ).count()

    return VulnerabilityStatsResponse(
        total=total,
        critical=critical,
        high=high,
        medium=medium,
        low=low,
        exploited=exploited,
        with_exploit=with_exploit,
    )


@router.post("/cve", response_model=CVEDetailResponse)
def lookup_cve(cve_id: str, db: Session = Depends(get_db)):
    cve_id = cve_id.upper()
    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    try:
        from core.cve_scanner import CVEScanner

        scanner = CVEScanner()
        result = scanner.check_cve(cve_id)

        if not result:
            raise HTTPException(status_code=404, detail="CVE not found")

        return CVEDetailResponse(
            id=result.get("id"),
            description=result.get("description"),
            cvss_score=result.get("cvss_score"),
            severity=result.get("severity"),
            is_exploited=result.get("is_exploited", False),
            published=str(result.get("published", "")),
            last_modified=str(result.get("last_modified", "")),
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cve/search", response_model=List[CVEDetailResponse])
def search_cve(request: CVESearchRequest, db: Session = Depends(get_db)):
    try:
        from core.cve_scanner import CVEScanner

        scanner = CVEScanner()
        results = scanner.search_cves_by_keyword(request.keyword, limit=request.limit)

        return [CVEDetailResponse(
            id=r.get("id"),
            cvss_score=r.get("cvss_score"),
            severity=r.get("severity"),
            is_exploited=r.get("is_exploited", False),
        ) for r in results]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/exploit/{cve_id}", response_model=List[ExploitResponse])
def get_exploits(cve_id: str, db: Session = Depends(get_db)):
    cve_id = cve_id.upper()

    try:
        from core.exploit_finder import ExploitFinder

        finder = ExploitFinder()
        results = finder.search_by_cve(cve_id)

        return [ExploitResponse(
            edb_id=str(r.get("edb_id", "")),
            title=r.get("title", ""),
            cve_id=cve_id,
            link=r.get("link", ""),
            source=r.get("source", "unknown"),
        ) for r in results]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/exploit/search", response_model=List[ExploitResponse])
def search_exploits(request: CVESearchRequest, db: Session = Depends(get_db)):
    try:
        from core.exploit_finder import ExploitFinder

        finder = ExploitFinder()
        results = finder.search_by_service(request.keyword)

        return [ExploitResponse(
            edb_id=str(r.get("edb_id", "")),
            title=r.get("title", ""),
            service=r.get("service", ""),
            version=r.get("version"),
            link=r.get("link", ""),
            source=r.get("source", "unknown"),
        ) for r in results]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{vuln_id}")
def delete_vulnerability(vuln_id: int, db: Session = Depends(get_db)):
    vuln = db.query(Vulnerability).filter(Vulnerability.id == vuln_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    db.delete(vuln)
    db.commit()
    return {"message": "Vulnerability deleted successfully"}


@router.post("/check-scan/{scan_id}", response_model=List[VulnerabilityResponse])
def check_scan_vulnerabilities(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    def run_in_background():
        db = SessionLocal()
        try:
            import json
            from core.cve_scanner import CVEScanner
            from core.exploit_finder import ExploitFinder

            scanner = CVEScanner()
            finder = ExploitFinder()

            results = json.loads(scan.results_json or "{}")
            services_info = []

            for host, host_data in results.items():
                for port, port_data in host_data.get("ports", {}).items():
                    if port_data.get("state") == "open":
                        services_info.append({
                            "host": host,
                            "port": port,
                            "service": port_data.get("service", ""),
                            "version": port_data.get("version", ""),
                        })

            vulns = scanner.detect_vulnerabilities(services_info)

            for vuln in vulns:
                existing = db.query(Vulnerability).filter(
                    Vulnerability.cve_id == vuln.get("cve_id"),
                    Vulnerability.host == vuln.get("host"),
                ).first()

                if not existing:
                    v = Vulnerability(
                        scan_type="network",
                        scan_id=scan_id,
                        host=vuln.get("host"),
                        port=vuln.get("port"),
                        service=vuln.get("service"),
                        version=vuln.get("version"),
                        cve_id=vuln.get("cve_id"),
                        severity=vuln.get("severity"),
                        cvss_score=str(vuln.get("cvss_score")) if vuln.get("cvss_score") else None,
                        is_exploited=vuln.get("is_exploited", False),
                    )
                    db.add(v)

            db.commit()

        except Exception as e:
            print(f"[!] Error checking scan vulnerabilities: {e}")
        finally:
            db.close()

    thread = threading.Thread(target=run_in_background)
    thread.daemon = True
    thread.start()

    return {"message": "Vulnerability check started", "scan_id": scan_id}