from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class ScanType(str, Enum):
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"
    DISCOVER = "discover"


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanBase(BaseModel):
    target: str
    scan_type: ScanType = ScanType.FULL


class ScanCreate(ScanBase):
    pass


class VulnerabilitySummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int

    class Config:
        from_attributes = True


class ScanDetail(ScanResponse):
    results: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None


class ScanListResponse(BaseModel):
    scans: List[ScanResponse]
    total: int
    page: int
    per_page: int


class StatsResponse(BaseModel):
    total_scans: int
    total_targets: int
    total_vulnerabilities: int
    vulnerabilities_by_severity: VulnerabilitySummary
    recent_scans: List[ScanResponse]
    top_vulnerable_targets: List[Dict[str, Any]]


class ReportResponse(BaseModel):
    scan: ScanDetail
    summary: Dict[str, Any]
    generated_at: datetime


class SubdomainRequest(BaseModel):
    target: str
    wordlist: Optional[str] = None
    threads: int = 40
    use_nuclei: bool = False


class SubdomainResponse(BaseModel):
    id: int
    target: str
    status: str
    wordlist: Optional[str] = None
    total_found: int = 0
    alive_count: int = 0
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class SubdomainDetail(SubdomainResponse):
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class SubdomainResultResponse(BaseModel):
    id: int
    enum_id: int
    subdomain: str
    is_alive: bool = False
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FuzzRequest(BaseModel):
    target: str
    wordlist: Optional[str] = None
    threads: int = 40
    extensions: Optional[str] = None


class FuzzResponse(BaseModel):
    id: int
    target: str
    status: str
    wordlist: Optional[str] = None
    total_found: int = 0
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class FuzzDetail(FuzzResponse):
    extensions: Optional[str] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None


class PathResultResponse(BaseModel):
    id: int
    fuzz_id: int
    path: str
    status_code: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class WordlistResponse(BaseModel):
    name: str
    path: str
    description: str


class CVESearchRequest(BaseModel):
    keyword: str
    limit: int = 20


class CVEDetailResponse(BaseModel):
    id: str
    description: Optional[str] = None
    cvss_score: Optional[float] = None
    severity: Optional[str] = None
    is_exploited: bool = False
    published: Optional[str] = None
    last_modified: Optional[str] = None


class ExploitResponse(BaseModel):
    edb_id: str
    title: str
    cve_id: Optional[str] = None
    service: Optional[str] = None
    version: Optional[str] = None
    link: str
    source: str


class VulnerabilityResponse(BaseModel):
    id: int
    scan_type: Optional[str] = None
    scan_id: Optional[int] = None
    enum_id: Optional[int] = None
    host: Optional[str] = None
    subdomain: Optional[str] = None
    service: Optional[str] = None
    port: Optional[int] = None
    cve_id: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[str] = None
    is_exploited: bool = False
    exploit_available: bool = False
    edb_id: Optional[str] = None
    description: Optional[str] = None
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class VulnerabilityStatsResponse(BaseModel):
    total: int
    critical: int
    high: int
    medium: int
    low: int
    exploited: int
    with_exploit: int
