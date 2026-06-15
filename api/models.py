from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    Text,
    Enum,
    Boolean,
    ForeignKey,
)
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from api.database import Base
import enum


class ScanStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class ScanType(str, enum.Enum):
    QUICK = "quick"
    FULL = "full"
    STEALTH = "stealth"
    DISCOVER = "discover"


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    scan_type = Column(String(50), nullable=False, default="full")
    status = Column(String(20), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    results_json = Column(Text, nullable=True)
    error_message = Column(Text, nullable=True)
    total_vulnerabilities = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    os_name = Column(String(255), nullable=True)
    os_family = Column(String(50), nullable=True)
    os_accuracy = Column(String(10), nullable=True)
    is_domain_controller = Column(Boolean, default=False)
    domain_name = Column(String(255), nullable=True)
    ad_vulnerabilities = Column(Integer, default=0)

    @property
    def results(self):
        import json

        if self.results_json:
            return json.loads(self.results_json)
        return None

    @results.setter
    def results(self, value):
        import json

        self.results_json = json.dumps(value) if value else None


class SubdomainEnum(Base):
    __tablename__ = "subdomain_enum"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    wordlist = Column(String(255), nullable=True)
    total_found = Column(Integer, default=0)
    alive_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    results = relationship("SubdomainResult", back_populates="enumeration")


class SubdomainResult(Base):
    __tablename__ = "subdomain_results"

    id = Column(Integer, primary_key=True, index=True)
    enum_id = Column(Integer, ForeignKey("subdomain_enum.id"))
    subdomain = Column(String(255), nullable=False)
    is_alive = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    enumeration = relationship("SubdomainEnum", back_populates="results")


class PathFuzz(Base):
    __tablename__ = "path_fuzz"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(255), nullable=False)
    status = Column(String(20), nullable=False, default="pending")
    wordlist = Column(String(255), nullable=True)
    extensions = Column(String(255), nullable=True)
    total_found = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True), nullable=True)
    error_message = Column(Text, nullable=True)

    results = relationship("PathResult", back_populates="fuzz")


class PathResult(Base):
    __tablename__ = "path_results"

    id = Column(Integer, primary_key=True, index=True)
    fuzz_id = Column(Integer, ForeignKey("path_fuzz.id"))
    path = Column(String(500), nullable=False)
    status_code = Column(String(10), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    fuzz = relationship("PathFuzz", back_populates="results")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=True)
    scan_id = Column(Integer, nullable=True)
    enum_id = Column(Integer, nullable=True)
    host = Column(String(255), nullable=True)
    subdomain = Column(String(255), nullable=True)
    service = Column(String(100), nullable=True)
    port = Column(Integer, nullable=True)
    cve_id = Column(String(20), nullable=True, index=True)
    title = Column(String(255), nullable=True)
    severity = Column(String(20), nullable=True)
    cvss_score = Column(String(10), nullable=True)
    is_exploited = Column(Boolean, default=False)
    exploit_available = Column(Boolean, default=False)
    edb_id = Column(String(20), nullable=True)
    description = Column(Text, nullable=True)
    host_os = Column(String(50), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    @property
    def severity_level(self):
        sev = self.severity.lower() if self.severity else ""
        if sev == "critical":
            return 5
        elif sev == "high":
            return 4
        elif sev == "medium":
            return 3
        elif sev == "low":
            return 2
        return 1
