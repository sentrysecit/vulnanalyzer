from sqlalchemy import Column, Integer, String, DateTime, Text, Enum, Boolean, ForeignKey
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
