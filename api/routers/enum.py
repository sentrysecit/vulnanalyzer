from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
import os
import threading

from api.database import get_db, SessionLocal
from api.models import SubdomainEnum, SubdomainResult, PathFuzz, PathResult
from api.schemas import (
    SubdomainRequest,
    SubdomainResponse,
    SubdomainDetail,
    FuzzRequest,
    FuzzResponse,
    FuzzDetail,
    WordlistResponse,
    SubdomainResultResponse,
    PathResultResponse,
)
from core.subdomain_enum import WORDLISTS as SUBDOMAIN_WORDLISTS, SubdomainEnumerator
from core.path_fuzz import WORDLISTS as PATH_WORDLISTS, PathFuzzer

router = APIRouter(prefix="/api/enum", tags=["enumeration"])


def get_output_dir():
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_dir, "tools", "fuzzing")


@router.get("/wordlists", response_model=List[WordlistResponse])
def get_wordlists(type: str = Query(..., description="Type: subdomain or fuzz")):
    if type == "subdomain":
        wordlists = SUBDOMAIN_WORDLISTS
    elif type == "fuzz":
        wordlists = PATH_WORDLISTS
    else:
        raise HTTPException(status_code=400, detail="Invalid type")

    available = []
    for name, path in wordlists.items():
        if os.path.exists(os.path.expanduser(path)):
            available.append(
                WordlistResponse(
                    name=name,
                    path=path,
                    description=f"Wordlist {name}",
                )
            )

    return available


@router.post("/subdomain", response_model=SubdomainResponse)
def start_subdomain_enum(request: SubdomainRequest, db: Session = Depends(get_db)):
    subdomain_enum = SubdomainEnum(
        target=request.target,
        status="running",
        wordlist=request.wordlist,
    )
    db.add(subdomain_enum)
    db.commit()
    db.refresh(subdomain_enum)

    output_dir = get_output_dir()
    output_file = os.path.join(output_dir, f"subdomains_{subdomain_enum.id}.txt")
    alive_file = os.path.join(output_dir, f"subdomains_{subdomain_enum.id}_alive.txt")

    def run_in_background():
        db = SessionLocal()
        try:
            enum = db.query(SubdomainEnum).filter(SubdomainEnum.id == subdomain_enum.id).first()
            if not enum:
                return

            enum.status = "running"
            db.commit()

            try:
                enumerator = SubdomainEnumerator(
                    target=request.target,
                    wordlist=request.wordlist,
                    threads=request.threads,
                    use_httpx=True,
                    use_nuclei=request.use_nuclei,
                    output=output_file,
                )
                results = enumerator.run()

                total_found = len(results.get("all", []))
                alive_list = results.get("alive", [])
                alive_count = len(alive_list)

                enum.total_found = total_found
                enum.alive_count = alive_count
                enum.status = "completed"
                enum.completed_at = datetime.now()

                for sub in results.get("all", []):
                    is_alive = sub in alive_list
                    result = SubdomainResult(
                        enum_id=enum.id,
                        subdomain=sub,
                        is_alive=is_alive,
                    )
                    db.add(result)

                db.commit()

            except Exception as e:
                enum.status = "failed"
                enum.error_message = str(e)
                enum.completed_at = datetime.now()
                db.commit()

        finally:
            db.close()

    thread = threading.Thread(target=run_in_background)
    thread.daemon = True
    thread.start()

    return SubdomainResponse(
        id=subdomain_enum.id,
        target=subdomain_enum.target,
        status=subdomain_enum.status,
        wordlist=subdomain_enum.wordlist,
    )


@router.get("/subdomain", response_model=List[SubdomainDetail])
def list_subdomain_enums(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    total = db.query(SubdomainEnum).count()
    enums = (
        db.query(SubdomainEnum)
        .order_by(SubdomainEnum.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return [SubdomainDetail.model_validate(e) for e in enums]


@router.get("/subdomain/{enum_id}", response_model=SubdomainDetail)
def get_subdomain_enum(enum_id: int, db: Session = Depends(get_db)):
    enum = db.query(SubdomainEnum).filter(SubdomainEnum.id == enum_id).first()
    if not enum:
        raise HTTPException(status_code=404, detail="Enumeration not found")
    return SubdomainDetail.model_validate(enum)


@router.get("/subdomain/{enum_id}/results", response_model=List[SubdomainResultResponse])
def get_subdomain_results(enum_id: int, db: Session = Depends(get_db)):
    enum = db.query(SubdomainEnum).filter(SubdomainEnum.id == enum_id).first()
    if not enum:
        raise HTTPException(status_code=404, detail="Enumeration not found")

    results = db.query(SubdomainResult).filter(SubdomainResult.enum_id == enum_id).all()
    return [SubdomainResultResponse.model_validate(r) for r in results]


@router.post("/fuzz", response_model=FuzzResponse)
def start_fuzz(request: FuzzRequest, db: Session = Depends(get_db)):
    path_fuzz = PathFuzz(
        target=request.target,
        status="running",
        wordlist=request.wordlist,
        extensions=request.extensions,
    )
    db.add(path_fuzz)
    db.commit()
    db.refresh(path_fuzz)

    output_dir = get_output_dir()
    output_file = os.path.join(output_dir, f"paths_{path_fuzz.id}.txt")

    def run_in_background():
        db = SessionLocal()
        try:
            fuzz = db.query(PathFuzz).filter(PathFuzz.id == path_fuzz.id).first()
            if not fuzz:
                return

            fuzz.status = "running"
            db.commit()

            try:
                extensions = request.extensions.split(",") if request.extensions else None
                fuzzer = PathFuzzer(
                    target=request.target,
                    wordlist=request.wordlist,
                    extensions=extensions,
                    threads=request.threads,
                    output=output_file,
                )
                results = fuzzer.run()

                total_found = len(results.get("all", []))

                fuzz.total_found = total_found
                fuzz.status = "completed"
                fuzz.completed_at = datetime.now()

                for path in results.get("all", []):
                    result = PathResult(
                        fuzz_id=fuzz.id,
                        path=path,
                    )
                    db.add(result)

                db.commit()

            except Exception as e:
                fuzz.status = "failed"
                fuzz.error_message = str(e)
                fuzz.completed_at = datetime.now()
                db.commit()

        finally:
            db.close()

    thread = threading.Thread(target=run_in_background)
    thread.daemon = True
    thread.start()

    return FuzzResponse(
        id=path_fuzz.id,
        target=path_fuzz.target,
        status=path_fuzz.status,
        wordlist=path_fuzz.wordlist,
    )


@router.get("/fuzz", response_model=List[FuzzDetail])
def list_fuzz_jobs(
    db: Session = Depends(get_db),
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
):
    total = db.query(PathFuzz).count()
    fuzz_jobs = (
        db.query(PathFuzz)
        .order_by(PathFuzz.created_at.desc())
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return [FuzzDetail.model_validate(f) for f in fuzz_jobs]


@router.get("/fuzz/{fuzz_id}", response_model=FuzzDetail)
def get_fuzz_job(fuzz_id: int, db: Session = Depends(get_db)):
    fuzz = db.query(PathFuzz).filter(PathFuzz.id == fuzz_id).first()
    if not fuzz:
        raise HTTPException(status_code=404, detail="Fuzzing not found")
    return FuzzDetail.model_validate(fuzz)


@router.get("/fuzz/{fuzz_id}/results", response_model=List[PathResultResponse])
def get_fuzz_results(fuzz_id: int, db: Session = Depends(get_db)):
    fuzz = db.query(PathFuzz).filter(PathFuzz.id == fuzz_id).first()
    if not fuzz:
        raise HTTPException(status_code=404, detail="Fuzzing not found")

    results = db.query(PathResult).filter(PathResult.fuzz_id == fuzz_id).all()
    return [PathResultResponse.model_validate(r) for r in results]