from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app.models.contracts import (
    ScanConfiguration,
    ScanResult,
    ScanStatus,
)
from app.services.scan_runner import ScanEngine, get_scan_engine, run_scan


router = APIRouter(
    prefix="/scans",
    tags=["scans"],
)


# =========================================================
# Temporary in-memory storage
# =========================================================
#
# This is NOT a database.
# Scan history will be kept while the backend is running,
# but it will disappear when the backend restarts.
#
# Later, this can be replaced by ScanRepository/database code.

SCAN_RESULTS: dict[str, ScanResult] = {}
SCAN_STATUSES: dict[str, ScanStatus] = {}


# =========================================================
# POST /scans
# Create a new scan
# =========================================================

@router.post(
    "",
    response_model=ScanStatus,
    status_code=201,
)
def create_scan(
    configuration: ScanConfiguration,
    background_tasks: BackgroundTasks,
    engine: ScanEngine = Depends(get_scan_engine),
) -> ScanStatus:

    # Give every scan a unique ID
    scan_id = f"scan-{uuid4().hex[:8]}"

    now = datetime.now(timezone.utc)

    # Record the scan as queued so it appears in history right away.
    SCAN_RESULTS[scan_id] = ScanResult(
        scan_id=scan_id,
        target=configuration.target,
        start_time=now,
        status="queued",
    )

    status = ScanStatus(
        scan_id=scan_id,
        status="queued",
        progress_percent=0,
        current_host=configuration.target,
        elapsed_time=0.0,
        message="Scan queued.",
        updated_at=now,
    )
    SCAN_STATUSES[scan_id] = status

    # Run the real scan engine after responding (KAN-102). The frontend
    # polls GET /scans/{scan_id}/status until the scan finishes.
    background_tasks.add_task(
        run_scan,
        scan_id,
        configuration,
        engine,
        SCAN_RESULTS,
        SCAN_STATUSES,
    )

    return status


# =========================================================
# GET /scans
# Return scan history
# =========================================================

@router.get(
    "",
    response_model=list[ScanResult],
)
def list_scans() -> list[ScanResult]:

    # Convert dictionary values into a list
    scans = list(SCAN_RESULTS.values())

    # Sort newest first
    scans.sort(
        key=lambda scan: scan.start_time,
        reverse=True,
    )

    return scans


# =========================================================
# GET /scans/{scan_id}
# Return one scan
# =========================================================

@router.get(
    "/{scan_id}",
    response_model=ScanResult,
)
def get_scan(
    scan_id: str,
) -> ScanResult:

    result = SCAN_RESULTS.get(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return result


# =========================================================
# GET /scans/{scan_id}/status
# Return current scan status
# =========================================================

@router.get(
    "/{scan_id}/status",
    response_model=ScanStatus,
)
def get_scan_status(
    scan_id: str,
) -> ScanStatus:

    status = SCAN_STATUSES.get(scan_id)

    if status is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return status


# =========================================================
# GET /scans/{scan_id}/results
# Return scan results
# =========================================================

@router.get(
    "/{scan_id}/results",
    response_model=ScanResult,
)
def get_scan_results(
    scan_id: str,
) -> ScanResult:

    result = SCAN_RESULTS.get(scan_id)

    if result is None:
        raise HTTPException(
            status_code=404,
            detail="Scan not found",
        )

    return result