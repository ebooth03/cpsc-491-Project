
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

from app.models.contracts import (
    ScanConfiguration,
    ScanResult,
    ScanStatus,
)
from app.services.scan_authentication import require_scan_requester
from app.services.scan_authorization import require_authorized_target
from app.services.scan_runner import ScanEngine, get_scan_engine, run_scan
from app.services.scan_limiter import scan_limiter


router = APIRouter(
    prefix="/scans",
    tags=["scans"],
)


# =========================================================
# Temporary in-memory storage
# =========================================================

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
    requester_id: str | None = Depends(require_scan_requester),
) -> ScanStatus:

    # Verify target authorization before reserving capacity.
    require_authorized_target(
        configuration,
        requester_id=requester_id,
    )

    # Generate a unique scan ID.
    scan_id = f"scan-{uuid4().hex[:8]}"

    # KAN-105: Reserve capacity before accepting the scan.
    # The limit includes queued and running scans.
    if not scan_limiter.try_acquire(scan_id):
        raise HTTPException(
            status_code=429,
            detail="Maximum concurrent scan limit reached.",
            headers={"Retry-After": "1"},
        )

    try:
        now = datetime.now(timezone.utc)

        # Record the accepted scan as queued.
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

        # Schedule the scan and pass its reservation limiter.
        background_tasks.add_task(
            run_scan,
            scan_id,
            configuration,
            engine,
            SCAN_RESULTS,
            SCAN_STATUSES,
            scan_limiter,
        )

        return status

    except Exception:
        # Release capacity if scan setup or scheduling fails.
        SCAN_RESULTS.pop(scan_id, None)
        SCAN_STATUSES.pop(scan_id, None)
        scan_limiter.release(scan_id)
        raise


# =========================================================
# GET /scans
# Return scan history
# =========================================================

@router.get(
    "",
    response_model=list[ScanResult],
)
def list_scans() -> list[ScanResult]:

    scans = list(SCAN_RESULTS.values())

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
