from datetime import datetime, timezone

from fastapi import APIRouter

from app.models.contracts import (
    HostResult,
    PortResult,
    ScanConfiguration,
    ScanResult,
    ScanStatus,
)


router = APIRouter(
    prefix="/scans",
    tags=["scans"],
)


SAMPLE_SCAN_RESULT = ScanResult(
    scan_id="scan-123",
    target="192.168.1.10",
    start_time=datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc),
    end_time=datetime(2026, 9, 14, 12, 1, tzinfo=timezone.utc),
    status="completed",
    hosts=[
        HostResult(
            host="192.168.1.10",
            ports=[
                PortResult(
                    port=22,
                    protocol="tcp",
                    state="open",
                    service="ssh",
                    version="OpenSSH 9.x",
                )
            ],
        )
    ],
    errors_warnings=[],
)


SAMPLE_SCAN_STATUS = ScanStatus(
    scan_id="scan-123",
    status="completed",
    progress_percent=100,
    current_host="192.168.1.10",
    current_port=22,
    current_service="ssh",
    elapsed_time=60.0,
    message="Sample scan completed.",
    updated_at=datetime(2026, 9, 14, 12, 1, tzinfo=timezone.utc),
)


@router.post("", response_model=ScanStatus, status_code=201)
def create_scan(configuration: ScanConfiguration) -> ScanStatus:
    """
    Accept a scan configuration and return sample status data.

    No scanner is started and no data is persisted.
    """
    return SAMPLE_SCAN_STATUS


@router.get("", response_model=list[ScanResult])
def list_scans() -> list[ScanResult]:
    """
    Return sample scan history.

    No database is queried.
    """
    return [SAMPLE_SCAN_RESULT]


@router.get("/{scan_id}", response_model=ScanResult)
def get_scan(scan_id: str) -> ScanResult:
    """
    Return a sample scan.

    scan_id is not looked up because persistence is not implemented yet.
    """
    return SAMPLE_SCAN_RESULT


@router.get("/{scan_id}/status", response_model=ScanStatus)
def get_scan_status(scan_id: str) -> ScanStatus:
    """
    Return sample status data.

    No scanner or database is queried.
    """
    return SAMPLE_SCAN_STATUS


@router.get("/{scan_id}/results", response_model=ScanResult)
def get_scan_results(scan_id: str) -> ScanResult:
    """
    Return sample scan results.

    No scanner or database is queried.
    """
    return SAMPLE_SCAN_RESULT