"""
Runs the scan engine for a backend scan and stores the outcome (KAN-102).

The scan engine (scan_engine/) is owned by the scan engine developer and
returns its own dataclasses. This module is the backend side of that
boundary: it calls the engine, converts its output into the shared
backend contracts, and records scan status as the scan progresses:

    queued -> running -> completed | failed

Conversion of individual ports reuses the scan engine's own
backend_adapter, so both components agree on one mapping.
"""

import logging
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from app.models.contracts import (
    HostResult,
    PortResult,
    ScanConfiguration,
    ScanResult,
    ScanStatus,
)

# The scan engine package lives at the repository root, outside backend/.
# Make it importable when the API is started from backend/ as the README
# describes. Appended (not prepended) so it never shadows backend modules.
_REPO_ROOT = Path(__file__).resolve().parents[3]
if str(_REPO_ROOT) not in sys.path:
    sys.path.append(str(_REPO_ROOT))

from scan_engine.backend_adapter import (  # noqa: E402
    service_result_to_backend_port,
)
from scan_engine.engine import ScanEngine  # noqa: E402
from scan_engine.models import ScanResult as EngineScanResult  # noqa: E402


logger = logging.getLogger(__name__)

UNREACHABLE_NOTE = (
    "Host {host} did not respond on the discovery ports (22, 80, 443); "
    "the port scan was skipped."
)
UNEXPECTED_ERROR_MESSAGE = (
    "The scan engine stopped unexpectedly. See the server log for details."
)
NETWORK_ERROR_MESSAGE = (
    "Network error: the target could not be reached. "
    "See the server log for details."
)
ENGINE_FAILURE_MESSAGE = (
    "The scan engine could not complete the scan. "
    "See the server log for details."
)


def get_scan_engine() -> ScanEngine:
    """FastAPI dependency. Tests override this with a fake engine."""
    return ScanEngine()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def public_engine_error(raw_error: str | None) -> str:
    """
    Map a scan engine error to a message that is safe to show clients.

    Raw engine errors can include operating-system details, so they are
    logged on the server (see run_scan) and replaced with a controlled
    message here.
    """
    if raw_error and raw_error.startswith("Network error"):
        return NETWORK_ERROR_MESSAGE
    return ENGINE_FAILURE_MESSAGE


def convert_engine_result(
    scan_id: str,
    configuration: ScanConfiguration,
    engine_result: EngineScanResult,
    start_time: datetime,
    end_time: datetime,
) -> ScanResult:
    """Convert a scan engine ScanResult into the backend ScanResult."""

    hosts = []
    notes = []

    for engine_host in engine_result.hosts:
        ports = [
            PortResult(**service_result_to_backend_port(service))
            for service in engine_host.services
        ]
        hosts.append(HostResult(host=engine_host.address, ports=ports))

        if engine_host.state != "reachable":
            notes.append(UNREACHABLE_NOTE.format(host=engine_host.address))

    failed = engine_result.status == "failed"
    errors = [public_engine_error(engine_result.error)] if failed else []

    return ScanResult(
        scan_id=scan_id,
        target=configuration.target,
        start_time=start_time,
        end_time=end_time,
        status="failed" if failed else "completed",
        hosts=hosts,
        errors=errors + notes,
    )


def _summary_message(result: ScanResult) -> str:
    if result.status == "failed":
        return result.errors[0] if result.errors else ENGINE_FAILURE_MESSAGE

    open_ports = sum(len(host.ports) for host in result.hosts)
    if result.errors:
        return f"Scan completed. {result.errors[0]}"
    return f"Scan completed: {open_ports} open port(s) found."


def run_scan(
    scan_id: str,
    configuration: ScanConfiguration,
    engine: ScanEngine,
    results: dict[str, ScanResult],
    statuses: dict[str, ScanStatus],
) -> None:
    """
    Execute one scan and record its result and status.

    Runs as a FastAPI background task after POST /scans has responded.
    Never raises: any failure is recorded as a failed scan so the API
    keeps serving other requests.
    """

    start_time = results[scan_id].start_time
    started = time.monotonic()

    statuses[scan_id] = ScanStatus(
        scan_id=scan_id,
        status="running",
        progress_percent=0,
        current_host=configuration.target,
        elapsed_time=0.0,
        message=(
            f"Scanning ports {configuration.port_range.start}-"
            f"{configuration.port_range.end} on {configuration.target}."
        ),
        updated_at=_now(),
    )
    results[scan_id] = results[scan_id].model_copy(
        update={"status": "running"}
    )

    try:
        engine_result = engine.scan(
            target=configuration.target,
            start_port=configuration.port_range.start,
            end_port=configuration.port_range.end,
            timeout=configuration.timeout,
        )
        result = convert_engine_result(
            scan_id=scan_id,
            configuration=configuration,
            engine_result=engine_result,
            start_time=start_time,
            end_time=_now(),
        )
        if engine_result.status == "failed":
            logger.warning(
                "Scan %s: scan engine reported a failure: %s",
                scan_id,
                engine_result.error,
            )
    except Exception:
        # Log the details for developers; never expose them to clients.
        logger.exception("Scan %s failed in the scan engine.", scan_id)
        result = ScanResult(
            scan_id=scan_id,
            target=configuration.target,
            start_time=start_time,
            end_time=_now(),
            status="failed",
            errors=[UNEXPECTED_ERROR_MESSAGE],
        )

    results[scan_id] = result
    statuses[scan_id] = ScanStatus(
        scan_id=scan_id,
        status=result.status,
        progress_percent=100 if result.status == "completed" else 0,
        current_host=configuration.target,
        elapsed_time=round(time.monotonic() - started, 3),
        message=_summary_message(result),
        updated_at=_now(),
    )
