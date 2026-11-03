
"""
Runs the scan engine for a backend scan and stores the outcome (KAN-102).

The scan engine returns its own dataclasses. This module calls the
engine, converts its output into backend contracts, and records scan
status as execution progresses:

    queued -> running -> completed | failed

KAN-105 adds concurrency reservation cleanup.
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
from app.services.scan_limiter import ScanLimiter


# Make the repository-level scan engine importable when
# the API is started from the backend directory.
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
    Convert raw engine errors into safe public messages.
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
    """Convert scan-engine results into backend contracts."""

    hosts = []
    notes = []

    for engine_host in engine_result.hosts:

        ports = [
            PortResult(
                **service_result_to_backend_port(service)
            )
            for service in engine_host.services
        ]

        hosts.append(
            HostResult(
                host=engine_host.address,
                ports=ports,
            )
        )

        if engine_host.state != "reachable":
            notes.append(
                UNREACHABLE_NOTE.format(
                    host=engine_host.address
                )
            )

    failed = engine_result.status == "failed"

    errors = (
        [public_engine_error(engine_result.error)]
        if failed
        else []
    )

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
        return (
            result.errors[0]
            if result.errors
            else ENGINE_FAILURE_MESSAGE
        )

    open_ports = sum(
        len(host.ports)
        for host in result.hosts
    )

    if result.errors:
        return f"Scan completed. {result.errors[0]}"

    return f"Scan completed: {open_ports} open port(s) found."


def run_scan(
    scan_id: str,
    configuration: ScanConfiguration,
    engine: ScanEngine,
    results: dict[str, ScanResult],
    statuses: dict[str, ScanStatus],
    limiter: ScanLimiter | None = None,
) -> None:
    """
    Execute a scan and record its outcome.

    KAN-105: Always release the concurrency reservation,
    including successful and failed execution.

    The optional limiter preserves compatibility with
    existing direct run_scan() calls.
    """

    try:
        start_time = results[scan_id].start_time
        started = time.monotonic()

        # Update scan status to running.
        statuses[scan_id] = ScanStatus(
            scan_id=scan_id,
            status="running",
            progress_percent=0,
            current_host=configuration.target,
            elapsed_time=0.0,
            message=(
                f"Scanning ports {configuration.port_range.start}-"
                f"{configuration.port_range.end} "
                f"on {configuration.target}."
            ),
            updated_at=_now(),
        )

        results[scan_id] = results[scan_id].model_copy(
            update={"status": "running"}
        )

        try:
            # Preserve the authorization acknowledgment
            # introduced in the latest main branch.
            engine_result = engine.scan(
                authorization_acknowledged=(
                    configuration.options.get(
                        "authorization_acknowledged",
                        False,
                    )
                ),
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
            # Record unexpected engine failures safely.
            logger.exception(
                "Scan %s failed in the scan engine.",
                scan_id,
            )

            result = ScanResult(
                scan_id=scan_id,
                target=configuration.target,
                start_time=start_time,
                end_time=_now(),
                status="failed",
                errors=[UNEXPECTED_ERROR_MESSAGE],
            )

        # Publish the final result.
        results[scan_id] = result

        statuses[scan_id] = ScanStatus(
            scan_id=scan_id,
            status=result.status,
            progress_percent=(
                100 if result.status == "completed" else 0
            ),
            current_host=configuration.target,
            elapsed_time=round(
                time.monotonic() - started,
                3,
            ),
            message=_summary_message(result),
            updated_at=_now(),
        )

    finally:
        # KAN-105: Release capacity regardless of outcome.
        if limiter is not None:
            limiter.release(scan_id)
