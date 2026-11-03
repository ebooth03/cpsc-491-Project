"""Restrict API scans to explicitly acknowledged, approved IPv4 targets."""

import ipaddress
import os

from fastapi import HTTPException

from app.models.contracts import ScanConfiguration


def _require_configured_target(configuration: ScanConfiguration) -> None:
    """Reject requests before scan storage or background work is created."""
    if configuration.options.get("authorization_acknowledged") is not True:
        raise HTTPException(
            status_code=403,
            detail="Explicit scan authorization acknowledgement is required.",
        )

    raw = os.environ.get("SCANNER_APPROVED_TARGETS", "")
    entries = [entry.strip() for entry in raw.split(",")]
    if not raw.strip() or any(not entry for entry in entries):
        raise HTTPException(
            status_code=503,
            detail="Approved scan targets are not configured correctly.",
        )

    try:
        approved = {str(ipaddress.IPv4Address(entry)) for entry in entries}
    except ipaddress.AddressValueError:
        raise HTTPException(
            status_code=503,
            detail="Approved scan targets are not configured correctly.",
        ) from None

    if configuration.target not in approved:
        raise HTTPException(
            status_code=403,
            detail="Target is not approved for scanning.",
        )


def require_authorized_target(configuration: ScanConfiguration) -> None:
    """Check approval and record the decision before queuing a scan."""
    import os
    import sqlite3
    from datetime import datetime, timezone
    from pathlib import Path

    from app.repository.scan_audit_repository import ScanAuditEvent, ScanAuditRepository
    from app.repository.target_approval_repository import TargetApprovalRepository

    database_path = os.environ.get("SCANNER_AUTHORIZATION_DB")
    if database_path is None:
        _require_configured_target(configuration)
        return
    if not database_path.strip():
        raise HTTPException(status_code=503, detail="Scan authorization database is unavailable.")

    database = Path(database_path)
    now = datetime.now(timezone.utc)
    target = configuration.target
    scope = configuration.scan_type
    rejection = None
    reason = "active_target_approval"

    try:
        try:
            _require_configured_target(configuration)
        except HTTPException as exc:
            rejection = exc
            reason = "scan_policy_denied" if exc.status_code == 403 else "scan_policy_unavailable"
        else:
            approval = TargetApprovalRepository(database).find_active(target, scope, now)
            if approval is None:
                rejection = HTTPException(
                    status_code=403,
                    detail="An active approval for this target and scan type is required.",
                )
                reason = "no_active_target_approval"

        ScanAuditRepository(database).record(ScanAuditEvent(
            occurred_at=now,
            target=target,
            scope=scope,
            outcome="deny" if rejection is not None else "allow",
            reason_code=reason,
        ))
    except sqlite3.Error as exc:
        raise HTTPException(
            status_code=503,
            detail="Scan authorization database is unavailable.",
        ) from exc

    if rejection is not None:
        raise rejection
