"""Translate shared scan authorization failures into API responses."""

from fastapi import HTTPException

from app.models.contracts import ScanConfiguration
from scan_engine.authorization import (
    ScanAllowlistConfigurationError,
    ScanAuthorizationError,
    require_authorized_target as check_authorized_target,
)


def _require_configured_target(configuration: ScanConfiguration) -> None:
    """Reject requests before scan storage or background work is created."""
    try:
        check_authorized_target(
            configuration.target,
            configuration.options.get("authorization_acknowledged"),
        )
    except ScanAllowlistConfigurationError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ScanAuthorizationError as exc:
        raise HTTPException(status_code=403, detail=str(exc)) from exc


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
