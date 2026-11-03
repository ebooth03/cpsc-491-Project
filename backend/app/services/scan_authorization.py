"""Translate shared scan authorization failures into API responses."""

from fastapi import HTTPException

from app.models.contracts import ScanConfiguration
from scan_engine.authorization import (
    ScanAllowlistConfigurationError,
    ScanAuthorizationError,
    require_authorized_target as check_authorized_target,
)


def require_authorized_target(configuration: ScanConfiguration) -> None:
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
