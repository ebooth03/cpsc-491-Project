"""Restrict API scans to explicitly acknowledged, approved IPv4 targets."""

import ipaddress
import os

from fastapi import HTTPException

from app.models.contracts import ScanConfiguration


def require_authorized_target(configuration: ScanConfiguration) -> None:
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
