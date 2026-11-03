"""Shared authorization policy for scan entry points."""

import ipaddress
import os


class ScanAuthorizationError(ValueError):
    """The caller or target is not authorized to scan."""


class ScanAllowlistConfigurationError(ScanAuthorizationError):
    """The server has no usable approved-target configuration."""


def require_authorized_target(target: str, acknowledged: object) -> None:
    if acknowledged is not True:
        raise ScanAuthorizationError(
            "Explicit scan authorization acknowledgement is required."
        )

    raw = os.environ.get("SCANNER_APPROVED_TARGETS", "")
    entries = [entry.strip() for entry in raw.split(",")]
    if not raw.strip() or any(not entry for entry in entries):
        raise ScanAllowlistConfigurationError(
            "Approved scan targets are not configured correctly."
        )

    try:
        approved = {str(ipaddress.IPv4Address(entry)) for entry in entries}
    except ipaddress.AddressValueError:
        raise ScanAllowlistConfigurationError(
            "Approved scan targets are not configured correctly."
        ) from None

    if target not in approved:
        raise ScanAuthorizationError("Target is not approved for scanning.")
