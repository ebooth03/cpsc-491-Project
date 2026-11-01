from datetime import datetime
from typing import Any, Literal
import ipaddress
import os

from pydantic import BaseModel, Field, ValidationInfo, field_validator

MAX_PORTS_PER_SCAN = int(os.getenv("MAX_PORTS_PER_SCAN", "1024"))

if not 1 <= MAX_PORTS_PER_SCAN <= 65535:
    raise ValueError(
        "MAX_PORTS_PER_SCAN must be between 1 and 65535."
    )




class PortRange(BaseModel):
    start: int = Field(strict=True, ge=1, le=65535)
    end: int = Field(strict=True, ge=1, le=65535)

    @field_validator("end")
    @classmethod
    def validate_order(
        cls, value: int, info: ValidationInfo
    ) -> int:
        start = info.data.get("start")

        if start is not None:
            # Reject reversed port ranges
            if value < start:
                raise ValueError(
                    "End port must be greater than or equal to start port."
                )

            # KAN-103: Enforce maximum scan size
            port_count = value - start + 1

            if port_count > MAX_PORTS_PER_SCAN:
                raise ValueError(
                    f"Scan exceeds maximum allowed port count "
                    f"of {MAX_PORTS_PER_SCAN}."
                )

        return value


class ScanConfiguration(BaseModel):
    target: str
    target_type: Literal["ip"]
    port_range: PortRange
    scan_type: Literal["tcp"]
    scan_depth: Literal["quick", "standard", "deep"]
    timeout: int = Field(strict=True, ge=1)
    options: dict[str, Any] = Field(default_factory=dict)

    @field_validator("target")
    @classmethod
    def validate_target(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Target must not be empty.")
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            raise ValueError("Target must be a valid IPv4 address.") from None
        if address.version != 4:
            raise ValueError("Only IPv4 targets are currently supported.")
        return str(address)


class PortResult(BaseModel):
    port: int = Field(strict=True, ge=1, le=65535)
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None
    banner: str | None = None


class HostResult(BaseModel):
    host: str
    ports: list[PortResult] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    finding_id: str
    scan_id: str
    host: str
    port: int = Field(strict=True, ge=1, le=65535)
    protocol: str
    service: str
    detected_version: str | None = None
    cve_id: str
    cvss_score: float | None = Field(default=None, ge=0, le=10, allow_inf_nan=False)
    severity: str
    description: str
    remediation: str | None = None
    reference_url: str | None = None


class ScanResult(BaseModel):
    scan_id: str
    target: str
    start_time: datetime
    end_time: datetime | None = None
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    hosts: list[HostResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    findings: list[VulnerabilityFinding] = Field(default_factory=list)


class ScanStatus(BaseModel):
    scan_id: str
    status: Literal["queued", "running", "completed", "failed", "cancelled"]
    progress_percent: int = Field(strict=True, ge=0, le=100)
    current_host: str | None = None
    current_port: int | None = Field(default=None, strict=True, ge=1, le=65535)
    current_service: str | None = None
    elapsed_time: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    message: str | None = None
    updated_at: datetime