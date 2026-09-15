from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class PortRange(BaseModel):
    start: int
    end: int


class ScanConfiguration(BaseModel):
    target: str
    target_type: str
    port_range: PortRange
    scan_type: str
    scan_depth: str
    timeout: int
    options: dict[str, Any] = Field(default_factory=dict)


class PortResult(BaseModel):
    port: int
    protocol: str
    state: str
    service: str | None = None
    version: str | None = None
    banner: str | None = None


class HostResult(BaseModel):
    host: str
    ports: list[PortResult] = Field(default_factory=list)


class ScanResult(BaseModel):
    scan_id: str
    target: str
    start_time: datetime
    end_time: datetime | None = None
    status: str
    hosts: list[HostResult] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class VulnerabilityFinding(BaseModel):
    finding_id: str
    scan_id: str
    host: str
    port: int
    protocol: str
    service: str
    detected_version: str | None = None
    cve_id: str
    cvss_score: float | None = None
    severity: str
    description: str
    remediation: str | None = None
    reference_url: str | None = None


class ScanStatus(BaseModel):
    scan_id: str
    status: str
    progress_percent: int
    current_host: str | None = None
    current_port: int | None = None
    current_service: str | None = None
    elapsed_time: float | None = None
    message: str | None = None
    updated_at: datetime