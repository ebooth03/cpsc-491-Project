from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ServiceResult:
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


@dataclass
class HostResult:
    address: str
    state: str
    services: list[ServiceResult] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    status: str
    hosts: list[HostResult] = field(default_factory=list)
    error: Optional[str] = None