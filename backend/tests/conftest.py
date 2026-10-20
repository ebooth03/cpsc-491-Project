from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.contracts import (
    ScanConfiguration,
    ScanResult,
    ScanStatus,
    VulnerabilityFinding,
)
from app.routes import scans as scans_routes
from app.services.scan_runner import get_scan_engine
from scan_engine.models import (
    HostResult as EngineHostResult,
    ScanResult as EngineScanResult,
    ServiceResult as EngineServiceResult,
)


@pytest.fixture(autouse=True)
def isolated_scan_storage(monkeypatch):
    """Give every backend test fresh in-memory storage."""
    monkeypatch.setattr(scans_routes, "SCAN_RESULTS", {})
    monkeypatch.setattr(scans_routes, "SCAN_STATUSES", {})


class FakeScanEngine:
    """
    Stand-in for scan_engine.engine.ScanEngine (KAN-102 / KAN-74).

    Built from the real scan engine dataclasses, so a renamed engine
    field breaks these tests instead of failing at integration time.
    Records every call and never touches the network.
    """

    def __init__(self):
        self.calls = []
        self.result = None
        self.error = None
        self.on_scan = None

    def scan(self, target, start_port, end_port, timeout=0.5):
        self.calls.append({
            "target": target,
            "start_port": start_port,
            "end_port": end_port,
            "timeout": timeout,
        })
        if self.on_scan is not None:
            self.on_scan()
        if self.error is not None:
            raise self.error
        if self.result is not None:
            return self.result
        return EngineScanResult(
            target=target,
            status="completed",
            hosts=[EngineHostResult(
                address=target,
                state="reachable",
                services=[EngineServiceResult(
                    port=22, protocol="tcp", state="open",
                    service="ssh", product="OpenSSH", version="9.0",
                )],
            )],
        )


@pytest.fixture(autouse=True)
def fake_scan_engine():
    """Every backend test uses the fake engine unless it replaces it."""
    engine = FakeScanEngine()
    app.dependency_overrides[get_scan_engine] = lambda: engine
    yield engine
    app.dependency_overrides.pop(get_scan_engine, None)


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def scan_config_factory():
    def create(**overrides):
        values = {
            "target": "192.0.2.10",
            "target_type": "ip",
            "port_range": {"start": 1, "end": 1024},
            "scan_type": "tcp",
            "scan_depth": "standard",
            "timeout": 5,
            "options": {},
        }
        values.update(overrides)
        return ScanConfiguration(**values)
    return create


@pytest.fixture
def scan_result_factory():
    def create(scan_id="fixture-scan", findings=None, **overrides):
        values = {
            "scan_id": scan_id,
            "target": "192.0.2.10",
            "start_time": datetime.now(timezone.utc),
            "status": "completed",
            "findings": [] if findings is None else findings,
        }
        values.update(overrides)
        return ScanResult(**values)
    return create


@pytest.fixture
def finding_factory():
    def create(scan_id="fixture-scan", **overrides):
        values = {
            "finding_id": f"fixture-{uuid4().hex[:8]}",
            "scan_id": scan_id,
            "host": "192.0.2.10",
            "port": 80,
            "protocol": "tcp",
            "service": "http",
            "detected_version": "Apache 2.4.49",
            "cve_id": "CVE-2021-41773",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "description": "Controlled API test fixture.",
        }
        values.update(overrides)
        return VulnerabilityFinding(**values)
    return create


@pytest.fixture
def scan_status_factory():
    def create(scan_id="fixture-scan", **overrides):
        values = {
            "scan_id": scan_id,
            "status": "completed",
            "progress_percent": 100,
            "updated_at": datetime.now(timezone.utc),
        }
        values.update(overrides)
        return ScanStatus(**values)
    return create
