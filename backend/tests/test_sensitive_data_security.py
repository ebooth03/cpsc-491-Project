"""Sprint 4 CC6.1/CC6.7: baseline API access and error disclosure tests.

Run from backend/: python -m pytest tests/test_sensitive_data_security.py -v
No real network scanning is performed.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.contracts import ScanResult
from app.routes.scans import SCAN_RESULTS, SCAN_STATUSES
from app.services.scan_runner import get_scan_engine


@pytest.fixture
def client():
    # Isolate this test file from other test data and dependency overrides.
    old_results = SCAN_RESULTS.copy()
    old_statuses = SCAN_STATUSES.copy()
    SCAN_RESULTS.clear()
    SCAN_STATUSES.clear()
    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        SCAN_RESULTS.clear()
        SCAN_RESULTS.update(old_results)
        SCAN_STATUSES.clear()
        SCAN_STATUSES.update(old_statuses)
        app.dependency_overrides.pop(get_scan_engine, None)


def _seed_scan():
    scan_id = "sprint4-security-test"
    SCAN_RESULTS[scan_id] = ScanResult(
        scan_id=scan_id,
        target="192.0.2.10",  # Reserved documentation IP; not scanned.
        start_time=datetime.now(timezone.utc),
        status="completed",
    )
    return scan_id


@pytest.mark.xfail(strict=True, reason="Known gap: scan history has no authentication")
def test_scan_history_requires_authentication(client):
    _seed_scan()
    response = client.get("/scans")
    assert response.status_code == 401


@pytest.mark.xfail(strict=True, reason="Known gap: scan results have no authentication")
def test_scan_results_require_authentication(client):
    scan_id = _seed_scan()
    response = client.get(f"/scans/{scan_id}/results")
    assert response.status_code == 401


def test_internal_engine_error_is_not_returned_to_api_client(client, monkeypatch):
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", "192.0.2.10")
    secret_marker = "SYNTHETIC_SECRET_DO_NOT_USE_491"

    class FailingEngine:
        def scan(self, **kwargs):
            raise RuntimeError(f"Engine failure with marker: {secret_marker}")

    app.dependency_overrides[get_scan_engine] = lambda: FailingEngine()

    response = client.post(
        "/scans",
        json={
            "target": "192.0.2.10",
            "target_type": "ip",
            "port_range": {"start": 80, "end": 80},
            "scan_type": "tcp",
            "scan_depth": "quick",
            "timeout": 1,
            "options": {"authorization_acknowledged": True},
        },
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    result_response = client.get(f"/scans/{scan_id}/results")
    assert result_response.status_code == 200
    result = result_response.json()
    assert result["status"] == "failed"
    assert secret_marker not in result_response.text
    assert secret_marker not in client.get(f"/scans/{scan_id}/status").text
