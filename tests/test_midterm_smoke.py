
import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


@pytest.fixture
def scan_id():
    payload = {
        "target": "127.0.0.1",
        "target_type": "ip",
        "port_range": {"start": 1, "end": 1024},
        "scan_type": "tcp",
        "scan_depth": "standard",
        "timeout": 10,
        "options": {},
    }

    response = client.post("/scans", json=payload)

    assert response.status_code == 201
    assert response.json().get("scan_id")

    return response.json()["scan_id"]


def test_application_starts():
    response = client.get("/")
    assert response.status_code == 200


def test_scan_history_available():
    response = client.get("/scans")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_scan_creation(scan_id):
    assert scan_id.startswith("scan-")


def test_scan_status(scan_id):
    response = client.get(f"/scans/{scan_id}/status")

    assert response.status_code == 200
    assert response.json()["status"] == "completed"
    assert response.json()["progress_percent"] == 100


def test_scan_results(scan_id):
    response = client.get(f"/scans/{scan_id}/results")

    assert response.status_code == 200
    assert response.json()["target"] == "127.0.0.1"
    assert len(response.json()["hosts"]) > 0


def test_scan_in_history(scan_id):
    response = client.get("/scans")

    assert response.status_code == 200
    assert any(
        scan["scan_id"] == scan_id
        for scan in response.json()
    )


def test_invalid_scan_rejected():
    response = client.post(
        "/scans",
        json={"target": "127.0.0.1"},
    )

    assert response.status_code == 422


def test_unknown_scan_returns_404():
    response = client.get("/scans/nonexistent-id")
    assert response.status_code == 404
