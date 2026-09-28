from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


SCAN_CONFIG = {
    "target": "192.168.1.10",
    "target_type": "ip",
    "port_range": {
        "start": 1,
        "end": 1024,
    },
    "scan_type": "tcp",
    "scan_depth": "standard",
    "timeout": 5,
    "options": {},
}


def create_test_scan():
    response = client.post(
        "/scans",
        json=SCAN_CONFIG,
    )

    assert response.status_code == 201

    return response.json()


def test_create_scan():
    scan = create_test_scan()

    assert scan["scan_id"].startswith("scan-")
    assert scan["status"] == "completed"


def test_list_scans():
    created_scan = create_test_scan()

    response = client.get("/scans")

    assert response.status_code == 200

    scans = response.json()

    assert isinstance(scans, list)

    assert any(
        scan["scan_id"] == created_scan["scan_id"]
        for scan in scans
    )


def test_get_scan():
    created_scan = create_test_scan()
    scan_id = created_scan["scan_id"]

    response = client.get(
        f"/scans/{scan_id}"
    )

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_get_scan_status():
    created_scan = create_test_scan()
    scan_id = created_scan["scan_id"]

    response = client.get(
        f"/scans/{scan_id}/status"
    )

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_get_scan_results():
    created_scan = create_test_scan()
    scan_id = created_scan["scan_id"]

    response = client.get(
        f"/scans/{scan_id}/results"
    )

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id