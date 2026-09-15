from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def test_create_scan():
    response = client.post(
        "/scans",
        json={
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
        },
    )

    assert response.status_code == 201
    assert response.json()["scan_id"] == "scan-123"


def test_list_scans():
    response = client.get("/scans")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert response.json()[0]["scan_id"] == "scan-123"


def test_get_scan():
    response = client.get("/scans/scan-123")

    assert response.status_code == 200

    body = response.json()

    assert body["scan_id"] == "scan-123"
    assert body["target"] == "192.168.1.10"
    assert body["hosts"][0]["ports"][0]["port"] == 22


def test_get_scan_status():
    response = client.get("/scans/scan-123/status")

    assert response.status_code == 200

    body = response.json()

    assert body["scan_id"] == "scan-123"
    assert body["status"] == "completed"
    assert body["progress_percent"] == 100


def test_get_scan_results():
    response = client.get("/scans/scan-123/results")

    assert response.status_code == 200

    body = response.json()

    assert body["scan_id"] == "scan-123"
    assert body["hosts"][0]["ports"][0]["service"] == "ssh"