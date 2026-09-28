from fastapi.testclient import TestClient

from app.main import app


client = TestClient(app)


def build_scan_payload():
    return {
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


def create_scan_and_get_id():
    response = client.post("/scans", json=build_scan_payload())
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    assert scan_id.startswith("scan-")
    return scan_id


def test_create_scan():
    scan_id = create_scan_and_get_id()
    assert scan_id.startswith("scan-")


def test_list_scans():
    response = client.get("/scans")

    assert response.status_code == 200
    assert isinstance(response.json(), list)
    assert len(response.json()) > 0
    assert all(scan["scan_id"].startswith("scan-") for scan in response.json())


def test_get_scan():
    scan_id = create_scan_and_get_id()
    response = client.get(f"/scans/{scan_id}")

    assert response.status_code == 200

    body = response.json()

    assert body["scan_id"] == scan_id
    assert body["target"] == "192.168.1.10"
    assert body["hosts"][0]["ports"][0]["port"] == 22


def test_get_scan_status():
    scan_id = create_scan_and_get_id()
    response = client.get(f"/scans/{scan_id}/status")

    assert response.status_code == 200

    body = response.json()

    assert body["scan_id"] == scan_id
    assert body["status"] == "completed"
    assert body["progress_percent"] == 100


def test_get_scan_results():
    scan_id = create_scan_and_get_id()
    response = client.get(f"/scans/{scan_id}/results")

    assert response.status_code == 200

    body = response.json()

    assert body["scan_id"] == scan_id
    assert body["hosts"][0]["ports"][0]["service"] == "ssh"
