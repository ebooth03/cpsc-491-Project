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


def create_test_scan(client):
    response = client.post(
        "/scans",
        json=SCAN_CONFIG,
    )

    assert response.status_code == 201

    return response.json()


def test_create_scan(client):
    scan = create_test_scan(client)

    assert scan["scan_id"].startswith("scan-")

    # POST responds before the scan runs; the scan then completes in the
    # background (KAN-102).
    assert scan["status"] == "queued"
    status = client.get(f"/scans/{scan['scan_id']}/status").json()
    assert status["status"] == "completed"


def test_list_scans(client):
    created_scan = create_test_scan(client)

    response = client.get("/scans")

    assert response.status_code == 200

    scans = response.json()

    assert isinstance(scans, list)

    assert any(
        scan["scan_id"] == created_scan["scan_id"]
        for scan in scans
    )


def test_get_scan(client):
    created_scan = create_test_scan(client)
    scan_id = created_scan["scan_id"]

    response = client.get(
        f"/scans/{scan_id}"
    )

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_get_scan_status(client):
    created_scan = create_test_scan(client)
    scan_id = created_scan["scan_id"]

    response = client.get(
        f"/scans/{scan_id}/status"
    )

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id


def test_get_scan_results(client):
    created_scan = create_test_scan(client)
    scan_id = created_scan["scan_id"]

    response = client.get(
        f"/scans/{scan_id}/results"
    )

    assert response.status_code == 200
    assert response.json()["scan_id"] == scan_id