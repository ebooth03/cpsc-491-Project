import pytest

from app.routes import scans as scans_routes


@pytest.mark.parametrize("run", [1, 2])
def test_each_test_starts_with_empty_storage(
    client, scan_config_factory, run
):
    """Each parametrized case must start without another case's data."""
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}
    assert client.get("/scans").json() == []

    response = client.post(
        "/scans",
        json=scan_config_factory().model_dump(mode="json"),
    )
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    assert scan_id in scans_routes.SCAN_RESULTS
    assert scan_id in scans_routes.SCAN_STATUSES


def test_seeded_result_and_status_are_retrievable(
    client, scan_result_factory, scan_status_factory
):
    scan_id = "fixture-seeded"
    scans_routes.SCAN_RESULTS[scan_id] = scan_result_factory(scan_id)
    scans_routes.SCAN_STATUSES[scan_id] = scan_status_factory(
        scan_id, status="running", progress_percent=40
    )

    result = client.get(f"/scans/{scan_id}/results")
    status = client.get(f"/scans/{scan_id}/status")
    assert result.status_code == status.status_code == 200
    assert result.json()["scan_id"] == scan_id
    assert status.json()["status"] == "running"
    assert status.json()["progress_percent"] == 40
