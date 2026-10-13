import pytest
from app.routes import scans as scans_routes


def test_mock_scan_returns_empty_findings(client):
    response = client.post("/scans", json={
        "target": "192.0.2.10",
        "target_type": "ip",
        "port_range": {"start": 1, "end": 1024},
        "scan_type": "tcp",
        "scan_depth": "standard",
        "timeout": 5,
        "options": {},
    })
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]

    result = client.get(f"/scans/{scan_id}/results")
    assert result.status_code == 200
    assert result.json()["findings"] == []


@pytest.mark.parametrize("endpoint", [
    "/scans/fixture-scan",
    "/scans/fixture-scan/results",
    "/scans",
])
def test_api_preserves_supplied_findings(client, endpoint, finding_factory, scan_result_factory):
    finding = finding_factory("fixture-scan")
    scans_routes.SCAN_RESULTS["fixture-scan"] = scan_result_factory(
        "fixture-scan", [finding]
    )

    response = client.get(endpoint)
    assert response.status_code == 200
    body = response.json()
    if endpoint == "/scans":
        assert len(body) == 1
        body = body[0]

    assert body["findings"] == [finding.model_dump(mode="json")]


def test_results_keep_findings_separate_between_scans(client, finding_factory, scan_result_factory):
    scans_routes.SCAN_RESULTS["scan-a"] = scan_result_factory(
        "scan-a", [finding_factory("scan-a")]
    )
    scans_routes.SCAN_RESULTS["scan-b"] = scan_result_factory("scan-b")

    first = client.get("/scans/scan-a/results")
    second = client.get("/scans/scan-b/results")

    assert first.status_code == second.status_code == 200
    assert first.json()["findings"][0]["scan_id"] == "scan-a"
    assert second.json()["findings"] == []


def test_openapi_exposes_findings_as_vulnerability_finding_array(client):
    response = client.get("/openapi.json")
    assert response.status_code == 200
    schemas = response.json()["components"]["schemas"]
    field = schemas["ScanResult"]["properties"]["findings"]

    assert field["type"] == "array"
    assert field["items"]["$ref"] == (
        "#/components/schemas/VulnerabilityFinding"
    )
