import pytest
from pydantic import ValidationError

from app.models.contracts import PortRange, ScanConfiguration
from app.routes import scans as scans_routes


INVALID_CONFIGS = [
    ({"target": ""}, ["target"]),
    ({"target": "   "}, ["target"]),
    ({"target": "999.1.1.1"}, ["target"]),
    ({"target": "::1"}, ["target"]),
    ({"target": "localhost"}, ["target"]),
    ({"target": "192.0.2.0/24"}, ["target"]),
    ({"target_type": "hostname"}, ["target_type"]),
    ({"target_type": "cidr"}, ["target_type"]),
    ({"scan_type": "udp"}, ["scan_type"]),
    ({"scan_depth": "invalid"}, ["scan_depth"]),
    ({"timeout": -5}, ["timeout"]),
    ({"timeout": 0}, ["timeout"]),
    ({"timeout": True}, ["timeout"]),
    ({"timeout": 1.5}, ["timeout"]),
    ({"timeout": "5"}, ["timeout"]),
    ({"port_range": {"start": 0, "end": 80}}, ["port_range", "start"]),
    ({"port_range": {"start": 1, "end": 0}}, ["port_range", "end"]),
    ({"port_range": {"start": 65536, "end": 65536}},
     ["port_range", "start"]),
    ({"port_range": {"start": 1, "end": 99999}},
     ["port_range", "end"]),
    ({"port_range": {"start": 81, "end": 80}},
     ["port_range", "end"]),
    ({"port_range": {"start": True, "end": 80}},
     ["port_range", "start"]),
    ({"port_range": {"start": 1.5, "end": 80}},
     ["port_range", "start"]),
    ({"port_range": {"start": 1, "end": "80"}},
     ["port_range", "end"]),
    ({"port_range": {"start": 1}}, ["port_range", "end"]),
]


@pytest.mark.parametrize("changes,field", INVALID_CONFIGS)
def test_invalid_configuration_rejected_by_model_and_api(
    client, scan_config_factory, changes, field
):
    payload = scan_config_factory().model_dump(mode="json")
    payload.update(changes)

    with pytest.raises(ValidationError) as caught:
        ScanConfiguration(**payload)
    assert any(
        list(error["loc"]) == field
        for error in caught.value.errors()
    )

    response = client.post("/scans", json=payload)
    assert response.status_code == 422
    errors = response.json()["detail"]
    assert any(
        error["loc"] == ["body"] + field and error["msg"]
        for error in errors
    )
    # Rejected requests must not create partial scans.
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}


@pytest.mark.parametrize("port", [1, 2, 65534, 65535])
def test_valid_port_boundaries_are_accepted(
    client, scan_config_factory, port
):
    assert PortRange(start=port, end=port).start == port
    payload = scan_config_factory(
        port_range={"start": port, "end": port}
    ).model_dump(mode="json")
    assert client.post("/scans", json=payload).status_code == 201


@pytest.mark.parametrize("depth", ["quick", "standard", "deep"])
def test_supported_depth_values_are_accepted(
    client, scan_config_factory, depth
):
    payload = scan_config_factory(
        scan_depth=depth, timeout=1
    ).model_dump(mode="json")
    assert client.post("/scans", json=payload).status_code == 201


def test_ipv4_target_whitespace_is_normalized(
    client, scan_config_factory
):
    payload = scan_config_factory().model_dump(mode="json")
    payload["target"] = " 192.0.2.10 "
    response = client.post("/scans", json=payload)
    assert response.status_code == 201
    scan_id = response.json()["scan_id"]
    assert client.get(f"/scans/{scan_id}/results").json()["target"] == (
        "192.0.2.10"
    )


@pytest.mark.parametrize("score", [None, 0, 0.1, 9.9, 10])
def test_valid_cvss_boundaries(finding_factory, score):
    assert finding_factory(cvss_score=score).cvss_score == score


@pytest.mark.parametrize(
    "score", [-0.1, 10.1, 42, float("nan"), float("inf")]
)
def test_invalid_cvss_scores(finding_factory, score):
    with pytest.raises(ValidationError) as caught:
        finding_factory(cvss_score=score)
    assert caught.value.errors()[0]["loc"] == ("cvss_score",)


@pytest.mark.parametrize("port", [0, -1, 65536, True, 1.5, "80"])
def test_invalid_finding_ports(finding_factory, port):
    with pytest.raises(ValidationError) as caught:
        finding_factory(port=port)
    assert caught.value.errors()[0]["loc"] == ("port",)


@pytest.mark.parametrize("percent", [0, 1, 99, 100])
def test_valid_progress_boundaries(scan_status_factory, percent):
    assert scan_status_factory(
        progress_percent=percent
    ).progress_percent == percent


@pytest.mark.parametrize("changes,field", [
    ({"progress_percent": -1}, "progress_percent"),
    ({"progress_percent": 101}, "progress_percent"),
    ({"progress_percent": True}, "progress_percent"),
    ({"progress_percent": 1.5}, "progress_percent"),
    ({"status": "unknown"}, "status"),
    ({"current_port": 0}, "current_port"),
    ({"current_port": 65536}, "current_port"),
    ({"elapsed_time": -0.1}, "elapsed_time"),
    ({"elapsed_time": float("inf")}, "elapsed_time"),
])
def test_invalid_status_values(scan_status_factory, changes, field):
    with pytest.raises(ValidationError) as caught:
        scan_status_factory(**changes)
    assert any(
        error["loc"] == (field,)
        for error in caught.value.errors()
    )


@pytest.mark.parametrize(
    "state", ["queued", "running", "completed", "failed", "cancelled"]
)
def test_supported_statuses(scan_status_factory, scan_result_factory, state):
    assert scan_status_factory(status=state).status == state
    assert scan_result_factory(status=state).status == state
