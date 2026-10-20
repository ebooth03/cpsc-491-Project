"""
Scan engine -> backend integration and contract tests (KAN-102, KAN-74).

These tests cover the backend side of the boundary with the scan engine:
how POST /scans runs a scan and how the engine's output is converted into
the shared backend contracts. The engine itself is replaced by the
FakeScanEngine from conftest.py, so no test touches the network and the
scan engine's own logic is left to its owner's tests.
"""

import dataclasses
from datetime import datetime, timezone

import pytest

from app.routes import scans as scans_routes
from app.services import scan_runner
from app.services.scan_runner import convert_engine_result
from scan_engine.models import (
    HostResult as EngineHostResult,
    ScanResult as EngineScanResult,
    ServiceResult as EngineServiceResult,
)


def engine_result(status="completed", hosts=None, error=None):
    return EngineScanResult(
        target="192.0.2.10",
        status=status,
        hosts=[] if hosts is None else hosts,
        error=error,
    )


def engine_host(address="192.0.2.10", state="reachable", services=None):
    return EngineHostResult(
        address=address,
        state=state,
        services=[] if services is None else services,
    )


def engine_service(port, service=None, product=None, version=None):
    return EngineServiceResult(
        port=port,
        protocol="tcp",
        state="open",
        service=service,
        product=product,
        version=version,
    )


@pytest.fixture
def start_scan(client, scan_config_factory):
    """POST a scan and return (create_response_json, scan_id)."""

    def start(**overrides):
        payload = scan_config_factory(**overrides).model_dump(mode="json")
        response = client.post("/scans", json=payload)
        assert response.status_code == 201
        body = response.json()
        return body, body["scan_id"]

    return start


# =========================================================
# Contract: fields the backend relies on from the scan engine
# =========================================================


@pytest.mark.parametrize("model,fields", [
    (EngineScanResult, {"target", "status", "hosts", "error"}),
    (EngineHostResult, {"address", "state", "services"}),
    (EngineServiceResult,
     {"port", "protocol", "state", "service", "product", "version"}),
])
def test_engine_models_expose_fields_backend_relies_on(model, fields):
    """Fails with a clear message if the scan engine renames a field."""
    available = {field.name for field in dataclasses.fields(model)}
    missing = fields - available
    assert not missing, (
        f"scan_engine {model.__name__} no longer has {sorted(missing)}; "
        "update app/services/scan_runner.py to match."
    )


# =========================================================
# POST /scans runs the engine in the background
# =========================================================


def test_post_responds_queued_then_scan_completes(start_scan, client):
    created, scan_id = start_scan()

    assert created["status"] == "queued"
    assert created["progress_percent"] == 0

    status = client.get(f"/scans/{scan_id}/status").json()
    assert status["status"] == "completed"
    assert status["progress_percent"] == 100
    assert status["elapsed_time"] >= 0


def test_engine_receives_validated_configuration(
    start_scan, fake_scan_engine
):
    start_scan(
        target=" 192.0.2.44 ",
        port_range={"start": 20, "end": 25},
        timeout=3,
    )

    assert fake_scan_engine.calls == [{
        "target": "192.0.2.44",
        "start_port": 20,
        "end_port": 25,
        "timeout": 3,
    }]


@pytest.mark.parametrize("changes", [
    {"target": ""},
    {"target": "not-an-ip"},
    {"port_range": {"start": 0, "end": 80}},
    {"port_range": {"start": 100, "end": 80}},
    {"timeout": 0},
    {"scan_type": "udp"},
])
def test_invalid_configuration_never_reaches_engine(
    client, scan_config_factory, fake_scan_engine, changes
):
    payload = scan_config_factory().model_dump(mode="json")
    payload.update(changes)

    assert client.post("/scans", json=payload).status_code == 422
    assert fake_scan_engine.calls == []
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}


def test_status_is_running_while_engine_works(
    start_scan, fake_scan_engine
):
    seen = {}

    def record_state():
        scan_id = next(iter(scans_routes.SCAN_STATUSES))
        seen["status"] = scans_routes.SCAN_STATUSES[scan_id].status
        seen["result"] = scans_routes.SCAN_RESULTS[scan_id].status

    fake_scan_engine.on_scan = record_state
    start_scan()

    assert seen == {"status": "running", "result": "running"}


def test_queued_scan_is_listed_in_history(start_scan, client):
    _, scan_id = start_scan()

    history = client.get("/scans").json()

    assert [scan["scan_id"] for scan in history] == [scan_id]


# =========================================================
# Conversion of engine output into backend contracts
# =========================================================


def test_open_ports_are_converted_with_adapter(
    start_scan, client, fake_scan_engine
):
    fake_scan_engine.result = engine_result(hosts=[engine_host(services=[
        engine_service(22, "ssh", "OpenSSH", "9.0"),
        engine_service(80, "http", "Apache", None),
        engine_service(8443, None, None, None),
    ])])

    _, scan_id = start_scan()
    result = client.get(f"/scans/{scan_id}/results").json()

    assert result["status"] == "completed"
    assert result["errors"] == []
    assert result["end_time"] is not None
    assert len(result["hosts"]) == 1
    assert result["hosts"][0]["host"] == "192.0.2.10"
    assert [
        (p["port"], p["protocol"], p["state"], p["service"], p["version"])
        for p in result["hosts"][0]["ports"]
    ] == [
        (22, "tcp", "open", "ssh", "OpenSSH 9.0"),
        (80, "tcp", "open", "http", "Apache"),
        (8443, "tcp", "open", None, None),
    ]


def test_reachable_host_with_no_open_ports(
    start_scan, client, fake_scan_engine
):
    fake_scan_engine.result = engine_result(hosts=[engine_host()])

    _, scan_id = start_scan()
    result = client.get(f"/scans/{scan_id}/results").json()
    status = client.get(f"/scans/{scan_id}/status").json()

    assert result["status"] == "completed"
    assert result["hosts"] == [{"host": "192.0.2.10", "ports": []}]
    assert status["message"] == "Scan completed: 0 open port(s) found."


def test_unreachable_host_completes_with_explanation(
    start_scan, client, fake_scan_engine
):
    fake_scan_engine.result = engine_result(
        hosts=[engine_host(state="unknown")]
    )

    _, scan_id = start_scan()
    result = client.get(f"/scans/{scan_id}/results").json()
    status = client.get(f"/scans/{scan_id}/status").json()

    assert result["status"] == "completed"
    assert result["hosts"] == [{"host": "192.0.2.10", "ports": []}]
    assert "did not respond" in result["errors"][0]
    assert "did not respond" in status["message"]


def test_convert_engine_result_preserves_scan_identity(
    scan_config_factory,
):
    start = datetime(2026, 10, 18, 12, 0, tzinfo=timezone.utc)
    end = datetime(2026, 10, 18, 12, 1, tzinfo=timezone.utc)

    result = convert_engine_result(
        scan_id="scan-abc",
        configuration=scan_config_factory(),
        engine_result=engine_result(hosts=[engine_host()]),
        start_time=start,
        end_time=end,
    )

    assert result.scan_id == "scan-abc"
    assert result.target == "192.0.2.10"
    assert (result.start_time, result.end_time) == (start, end)


# =========================================================
# Failure handling
# =========================================================


@pytest.mark.parametrize("raw_error,public_message", [
    (
        "Network error: [Errno 113] No route to host (/srv/internal)",
        scan_runner.NETWORK_ERROR_MESSAGE,
    ),
    (
        "Invalid target IP address: 192.0.2.10 (/srv/internal)",
        scan_runner.ENGINE_FAILURE_MESSAGE,
    ),
    (None, scan_runner.ENGINE_FAILURE_MESSAGE),
])
def test_engine_reported_failure_uses_controlled_message(
    start_scan, client, fake_scan_engine, caplog, raw_error, public_message
):
    fake_scan_engine.result = engine_result(status="failed", error=raw_error)

    _, scan_id = start_scan()
    result = client.get(f"/scans/{scan_id}/results")
    status = client.get(f"/scans/{scan_id}/status")

    assert result.json()["status"] == status.json()["status"] == "failed"
    assert result.json()["hosts"] == []
    # Same controlled message on both endpoints.
    assert result.json()["errors"] == [public_message]
    assert status.json()["message"] == public_message
    # Raw engine text never reaches clients but is logged for developers.
    for body in (result.text, status.text):
        assert "/srv/internal" not in body
        assert "Errno" not in body
    if raw_error:
        assert raw_error in caplog.text


def test_conversion_failure_still_ends_in_failed_state(
    start_scan, client, fake_scan_engine, caplog
):
    """
    If the engine returns data the backend contracts reject (port 0 here),
    the scan must still reach a final state instead of staying "running".
    """
    fake_scan_engine.result = engine_result(
        hosts=[engine_host(services=[engine_service(0, "bogus")])]
    )

    _, scan_id = start_scan()
    result = client.get(f"/scans/{scan_id}/results").json()
    status = client.get(f"/scans/{scan_id}/status").json()

    assert result["status"] == status["status"] == "failed"
    assert result["end_time"] is not None
    assert result["errors"] == [scan_runner.UNEXPECTED_ERROR_MESSAGE]
    assert "ValidationError" in caplog.text


class RecordingStatuses(dict):
    """Checks the final result is stored before the final status."""

    def __init__(self, results):
        super().__init__()
        self.results = results
        self.final_status_saw_result = None

    def __setitem__(self, scan_id, status):
        if status.status in {"completed", "failed"}:
            self.final_status_saw_result = self.results[scan_id].status
        super().__setitem__(scan_id, status)


@pytest.mark.parametrize("outcome", ["completed", "failed"])
def test_final_result_is_published_before_final_status(
    scan_config_factory, scan_result_factory, fake_scan_engine, outcome
):
    """
    The frontend loads results once status says the scan finished, so
    results must already be final by then.
    """
    if outcome == "failed":
        fake_scan_engine.error = RuntimeError("boom")
    results = {"scan-1": scan_result_factory("scan-1", status="queued")}
    statuses = RecordingStatuses(results)

    scan_runner.run_scan(
        "scan-1", scan_config_factory(), fake_scan_engine, results, statuses
    )

    assert statuses["scan-1"].status == outcome
    assert statuses.final_status_saw_result == outcome


def test_engine_exception_marks_scan_failed_without_leaking_details(
    start_scan, client, fake_scan_engine, caplog
):
    fake_scan_engine.error = RuntimeError(
        "secret internal detail at /srv/app/scan_engine/engine.py"
    )

    _, scan_id = start_scan()
    result = client.get(f"/scans/{scan_id}/results")
    status = client.get(f"/scans/{scan_id}/status")

    assert result.status_code == status.status_code == 200
    assert result.json()["status"] == status.json()["status"] == "failed"
    assert result.json()["errors"] == [
        scan_runner.UNEXPECTED_ERROR_MESSAGE
    ]
    for body in (result.text, status.text):
        assert "secret internal detail" not in body
        assert "Traceback" not in body
    # Developers still get the details in the server log.
    assert "secret internal detail" in caplog.text


def test_api_keeps_working_after_a_failed_scan(
    start_scan, client, fake_scan_engine
):
    fake_scan_engine.error = RuntimeError("boom")
    _, failed_id = start_scan()

    fake_scan_engine.error = None
    _, ok_id = start_scan()

    statuses = {
        scan_id: client.get(f"/scans/{scan_id}/status").json()["status"]
        for scan_id in (failed_id, ok_id)
    }
    assert statuses == {failed_id: "failed", ok_id: "completed"}
    assert len(client.get("/scans").json()) == 2


def test_get_scan_engine_returns_real_engine():
    from scan_engine.engine import ScanEngine

    assert isinstance(scan_runner.get_scan_engine(), ScanEngine)
