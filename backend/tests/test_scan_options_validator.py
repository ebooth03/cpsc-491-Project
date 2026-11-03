
"""
KAN-104: Validate Supported Scan Options.

Verify that empty or omitted scan options are accepted
and unsupported options are rejected before scanning.
"""

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.models.contracts import ScanConfiguration


def valid_scan_payload():
    return {
        "target": "127.0.0.1",
        "target_type": "ip",
        "port_range": {"start": 1, "end": 10},
        "scan_type": "tcp",
        "scan_depth": "standard",
        "timeout": 5,
        "options": {},
    }


# --------------------------------------------------
# Model Validation Tests
# --------------------------------------------------

def test_empty_options_accepted():
    config = ScanConfiguration(**valid_scan_payload())
    assert config.options == {}


def test_omitted_options_default_to_empty():
    payload = valid_scan_payload()
    del payload["options"]

    config = ScanConfiguration(**payload)

    assert config.options == {}


def test_unknown_option_rejected():
    payload = valid_scan_payload()
    payload["options"] = {"unknown_option": True}

    with pytest.raises(
        ValidationError,
        match="Unsupported scan options"
    ):
        ScanConfiguration(**payload)


@pytest.mark.parametrize(
    "unsupported_options",
    [
        {"aggressive": True},
        {"timeout_override": 100},
        {"scan_all_ports": True},
        {"unknown_option": "value"},
    ],
)
def test_unsupported_options_rejected(unsupported_options):
    payload = valid_scan_payload()
    payload["options"] = unsupported_options

    with pytest.raises(
        ValidationError,
        match="Unsupported scan options"
    ):
        ScanConfiguration(**payload)


# --------------------------------------------------
# API Validation Tests
# --------------------------------------------------

def test_api_rejects_unsupported_options():
    payload = valid_scan_payload()
    payload["options"] = {"unknown_option": True}

    with TestClient(app) as client:
        response = client.post("/scans", json=payload)

    assert response.status_code == 422


def test_api_rejects_empty_options_without_acknowledgement():
    payload = valid_scan_payload()

    with TestClient(app) as client:
        response = client.post("/scans", json=payload)

    assert response.status_code == 403, response.text


def test_unsupported_options_never_reach_scan_engine(
    client, fake_scan_engine
):
    """
    KAN-104: Verify unsupported scan options are rejected
    before the scan engine executes.
    """

    payload = valid_scan_payload()

    # Submit an unsupported scan option.
    payload["options"] = {
        "aggressive": True
    }

    # Send the invalid request to the backend API.
    response = client.post("/scans", json=payload)

    # The backend must reject the request.
    assert response.status_code == 422

    # The scan engine must never be invoked.
    assert fake_scan_engine.calls == []


def test_authorized_options_allow_scan_engine_execution(
    client, fake_scan_engine, monkeypatch
):
    """
    KAN-104: Verify valid scan requests continue
    to reach the scan engine.
    """

    payload = valid_scan_payload()
    payload["options"] = {"authorization_acknowledged": True}
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", payload["target"])

    response = client.post("/scans", json=payload)

    # A valid scan request should be accepted.
    assert response.status_code == 201, response.text

    # The fake scan engine should execute exactly once.
    assert len(fake_scan_engine.calls) == 1

    # Verify the expected scan configuration.
    assert fake_scan_engine.calls[0]["target"] == "127.0.0.1"
    assert fake_scan_engine.calls[0]["start_port"] == 1
    assert fake_scan_engine.calls[0]["end_port"] == 10
