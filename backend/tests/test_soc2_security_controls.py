
"""
KAN-106: SOC 2-aligned security control verification.

Covers input validation, resource limits, unsupported
scan options, and controlled API rejection.

All tests use the backend FakeScanEngine fixture.
No real network scanning is performed.
"""

import pytest

from app.routes import scans as scans_routes
from app.models.contracts import ScanConfiguration

pytestmark = pytest.mark.usefixtures(
    "approved_local_scan_target"
)



def valid_payload():
    """
    Return a valid scan request that satisfies
    the authorization acknowledgment requirement.
    """
    return {
        "target": "127.0.0.1",
        "target_type": "ip",
        "port_range": {"start": 1, "end": 10},
        "scan_type": "tcp",
        "scan_depth": "standard",
        "timeout": 5,
        "options": {
            "authorization_acknowledged": True
        },
    }



# --------------------------------------------------
# Input validation
# --------------------------------------------------

@pytest.mark.parametrize(
    "target",
    [
        "",
        "invalid-ip",
        "999.999.999.999",
        "::1",
        "localhost",
    ],
)
def test_invalid_targets_rejected_before_scanning(
    client, fake_scan_engine, target
):
    payload = valid_payload()
    payload["target"] = target

    response = client.post("/scans", json=payload)

    assert response.status_code == 422
    assert fake_scan_engine.calls == []


@pytest.mark.parametrize(
    "start,end",
    [
        (0, 80),
        (80, 65536),
        (100, 50),
        (-1, 80),
    ],
)
def test_invalid_port_ranges_rejected_before_scanning(
    client, fake_scan_engine, start, end
):
    payload = valid_payload()
    payload["port_range"] = {
        "start": start,
        "end": end,
    }

    response = client.post("/scans", json=payload)

    assert response.status_code == 422
    assert fake_scan_engine.calls == []


# --------------------------------------------------
# KAN-103: Maximum scan-size enforcement
# --------------------------------------------------

def test_maximum_scan_size_accepted(
    client, fake_scan_engine
):
    payload = valid_payload()
    payload["port_range"] = {
        "start": 1,
        "end": 1024,
    }

    response = client.post("/scans", json=payload)

    assert response.status_code == 201
    assert len(fake_scan_engine.calls) == 1


def test_excessive_scan_size_rejected(
    client, fake_scan_engine
):
    payload = valid_payload()
    payload["port_range"] = {
        "start": 1,
        "end": 1025,
    }

    response = client.post("/scans", json=payload)

    assert response.status_code == 422
    assert fake_scan_engine.calls == []


# --------------------------------------------------
# KAN-104: Supported scan options
# --------------------------------------------------

def test_empty_options_accepted():
    payload = valid_payload()
    payload["options"] = {}

    configuration = ScanConfiguration(**payload)

    assert configuration.options == {}


def test_unsupported_options_rejected(
    client, fake_scan_engine
):
    payload = valid_payload()
    payload["options"] = {
        "aggressive": True,
    }

    response = client.post("/scans", json=payload)

    assert response.status_code == 422
    assert fake_scan_engine.calls == []


# --------------------------------------------------
# KAN-105: Concurrent scan limits
# --------------------------------------------------

def test_concurrency_limit_rejects_excess_request(
    client, fake_scan_engine
):
    limiter = scans_routes.scan_limiter

    assert limiter.try_acquire("existing-1")
    assert limiter.try_acquire("existing-2")

    response = client.post(
        "/scans",
        json=valid_payload(),
    )

    assert response.status_code == 429
    assert fake_scan_engine.calls == []
    assert limiter.active_count == 2


# --------------------------------------------------
# Controlled API error handling
# --------------------------------------------------

def test_invalid_request_does_not_create_scan(
    client, fake_scan_engine
):
    payload = valid_payload()
    payload["target"] = "invalid-ip"

    response = client.post("/scans", json=payload)

    assert response.status_code == 422
    assert fake_scan_engine.calls == []
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}


def test_rejected_concurrency_request_does_not_create_scan(
    client, fake_scan_engine
):
    limiter = scans_routes.scan_limiter

    limiter.try_acquire("existing-1")
    limiter.try_acquire("existing-2")

    response = client.post(
        "/scans",
        json=valid_payload(),
    )

    assert response.status_code == 429
    assert fake_scan_engine.calls == []
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}



def test_unauthorized_target_does_not_consume_capacity(
    client, fake_scan_engine
):
    """
    KAN-106: Unauthorized requests must be rejected
    before reserving scan concurrency capacity.
    """

    limiter = scans_routes.scan_limiter

    payload = valid_payload()
    payload["target"] = "192.0.2.10"

    response = client.post("/scans", json=payload)

    assert response.status_code == 403
    assert limiter.active_count == 0
    assert fake_scan_engine.calls == []
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}
