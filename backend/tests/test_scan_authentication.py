import hashlib
import json

import pytest


@pytest.fixture
def scan_principals(monkeypatch):
    principals = {
        hashlib.sha256(b"test-operator-token").hexdigest(): {
            "id": "operator",
            "can_scan": True,
        },
        hashlib.sha256(b"test-viewer-token").hexdigest(): {
            "id": "viewer",
            "can_scan": False,
        },
    }
    monkeypatch.setenv("SCANNER_AUTH_PRINCIPALS", json.dumps(principals))


@pytest.mark.parametrize(
    ("authorization", "expected"),
    [
        (None, 401),
        ("Bearer wrong-token", 401),
        ("Basic test-operator-token", 401),
        ("Bearer test-viewer-token", 403),
    ],
)
def test_rejected_requester_never_starts_scan(
    client, scan_config_factory, fake_scan_engine, scan_principals,
    authorization, expected,
):
    payload = scan_config_factory().model_dump(mode="json")
    headers = {} if authorization is None else {"Authorization": authorization}

    response = client.post("/scans", json=payload, headers=headers)

    assert response.status_code == expected, response.text
    if expected == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"
    assert fake_scan_engine.calls == []
    assert client.get("/scans").json() == []


def test_permitted_requester_still_needs_approved_target(
    client, scan_config_factory, fake_scan_engine, scan_principals, monkeypatch,
):
    payload = scan_config_factory().model_dump(mode="json")
    headers = {"Authorization": "Bearer test-operator-token"}

    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", "127.0.0.2")
    denied = client.post("/scans", json=payload, headers=headers)
    assert denied.status_code == 403, denied.text
    assert fake_scan_engine.calls == []
    assert client.get("/scans").json() == []

    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", payload["target"])
    allowed = client.post("/scans", json=payload, headers=headers)
    assert allowed.status_code == 201, allowed.text
    assert len(fake_scan_engine.calls) == 1


@pytest.mark.parametrize("configuration", ["", "not-json", "{}"])
def test_bad_authentication_configuration_blocks_scans(
    client, scan_config_factory, fake_scan_engine, monkeypatch, configuration,
):
    monkeypatch.setenv("SCANNER_AUTH_PRINCIPALS", configuration)
    response = client.post(
        "/scans",
        json=scan_config_factory().model_dump(mode="json"),
        headers={"Authorization": "Bearer test-operator-token"},
    )

    assert response.status_code == 503, response.text
    assert fake_scan_engine.calls == []
    assert client.get("/scans").json() == []
