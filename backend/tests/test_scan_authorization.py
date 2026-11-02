"""Authorized-target control tests. All engine calls are mocked."""

import pytest

from app.routes import scans as scans_routes


def assert_blocked(client, payload, engine, expected):
    response = client.post("/scans", json=payload)
    assert response.status_code == expected, response.text
    assert engine.calls == []
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}


def test_approved_acknowledged_target_runs(
    client, scan_config_factory, fake_scan_engine, monkeypatch
):
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", "192.0.2.10")
    payload = scan_config_factory().model_dump(mode="json")

    response = client.post("/scans", json=payload)

    assert response.status_code == 201
    assert len(fake_scan_engine.calls) == 1
    assert fake_scan_engine.calls[0]["target"] == "192.0.2.10"


@pytest.mark.parametrize("ack", [False, None, "true", "false", 1, 0, [], {}])
def test_non_boolean_or_false_acknowledgement_is_blocked(
    client, scan_config_factory, fake_scan_engine, ack
):
    payload = scan_config_factory(
        options={"authorization_acknowledged": ack}
    ).model_dump(mode="json")
    assert_blocked(client, payload, fake_scan_engine, 403)


def test_missing_acknowledgement_is_blocked(
    client, scan_config_factory, fake_scan_engine
):
    payload = scan_config_factory(options={}).model_dump(mode="json")
    assert_blocked(client, payload, fake_scan_engine, 403)


def test_unapproved_target_is_blocked(
    client, scan_config_factory, fake_scan_engine, monkeypatch
):
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", "192.0.2.11")
    payload = scan_config_factory().model_dump(mode="json")
    assert_blocked(client, payload, fake_scan_engine, 403)


@pytest.mark.parametrize("approved", [
    "", " ", "not-an-ip", "192.0.2.10,bad",
    "192.0.2.10,", "2001:db8::1", "192.0.2.0/24",
])
def test_invalid_allowlist_blocks_scanning(
    client, scan_config_factory, fake_scan_engine, monkeypatch, approved
):
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", approved)
    payload = scan_config_factory().model_dump(mode="json")
    assert_blocked(client, payload, fake_scan_engine, 503)


def test_missing_allowlist_blocks_scanning(
    client, scan_config_factory, fake_scan_engine, monkeypatch
):
    monkeypatch.delenv("SCANNER_APPROVED_TARGETS", raising=False)
    payload = scan_config_factory().model_dump(mode="json")
    assert_blocked(client, payload, fake_scan_engine, 503)


def test_client_options_cannot_override_server_allowlist(
    client, scan_config_factory, fake_scan_engine, monkeypatch
):
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", "192.0.2.11")
    payload = scan_config_factory(options={
        "authorization_acknowledged": True,
        "approved_targets": ["192.0.2.10"],
    }).model_dump(mode="json")
    assert_blocked(client, payload, fake_scan_engine, 403)


def test_invalid_target_is_rejected_before_engine(
    client, scan_config_factory, fake_scan_engine
):
    payload = scan_config_factory().model_dump(mode="json")
    payload["target"] = "not-an-ip"
    assert_blocked(client, payload, fake_scan_engine, 422)


def test_allowlist_whitespace_and_multiple_entries(
    client, scan_config_factory, fake_scan_engine, monkeypatch
):
    monkeypatch.setenv(
        "SCANNER_APPROVED_TARGETS", " 192.0.2.11 , 192.0.2.10 "
    )
    payload = scan_config_factory(target=" 192.0.2.10 ").model_dump(mode="json")
    response = client.post("/scans", json=payload)
    assert response.status_code == 201
    assert fake_scan_engine.calls[0]["target"] == "192.0.2.10"
