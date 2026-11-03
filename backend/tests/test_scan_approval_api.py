import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta, timezone

from app.repository.target_approval_repository import (
    TargetApproval,
    TargetApprovalRepository,
)


def test_scan_requires_active_approval_and_records_both_decisions(
    client, scan_config_factory, fake_scan_engine, monkeypatch, tmp_path
):
    database = tmp_path / "authorization.sqlite3"
    payload = scan_config_factory().model_dump(mode="json")
    target = payload["target"]
    scope = payload["scan_type"]
    payload["options"] = {"authorization_acknowledged": True}
    monkeypatch.setenv("SCANNER_AUTHORIZATION_DB", str(database))
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", target)
    token = "test-audit-token"
    digest = hashlib.sha256(token.encode()).hexdigest()
    monkeypatch.setenv("SCANNER_AUTH_PRINCIPALS", json.dumps({
        digest: {"id": "audit-test-operator", "can_scan": True},
    }))
    headers = {"Authorization": f"Bearer {token}"}
    approvals = TargetApprovalRepository(database)
    now = datetime.now(timezone.utc)

    approvals.save(TargetApproval(
        target, "test-admin", scope, now - timedelta(hours=1)
    ))
    response = client.post("/scans", json=payload, headers=headers)
    assert response.status_code == 403, response.text
    assert fake_scan_engine.calls == []
    assert client.get("/scans").json() == []

    approvals.save(TargetApproval(
        target, "test-admin", scope, now + timedelta(hours=1)
    ))
    response = client.post("/scans", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    assert len(fake_scan_engine.calls) == 1

    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute("""
            SELECT target, scope, outcome, reason_code, requester_id
            FROM scan_authorization_events
            ORDER BY event_id
        """).fetchall()

    assert rows == [
        (target, scope, "deny", "no_active_target_approval", "audit-test-operator"),
        (target, scope, "allow", "active_target_approval", "audit-test-operator"),
    ]
