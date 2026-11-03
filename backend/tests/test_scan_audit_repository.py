import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from app.repository.scan_audit_repository import (
    ScanAuditEvent,
    ScanAuditRepository,
)


def test_allow_and_deny_decisions_are_both_retained(tmp_path):
    database = tmp_path / "scan_audit.sqlite3"
    now = datetime(2026, 11, 2, 23, 0, tzinfo=timezone.utc)

    ScanAuditRepository(database).record(ScanAuditEvent(
        now, "127.0.0.1", "tcp", "allow", "approved_target", "test-user",
    ))
    ScanAuditRepository(database).record(ScanAuditEvent(
        now, "127.0.0.1", "tcp", "deny", "approval_expired",
    ))

    with closing(sqlite3.connect(database)) as connection:
        rows = connection.execute("""
            SELECT occurred_at, target, scope, outcome, reason_code, requester_id
            FROM scan_authorization_events
            ORDER BY event_id
        """).fetchall()

    stamp = "2026-11-02T23:00:00.000000+00:00"
    assert rows == [
        (stamp, "127.0.0.1", "tcp", "allow", "approved_target", "test-user"),
        (stamp, "127.0.0.1", "tcp", "deny", "approval_expired", None),
    ]
