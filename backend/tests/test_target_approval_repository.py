from datetime import datetime, timedelta, timezone

from app.repository.target_approval_repository import (
    TargetApproval,
    TargetApprovalRepository,
)


def test_approval_persists_and_is_only_active_for_its_scope(tmp_path):
    database = tmp_path / "approvals.sqlite3"
    now = datetime(2026, 11, 2, tzinfo=timezone.utc)
    expiry = now + timedelta(hours=1)
    approval = TargetApproval("127.0.0.1", "test-admin", "tcp", expiry)

    TargetApprovalRepository(database).save(approval)
    reopened = TargetApprovalRepository(database)

    assert reopened.find_active("127.0.0.1", "tcp", now) == approval
    assert reopened.find_active("127.0.0.1", "udp", now) is None
    assert reopened.find_active("127.0.0.2", "tcp", now) is None
    assert reopened.find_active("127.0.0.1", "tcp", expiry) is None
    assert reopened.find_active(
        "127.0.0.1", "tcp", expiry + timedelta(seconds=1)
    ) is None
