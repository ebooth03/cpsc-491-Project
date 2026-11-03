"""Persistent records of who approved a scan target and for what scope."""

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timezone
from ipaddress import IPv4Address
from pathlib import Path


def utc_timestamp(value: datetime) -> str:
    if value.utcoffset() is None:
        raise ValueError("Approval timestamps must include a timezone.")
    return value.astimezone(timezone.utc).isoformat(timespec="microseconds")


@dataclass(frozen=True)
class TargetApproval:
    target: str
    approved_by: str
    scope: str
    expires_at: datetime


class TargetApprovalRepository:
    def __init__(self, database: Path):
        self.database = database
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS target_approvals (
                    target TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    PRIMARY KEY (target, scope)
                )
            """)

    def save(self, approval: TargetApproval) -> None:
        target = str(IPv4Address(approval.target))
        if not approval.approved_by.strip() or not approval.scope.strip():
            raise ValueError("Approver and scope are required.")
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("""
                INSERT INTO target_approvals (target, approved_by, scope, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT (target, scope) DO UPDATE SET
                    approved_by = excluded.approved_by,
                    expires_at = excluded.expires_at
            """, (target, approval.approved_by, approval.scope,
                  utc_timestamp(approval.expires_at)))

    def find_active(
        self, target: str, scope: str, now: datetime
    ) -> TargetApproval | None:
        with closing(sqlite3.connect(self.database)) as connection:
            row = connection.execute("""
                SELECT target, approved_by, scope, expires_at
                FROM target_approvals
                WHERE target = ? AND scope = ? AND expires_at > ?
            """, (str(IPv4Address(target)), scope, utc_timestamp(now))).fetchone()
        if row is None:
            return None
        return TargetApproval(row[0], row[1], row[2], datetime.fromisoformat(row[3]))
