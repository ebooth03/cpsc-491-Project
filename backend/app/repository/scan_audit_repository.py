"""Persist scan authorization decisions."""

import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address
from pathlib import Path
from typing import Literal

from app.repository.target_approval_repository import utc_timestamp


@dataclass(frozen=True)
class ScanAuditEvent:
    occurred_at: datetime
    target: str
    scope: str
    outcome: Literal["allow", "deny"]
    reason_code: str
    requester_id: str | None = None


class ScanAuditRepository:
    def __init__(self, database: Path):
        self.database = database
        with closing(sqlite3.connect(database)) as connection, connection:
            connection.execute("""
                CREATE TABLE IF NOT EXISTS scan_authorization_events (
                    event_id INTEGER PRIMARY KEY,
                    occurred_at TEXT NOT NULL,
                    target TEXT NOT NULL,
                    scope TEXT NOT NULL,
                    outcome TEXT NOT NULL CHECK (outcome IN ('allow', 'deny')),
                    reason_code TEXT NOT NULL,
                    requester_id TEXT
                )
            """)

    def record(self, event: ScanAuditEvent) -> None:
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("""
                INSERT INTO scan_authorization_events
                    (occurred_at, target, scope, outcome, reason_code, requester_id)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                utc_timestamp(event.occurred_at),
                str(IPv4Address(event.target)),
                event.scope,
                event.outcome,
                event.reason_code,
                event.requester_id,
            ))
