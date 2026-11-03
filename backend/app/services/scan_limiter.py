
"""
KAN-105: Thread-safe, process-local scan concurrency limiter.

A reservation is held from scan admission until execution
finishes, including queued and running states.
"""

import os
from threading import Lock


MAX_CONCURRENT_SCANS = int(
    os.getenv("MAX_CONCURRENT_SCANS", "2")
)

if MAX_CONCURRENT_SCANS < 1:
    raise ValueError(
        "MAX_CONCURRENT_SCANS must be at least 1."
    )


class ScanLimiter:
    def __init__(self, max_scans: int = MAX_CONCURRENT_SCANS):
        if max_scans < 1:
            raise ValueError("max_scans must be at least 1.")

        self.max_scans = max_scans
        self._active_ids: set[str] = set()
        self._lock = Lock()

    def try_acquire(self, scan_id: str) -> bool:
        """Atomically reserve capacity for a scan."""
        with self._lock:
            if scan_id in self._active_ids:
                return False

            if len(self._active_ids) >= self.max_scans:
                return False

            self._active_ids.add(scan_id)
            return True

    def release(self, scan_id: str) -> None:
        """Release a scan reservation safely."""
        with self._lock:
            self._active_ids.discard(scan_id)

    @property
    def active_count(self) -> int:
        with self._lock:
            return len(self._active_ids)


scan_limiter = ScanLimiter()
