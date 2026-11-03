
"""
KAN-105: Concurrent scan limit security tests.

Tests use a fake scan engine and do not initiate
real network scanning.
"""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock, Thread

import pytest

from app.routes import scans as scans_routes
from app.services.scan_limiter import ScanLimiter


def valid_payload():
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
# Limiter unit tests
# --------------------------------------------------

def test_limiter_accepts_two_reservations():
    limiter = ScanLimiter(max_scans=2)

    assert limiter.try_acquire("scan-1") is True
    assert limiter.try_acquire("scan-2") is True
    assert limiter.active_count == 2


def test_limiter_rejects_third_reservation():
    limiter = ScanLimiter(max_scans=2)

    assert limiter.try_acquire("scan-1") is True
    assert limiter.try_acquire("scan-2") is True
    assert limiter.try_acquire("scan-3") is False
    assert limiter.active_count == 2


def test_release_restores_capacity():
    limiter = ScanLimiter(max_scans=2)

    limiter.try_acquire("scan-1")
    limiter.try_acquire("scan-2")

    limiter.release("scan-1")

    assert limiter.active_count == 1
    assert limiter.try_acquire("scan-3") is True


def test_duplicate_reservation_is_rejected():
    limiter = ScanLimiter(max_scans=2)

    assert limiter.try_acquire("scan-1") is True
    assert limiter.try_acquire("scan-1") is False
    assert limiter.active_count == 1


def test_release_unknown_scan_is_safe():
    limiter = ScanLimiter(max_scans=2)

    limiter.release("nonexistent-scan")

    assert limiter.active_count == 0


def test_invalid_limit_rejected():
    with pytest.raises(ValueError):
        ScanLimiter(max_scans=0)


def test_simultaneous_reservations_never_exceed_limit():
    limiter = ScanLimiter(max_scans=2)
    barrier = Barrier(5)
    results = []

    def reserve(index):
        barrier.wait()
        results.append(
            limiter.try_acquire(f"scan-{index}")
        )

    threads = [
        Thread(target=reserve, args=(i,))
        for i in range(5)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert results.count(True) == 2
    assert results.count(False) == 3
    assert limiter.active_count == 2


# --------------------------------------------------
# API admission-control tests
# --------------------------------------------------

def test_api_rejects_request_when_limit_reached(client):
    limiter = scans_routes.scan_limiter

    assert limiter.try_acquire("existing-1")
    assert limiter.try_acquire("existing-2")

    response = client.post("/scans", json=valid_payload())

    assert response.status_code == 429
    assert response.json()["detail"] == (
        "Maximum concurrent scan limit reached."
    )
    assert limiter.active_count == 2


def test_rejected_request_does_not_invoke_engine(
    client, fake_scan_engine
):
    limiter = scans_routes.scan_limiter

    limiter.try_acquire("existing-1")
    limiter.try_acquire("existing-2")

    response = client.post("/scans", json=valid_payload())

    assert response.status_code == 429
    assert fake_scan_engine.calls == []
    assert scans_routes.SCAN_RESULTS == {}
    assert scans_routes.SCAN_STATUSES == {}


def test_invalid_request_does_not_consume_capacity(client):
    limiter = scans_routes.scan_limiter

    payload = valid_payload()
    payload["options"] = {"unsupported": True}

    response = client.post("/scans", json=payload)

    assert response.status_code == 422
    assert limiter.active_count == 0


def test_completed_scan_releases_reservation(client):
    limiter = scans_routes.scan_limiter

    response = client.post("/scans", json=valid_payload())

    assert response.status_code == 201
    assert limiter.active_count == 0


def test_failed_scan_releases_reservation(
    client, fake_scan_engine
):
    limiter = scans_routes.scan_limiter
    fake_scan_engine.error = RuntimeError("simulated failure")

    response = client.post("/scans", json=valid_payload())

    assert response.status_code == 201
    assert limiter.active_count == 0

    scan_id = response.json()["scan_id"]
    status = client.get(f"/scans/{scan_id}/status")

    assert status.json()["status"] == "failed"


def test_three_overlapping_requests_enforce_limit(
    client, fake_scan_engine
):
    """
    KAN-105: Verify that two overlapping scans are accepted
    and a third request is rejected with HTTP 429.

    The fake engine is held using synchronization events.
    No real network connections are made.
    """

    limiter = scans_routes.scan_limiter

    # Signals when both accepted scans have started.
    both_started = Event()

    # Prevents the accepted scans from finishing early.
    release_scans = Event()

    # Protects the shared counter.
    counter_lock = Lock()
    started_count = 0

    def hold_scan():
        nonlocal started_count

        with counter_lock:
            started_count += 1

            if started_count == 2:
                both_started.set()

        # Wait until the test allows scans to finish.
        if not release_scans.wait(timeout=10):
            raise TimeoutError(
                "Timed out waiting to release fake scans."
            )

    fake_scan_engine.on_scan = hold_scan

    def submit_scan():
        return client.post(
            "/scans",
            json=valid_payload(),
        )

    with ThreadPoolExecutor(max_workers=3) as executor:
        first = executor.submit(submit_scan)
        second = executor.submit(submit_scan)

        try:
            # Wait until both fake scans are executing.
            assert both_started.wait(timeout=5), (
                "Two scans did not start within the timeout."
            )

            # Both reservations must still be occupied.
            assert limiter.active_count == 2

            # A third overlapping request must be rejected.
            third_response = submit_scan()

            assert third_response.status_code == 429
            assert third_response.json()["detail"] == (
                "Maximum concurrent scan limit reached."
            )

            # Rejected requests must not invoke the engine.
            assert len(fake_scan_engine.calls) == 2

            # Only two accepted scans should be recorded.
            assert len(scans_routes.SCAN_RESULTS) == 2

        finally:
            # Always release the fake scans, even if an
            # assertion fails, preventing test deadlocks.
            release_scans.set()

        first_response = first.result(timeout=10)
        second_response = second.result(timeout=10)

    # The first two requests must have been accepted.
    assert first_response.status_code == 201
    assert second_response.status_code == 201

    # Completed scans must release their reservations.
    assert limiter.active_count == 0

    # Exactly two scans must have executed.
    assert len(fake_scan_engine.calls) == 2

    # Both accepted scans should have completed.
    for response in (first_response, second_response):
        scan_id = response.json()["scan_id"]

        status_response = client.get(
            f"/scans/{scan_id}/status"
        )

        assert status_response.status_code == 200
        assert status_response.json()["status"] == "completed"
