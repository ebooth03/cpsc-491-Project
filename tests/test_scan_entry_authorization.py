from unittest.mock import Mock

import pytest

from scan_engine.authorization import ScanAuthorizationError
from scan_engine.engine import ScanEngine
from scanner.scanner import Scanner


@pytest.mark.parametrize(
    ("target", "acknowledged", "reason"),
    [
        ("127.0.0.1", False, "acknowledgement is required"),
        ("127.0.0.2", True, "Target is not approved"),
    ],
)
def test_direct_scan_calls_block_denied_requests_before_network(
    monkeypatch, target, acknowledged, reason
):
    monkeypatch.setenv("SCANNER_APPROVED_TARGETS", "127.0.0.1")
    discovery = Mock()
    tcp_scan = Mock()
    monkeypatch.setattr("scan_engine.engine.discover_host", discovery)
    monkeypatch.setattr("scanner.scanner.scan_tcp_port", tcp_scan)

    result = ScanEngine().scan(
        target=target, start_port=80, end_port=80,
        authorization_acknowledged=acknowledged,
    )
    assert result.status == "failed"
    assert reason in result.error
    discovery.assert_not_called()

    with pytest.raises(ScanAuthorizationError, match=reason):
        Scanner().scan(target, [80], authorization_acknowledged=acknowledged)
    tcp_scan.assert_not_called()
