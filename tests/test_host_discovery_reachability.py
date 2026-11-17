"""Discovery regression tests using mocked sockets; no network traffic."""

import errno
from unittest.mock import MagicMock, patch

import pytest

from scan_engine.host_discovery import discover_host


@pytest.mark.parametrize(
    "connection_result, expected",
    [
        (0, "reachable"),
        (errno.ECONNREFUSED, "reachable"),
        (errno.ETIMEDOUT, "unknown"),
        (errno.EHOSTUNREACH, "unknown"),
    ],
    ids=["open", "refused", "timeout", "unreachable"],
)
def test_discovery_distinguishes_response_from_no_response(
    connection_result, expected
):
    fake_socket = MagicMock()
    fake_socket.__enter__.return_value = fake_socket
    fake_socket.connect_ex.return_value = connection_result

    with patch(
        "scan_engine.host_discovery.socket.socket",
        return_value=fake_socket,
    ):
        assert discover_host("127.0.0.1") == expected
