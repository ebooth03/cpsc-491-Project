"""
Automated CI tests for the network scanning functionality (KAN-47).

These tests check scanner behavior and error handling without relying on
external network targets, so they run the same way on a developer laptop
and in a clean GitHub Actions runner.

Two strategies are used:

1. Mocked sockets: socket.socket is replaced with a fake so each test
   controls exactly what a "connection" returns (open, closed, error).
   No real network traffic happens.

2. Local loopback listeners: a test opens a real TCP listener on
   127.0.0.1 using an OS-assigned free port, then scans it. The test
   owns both ends of the connection, so the result is deterministic.
"""

import errno
import socket
from unittest.mock import MagicMock, patch

import pytest

from scan_engine.engine import ScanEngine
from scan_engine.host_discovery import discover_host
from scan_engine.tcp_scanner import scan_tcp_port, scan_tcp_range
from scanner.scanner import Scanner


LOOPBACK = "127.0.0.1"
FAST_TIMEOUT = 0.2


# =========================================================
# Helpers
# =========================================================


def make_fake_socket(connect_results):
    """
    Build a replacement for socket.socket.

    connect_results maps port -> value returned by connect_ex,
    or an exception instance to raise. Ports not listed are
    treated as closed (ECONNREFUSED).

    Returns (factory, created) where created is a list of every
    fake socket made, so tests can inspect calls like settimeout.
    """

    created = []

    def factory(*args, **kwargs):
        sock = MagicMock()
        sock.__enter__.return_value = sock
        sock.__exit__.return_value = False

        def connect_ex(address):
            _host, port = address
            outcome = connect_results.get(port, errno.ECONNREFUSED)
            if isinstance(outcome, BaseException):
                raise outcome
            return outcome

        sock.connect_ex.side_effect = connect_ex
        created.append(sock)
        return sock

    return factory, created


@pytest.fixture
def open_local_port():
    """Start a real TCP listener on loopback and yield its port."""

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LOOPBACK, 0))
    server.listen(5)

    yield server.getsockname()[1]

    server.close()


@pytest.fixture
def closed_local_port():
    """
    Return a loopback port with nothing listening on it.

    The OS hands out a free port, then the socket is closed
    without ever calling listen(), so connections are refused.
    """

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind((LOOPBACK, 0))
    port = probe.getsockname()[1]
    probe.close()

    return port


# =========================================================
# scan_tcp_port: mocked sockets
# =========================================================


class TestScanTcpPortMocked:

    def test_returns_true_when_connection_succeeds(self):
        factory, _ = make_fake_socket({80: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_port("10.0.0.5", 80) is True

    def test_returns_false_when_connection_refused(self):
        factory, _ = make_fake_socket({80: errno.ECONNREFUSED})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_port("10.0.0.5", 80) is False

    def test_returns_false_on_unreachable_host_code(self):
        factory, _ = make_fake_socket({80: errno.EHOSTUNREACH})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_port("10.0.0.5", 80) is False

    def test_returns_false_when_socket_raises_oserror(self):
        factory, _ = make_fake_socket({80: OSError("network is down")})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_port("10.0.0.5", 80) is False

    def test_returns_false_when_socket_times_out(self):
        factory, _ = make_fake_socket({80: socket.timeout("timed out")})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_port("10.0.0.5", 80) is False

    def test_returns_false_when_socket_cannot_be_created(self):
        with patch(
            "scan_engine.tcp_scanner.socket.socket",
            side_effect=OSError("too many open files"),
        ):
            assert scan_tcp_port("10.0.0.5", 80) is False

    def test_applies_requested_timeout(self):
        factory, created = make_fake_socket({443: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            scan_tcp_port("10.0.0.5", 443, timeout=1.25)

        created[0].settimeout.assert_called_once_with(1.25)

    def test_uses_default_timeout_when_not_given(self):
        factory, created = make_fake_socket({443: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            scan_tcp_port("10.0.0.5", 443)

        created[0].settimeout.assert_called_once_with(0.5)

    def test_connects_to_requested_target_and_port(self):
        factory, created = make_fake_socket({8080: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            scan_tcp_port("10.0.0.5", 8080)

        created[0].connect_ex.assert_called_once_with(("10.0.0.5", 8080))


# =========================================================
# scan_tcp_range: mocked sockets
# =========================================================


class TestScanTcpRangeMocked:

    def test_returns_only_open_ports(self):
        factory, _ = make_fake_socket({20: 0, 22: 0, 25: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_range("10.0.0.5", 20, 25) == [20, 22, 25]

    def test_range_is_inclusive_of_both_ends(self):
        factory, created = make_fake_socket({})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            scan_tcp_range("10.0.0.5", 100, 104)

        probed = [s.connect_ex.call_args.args[0][1] for s in created]

        assert probed == [100, 101, 102, 103, 104]

    def test_single_port_range(self):
        factory, created = make_fake_socket({443: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_range("10.0.0.5", 443, 443) == [443]

        assert len(created) == 1

    def test_returns_empty_list_when_all_closed(self):
        factory, _ = make_fake_socket({})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_range("10.0.0.5", 1, 50) == []

    def test_continues_after_error_on_one_port(self):
        factory, _ = make_fake_socket({
            21: OSError("connection reset"),
            22: 0,
        })

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_range("10.0.0.5", 21, 23) == [22]

    def test_passes_timeout_to_every_probe(self):
        factory, created = make_fake_socket({})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            scan_tcp_range("10.0.0.5", 1, 3, timeout=0.75)

        for sock in created:
            sock.settimeout.assert_called_once_with(0.75)

    def test_reversed_range_scans_nothing(self):
        factory, created = make_fake_socket({})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_range("10.0.0.5", 100, 50) == []

        assert created == []

    def test_open_ports_returned_in_ascending_order(self):
        factory, _ = make_fake_socket({5: 0, 2: 0, 9: 0})

        with patch("scan_engine.tcp_scanner.socket.socket", factory):
            assert scan_tcp_range("10.0.0.5", 1, 10) == [2, 5, 9]


# =========================================================
# discover_host: mocked sockets
# =========================================================


class TestDiscoverHostMocked:

    def test_reachable_when_ssh_responds(self):
        factory, _ = make_fake_socket({22: 0})

        with patch("scan_engine.host_discovery.socket.socket", factory):
            assert discover_host("10.0.0.5") == "reachable"

    def test_reachable_when_only_https_responds(self):
        factory, _ = make_fake_socket({443: 0})

        with patch("scan_engine.host_discovery.socket.socket", factory):
            assert discover_host("10.0.0.5") == "reachable"

    def test_unknown_when_no_probe_port_responds(self):
        factory, _ = make_fake_socket({})

        with patch("scan_engine.host_discovery.socket.socket", factory):
            assert discover_host("10.0.0.5") == "unknown"

    def test_probes_22_80_443_in_order(self):
        factory, created = make_fake_socket({})

        with patch("scan_engine.host_discovery.socket.socket", factory):
            discover_host("10.0.0.5")

        probed = [s.connect_ex.call_args.args[0][1] for s in created]

        assert probed == [22, 80, 443]

    def test_stops_probing_after_first_success(self):
        factory, created = make_fake_socket({80: 0})

        with patch("scan_engine.host_discovery.socket.socket", factory):
            assert discover_host("10.0.0.5") == "reachable"

        probed = [s.connect_ex.call_args.args[0][1] for s in created]

        assert probed == [22, 80]

    def test_oserror_on_one_probe_does_not_stop_discovery(self):
        factory, _ = make_fake_socket({
            22: OSError("network is down"),
            80: 0,
        })

        with patch("scan_engine.host_discovery.socket.socket", factory):
            assert discover_host("10.0.0.5") == "reachable"

    def test_unknown_when_every_probe_raises(self):
        factory, _ = make_fake_socket({
            22: OSError("err"),
            80: OSError("err"),
            443: OSError("err"),
        })

        with patch("scan_engine.host_discovery.socket.socket", factory):
            assert discover_host("10.0.0.5") == "unknown"

    def test_applies_requested_timeout(self):
        factory, created = make_fake_socket({})

        with patch("scan_engine.host_discovery.socket.socket", factory):
            discover_host("10.0.0.5", timeout=2.0)

        for sock in created:
            sock.settimeout.assert_called_once_with(2.0)


# =========================================================
# Real loopback sockets (no external network)
# =========================================================


class TestLoopbackScanning:

    def test_detects_listening_port_as_open(self, open_local_port):
        assert scan_tcp_port(LOOPBACK, open_local_port, FAST_TIMEOUT) is True

    def test_detects_non_listening_port_as_closed(self, closed_local_port):
        assert scan_tcp_port(LOOPBACK, closed_local_port, FAST_TIMEOUT) is False

    def test_range_finds_listening_port(self, open_local_port):
        open_ports = scan_tcp_range(
            LOOPBACK,
            open_local_port,
            open_local_port,
            FAST_TIMEOUT,
        )

        assert open_ports == [open_local_port]

    def test_port_reported_closed_after_listener_stops(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind((LOOPBACK, 0))
        server.listen(1)
        port = server.getsockname()[1]

        assert scan_tcp_port(LOOPBACK, port, FAST_TIMEOUT) is True

        server.close()

        assert scan_tcp_port(LOOPBACK, port, FAST_TIMEOUT) is False

    def test_scanner_class_reports_open_and_closed(
        self,
        open_local_port,
        closed_local_port,
    ):
        results = Scanner().scan(
            LOOPBACK,
            [open_local_port, closed_local_port],
        )

        states = {r["port"]: r["state"] for r in results}

        assert states[open_local_port] == "open"
        assert states[closed_local_port] == "closed"

    def test_unresolvable_hostname_reported_closed(self):
        # .invalid is reserved (RFC 2606) and never resolves, so this
        # exercises the error path without touching a real host.
        assert scan_tcp_port("scanner-test.invalid", 80, FAST_TIMEOUT) is False


# =========================================================
# ScanEngine end to end against loopback
# =========================================================


class TestScanEngineLoopback:

    @patch("scan_engine.engine.discover_host", return_value="reachable")
    def test_engine_finds_listening_port_and_labels_service(
        self,
        _mock_discover,
        open_local_port,
    ):
        result = ScanEngine().scan(
            target=LOOPBACK,
            start_port=open_local_port,
            end_port=open_local_port,
            timeout=FAST_TIMEOUT,
        )

        assert result.status == "completed"
        assert result.error is None
        assert len(result.hosts) == 1

        host = result.hosts[0]

        assert host.address == LOOPBACK
        assert host.state == "reachable"
        assert [s.port for s in host.services] == [open_local_port]
        assert host.services[0].state == "open"
        assert host.services[0].protocol == "tcp"

    @patch("scan_engine.engine.discover_host", return_value="reachable")
    def test_engine_reports_no_services_when_port_closed(
        self,
        _mock_discover,
        closed_local_port,
    ):
        result = ScanEngine().scan(
            target=LOOPBACK,
            start_port=closed_local_port,
            end_port=closed_local_port,
            timeout=FAST_TIMEOUT,
        )

        assert result.status == "completed"
        assert result.hosts[0].services == []


# =========================================================
# ScanEngine error handling
# =========================================================


class TestScanEngineErrorHandling:

    @patch("scan_engine.engine.discover_host", side_effect=OSError("no route"))
    def test_network_error_in_discovery_returns_failed(self, _mock):
        result = ScanEngine().scan("10.0.0.5", 1, 10, timeout=FAST_TIMEOUT)

        assert result.status == "failed"
        assert result.error.startswith("Network error:")
        assert "no route" in result.error
        assert result.hosts == []

    @patch("scan_engine.engine.scan_tcp_range", side_effect=OSError("reset"))
    @patch("scan_engine.engine.discover_host", return_value="reachable")
    def test_network_error_during_port_scan_returns_failed(self, _d, _s):
        result = ScanEngine().scan("10.0.0.5", 1, 10, timeout=FAST_TIMEOUT)

        assert result.status == "failed"
        assert "Network error" in result.error
        assert result.hosts == []

    @patch("scan_engine.engine.scan_tcp_range")
    @patch("scan_engine.engine.discover_host")
    def test_invalid_config_never_touches_network(self, mock_discover, mock_scan):
        result = ScanEngine().scan("10.0.0.5", 1, 10, timeout=0)

        assert result.status == "failed"
        mock_discover.assert_not_called()
        mock_scan.assert_not_called()

    @patch("scan_engine.engine.scan_tcp_range")
    @patch("scan_engine.engine.discover_host", return_value="unknown")
    def test_unreachable_host_skips_port_scan(self, _mock_discover, mock_scan):
        result = ScanEngine().scan("10.0.0.5", 1, 10, timeout=FAST_TIMEOUT)

        assert result.status == "completed"
        assert result.hosts[0].state == "unknown"
        mock_scan.assert_not_called()

    @pytest.mark.parametrize("target", [
        "localhost",
        "example.com",
        "10.0.0",
        "::1",
        "",
    ])
    def test_non_ipv4_targets_fail_validation(self, target):
        result = ScanEngine().scan(target, 1, 10, timeout=FAST_TIMEOUT)

        assert result.status == "failed"
        assert result.error is not None
