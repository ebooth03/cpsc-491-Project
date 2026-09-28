from unittest.mock import patch

from scan_engine.engine import ScanEngine


def test_scan_returns_failed_for_invalid_target():
    engine = ScanEngine()

    result = engine.scan(
        target="999.999.1.1",
        start_port=1,
        end_port=100,
        timeout=0.5,
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.hosts == []


def test_scan_returns_failed_for_invalid_port_range():
    engine = ScanEngine()

    result = engine.scan(
        target="127.0.0.1",
        start_port=1000,
        end_port=500,
        timeout=0.5,
    )

    assert result.status == "failed"
    assert result.error is not None
    assert result.hosts == []


@patch("scan_engine.engine.discover_host")
def test_scan_returns_unknown_host_when_not_reachable(
    mock_discover_host
):
    mock_discover_host.return_value = "unknown"

    engine = ScanEngine()

    result = engine.scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
        timeout=0.5,
    )

    assert result.status == "completed"
    assert len(result.hosts) == 1
    assert result.hosts[0].address == "127.0.0.1"
    assert result.hosts[0].state == "unknown"
    assert result.hosts[0].services == []


@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_scan_returns_reachable_host_with_no_open_ports(
    mock_discover_host,
    mock_scan_tcp_range,
):
    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.return_value = []

    engine = ScanEngine()

    result = engine.scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
        timeout=0.5,
    )

    assert result.status == "completed"
    assert len(result.hosts) == 1
    assert result.hosts[0].state == "reachable"
    assert result.hosts[0].services == []


@patch("scan_engine.engine.detect_service")
@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_scan_detects_services_on_open_ports(
    mock_discover_host,
    mock_scan_tcp_range,
    mock_detect_service,
):
    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.return_value = [22, 80]

    from scan_engine.models import ServiceResult

    mock_detect_service.side_effect = [
        ServiceResult(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
        ),
        ServiceResult(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
        ),
    ]

    engine = ScanEngine()

    result = engine.scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
        timeout=0.5,
    )

    assert result.status == "completed"
    assert len(result.hosts) == 1

    host = result.hosts[0]

    assert host.state == "reachable"
    assert len(host.services) == 2

    assert host.services[0].port == 22
    assert host.services[0].service == "ssh"

    assert host.services[1].port == 80
    assert host.services[1].service == "http"


@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_scan_passes_correct_values_to_tcp_scanner(
    mock_discover_host,
    mock_scan_tcp_range,
):
    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.return_value = []

    engine = ScanEngine()

    engine.scan(
        target="127.0.0.1",
        start_port=20,
        end_port=100,
        timeout=1.0,
    )

    mock_scan_tcp_range.assert_called_once_with(
        target="127.0.0.1",
        start_port=20,
        end_port=100,
        timeout=1.0,
    )