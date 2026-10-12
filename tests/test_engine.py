from unittest.mock import call, patch

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



# -------------------------------------------------
# KAN-87: Scan-engine integration and regression tests
# -------------------------------------------------



@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_unreachable_host_skips_tcp_scan(
    mock_discover_host,
    mock_scan_tcp_range,
):
    mock_discover_host.return_value = "unknown"

    result = ScanEngine().scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
        timeout=0.5,
    )

    assert result.status == "completed"
    assert result.hosts[0].state == "unknown"
    assert result.hosts[0].services == []

    mock_scan_tcp_range.assert_not_called()


@patch("scan_engine.engine.detect_service")
@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_no_open_ports_skips_service_detection(
    mock_discover_host,
    mock_scan_tcp_range,
    mock_detect_service,
):
    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.return_value = []

    result = ScanEngine().scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
    )

    assert result.status == "completed"
    assert result.hosts[0].services == []
    mock_detect_service.assert_not_called()


@patch("scan_engine.engine.detect_service")
@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_every_open_port_is_sent_to_service_detector(
    mock_discover_host,
    mock_scan_tcp_range,
    mock_detect_service,
):
    from scan_engine.models import ServiceResult

    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.return_value = [22, 80, 443]

    mock_detect_service.side_effect = [
        ServiceResult(port=22, protocol="tcp", state="open", service="ssh"),
        ServiceResult(port=80, protocol="tcp", state="open", service="http"),
        ServiceResult(port=443, protocol="tcp", state="open", service="https"),
    ]

    result = ScanEngine().scan(
        target="127.0.0.1",
        start_port=1,
        end_port=500,
    )

    assert result.status == "completed"
    assert len(result.hosts[0].services) == 3

    assert mock_detect_service.call_args_list == [
        call(22),
        call(80),
        call(443),
    ]


@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_host_discovery_receives_correct_parameters(
    mock_discover_host,
    mock_scan_tcp_range,
):
    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.return_value = []

    ScanEngine().scan(
        target="192.168.1.10",
        start_port=20,
        end_port=100,
        timeout=1.5,
    )

    mock_discover_host.assert_called_once_with(
        target="192.168.1.10",
        timeout=1.5,
    )


@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_network_error_during_tcp_scan_returns_failed(
    mock_discover_host,
    mock_scan_tcp_range,
):
    mock_discover_host.return_value = "reachable"
    mock_scan_tcp_range.side_effect = OSError("Connection failed")

    result = ScanEngine().scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
    )

    assert result.status == "failed"
    assert "Network error" in result.error
    assert result.hosts == []


@patch("scan_engine.engine.discover_host")
def test_network_error_during_host_discovery_returns_failed(
    mock_discover_host,
):
    mock_discover_host.side_effect = OSError("Network unreachable")

    result = ScanEngine().scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
    )

    assert result.status == "failed"
    assert "Network error" in result.error
    assert result.hosts == []


@patch("scan_engine.engine.scan_tcp_range")
@patch("scan_engine.engine.discover_host")
def test_invalid_timeout_prevents_network_operations(
    mock_discover_host,
    mock_scan_tcp_range,
):
    result = ScanEngine().scan(
        target="127.0.0.1",
        start_port=1,
        end_port=100,
        timeout=0,
    )

    assert result.status == "failed"
    mock_discover_host.assert_not_called()
    mock_scan_tcp_range.assert_not_called()



def test_failed_scan_returns_structured_error():
    engine = ScanEngine()

    result = engine.scan(
        target="invalid-ip",
        start_port=1,
        end_port=100,
        timeout=0.5,
    )

    assert result.status == "failed"
    assert result.error is not None
    assert isinstance(result.error, str)
    assert result.hosts == []