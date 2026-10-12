from scan_engine.service_detector import detect_service
import pytest 


def test_detect_ssh_service():
    result = detect_service(22)

    assert result.port == 22
    assert result.protocol == "tcp"
    assert result.state == "open"
    assert result.service == "ssh"
    assert result.product is None
    assert result.version is None


def test_detect_http_service():
    result = detect_service(80)

    assert result.port == 80
    assert result.service == "http"


def test_detect_https_service():
    result = detect_service(443)

    assert result.port == 443
    assert result.service == "https"


def test_unknown_service():
    result = detect_service(9999)

    assert result.port == 9999
    assert result.protocol == "tcp"
    assert result.state == "open"
    assert result.service is None



# -------------------------------------------------
# KAN-87: Service identification edge-case tests
# -------------------------------------------------

@pytest.mark.parametrize(
    "port,expected_service",
    [
        (21, "ftp"),
        (23, "telnet"),
        (25, "smtp"),
        (53, "dns"),
        (110, "pop3"),
        (143, "imap"),
        (445, "smb"),
        (3306, "mysql"),
        (3389, "rdp"),
        (5432, "postgresql"),
        (8080, "http-alt"),
    ],
)
def test_additional_known_service_ports(port, expected_service):
    result = detect_service(port)

    assert result.port == port
    assert result.protocol == "tcp"
    assert result.state == "open"
    assert result.service == expected_service
    assert result.product is None
    assert result.version is None


@pytest.mark.parametrize("port", [1, 9999, 65535])
def test_unknown_service_ports(port):
    result = detect_service(port)

    assert result.port == port
    assert result.service is None
    assert result.state == "open"


def test_service_detector_preserves_custom_protocol():
    result = detect_service(53, protocol="udp")

    assert result.port == 53
    assert result.protocol == "udp"
    assert result.service == "dns"