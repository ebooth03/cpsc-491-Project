from scan_engine.service_detector import detect_service


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