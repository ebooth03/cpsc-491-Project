import pytest

from scanner.scanner import Scanner


@pytest.fixture
def scanner():
    return Scanner()


def test_scanner_accepts_valid_target(scanner):
    results = scanner.scan("127.0.0.1", [80])

    assert len(results) == 1
    assert results[0]["target"] == "127.0.0.1"


def test_scanner_accepts_multiple_ports(scanner):
    results = scanner.scan("127.0.0.1", [22, 80, 443])

    assert len(results) == 3
    assert [result["port"] for result in results] == [22, 80, 443]


def test_scanner_rejects_empty_target(scanner):
    with pytest.raises(ValueError):
        scanner.scan("", [80])


def test_scanner_rejects_none_target(scanner):
    with pytest.raises(ValueError):
        scanner.scan(None, [80])


def test_scanner_rejects_empty_ports(scanner):
    with pytest.raises(ValueError):
        scanner.scan("127.0.0.1", [])


@pytest.mark.parametrize("port", [
    0,
    -1,
    65536,
    100000,
    "80",
])
def test_scanner_rejects_invalid_ports(scanner, port):
    with pytest.raises(ValueError):
        scanner.scan("127.0.0.1", [port])


def test_scan_result_contains_expected_fields(scanner):
    result = scanner.scan("127.0.0.1", [443])[0]

    assert "target" in result
    assert "port" in result
    assert "state" in result
    assert "service" in result


def test_unknown_service_defaults_to_none(scanner):
    result = scanner.scan("127.0.0.1", [12345])[0]

    assert result["service"] is None