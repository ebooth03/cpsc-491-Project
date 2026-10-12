import pytest
from dataclasses import asdict

from scan_engine.backend_adapter import service_result_to_backend_port
from scan_engine.models import ServiceResult
from app.models.contracts import PortResult, HostResult


# -------------------------------------------------
# Existing adapter functionality
# -------------------------------------------------

def test_adapter_converts_service_result():
    service = ServiceResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product="OpenSSH",
        version="9.0",
    )

    result = service_result_to_backend_port(service)

    assert result == {
        "port": 22,
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 9.0",
    }


def test_adapter_handles_missing_product_and_version():
    service = ServiceResult(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        product=None,
        version=None,
    )

    result = service_result_to_backend_port(service)

    assert result == {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "version": None,
    }


def test_adapter_handles_product_without_version():
    service = ServiceResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product="OpenSSH",
        version=None,
    )

    result = service_result_to_backend_port(service)

    assert result["version"] == "OpenSSH"


def test_adapter_handles_version_without_product():
    service = ServiceResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product=None,
        version="9.0",
    )

    result = service_result_to_backend_port(service)

    assert result["version"] == "9.0"


# -------------------------------------------------
# Contract testing
# -------------------------------------------------

def test_adapter_returns_expected_backend_fields():
    service = ServiceResult(
        port=443,
        protocol="tcp",
        state="open",
        service="https",
        product="nginx",
        version="1.24",
    )

    result = service_result_to_backend_port(service)

    assert set(result.keys()) == {
        "port",
        "protocol",
        "state",
        "service",
        "version",
    }

    assert isinstance(result["port"], int)
    assert isinstance(result["protocol"], str)
    assert isinstance(result["state"], str)
    assert isinstance(result["service"], str)
    assert isinstance(result["version"], str)


def test_adapter_preserves_port_and_service_information():
    service = ServiceResult(
        port=8080,
        protocol="tcp",
        state="open",
        service="http",
        product="Apache",
        version="2.4",
    )

    result = service_result_to_backend_port(service)

    assert result["port"] == 8080
    assert result["protocol"] == "tcp"
    assert result["state"] == "open"
    assert result["service"] == "http"
    assert result["version"] == "Apache 2.4"


# -------------------------------------------------
# Edge-case testing
# -------------------------------------------------

def test_adapter_handles_unknown_service():
    service = ServiceResult(
        port=9999,
        protocol="tcp",
        state="open",
        service=None,
        product=None,
        version=None,
    )

    result = service_result_to_backend_port(service)

    assert result["port"] == 9999
    assert result["service"] is None
    assert result["version"] is None


def test_adapter_preserves_closed_port_state():
    service = ServiceResult(
        port=80,
        protocol="tcp",
        state="closed",
        service=None,
    )

    result = service_result_to_backend_port(service)

    assert result["state"] == "closed"
    assert result["port"] == 80


@pytest.mark.parametrize(
    "product,version,expected",
    [
        ("OpenSSH", "9.0", "OpenSSH 9.0"),
        ("OpenSSH", None, "OpenSSH"),
        (None, "9.0", "9.0"),
        (None, None, None),
        ("", "", None),
        ("nginx", "1.24", "nginx 1.24"),
    ],
)
def test_adapter_version_formatting(product, version, expected):
    service = ServiceResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product=product,
        version=version,
    )

    result = service_result_to_backend_port(service)

    assert result["version"] == expected


# -------------------------------------------------
# Multiple result integration testing
# -------------------------------------------------

def test_adapter_converts_multiple_service_results():
    services = [
        ServiceResult(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            product="OpenSSH",
            version="9.0",
        ),
        ServiceResult(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            product="Apache",
            version="2.4",
        ),
        ServiceResult(
            port=443,
            protocol="tcp",
            state="open",
            service="https",
            product="nginx",
            version="1.24",
        ),
    ]

    results = [
        service_result_to_backend_port(service)
        for service in services
    ]

    assert len(results) == 3
    assert [result["port"] for result in results] == [22, 80, 443]

    assert results[0]["version"] == "OpenSSH 9.0"
    assert results[1]["version"] == "Apache 2.4"
    assert results[2]["version"] == "nginx 1.24"


def test_adapter_handles_empty_service_collection():
    services = []

    results = [
        service_result_to_backend_port(service)
        for service in services
    ]

    assert results == []


# -------------------------------------------------
# Negative testing
# -------------------------------------------------

def test_adapter_rejects_none_input():
    with pytest.raises((AttributeError, TypeError, ValueError)):
        service_result_to_backend_port(None)


def test_adapter_rejects_invalid_object():
    with pytest.raises((AttributeError, TypeError, ValueError)):
        service_result_to_backend_port("invalid-service")


# -------------------------------------------------
# Data integrity testing
# -------------------------------------------------

def test_adapter_does_not_modify_original_service():
    service = ServiceResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product="OpenSSH",
        version="9.0",
    )

    original = asdict(service)

    service_result_to_backend_port(service)

    assert asdict(service) == original


# -------------------------------------------------
# Backend Pydantic model compatibility testing
# KAN-86
# -------------------------------------------------

def test_adapter_output_accepted_by_backend_port_result():
    service = ServiceResult(
        port=22,
        protocol="tcp",
        state="open",
        service="ssh",
        product="OpenSSH",
        version="9.0",
    )

    converted = service_result_to_backend_port(service)
    backend_port = PortResult(**converted)

    assert backend_port.port == 22
    assert backend_port.protocol == "tcp"
    assert backend_port.state == "open"
    assert backend_port.service == "ssh"
    assert backend_port.version == "OpenSSH 9.0"
    assert backend_port.banner is None


def test_adapter_missing_version_accepted_by_backend():
    service = ServiceResult(
        port=80,
        protocol="tcp",
        state="open",
        service="http",
        product=None,
        version=None,
    )

    converted = service_result_to_backend_port(service)
    backend_port = PortResult(**converted)

    assert backend_port.port == 80
    assert backend_port.service == "http"
    assert backend_port.version is None


def test_adapter_unknown_service_accepted_by_backend():
    service = ServiceResult(
        port=9999,
        protocol="tcp",
        state="open",
        service=None,
        product=None,
        version=None,
    )

    converted = service_result_to_backend_port(service)
    backend_port = PortResult(**converted)

    assert backend_port.port == 9999
    assert backend_port.service is None
    assert backend_port.version is None


def test_multiple_adapter_results_accepted_by_backend_host():
    services = [
        ServiceResult(
            port=22,
            protocol="tcp",
            state="open",
            service="ssh",
            product="OpenSSH",
            version="9.0",
        ),
        ServiceResult(
            port=80,
            protocol="tcp",
            state="open",
            service="http",
            product="Apache",
            version="2.4",
        ),
    ]

    backend_ports = [
        PortResult(**service_result_to_backend_port(service))
        for service in services
    ]

    backend_host = HostResult(
        host="127.0.0.1",
        ports=backend_ports,
    )

    assert backend_host.host == "127.0.0.1"
    assert len(backend_host.ports) == 2
    assert backend_host.ports[0].port == 22
    assert backend_host.ports[0].version == "OpenSSH 9.0"
    assert backend_host.ports[1].port == 80
    assert backend_host.ports[1].version == "Apache 2.4"


def test_adapter_output_preserves_backend_field_types():
    service = ServiceResult(
        port=443,
        protocol="tcp",
        state="open",
        service="https",
        product="nginx",
        version="1.24",
    )

    converted = service_result_to_backend_port(service)
    backend_port = PortResult(**converted)

    assert isinstance(backend_port.port, int)
    assert isinstance(backend_port.protocol, str)
    assert isinstance(backend_port.state, str)
    assert isinstance(backend_port.service, str)
    assert isinstance(backend_port.version, str)


def test_backend_rejects_invalid_adapter_port_data():
    from pydantic import ValidationError

    invalid_data = {
        "port": "not-a-port",
        "protocol": "tcp",
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 9.0",
    }

    with pytest.raises(ValidationError):
        PortResult(**invalid_data)