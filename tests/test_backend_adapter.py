from scan_engine.backend_adapter import service_result_to_backend_port
from scan_engine.models import ServiceResult


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