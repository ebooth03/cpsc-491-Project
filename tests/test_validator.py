
import pytest

from scan_engine.validator import (
    MAX_PORTS_PER_SCAN,
    validate_port_range,
    validate_scan_config,
    validate_target,
    validate_timeout,
)


# --------------------------------------------------
# IPv4 Target Validation Tests
# --------------------------------------------------

def test_validate_target_accepts_valid_ipv4():
    assert validate_target("127.0.0.1") is True


def test_validate_target_rejects_invalid_ipv4():
    with pytest.raises(ValueError):
        validate_target("999.999.1.1")


def test_validate_target_rejects_ipv6():
    with pytest.raises(ValueError):
        validate_target("::1")


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "192.168.1.1",
        "10.0.0.1",
        "0.0.0.0",
        "255.255.255.255",
    ],
)
def test_validate_target_accepts_ipv4_equivalence_classes(target):
    assert validate_target(target) is True


@pytest.mark.parametrize(
    "target",
    [
        "",
        "invalid-ip",
        "999.999.999.999",
        "192.168.1",
        "localhost",
        "::1",
        "2001:db8::1",
        "192.168.1.256",
    ],
)
def test_validate_target_rejects_invalid_equivalence_classes(target):
    with pytest.raises(ValueError):
        validate_target(target)


# --------------------------------------------------
# TCP Port Range Validation Tests
# --------------------------------------------------

def test_validate_port_range_accepts_valid_range():
    assert validate_port_range(1, 1000) is True


def test_validate_port_range_accepts_same_start_and_end():
    assert validate_port_range(80, 80) is True


def test_validate_port_range_rejects_start_below_one():
    with pytest.raises(ValueError):
        validate_port_range(0, 100)


def test_validate_port_range_rejects_end_above_65535():
    with pytest.raises(ValueError):
        validate_port_range(1, 65536)


def test_validate_port_range_rejects_reversed_range():
    with pytest.raises(ValueError):
        validate_port_range(1000, 500)


@pytest.mark.parametrize(
    "start_port,end_port",
    [
        (1, 1),          # Minimum valid TCP port
        (2, 2),          # Just above minimum
        (65534, 65534),  # Just below maximum
        (65535, 65535),  # Maximum valid TCP port
        (80, 80),        # Single-port range
    ],
)
def test_validate_port_range_accepts_boundary_values(
    start_port, end_port
):
    assert validate_port_range(start_port, end_port) is True


@pytest.mark.parametrize(
    "start_port,end_port",
    [
        (0, 80),
        (-1, 80),
        (65536, 65536),
        (80, 0),
        (80, 65536),
        (100, 50),
    ],
)
def test_validate_port_range_rejects_invalid_boundaries(
    start_port, end_port
):
    with pytest.raises(ValueError):
        validate_port_range(start_port, end_port)


@pytest.mark.parametrize(
    "start_port,end_port",
    [
        ("abc", 80),
        (80, "abc"),
        (None, 80),
        (80, None),
        (1.5, 80),
        (80, 80.5),
    ],
)
def test_validate_port_range_rejects_invalid_types(
    start_port, end_port
):
    with pytest.raises((TypeError, ValueError)):
        validate_port_range(start_port, end_port)


# --------------------------------------------------
# KAN-103: Maximum TCP Scan Size Tests
# --------------------------------------------------

def test_maximum_scan_size_is_accepted():
    """
    A scan containing exactly MAX_PORTS_PER_SCAN
    ports must be accepted.
    """
    assert validate_port_range(
        1, MAX_PORTS_PER_SCAN
    ) is True


def test_maximum_scan_size_plus_one_is_rejected():
    """
    A scan exceeding the configured maximum by
    one port must be rejected.
    """
    if MAX_PORTS_PER_SCAN == 65535:
        pytest.skip("No larger valid TCP range exists")

    with pytest.raises(
        ValueError,
        match="maximum allowed port count"
    ):
        validate_port_range(
            1, MAX_PORTS_PER_SCAN + 1
        )


def test_full_tcp_range_rejected_when_above_limit():
    """
    The full TCP range must be rejected when
    the configured maximum is less than 65535.
    """
    if MAX_PORTS_PER_SCAN == 65535:
        pytest.skip("Full TCP range is within the configured limit")

    with pytest.raises(
        ValueError,
        match="maximum allowed port count"
    ):
        validate_port_range(1, 65535)


def test_maximum_scan_size_near_upper_boundary():
    """
    A maximum-sized range ending at port 65535
    must be accepted.
    """
    start_port = 65535 - MAX_PORTS_PER_SCAN + 1

    assert validate_port_range(
        start_port, 65535
    ) is True


def test_excessive_scan_near_upper_boundary():
    """
    A range exceeding the maximum by one port
    near the upper TCP boundary must be rejected.
    """
    if MAX_PORTS_PER_SCAN == 65535:
        pytest.skip("No larger valid TCP range exists")

    start_port = 65535 - MAX_PORTS_PER_SCAN

    with pytest.raises(
        ValueError,
        match="maximum allowed port count"
    ):
        validate_port_range(start_port, 65535)


def test_scan_config_rejects_excessive_port_range():
    """
    Complete scan configuration validation must
    reject requests exceeding the maximum.
    """
    if MAX_PORTS_PER_SCAN == 65535:
        pytest.skip("No larger valid TCP range exists")

    with pytest.raises(
        ValueError,
        match="maximum allowed port count"
    ):
        validate_scan_config(
            target="127.0.0.1",
            start_port=1,
            end_port=MAX_PORTS_PER_SCAN + 1,
            timeout=0.5,
        )


def test_scan_config_accepts_maximum_port_range():
    """
    Complete scan configuration validation must
    accept requests at the maximum.
    """
    assert validate_scan_config(
        target="127.0.0.1",
        start_port=1,
        end_port=MAX_PORTS_PER_SCAN,
        timeout=0.5,
    ) is True


# --------------------------------------------------
# Timeout Validation Tests
# --------------------------------------------------

def test_validate_timeout_accepts_positive_timeout():
    assert validate_timeout(0.5) is True


def test_validate_timeout_rejects_zero():
    with pytest.raises(ValueError):
        validate_timeout(0)


def test_validate_timeout_rejects_negative_value():
    with pytest.raises(ValueError):
        validate_timeout(-1)


@pytest.mark.parametrize(
    "timeout",
    [
        0,
        -0.1,
        -1,
        -100,
    ],
)
def test_validate_timeout_rejects_nonpositive_values(timeout):
    with pytest.raises(ValueError):
        validate_timeout(timeout)


# --------------------------------------------------
# Complete Scan Configuration Tests
# --------------------------------------------------

def test_validate_scan_config_accepts_valid_config():
    assert validate_scan_config(
        target="127.0.0.1",
        start_port=1,
        end_port=1000,
        timeout=0.5,
    ) is True


def test_validate_scan_config_rejects_invalid_target():
    with pytest.raises(ValueError):
        validate_scan_config(
            target="invalid-ip",
            start_port=1,
            end_port=1000,
            timeout=0.5,
        )


def test_validate_scan_config_rejects_invalid_port_range():
    with pytest.raises(ValueError):
        validate_scan_config(
            target="127.0.0.1",
            start_port=1000,
            end_port=500,
            timeout=0.5,
        )


def test_validate_scan_config_rejects_invalid_timeout():
    with pytest.raises(ValueError):
        validate_scan_config(
            target="127.0.0.1",
            start_port=1,
            end_port=1000,
            timeout=0,
        )
