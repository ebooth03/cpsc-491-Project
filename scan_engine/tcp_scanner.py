
import socket

from scan_engine.validator import (
    validate_target,
    validate_port_range,
    validate_timeout,
)


def scan_tcp_port(
    target: str,
    port: int,
    timeout: float = 0.5
) -> bool:

    try:
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:

            sock.settimeout(timeout)

            result = sock.connect_ex((target, port))

            return result == 0

    except OSError:
        return False


def scan_tcp_range(
    target: str,
    start_port: int,
    end_port: int,
    timeout: float = 0.5
) -> list[int]:
    """
    Scan a validated TCP port range.

    KAN-103: Enforce the configured maximum TCP scan size
    even when this function is called directly.
    """

    # Validate before initiating any network connections.
    validate_target(target)
    validate_port_range(start_port, end_port)
    validate_timeout(timeout)

    open_ports = []

    for port in range(start_port, end_port + 1):

        if scan_tcp_port(target, port, timeout):
            open_ports.append(port)

    return open_ports
