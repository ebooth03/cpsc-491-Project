
import ipaddress
import os


# Must match the backend MAX_PORTS_PER_SCAN configuration.
MAX_PORTS_PER_SCAN = int(os.getenv("MAX_PORTS_PER_SCAN", "1024"))

if not 1 <= MAX_PORTS_PER_SCAN <= 65535:
    raise ValueError(
        "MAX_PORTS_PER_SCAN must be between 1 and 65535."
    )


def validate_target(target: str) -> bool:
    """
    Validate that the target is a valid IPv4 address.

    Args:
        target: Target IPv4 address as a string.

    Returns:
        True if the target is a valid IPv4 address.

    Raises:
        ValueError: If the target is not a valid IPv4 address.
    """
    try:
        ip = ipaddress.ip_address(target)
    except ValueError as exc:
        raise ValueError(f"Invalid target IP address: {target}") from exc

    if ip.version != 4:
        raise ValueError(f"Only IPv4 addresses are supported: {target}")

    return True


def validate_port_range(
    start_port: int,
    end_port: int
) -> bool:
    """
    Validate a TCP port range.

    Raises:
        ValueError: If ports are not integers, outside 1-65535,
                    reversed, or exceed MAX_PORTS_PER_SCAN.
    """

    # Validate port data types
    if type(start_port) is not int:
        raise ValueError(
            f"Start port must be an integer: {start_port}"
        )

    if type(end_port) is not int:
        raise ValueError(
            f"End port must be an integer: {end_port}"
        )

    # Validate port boundaries
    if not 1 <= start_port <= 65535:
        raise ValueError(
            f"Start port must be between 1 and 65535: {start_port}"
        )

    if not 1 <= end_port <= 65535:
        raise ValueError(
            f"End port must be between 1 and 65535: {end_port}"
        )

    # Validate port range order
    if start_port > end_port:
        raise ValueError(
            f"Start port cannot be greater than end port: "
            f"{start_port} > {end_port}"
        )

    port_count = end_port - start_port + 1

    if port_count > MAX_PORTS_PER_SCAN:
        raise ValueError(
            f"Scan exceeds maximum allowed port count "
            f"of {MAX_PORTS_PER_SCAN}."
        )

    return True


def validate_timeout(timeout: float) -> bool:
    """
    Validate the socket timeout value.

    Args:
        timeout: Socket timeout in seconds.

    Returns:
        True if the timeout is valid.

    Raises:
        ValueError: If the timeout is zero or negative.
    """
    if timeout <= 0:
        raise ValueError(
            f"Timeout must be greater than 0: {timeout}"
        )

    return True


def validate_scan_config(
    target: str,
    start_port: int,
    end_port: int,
    timeout: float
) -> bool:
    """
    Validate all scan configuration values.

    Args:
        target: Target IPv4 address.
        start_port: First TCP port to scan.
        end_port: Last TCP port to scan.
        timeout: Socket timeout in seconds.

    Returns:
        True if all scan configuration values are valid.
    """
    validate_target(target)
    validate_port_range(start_port, end_port)
    validate_timeout(timeout)

    return True
