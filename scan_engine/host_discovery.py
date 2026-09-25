import socket


def discover_host(target: str, timeout: float = 0.5) -> str:
    """
    Attempts to determine whether a host appears reachable.

    Returns:
        "reachable"
        "unknown"
    """

    probe_ports = [22, 80, 443]

    for port in probe_ports:
        try:
            with socket.socket(
                socket.AF_INET,
                socket.SOCK_STREAM
            ) as sock:

                sock.settimeout(timeout)

                result = sock.connect_ex((target, port))

                if result == 0:
                    return "reachable"

        except OSError:
            continue

    return "unknown"