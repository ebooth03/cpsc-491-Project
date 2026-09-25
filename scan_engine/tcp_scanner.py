import socket


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

    open_ports = []

    for port in range(start_port, end_port + 1):

        if scan_tcp_port(target, port, timeout):
            open_ports.append(port)

    return open_ports