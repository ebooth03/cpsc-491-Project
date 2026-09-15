import socket


class NetworkScanner:
    """Basic TCP network scanner."""

    def __init__(self, timeout=1):
        self.timeout = timeout

    def scan_port(self, host, port):
        """Check whether a TCP port is open."""

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)

        try:
            result = sock.connect_ex((host, port))
            return result == 0

        finally:
            sock.close()