from scan_engine.tcp_scanner import scan_tcp_port


class ScannerError(Exception):
    """Raised when a scan cannot be completed."""
    pass


class Scanner:
    """Scans TCP ports on a target host."""

    def scan(self, target, ports):
        if not isinstance(target, str) or not target.strip():
            raise ValueError("Target must be a non-empty string")

        if not ports:
            raise ValueError("At least one port must be provided")

        for port in ports:
            if (
                isinstance(port, bool)
                or not isinstance(port, int)
                or not 1 <= port <= 65535
            ):
                raise ValueError(f"Invalid port: {port}")

        results = []

        for port in ports:
            is_open = scan_tcp_port(target, port)

            results.append({
                "target": target,
                "port": port,
                "state": "open" if is_open else "closed",
                "service": None,
            })

        return results
