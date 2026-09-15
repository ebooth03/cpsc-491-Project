class ScannerError(Exception):
    """Raised when a scan cannot be completed."""
    pass


class Scanner:
    def scan(self, target, ports):
        if not target or not isinstance(target, str):
            raise ValueError("Target must be a non-empty string")

        if not ports:
            raise ValueError("At least one port must be provided")

        for port in ports:
            if not isinstance(port, int) or not 1 <= port <= 65535:
                raise ValueError(f"Invalid port: {port}")

        results = []

        for port in ports:
            results.append({
                "target": target,
                "port": port,
                "state": "unknown",
                "service": None,
            })

        return results