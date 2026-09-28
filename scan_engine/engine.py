from scan_engine.host_discovery import discover_host
from scan_engine.models import HostResult, ScanResult
from scan_engine.service_detector import detect_service
from scan_engine.tcp_scanner import scan_tcp_range
from scan_engine.validator import validate_scan_config


class ScanEngine:
    """
    Coordinates the Scan Engine pipeline.

    The engine validates the scan configuration, performs host
    discovery, scans TCP ports, identifies services on open ports,
    and returns a structured ScanResult.
    """

    def scan(
        self,
        target: str,
        start_port: int,
        end_port: int,
        timeout: float = 0.5,
    ) -> ScanResult:
        try:
            # Validate input before performing network operations.
            validate_scan_config(
                target=target,
                start_port=start_port,
                end_port=end_port,
                timeout=timeout,
            )

            # Determine whether the target appears reachable.
            host_state = discover_host(
                target=target,
                timeout=timeout,
            )

            # If host discovery cannot confirm the host is reachable,
            # return the discovery result without performing a port scan.
            if host_state != "reachable":
                host_result = HostResult(
                    address=target,
                    state=host_state,
                    services=[],
                )

                return ScanResult(
                    target=target,
                    status="completed",
                    hosts=[host_result],
                )

            # Scan the requested TCP port range.
            open_ports = scan_tcp_range(
                target=target,
                start_port=start_port,
                end_port=end_port,
                timeout=timeout,
            )

            # Identify the likely service for each open port.
            services = [
                detect_service(port)
                for port in open_ports
            ]

            host_result = HostResult(
                address=target,
                state="reachable",
                services=services,
            )

            return ScanResult(
                target=target,
                status="completed",
                hosts=[host_result],
            )

        except ValueError as exc:
            return ScanResult(
                target=target,
                status="failed",
                error=str(exc),
            )

        except OSError as exc:
            return ScanResult(
                target=target,
                status="failed",
                error=f"Network error: {exc}",
            )