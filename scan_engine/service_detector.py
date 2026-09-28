from scan_engine.models import ServiceResult


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    8080: "http-alt",
}


def detect_service(
    port: int,
    protocol: str = "tcp"
) -> ServiceResult:

    service_name = COMMON_SERVICES.get(port)

    return ServiceResult(
        port=port,
        protocol=protocol,
        state="open",
        service=service_name,
        product=None,
        version=None
    )