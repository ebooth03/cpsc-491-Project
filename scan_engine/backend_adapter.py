from scan_engine.models import ServiceResult


def service_result_to_backend_port(
    service: ServiceResult
) -> dict:
    """
    Convert a Scan Engine ServiceResult into the structure
    expected by the backend PortResult model.

    The Scan Engine stores product and version separately,
    while the backend currently expects a single version field.

    Args:
        service: ServiceResult produced by the Scan Engine.

    Returns:
        Dictionary compatible with the backend port-result shape.
    """

    version = None

    if service.product and service.version:
        version = f"{service.product} {service.version}"
    elif service.version:
        version = service.version
    elif service.product:
        version = service.product

    return {
        "port": service.port,
        "protocol": service.protocol,
        "state": service.state,
        "service": service.service,
        "version": version,
    }