from sslyze import (
    Scanner,
    ServerScanRequest,
    ServerNetworkLocation,
    ServerScanStatusEnum,
)


def run_scan(hostname: str, port: int):
    """
    Executa o scan sslyze contra o alvo e retorna o scan_result.
    Lança RuntimeError se o servidor for inacessível.
    """
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(hostname=hostname, port=port)
    )
    scanner = Scanner()
    scanner.queue_scans([request])
    result = next(iter(scanner.get_results()))

    if result.scan_status != ServerScanStatusEnum.COMPLETED:
        raise RuntimeError("Servidor inacessível para varredura TLS.")

    return result.scan_result
