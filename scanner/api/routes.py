from datetime import datetime, timezone

from fastapi import APIRouter

from models import ScanInput, ScanResponse, ScanError
from core import run_scan, normalize

router = APIRouter()


@router.get("/health")
def health():
    return {"status": "ok"}


@router.post("/scan", response_model=ScanResponse | ScanError)
def scan_endpoint(payload: ScanInput):
    alvo = f"{payload.hostname}:{payload.port}"

    try:
        scan_result = run_scan(payload.hostname, payload.port)
    except Exception as e:
        return ScanError(target=alvo, reachable=False, error=str(e), findings=[])

    findings = normalize(scan_result)

    resumo = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        resumo[f["severity_hint"]] = resumo.get(f["severity_hint"], 0) + 1

    return ScanResponse(
        target=alvo,
        scanned_at=datetime.now(timezone.utc),
        reachable=True,
        summary=resumo,
        total_findings=len(findings),
        findings=findings,
    )
