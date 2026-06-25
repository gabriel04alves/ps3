"""Cliente do microsserviço Scanner SSL/TLS.

Encapsula as chamadas HTTP ao FastAPI (`/health`, `/scan`) e devolve dados já
tipados (`ScanResult`). O contrato segue `scanner/models/schemas.py` — em
especial a regra de ouro do README: **ramificar pelo campo `reachable`**, não
pelo status HTTP, porque "alvo inacessível" volta como `200`.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import requests

from config import SCANNER_URL, SCAN_TIMEOUT_S, HEALTH_TIMEOUT_S


@dataclass
class ScanResult:
    """Resultado normalizado de uma chamada a `/scan`.

    Unifica `ScanResponse` e `ScanError` numa única estrutura para a UI, com
    o booleano `ok` indicando se há achados para exibir.
    """

    ok: bool
    target: str
    reachable: bool
    findings: list[dict] = field(default_factory=list)
    summary: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    scanned_at: str | None = None
    error: str | None = None


class ScannerError(Exception):
    """Falha de transporte/infra ao falar com o microsserviço (não de negócio)."""


def _base() -> str:
    return SCANNER_URL.rstrip("/")


def health() -> bool:
    """Retorna True se o microsserviço responde `{"status": "ok"}`."""
    try:
        resp = requests.get(f"{_base()}/health", timeout=HEALTH_TIMEOUT_S)
        return resp.status_code == 200 and resp.json().get("status") == "ok"
    except requests.RequestException:
        return False


def scan(hostname: str, port: int = 443) -> ScanResult:
    """Executa uma varredura e devolve um `ScanResult`.

    Levanta `ScannerError` apenas para falhas de transporte (serviço fora do ar,
    timeout, JSON inválido). Erros de negócio (alvo inacessível, falha de
    normalização) voltam como `ScanResult(ok=False, ...)` — status HTTP 200.
    """
    payload = {"hostname": hostname.strip(), "port": int(port)}

    try:
        resp = requests.post(
            f"{_base()}/scan", json=payload, timeout=SCAN_TIMEOUT_S
        )
    except requests.Timeout as exc:
        raise ScannerError(
            f"A varredura excedeu {SCAN_TIMEOUT_S}s. O alvo pode estar lento "
            "ou inacessível."
        ) from exc
    except requests.RequestException as exc:
        raise ScannerError(
            f"Não foi possível contatar o Scanner em {_base()}. Ele está no ar? "
            f"Detalhe: {exc}"
        ) from exc

    # 422 = entrada inválida (contrato do FastAPI).
    if resp.status_code == 422:
        detalhe = _extrair_detalhe_422(resp)
        raise ScannerError(f"Entrada inválida: {detalhe}")

    if resp.status_code >= 500:
        raise ScannerError(
            f"Erro interno do Scanner (HTTP {resp.status_code})."
        )

    try:
        data = resp.json()
    except ValueError as exc:
        raise ScannerError("O Scanner devolveu uma resposta não-JSON.") from exc

    # Regra de ouro: ramificar por `reachable`, não pelo status HTTP.
    if not data.get("reachable", False) or "error" in data:
        return ScanResult(
            ok=False,
            target=data.get("target", f"{hostname}:{port}"),
            reachable=bool(data.get("reachable", False)),
            error=data.get("error", "Alvo inacessível para varredura TLS."),
            findings=[],
        )

    return ScanResult(
        ok=True,
        target=data["target"],
        reachable=True,
        findings=data.get("findings", []),
        summary=data.get("summary", {}),
        total_findings=data.get("total_findings", 0),
        scanned_at=data.get("scanned_at"),
    )


def _extrair_detalhe_422(resp: requests.Response) -> str:
    try:
        itens = resp.json().get("detail", [])
        partes = [
            f"{'.'.join(str(p) for p in i.get('loc', []))}: {i.get('msg', '')}"
            for i in itens
        ]
        return "; ".join(partes) or "corpo da requisição inválido."
    except Exception:
        return "corpo da requisição inválido."
