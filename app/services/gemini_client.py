"""Camada de IA (Gemini) — classificação de risco a jusante.

O microsserviço Scanner faz **apenas** detecção determinística. Esta camada
recebe os achados crus e usa o Gemini para:

1. Atribuir uma **postura de risco geral** ao alvo (com justificativa);
2. **Priorizar** os achados (o que corrigir primeiro e por quê);
3. Redigir **recomendações acionáveis** em PT-BR.

Princípio de robustez: a IA é um *enriquecimento*. Se a chave não estiver
configurada ou a chamada falhar, o app continua funcional exibindo os achados
determinísticos com um fallback heurístico (sem IA).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from config import (
    GEMINI_API_KEY,
    GEMINI_MODEL,
    SEVERITY_ORDER,
    SEVERITY_LABELS_PT,
)


@dataclass
class RiskAssessment:
    """Resultado da análise de risco (com ou sem IA)."""

    overall_risk: str  # critical | high | medium | low | info
    summary: str
    prioridades: list[dict] = field(default_factory=list)  # {id, motivo, acao}
    usou_ia: bool = False
    erro: str | None = None


_PROMPT_SISTEMA = (
    "Você é um analista sênior de segurança ofensiva especializado em TLS/SSL. "
    "Recebe achados JÁ DETECTADOS de forma determinística por um scanner (sslyze). "
    "Sua tarefa NÃO é detectar nada novo, e sim: (1) classificar a postura de risco "
    "geral do alvo, (2) priorizar os achados existentes do mais ao menos urgente, "
    "e (3) escrever recomendações de correção concretas, em português do Brasil. "
    "Baseie-se SOMENTE nos achados fornecidos; não invente vulnerabilidades. "
    "Responda EXCLUSIVAMENTE com um objeto JSON válido, sem markdown, sem cercas "
    "de código, no formato exato:\n"
    "{\n"
    '  "overall_risk": "critical|high|medium|low|info",\n'
    '  "summary": "2-3 frases sobre a postura geral",\n'
    '  "prioridades": [\n'
    '    {"id": "<id do achado>", "motivo": "por que priorizar", '
    '"acao": "ação corretiva concreta"}\n'
    "  ]\n"
    "}"
)


def _prompt_usuario(target: str, findings: list[dict], summary: dict) -> str:
    return (
        f"Alvo auditado: {target}\n"
        f"Resumo por severidade: {json.dumps(summary, ensure_ascii=False)}\n"
        f"Achados detectados ({len(findings)}):\n"
        f"{json.dumps(findings, ensure_ascii=False, indent=2)}\n\n"
        "Classifique, priorize e recomende conforme as instruções."
    )


def avaliar_risco(target: str, findings: list[dict], summary: dict) -> RiskAssessment:
    """Enriquece os achados com IA; cai em heurística se a IA não estiver disponível."""
    if not findings:
        return RiskAssessment(
            overall_risk="info",
            summary="Nenhum achado de segurança foi detectado nesta varredura.",
            prioridades=[],
            usou_ia=False,
        )

    if not GEMINI_API_KEY:
        return _fallback_heuristico(
            findings, erro="GEMINI_API_KEY não configurada — análise heurística."
        )

    try:
        from google import genai

        client = genai.Client(api_key=GEMINI_API_KEY)
        resp = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=_prompt_usuario(target, findings, summary),
            config={
                "system_instruction": _PROMPT_SISTEMA,
                "response_mime_type": "application/json",
                "temperature": 0.2,
            },
        )
        dados = _parse_json(resp.text)
        return RiskAssessment(
            overall_risk=_normalizar_sev(dados.get("overall_risk", "")),
            summary=dados.get("summary", "").strip()
            or "Análise concluída.",
            prioridades=dados.get("prioridades", []),
            usou_ia=True,
        )
    except Exception as exc:  # qualquer falha → fallback funcional
        return _fallback_heuristico(
            findings, erro=f"Falha na IA, usando heurística: {exc}"
        )


def _normalizar_sev(valor: str) -> str:
    v = (valor or "").strip().lower()
    return v if v in SEVERITY_ORDER else "info"


def _parse_json(texto: str) -> dict:
    """Tolera cercas de código eventuais em volta do JSON."""
    t = (texto or "").strip()
    if t.startswith("```"):
        t = t.strip("`")
        if t.lower().startswith("json"):
            t = t[4:]
    return json.loads(t.strip())


def _fallback_heuristico(findings: list[dict], erro: str | None = None) -> RiskAssessment:
    """Sem IA: a postura geral é a maior severidade presente; prioriza por ordem."""
    presentes = {f.get("severity_hint", "info") for f in findings}
    overall = next((s for s in SEVERITY_ORDER if s in presentes), "info")

    ordenados = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity_hint", "info")),
    )
    prioridades = [
        {
            "id": f.get("id", ""),
            "motivo": f"Severidade {SEVERITY_LABELS_PT.get(f.get('severity_hint',''), '')}.",
            "acao": f.get("detail", ""),
        }
        for f in ordenados[:5]
    ]

    return RiskAssessment(
        overall_risk=overall,
        summary=(
            f"Postura de risco estimada como "
            f"'{SEVERITY_LABELS_PT.get(overall, overall)}' a partir de "
            f"{len(findings)} achado(s) determinístico(s)."
        ),
        prioridades=prioridades,
        usou_ia=False,
        erro=erro,
    )
