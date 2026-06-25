"""Geração do relatório de auditoria em Markdown (artefato 'Relatório').

Consolida alvo, postura de risco (IA/heurística), resumo por severidade e a
lista de achados com recomendações num documento baixável.
"""

from __future__ import annotations

from datetime import datetime

from config import SEVERITY_ORDER, SEVERITY_LABELS_PT, CATEGORY_LABELS_PT
from services.gemini_client import RiskAssessment
from services.scanner_client import ScanResult


def gerar_markdown(resultado: ScanResult, risco: RiskAssessment) -> str:
    """Monta o relatório completo em Markdown."""
    linhas: list[str] = []
    add = linhas.append

    add("# Relatório de Auditoria SSL/TLS\n")
    add(f"- **Alvo:** `{resultado.target}`")
    add(f"- **Varredura:** {resultado.scanned_at or '—'}")
    add(f"- **Gerado em:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    fonte = "IA (Gemini)" if risco.usou_ia else "Heurística determinística"
    add(f"- **Classificação de risco por:** {fonte}\n")

    add("## Postura de risco geral\n")
    add(f"**Nível:** {SEVERITY_LABELS_PT.get(risco.overall_risk, risco.overall_risk)}\n")
    add(f"{risco.summary}\n")

    add("## Resumo por severidade\n")
    add("| Severidade | Quantidade |")
    add("|------------|-----------|")
    for sev in SEVERITY_ORDER:
        add(f"| {SEVERITY_LABELS_PT[sev]} | {resultado.summary.get(sev, 0)} |")
    add(f"\n**Total de achados:** {resultado.total_findings}\n")

    if risco.prioridades:
        add("## Prioridades de correção\n")
        for i, p in enumerate(risco.prioridades, 1):
            add(f"### {i}. `{p.get('id', '')}`")
            if p.get("motivo"):
                add(f"- **Por que priorizar:** {p['motivo']}")
            if p.get("acao"):
                add(f"- **Ação corretiva:** {p['acao']}")
            add("")

    add("## Achados detectados\n")
    if not resultado.findings:
        add("_Nenhum achado de segurança detectado._\n")
    else:
        ordenados = sorted(
            resultado.findings,
            key=lambda f: SEVERITY_ORDER.index(f.get("severity_hint", "info")),
        )
        for f in ordenados:
            sev = SEVERITY_LABELS_PT.get(f.get("severity_hint", ""), "")
            cat = CATEGORY_LABELS_PT.get(f.get("category", ""), f.get("category", ""))
            add(f"### {f.get('title', '')}")
            add(f"- **ID:** `{f.get('id', '')}`")
            add(f"- **Categoria:** {cat}")
            add(f"- **Severidade:** {sev}")
            add(f"- **Detalhe:** {f.get('detail', '')}")
            add("")

    add("---")
    add("_Relatório gerado pelo dashboard Scanner SSL/TLS — Projeto de Segurança III._")
    add("_Varredura passiva e não destrutiva (sslyze)._")

    return "\n".join(linhas)
