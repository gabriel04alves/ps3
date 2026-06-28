"""Geração do relatório de auditoria (Markdown e PDF).

Consolida alvo, postura de risco (IA/heurística), resumo por severidade e a
lista de achados com recomendações em documentos baixáveis.
"""

from __future__ import annotations

import io
from datetime import datetime

from config import (
    SEVERITY_ORDER,
    SEVERITY_LABELS_PT,
    SEVERITY_COLORS,
    CATEGORY_LABELS_PT,
)
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


def gerar_pdf(resultado: ScanResult, risco: RiskAssessment) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=2 * cm,
        rightMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title=f"Relatorio SSL/TLS — {resultado.target}",
        author="Scanner SSL/TLS",
    )

    base = getSampleStyleSheet()
    estilo_titulo = ParagraphStyle(
        "Titulo",
        parent=base["Title"],
        fontName="Helvetica-Bold",
        fontSize=18,
        textColor=colors.HexColor("#0f1419"),
        spaceAfter=4,
    )
    estilo_subtitulo = ParagraphStyle(
        "Subtitulo",
        parent=base["Normal"],
        fontName="Helvetica",
        fontSize=9,
        textColor=colors.HexColor("#6b7787"),
        spaceAfter=14,
    )
    estilo_h2 = ParagraphStyle(
        "H2",
        parent=base["Heading2"],
        fontName="Helvetica-Bold",
        fontSize=13,
        textColor=colors.HexColor("#0f1419"),
        spaceBefore=14,
        spaceAfter=8,
    )
    estilo_h3 = ParagraphStyle(
        "H3",
        parent=base["Heading3"],
        fontName="Helvetica-Bold",
        fontSize=11,
        textColor=colors.HexColor("#1d2630"),
        spaceBefore=8,
        spaceAfter=4,
    )
    estilo_corpo = ParagraphStyle(
        "Corpo",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#1d2630"),
        alignment=TA_LEFT,
        spaceAfter=4,
    )
    estilo_meta = ParagraphStyle(
        "Meta",
        parent=base["BodyText"],
        fontName="Helvetica",
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#4b5563"),
    )
    estilo_id = ParagraphStyle(
        "FindingId",
        parent=base["BodyText"],
        fontName="Courier",
        fontSize=8,
        textColor=colors.HexColor("#6b7787"),
        spaceAfter=6,
    )

    historia: list = []
    historia.append(Paragraph("Relatório de Auditoria SSL/TLS", estilo_titulo))
    historia.append(
        Paragraph(
            "Diagnóstico automatizado de vulnerabilidades · Cenário 1 (Servidor Web)",
            estilo_subtitulo,
        )
    )

    fonte = "IA (Gemini)" if risco.usou_ia else "Heurística determinística"
    meta = [
        ["Alvo", resultado.target],
        ["Varredura", resultado.scanned_at or "—"],
        ["Gerado em", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
        ["Classificação por", fonte],
        ["Total de achados", str(resultado.total_findings)],
    ]
    tabela_meta = Table(meta, colWidths=[4.5 * cm, 11 * cm])
    tabela_meta.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4b5563")),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#1d2630")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("LINEBELOW", (0, 0), (-1, -2), 0.4, colors.HexColor("#e5e7eb")),
            ]
        )
    )
    historia.append(tabela_meta)

    historia.append(Paragraph("Postura de risco geral", estilo_h2))
    cor_risco = colors.HexColor(SEVERITY_COLORS.get(risco.overall_risk, "#6b7280"))
    nivel = SEVERITY_LABELS_PT.get(risco.overall_risk, risco.overall_risk)
    selo = Table(
        [[Paragraph(f"<b>{_esc(nivel)}</b>", estilo_corpo)]],
        colWidths=[3.5 * cm],
    )
    selo.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), cor_risco),
                ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
            ]
        )
    )
    historia.append(selo)
    historia.append(Spacer(1, 6))
    historia.append(Paragraph(_esc(risco.summary), estilo_corpo))

    historia.append(Paragraph("Resumo por severidade", estilo_h2))
    cabecalho = ["Severidade", "Quantidade"]
    linhas_sev = [cabecalho] + [
        [SEVERITY_LABELS_PT[sev], str(resultado.summary.get(sev, 0))]
        for sev in SEVERITY_ORDER
    ]
    tabela_sev = Table(linhas_sev, colWidths=[8 * cm, 3 * cm])
    estilo_sev = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f1419")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("ALIGN", (1, 0), (1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
    ]
    for i, sev in enumerate(SEVERITY_ORDER, start=1):
        estilo_sev.append(
            (
                "TEXTCOLOR",
                (0, i),
                (0, i),
                colors.HexColor(SEVERITY_COLORS[sev]),
            )
        )
        estilo_sev.append(("FONTNAME", (0, i), (0, i), "Helvetica-Bold"))
    tabela_sev.setStyle(TableStyle(estilo_sev))
    historia.append(tabela_sev)

    if risco.prioridades:
        historia.append(Paragraph("Prioridades de correção", estilo_h2))
        for i, p in enumerate(risco.prioridades, 1):
            historia.append(
                Paragraph(f"{i}. {_esc(p.get('id', ''))}", estilo_h3)
            )
            if p.get("motivo"):
                historia.append(
                    Paragraph(
                        f"<b>Por que priorizar:</b> {_esc(p['motivo'])}",
                        estilo_corpo,
                    )
                )
            if p.get("acao"):
                historia.append(
                    Paragraph(
                        f"<b>Ação corretiva:</b> {_esc(p['acao'])}",
                        estilo_corpo,
                    )
                )
            historia.append(Spacer(1, 4))

    historia.append(Paragraph("Achados detectados", estilo_h2))
    if not resultado.findings:
        historia.append(
            Paragraph(
                "<i>Nenhum achado de segurança detectado.</i>", estilo_corpo
            )
        )
    else:
        ordenados = sorted(
            resultado.findings,
            key=lambda f: SEVERITY_ORDER.index(f.get("severity_hint", "info")),
        )
        for f in ordenados:
            historia.append(_card_achado_pdf(f, estilo_h3, estilo_corpo, estilo_id))

    historia.append(Spacer(1, 12))
    historia.append(
        Paragraph(
            "Relatório gerado pelo dashboard Scanner SSL/TLS — Projeto de Segurança III. "
            "Varredura passiva e não destrutiva (sslyze).",
            estilo_meta,
        )
    )

    doc.build(historia)
    return buffer.getvalue()


def _card_achado_pdf(finding: dict, estilo_h3, estilo_corpo, estilo_id):
    from reportlab.lib import colors
    from reportlab.lib.units import cm
    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle

    sev = finding.get("severity_hint", "info")
    cor = colors.HexColor(SEVERITY_COLORS.get(sev, "#6b7280"))
    sev_label = SEVERITY_LABELS_PT.get(sev, sev)
    cat_label = CATEGORY_LABELS_PT.get(
        finding.get("category", ""), finding.get("category", "")
    )
    titulo = _esc(finding.get("title", ""))
    detalhe = _esc(finding.get("detail", ""))
    fid = _esc(finding.get("id", ""))

    conteudo = [
        [
            Paragraph(f"<b>{sev_label}</b>", estilo_corpo),
            Paragraph(f"<b>{titulo}</b>", estilo_corpo),
        ],
        [
            Paragraph(f"<i>{_esc(cat_label)}</i>", estilo_id),
            Paragraph(detalhe, estilo_corpo),
        ],
        ["", Paragraph(fid, estilo_id)],
    ]
    tabela = Table(conteudo, colWidths=[2.5 * cm, 13 * cm])
    tabela.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, -1), cor),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.white),
                ("ALIGN", (0, 0), (0, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (1, 0), (1, -1), 8),
                ("RIGHTPADDING", (1, 0), (1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ("BACKGROUND", (1, 0), (1, -1), colors.HexColor("#f9fafb")),
                ("BOX", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                ("SPAN", (0, 0), (0, -1)),
            ]
        )
    )
    return _wrap_kept(tabela)


def _wrap_kept(elemento):
    from reportlab.platypus import KeepTogether

    return KeepTogether([elemento, _spacer(6)])


def _spacer(altura: int):
    from reportlab.platypus import Spacer

    return Spacer(1, altura)


def _esc(texto: str) -> str:
    return (
        str(texto)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
