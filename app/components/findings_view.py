"""Componentes visuais reutilizáveis do dashboard.

Renderizam o resumo por severidade (métricas + gráfico) e a lista de achados
como cartões com faixa colorida — o elemento de assinatura da interface.
"""

from __future__ import annotations

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

from config import (
    SEVERITY_ORDER,
    SEVERITY_COLORS,
    SEVERITY_LABELS_PT,
    CATEGORY_LABELS_PT,
)
from components.styles import severity_badge_html


def metricas_severidade(summary: dict[str, int]) -> None:
    """Linha de métricas, uma coluna por severidade."""
    cols = st.columns(len(SEVERITY_ORDER))
    for col, sev in zip(cols, SEVERITY_ORDER):
        valor = summary.get(sev, 0)
        col.metric(SEVERITY_LABELS_PT[sev], valor)


def grafico_severidade(summary: dict[str, int]) -> None:
    """Barra horizontal de contagem por severidade (ordem canônica)."""
    sevs = [s for s in SEVERITY_ORDER if summary.get(s, 0) > 0]
    if not sevs:
        st.info("Nenhum achado para plotar.")
        return

    valores = [summary[s] for s in sevs]
    rotulos = [SEVERITY_LABELS_PT[s] for s in sevs]
    cores = [SEVERITY_COLORS[s] for s in sevs]

    fig = go.Figure(
        go.Bar(
            x=valores,
            y=rotulos,
            orientation="h",
            marker_color=cores,
            text=valores,
            textposition="outside",
        )
    )
    fig.update_layout(
        height=max(160, 52 * len(sevs)),
        margin=dict(l=10, r=20, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font_color="#b6c0cc",
        xaxis=dict(showgrid=True, gridcolor="#232d39", zeroline=False),
        yaxis=dict(autorange="reversed"),
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)


def grafico_categorias(findings: list[dict]) -> None:
    """Rosca de distribuição de achados por categoria."""
    if not findings:
        return
    df = pd.DataFrame(findings)
    contagem = df["category"].value_counts()
    rotulos = [CATEGORY_LABELS_PT.get(c, c) for c in contagem.index]

    fig = go.Figure(
        go.Pie(
            labels=rotulos,
            values=contagem.values,
            hole=0.55,
            marker=dict(colors=["#2f80ed", "#e8961e", "#b3203a", "#7fd1a3"]),
            textinfo="label+value",
        )
    )
    fig.update_layout(
        height=260,
        margin=dict(l=10, r=10, t=10, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        font_color="#b6c0cc",
        showlegend=False,
    )
    st.plotly_chart(fig, use_container_width=True)


def card_finding(finding: dict) -> None:
    """Cartão de um achado, com faixa lateral colorida por severidade."""
    sev = finding.get("severity_hint", "info")
    cor = SEVERITY_COLORS.get(sev, "#6b7280")
    cat = finding.get("category", "")

    html = f"""
    <div class="finding" style="border-left-color:{cor}">
      <div class="top">
        {severity_badge_html(sev, SEVERITY_LABELS_PT.get(sev, sev))}
        <span class="badge badge-cat">{CATEGORY_LABELS_PT.get(cat, cat)}</span>
        <span class="title">{_esc(finding.get('title', ''))}</span>
      </div>
      <div class="detail">{_esc(finding.get('detail', ''))}</div>
      <div class="fid">{_esc(finding.get('id', ''))}</div>
    </div>
    """
    st.markdown(html, unsafe_allow_html=True)


def lista_findings(findings: list[dict]) -> None:
    """Lista achados ordenados por severidade (mais grave primeiro)."""
    ordenados = sorted(
        findings,
        key=lambda f: SEVERITY_ORDER.index(f.get("severity_hint", "info")),
    )
    for f in ordenados:
        card_finding(f)


def _esc(texto: str) -> str:
    """Escape mínimo para evitar quebrar o HTML injetado."""
    return (
        str(texto)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
