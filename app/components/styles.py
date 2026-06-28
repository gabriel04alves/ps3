"""Identidade visual do dashboard (CSS injetado no Streamlit).

Direção de arte: *control room* de auditoria — superfícies em ardósia escura,
dados técnicos em monoespaçada, acentos codificados por severidade. O alvo de
auditoria (TLS) é técnico e sério, então a UI privilegia legibilidade de dados
sobre ornamento. O elemento de assinatura é a faixa de severidade colorida à
esquerda de cada achado.
"""

from __future__ import annotations

import streamlit as st

from config import SEVERITY_COLORS

_CSS = f"""
<style>
  /* --- Tipografia e base --------------------------------------------- */
  @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap');

  html, body, [class*="css"] {{
    font-family: 'IBM Plex Sans', -apple-system, sans-serif;
  }}

  .stApp {{ background: #0f1419; }}

  /* Cabeçalho do app */
  .ssl-hero {{
    border-left: 4px solid #2f80ed;
    padding: 0.2rem 0 0.2rem 1rem;
    margin-bottom: 0.5rem;
  }}
  .ssl-hero h1 {{
    font-size: 1.65rem; font-weight: 700; color: #e8edf2;
    margin: 0; letter-spacing: -0.01em;
  }}
  .ssl-hero .sub {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.8rem; color: #8b97a7; margin-top: 0.25rem;
  }}

  /* --- Cartão de achado ---------------------------------------------- */
  .finding {{
    background: #161c24;
    border: 1px solid #232d39;
    border-left-width: 5px;
    border-radius: 6px;
    padding: 0.85rem 1rem;
    margin-bottom: 0.6rem;
  }}
  .finding .top {{
    display: flex; align-items: center; gap: 0.6rem;
    flex-wrap: wrap; margin-bottom: 0.35rem;
  }}
  .finding .title {{
    font-weight: 600; font-size: 1rem; color: #e8edf2;
  }}
  .finding .detail {{
    color: #b6c0cc; font-size: 0.9rem; line-height: 1.45;
  }}
  .finding .fid {{
    font-family: 'IBM Plex Mono', monospace;
    font-size: 0.72rem; color: #6b7787;
    margin-top: 0.4rem;
  }}

  /* Badges */
  .badge {{
    display: inline-block; padding: 0.1rem 0.55rem;
    border-radius: 999px; font-size: 0.7rem; font-weight: 600;
    text-transform: uppercase; letter-spacing: 0.03em;
  }}
  .badge-cat {{
    background: #1d2630; color: #9fb0c2;
    border: 1px solid #2c3a49;
    font-family: 'IBM Plex Mono', monospace;
  }}

  /* --- Faixa de prioridade (IA) -------------------------------------- */
  .prio {{
    background: #131922; border: 1px solid #232d39;
    border-radius: 6px; padding: 0.7rem 0.9rem; margin-bottom: 0.5rem;
  }}
  .prio .rank {{
    font-family: 'IBM Plex Mono', monospace; font-weight: 600;
    color: #2f80ed; font-size: 0.85rem;
  }}
  .prio .motivo {{ color: #b6c0cc; font-size: 0.88rem; margin: 0.2rem 0; }}
  .prio .acao {{ color: #7fd1a3; font-size: 0.88rem; }}
  .prio .acao b {{ color: #9be3bd; }}

  /* Selo de fonte da análise (IA vs heurística) */
  .source-tag {{
    font-family: 'IBM Plex Mono', monospace; font-size: 0.72rem;
    padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 500;
  }}
  .source-ai {{ background: #16302a; color: #7fd1a3; border: 1px solid #1f4438; }}
  .source-heur {{ background: #2e2718; color: #e8b85a; border: 1px solid #463a1f; }}

  /* Reduz padding superior do container principal */
  .block-container {{ padding-top: 2rem; }}
</style>
"""


def inject() -> None:
    """Aplica o CSS global. Chamar uma vez no topo da página."""
    st.markdown(_CSS, unsafe_allow_html=True)


def severity_badge_html(severity: str, label: str) -> str:
    """Badge inline colorido por severidade."""
    cor = SEVERITY_COLORS.get(severity, "#6b7280")
    return (
        f'<span class="badge" style="background:{cor}22;color:{cor};'
        f'border:1px solid {cor}66">{label}</span>'
    )
