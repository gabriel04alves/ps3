"""Dashboard Scanner SSL/TLS — página principal (Streamlit).

Orquestra o fluxo de auditoria do Cenário 1 (Servidor Web):

    Usuário → Streamlit → (Scanner /scan, Gemini) → Streamlit (dashboard)

Coleta o alvo, dispara a varredura determinística no microsserviço, enriquece
os achados com classificação de risco da IA e apresenta tudo em um painel com
resumo, gráficos, lista de achados e relatório baixável.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone

import streamlit as st

from config import (
    APP_TITLE,
    APP_ICON,
    SCANNER_URL,
    SEVERITY_COLORS,
    SEVERITY_LABELS_PT,
    TEST_TARGETS,
)
from components import styles, findings_view, report
from services import scanner_client
from services.scanner_client import ScannerError
from services import gemini_client
from services import cache

st.set_page_config(page_title=APP_TITLE, page_icon=APP_ICON, layout="wide")
styles.inject()


def cabecalho() -> None:
    st.markdown(
        f"""
        <div class="ssl-hero">
          <h1>{APP_ICON} Scanner SSL/TLS</h1>
          <div class="sub">Diagnóstico automatizado de vulnerabilidades · Servidor Web</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def barra_lateral() -> tuple[str, int, bool]:
    """Renderiza a sidebar e devolve (hostname, port, disparar)."""
    with st.sidebar:
        st.subheader("Alvo da auditoria")

        no_ar = scanner_client.health()
        if no_ar:
            st.success(f"Scanner online · {SCANNER_URL}")
        else:
            st.error(f"Scanner offline · {SCANNER_URL}")
            st.caption("Suba o microsserviço: `uvicorn main:app` na pasta `scanner/`.")

        hostname = st.text_input(
            "Hostname", placeholder="exemplo.com", help="Sem esquema/URL (não use https://)."
        )
        port = st.number_input("Porta", min_value=1, max_value=65535, value=443)

        disparar = st.button(
            "Iniciar varredura", type="primary", use_container_width=True, disabled=not no_ar
        )

        st.warning(
            "**Aviso — uso acadêmico.** Esta ferramenta faz parte de um "
            "trabalho acadêmico. Execute varreduras apenas em **ambientes "
            "controlados** (ex.: `badssl.com`) ou em alvos com **autorização "
            "explícita do proprietário**. Varredura sem consentimento pode "
            "violar leis de crimes cibernéticos.",
            icon="⚠️",
        )

        st.divider()
        st.caption("Alvos de teste (badssl.com) — ambiente controlado:")
        for host, p, desc in TEST_TARGETS:
            if st.button(f"{host}:{p}", key=f"t_{host}_{p}", use_container_width=True):
                st.session_state["alvo_teste"] = (host, p)
                st.rerun()

        st.divider()
        _secao_recentes()

        st.divider()
        usando_ia = bool(gemini_client.GEMINI_API_KEY)
        st.caption(
            f"Classificação de risco: {'IA (Gemini)' if usando_ia else 'heurística'}"
        )

    return hostname, int(port), disparar


def _secao_recentes() -> None:
    recentes = cache.listar()
    st.caption(f"Varreduras recentes ({len(recentes)}):")

    if not recentes:
        st.caption("_Nenhuma varredura em cache ainda._")
        return

    for entrada in recentes[:8]:
        slug = entrada["slug"]
        target = entrada["target"]
        sev = entrada.get("overall_risk", "info")
        total = entrada.get("total_findings", 0)
        cor = SEVERITY_COLORS.get(sev, "#6b7280")
        nivel = SEVERITY_LABELS_PT.get(sev, sev)
        quando = _tempo_relativo(entrada.get("ts", 0))

        if st.button(target, key=f"r_{slug}", use_container_width=True):
            st.session_state["carregar_cache"] = slug
            st.rerun()
        st.markdown(
            f'<div style="margin:-0.4rem 0 0.5rem 0.25rem;font-size:0.72rem;'
            f'color:#8b97a7;font-family:\'IBM Plex Mono\',monospace;">'
            f'<span style="color:{cor};font-weight:600;">{nivel}</span>'
            f' · {total} achado(s) · {quando}</div>',
            unsafe_allow_html=True,
        )

    if st.button("Limpar cache", key="cache_clear", use_container_width=True):
        cache.limpar()
        for k in ("resultado", "risco"):
            st.session_state.pop(k, None)
        st.rerun()


def _tempo_relativo(ts: float) -> str:
    if not ts:
        return "—"
    delta = time.time() - ts
    if delta < 60:
        return "agora"
    if delta < 3600:
        return f"há {int(delta // 60)} min"
    if delta < 86400:
        return f"há {int(delta // 3600)} h"
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d")


def executar(hostname: str, port: int) -> None:
    """Roda varredura + análise e guarda o resultado na sessão."""
    if not hostname.strip():
        st.warning("Informe um hostname antes de iniciar a varredura.")
        return

    try:
        with st.spinner(f"Varrendo {hostname}:{port}… (pode levar 1–3 min)"):
            resultado = scanner_client.scan(hostname, port)
    except ScannerError as exc:
        st.error(str(exc))
        return

    if not resultado.ok:
        if not resultado.reachable:
            st.error(f"Alvo inacessível: {resultado.error}")
        else:
            st.error(f"Falha ao processar a varredura: {resultado.error}")
        return

    with st.spinner("Classificando risco e priorizando achados…"):
        risco = gemini_client.avaliar_risco(
            resultado.target, resultado.findings, resultado.summary
        )

    st.session_state["resultado"] = resultado
    st.session_state["risco"] = risco
    cache.salvar(resultado, risco)


def carregar_do_cache(slug: str) -> None:
    dados = cache.carregar(slug)
    if dados is None:
        st.warning("Entrada de cache não encontrada ou corrompida.")
        return
    resultado, risco = dados
    st.session_state["resultado"] = resultado
    st.session_state["risco"] = risco
    st.toast(f"Varredura carregada do cache: {resultado.target}", icon="📦")


def painel() -> None:
    """Renderiza o dashboard a partir do que está na sessão."""
    resultado = st.session_state.get("resultado")
    risco = st.session_state.get("risco")
    if not resultado:
        st.info(
            "Informe um alvo na barra lateral e inicie a varredura. "
            "Ou escolha um dos alvos de teste para ver o painel em ação."
        )
        return

    # Postura de risco geral + fonte da análise
    nivel = SEVERITY_LABELS_PT.get(risco.overall_risk, risco.overall_risk)
    fonte_cls = "source-ai" if risco.usou_ia else "source-heur"
    fonte_txt = "Análise por IA" if risco.usou_ia else "Análise heurística"

    c1, c2 = st.columns([3, 1])
    with c1:
        st.markdown(f"### Postura de risco: **{nivel}**")
        st.write(risco.summary)
    with c2:
        st.markdown(
            f'<span class="source-tag {fonte_cls}">{fonte_txt}</span>',
            unsafe_allow_html=True,
        )
        if risco.erro:
            st.caption(risco.erro)

    st.markdown(f"**Alvo:** `{resultado.target}` · **Achados:** {resultado.total_findings}")
    st.divider()

    findings_view.metricas_severidade(resultado.summary)

    if resultado.total_findings == 0:
        st.success("Nenhum achado de segurança foi detectado nesta varredura. ✅")
    else:
        g1, g2 = st.columns(2)
        with g1:
            st.caption("Achados por severidade")
            findings_view.grafico_severidade(resultado.summary)
        with g2:
            st.caption("Achados por categoria")
            findings_view.grafico_categorias(resultado.findings)

        aba_achados, aba_prio = st.tabs(["Achados detectados", "Prioridades de correção"])
        with aba_achados:
            findings_view.lista_findings(resultado.findings)
        with aba_prio:
            if not risco.prioridades:
                st.info("Sem prioridades calculadas.")
            for i, p in enumerate(risco.prioridades, 1):
                st.markdown(
                    f"""
                    <div class="prio">
                      <span class="rank">#{i} · {p.get('id','')}</span>
                      <div class="motivo">{p.get('motivo','')}</div>
                      <div class="acao"><b>Ação:</b> {p.get('acao','')}</div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

    st.divider()
    md = report.gerar_markdown(resultado, risco)
    nome = resultado.target.replace(":", "_").replace(".", "-")

    col_md, col_pdf = st.columns(2)
    with col_md:
        st.download_button(
            "Baixar relatório (Markdown)",
            data=md,
            file_name=f"relatorio_{nome}.md",
            mime="text/markdown",
            use_container_width=True,
        )
    with col_pdf:
        try:
            pdf_bytes = report.gerar_pdf(resultado, risco)
            st.download_button(
                "Baixar relatório (PDF)",
                data=pdf_bytes,
                file_name=f"relatorio_{nome}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        except Exception as exc:
            st.button(
                "PDF indisponível",
                disabled=True,
                use_container_width=True,
                help=f"Falha ao gerar PDF: {exc}",
            )

    with st.expander("Prévia do relatório"):
        st.markdown(md)


def main() -> None:
    cabecalho()
    hostname, port, disparar = barra_lateral()

    if "carregar_cache" in st.session_state:
        slug = st.session_state.pop("carregar_cache")
        carregar_do_cache(slug)
    elif "alvo_teste" in st.session_state:
        host_t, port_t = st.session_state.pop("alvo_teste")
        executar(host_t, port_t)
    elif disparar:
        executar(hostname, port)

    painel()


if __name__ == "__main__":
    main()
