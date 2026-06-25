"""Dashboard Scanner SSL/TLS — página principal (Streamlit).

Orquestra o fluxo de auditoria do Cenário 1 (Servidor Web):

    Usuário → Streamlit → (Scanner /scan, Gemini) → Streamlit (dashboard)

Coleta o alvo, dispara a varredura determinística no microsserviço, enriquece
os achados com classificação de risco da IA e apresenta tudo em um painel com
resumo, gráficos, lista de achados e relatório baixável.
"""

from __future__ import annotations

import streamlit as st

from config import (
    APP_TITLE,
    APP_ICON,
    SCANNER_URL,
    SEVERITY_LABELS_PT,
    TEST_TARGETS,
)
from components import styles, findings_view, report
from services import scanner_client
from services.scanner_client import ScannerError
from services import gemini_client

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

        st.divider()
        st.caption("Alvos de teste (badssl.com) — ambiente controlado:")
        for host, p, desc in TEST_TARGETS:
            if st.button(f"{host}:{p}", key=f"t_{host}_{p}", use_container_width=True):
                st.session_state["alvo_teste"] = (host, p)
                st.rerun()

        st.divider()
        usando_ia = bool(gemini_client.GEMINI_API_KEY)
        st.caption(
            f"Classificação de risco: {'IA (Gemini)' if usando_ia else 'heurística'}"
        )

    return hostname, int(port), disparar


def executar(hostname: str, port: int) -> None:
    """Roda varredura + análise e guarda o resultado na sessão."""
    if not hostname.strip():
        st.warning("Informe um hostname antes de iniciar a varredura.")
        return

    try:
        with st.spinner(f"Varrendo {hostname}:{port}… (pode levar 30–90 s)"):
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
    st.download_button(
        "Baixar relatório (Markdown)",
        data=md,
        file_name=f"relatorio_{nome}.md",
        mime="text/markdown",
        use_container_width=True,
    )
    with st.expander("Prévia do relatório"):
        st.markdown(md)


def main() -> None:
    cabecalho()
    hostname, port, disparar = barra_lateral()

    # Alvo de teste escolhido na sidebar tem prioridade
    if "alvo_teste" in st.session_state:
        host_t, port_t = st.session_state.pop("alvo_teste")
        executar(host_t, port_t)
    elif disparar:
        executar(hostname, port)

    painel()


if __name__ == "__main__":
    main()
