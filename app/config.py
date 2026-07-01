"""Configuração centralizada do dashboard.

Lê variáveis de ambiente (e `st.secrets`, quando disponível) para apontar o
microsserviço Scanner e a chave do Gemini, sem espalhar literais pelo código.
"""

from __future__ import annotations

import os
from pathlib import Path

# Carrega o `.env` da raiz do projeto (um nível acima de app/) para execução
# local sem Docker. `override=False`: variáveis já definidas no ambiente (ex.:
# injetadas pelo Docker Compose) têm precedência sobre o arquivo. Se o
# python-dotenv não estiver instalado, segue sem erro (o app lê do ambiente).
try:
    from dotenv import load_dotenv

    load_dotenv(Path(__file__).resolve().parent.parent / ".env", override=False)
except Exception:
    pass

try:
    import streamlit as st

    _SECRETS = dict(st.secrets) if hasattr(st, "secrets") else {}
except Exception:  # fora do contexto Streamlit (ex.: testes)
    _SECRETS = {}


def _get(chave: str, padrao: str = "") -> str:
    """Resolve um valor olhando primeiro o ambiente, depois `st.secrets`."""
    return os.getenv(chave) or str(_SECRETS.get(chave, padrao))


# --- Scanner (microsserviço FastAPI) ---------------------------------------
SCANNER_URL: str = _get("SCANNER_URL", "http://localhost:8000").rstrip("/")

# A varredura é remota e síncrona (~1–3 min, podendo ultrapassar em alvos com
# muitos protocolos legados ativos). Timeout folgado; pode ser sobrescrito via env var.
SCAN_TIMEOUT_S: int = int(_get("SCAN_TIMEOUT_S", "300"))
HEALTH_TIMEOUT_S: int = int(_get("HEALTH_TIMEOUT_S", "5"))

# --- Gemini (classificação de risco a jusante) -----------------------------
GEMINI_API_KEY: str = _get("GEMINI_API_KEY", "")
GEMINI_MODEL: str = _get("GEMINI_MODEL", "gemini-2.5-flash")

# --- Metadados de UI --------------------------------------------------------
APP_TITLE: str = "Scanner SSL/TLS — Diagnóstico de Vulnerabilidades"
APP_ICON: str = "🔒"

# Ordem canônica de severidade (do README do scanner): critical › … › info.
SEVERITY_ORDER: list[str] = ["critical", "high", "medium", "low", "info"]

# Paleta por severidade (usada em badges, métricas e gráficos).
SEVERITY_COLORS: dict[str, str] = {
    "critical": "#b3203a",
    "high": "#d9534f",
    "medium": "#e8961e",
    "low": "#2f80ed",
    "info": "#6b7280",
}

SEVERITY_LABELS_PT: dict[str, str] = {
    "critical": "Crítico",
    "high": "Alto",
    "medium": "Médio",
    "low": "Baixo",
    "info": "Informativo",
}

CATEGORY_LABELS_PT: dict[str, str] = {
    "protocol": "Protocolo",
    "cipher": "Cipher",
    "certificate": "Certificado",
    "configuration": "Configuração",
}

# Alvos de teste sugeridos (badssl.com) — ambiente controlado, não destrutivo.
TEST_TARGETS: list[tuple[str, int, str]] = [
    ("expired.badssl.com", 443, "Certificado expirado"),
    ("self-signed.badssl.com", 443, "Certificado autoassinado"),
    ("rc4.badssl.com", 443, "Cipher RC4 fraca"),
    ("tls-v1-0.badssl.com", 1010, "Protocolo TLS 1.0 obsoleto"),
]
