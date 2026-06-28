# Scanner — Interface Web (Streamlit)

Dashboard que orquestra o diagnóstico de vulnerabilidades SSL/TLS do **Cenário 1
(Servidor Web)**. Consome o microsserviço **Scanner** (`../scanner`, FastAPI +
sslyze) para a detecção determinística e usa o **Gemini** para classificar o
risco, priorizar os achados e redigir recomendações.

```
Usuário → Streamlit → (Scanner /scan, Gemini) → Streamlit (dashboard)
```

## O que a interface faz

- Coleta o alvo (hostname + porta) e dispara a varredura no Scanner.
- Trata corretamente a resposta de negócio: ramifica por `reachable`, não pelo
  status HTTP (alvo inacessível volta como `200`).
- Enriquece os achados com a IA: **postura de risco geral**, **prioridades de
  correção** e **recomendações** em PT-BR.
- Apresenta o painel: métricas por severidade, gráfico de severidade e de
  categoria, e a lista de achados com faixa colorida.
- Exporta o **relatório** de auditoria em **Markdown e PDF**
  (vulnerabilidades, riscos, recomendações).
- **Cacheia as varreduras** em `app/.cache/`: as últimas 20 ficam disponíveis
  na sidebar para recarregar sem refazer o scan (sslyze leva 30–90 s).
- Atalhos para alvos de teste do `badssl.com` (ambiente controlado).

> Sem `GEMINI_API_KEY` configurada, o app **continua funcional**: a classificação
> cai para uma heurística determinística (maior severidade presente).

## Estrutura

```
app/
├── Scanner_Web_Server.py     # página principal (orquestra o fluxo)
├── config.py                 # configuração central (URLs, chaves, paleta)
├── services/
│   ├── scanner_client.py     # cliente HTTP do microsserviço Scanner
│   ├── gemini_client.py      # camada de IA (classificação de risco)
│   └── cache.py              # cache em disco das últimas varreduras
├── components/
│   ├── styles.py             # CSS / identidade visual
│   ├── findings_view.py      # métricas, gráficos e cards de achados
│   └── report.py             # geração de relatório Markdown e PDF
├── .cache/                   # gerado em runtime; ignorado pelo git
└── .streamlit/
    └── secrets.toml.example  # modelo de configuração (copie p/ secrets.toml)
```

## Pré-requisitos

- Python 3.13+
- Esta pasta (`app/`) tem o seu **próprio** venv e `requirements.txt` — não
  compartilhe com o `scanner/`.
- O microsserviço `scanner/` precisa estar no ar (veja `../scanner/README.md`).

## Configuração

Copie `.streamlit/secrets.toml.example` para `.streamlit/secrets.toml` e
preencha, **ou** defina variáveis de ambiente de mesmo nome:

| Chave            | Padrão                    | Descrição                                  |
|------------------|---------------------------|--------------------------------------------|
| `SCANNER_URL`    | `http://localhost:8000`   | URL do microsserviço Scanner               |
| `GEMINI_API_KEY` | _(vazio)_                 | Chave do Gemini; vazio → heurística        |
| `GEMINI_MODEL`   | `gemini-2.5-flash`        | Modelo Gemini                              |
| `SCAN_TIMEOUT_S` | `300`                     | Timeout da varredura (a varredura é lenta) |

## Como rodar

```bash
cd app

# 1. Crie e ative o venv (só na primeira vez)
python -m venv venv
source venv/bin/activate          # Linux/macOS
# .\venv\Scripts\Activate.ps1     # Windows (PowerShell)

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Garanta o Scanner no ar (em outro terminal, dentro de ../scanner)
#    uvicorn main:app --host 0.0.0.0 --port 8000

# 4. Suba o dashboard
streamlit run Scanner_Web_Server.py
```

Acesse em `http://localhost:8501`. Informe um alvo na barra lateral (ou use um
alvo de teste) e clique em **Iniciar varredura**.

> A varredura é remota, real e síncrona (~1–3 min, podendo ultrapassar em
> alvos com vários protocolos legados ativos). Não execute testes destrutivos;
> use apenas alvos autorizados ou o `badssl.com`.
