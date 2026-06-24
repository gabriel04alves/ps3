# Scanner — Interface Web (Streamlit)

Dashboard que consome o microsserviço Scanner SSL/TLS. **Em estágio inicial** — hoje há apenas
um *hello world* (`Scanner_Web_Server.py`) para validar o ambiente antes do desenvolvimento da
interface.

## Pré-requisitos

- Python 3.13+
- Esta pasta (`app/`) tem o seu **próprio** venv e `requirements.txt` — não compartilhe com o `scanner/`.

## Como rodar o teste

```bash
cd app

# 1. Crie e ative o venv (só na primeira vez)
python -m venv venv
source venv/bin/activate          # Linux/macOS
# .\venv\Scripts\Activate.ps1     # Windows (PowerShell)

# 2. Instale as dependências
pip install -r requirements.txt

# 3. Suba o app
streamlit run Scanner_Web_Server.py
```

Acesse em `http://localhost:8501`. Você deve ver a página "Hello, World! 🔒".

Para parar: `Ctrl+C` no terminal.

> Sem ativar o venv? Rode direto com `venv/bin/streamlit run Scanner_Web_Server.py`.
