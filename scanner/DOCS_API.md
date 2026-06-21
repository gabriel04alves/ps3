# Scanner SSL/TLS — Documentação da API

Microsserviço que audita a postura criptográfica de um servidor web via sslyze.
Faz parte do pipeline (em desenvolvimento): **Streamlit → n8n → Scanner → Gemini → Streamlit**.

---

## Instalação

```bash
# Na raiz do projeto (ps3/)
pip install -r scanner/requirements.txt

uvicorn scanner.main:app --host 0.0.0.0 --port 8000
```

Interface interativa disponível em `http://localhost:8000/docs`.

---

## Endpoints

### `GET /health`

Verifica se o serviço está no ar.

**Resposta**
```json
{ "status": "ok" }
```

---

### `POST /scan`

Executa a varredura SSL/TLS contra um alvo e retorna os achados de segurança.

**Corpo da requisição**
```json
{
  "hostname": "expired.badssl.com",
  "port": 443
}
```

| Campo      | Tipo   | Padrão | Descrição          |
|------------|--------|--------|--------------------|
| `hostname` | string | —      | Host a auditar     |
| `port`     | int    | `443`  | Porta TLS do alvo  |

**Tempo de resposta:** 30–90 s (scan remoto real via sslyze).

**Resposta — sucesso**
```json
{
  "target": "expired.badssl.com:443",
  "scanned_at": "2026-06-21T18:00:00Z",
  "reachable": true,
  "summary": { "critical": 1, "high": 0, "medium": 0, "low": 1, "info": 0 },
  "total_findings": 2,
  "findings": [
    {
      "id": "cert_expired",
      "category": "certificate",
      "title": "Certificado expirado",
      "detail": "O certificado venceu em 2015-04-12.",
      "severity_hint": "critical"
    }
  ]
}
```

**Resposta — alvo inacessível**
```json
{
  "target": "host:443",
  "reachable": false,
  "error": "Servidor inacessível para varredura TLS.",
  "findings": []
}
```

---

## Categorias de achados

| `category`      | O que cobre                                      |
|-----------------|--------------------------------------------------|
| `protocol`      | SSLv2, SSLv3, TLS 1.0/1.1 ativos; ausência de TLS 1.2/1.3 |
| `cipher`        | NULL, RC4, EXPORT, 3DES, MD5, chave < 128 bits  |
| `certificate`   | Expirado, autoassinado, não confiável, SHA-1     |
| `configuration` | Heartbleed, CCS Injection, ROBOT, CRIME, HSTS   |

## Severidades

`critical` › `high` › `medium` › `low` › `info`

---

## Alvos de teste (badssl.com)

```bash
curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"hostname": "expired.badssl.com"}'

# Outros: self-signed.badssl.com | rc4.badssl.com | tls-v1-0.badssl.com
```
