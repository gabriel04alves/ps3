# Scanner SSL/TLS — Documentação da API

Microsserviço **FastAPI + sslyze** que audita a postura criptográfica (SSL/TLS) de um
servidor web. Recebe um alvo, executa uma varredura **passiva e não destrutiva** e devolve
uma lista normalizada de achados de segurança, já classificados por severidade.

> **Papel na arquitetura.** Este serviço é responsável **apenas pela detecção determinística**.
> A camada de orquestração (dashboard Streamlit) consome a saída deste endpoint e a envia ao
> Gemini para classificação de risco final, priorização e redação de recomendações. O scanner
> **nunca** usa IA — todo achado vem de regras auditáveis sobre os dados do sslyze.
>
> Fluxo: `Usuário → Streamlit → (Scanner /scan, Gemini) → Streamlit (dashboard)`.

**Fonte da verdade dos contratos:** `scanner/models/schemas.py`.

---

## Sumário

- [Scanner SSL/TLS — Documentação da API](#scanner-ssltls--documentação-da-api)
  - [Sumário](#sumário)
  - [Instalação e execução](#instalação-e-execução)
  - [Endpoints](#endpoints)
    - [`GET /health`](#get-health)
    - [`POST /scan`](#post-scan)
  - [Modelos de dados](#modelos-de-dados)
    - [`ScanInput`](#scaninput)
    - [`ScanResponse`](#scanresponse)
    - [`ScanError`](#scanerror)
    - [`Finding`](#finding)
  - [Catálogo de achados](#catálogo-de-achados)
    - [`protocol`](#protocol)
    - [`cipher`](#cipher)
    - [`certificate`](#certificate)
    - [`configuration`](#configuration)
  - [Severidades](#severidades)
  - [Tratamento de erros](#tratamento-de-erros)
  - [Exemplos de integração](#exemplos-de-integração)
    - [cURL](#curl)
    - [Python (`requests`)](#python-requests)
    - [Alvos de teste (badssl.com)](#alvos-de-teste-badsslcom)
  - [Como as regras são definidas](#como-as-regras-são-definidas)
  - [Cuidados conhecidos](#cuidados-conhecidos)

---

## Instalação e execução

Cada componente tem o seu próprio venv e `requirements.txt` (não compartilhar com o dashboard).

```bash
cd scanner
python -m venv venv

# Windows (PowerShell)
.\venv\Scripts\Activate.ps1
# Linux/macOS
# source venv/bin/activate

pip install -r requirements.txt

uvicorn main:app --host 0.0.0.0 --port 8000
```

- Interface interativa (Swagger UI): `http://localhost:8000/docs`
- Esquema OpenAPI bruto: `http://localhost:8000/openapi.json`

Dependências principais (fixadas em `requirements.txt`, **não atualizar sem testar**):
`fastapi`, `uvicorn`, `sslyze==6.3.1`, `pydantic`, `PyYAML`.

---

## Endpoints

Base URL padrão: `http://localhost:8000`

### `GET /health`

Verifica se o serviço está no ar. Não executa varredura. Use para *health check* /
*readiness probe*.

**Resposta `200`**
```json
{ "status": "ok" }
```

---

### `POST /scan`

Executa a varredura SSL/TLS contra um alvo e retorna os achados de segurança.

**Headers**

| Header         | Valor              |
|----------------|--------------------|
| `Content-Type` | `application/json` |

**Corpo da requisição** — [`ScanInput`](#scaninput)

```json
{
  "hostname": "expired.badssl.com",
  "port": 443
}
```

| Campo      | Tipo   | Obrigatório | Padrão | Descrição                        |
|------------|--------|-------------|--------|----------------------------------|
| `hostname` | string | sim         | —      | Host a auditar (sem esquema/URL) |
| `port`     | int    | não         | `443`  | Porta TLS do alvo                |

> **Tempo de resposta: ~30–90 s.** A varredura é remota e real (sslyze abre conexões TLS
> contra o alvo). A requisição é **síncrona** — configure o timeout do cliente para ≥ 120 s.

**Resposta `200` — alvo varrido** — [`ScanResponse`](#scanresponse)

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
    },
    {
      "id": "cfg_no_hsts",
      "category": "configuration",
      "title": "Cabeçalho HSTS ausente",
      "detail": "Sem Strict-Transport-Security, o cliente pode ser rebaixado para HTTP.",
      "severity_hint": "low"
    }
  ]
}
```

**Resposta `200` — alvo inacessível** — [`ScanError`](#scanerror)

Quando o sslyze não consegue estabelecer conectividade TLS com o alvo, o serviço responde
com **status `200`** e um corpo de erro (note `reachable: false` e ausência de `summary`/
`scanned_at`/`total_findings`). O cliente deve **ramificar pelo campo `reachable`**, não pelo
status HTTP.

```json
{
  "target": "host-inexistente.example:443",
  "reachable": false,
  "error": "Servidor inacessível para varredura TLS.",
  "findings": []
}
```

**Resposta `422` — entrada inválida**

Erro padrão de validação do FastAPI (ex.: `hostname` ausente, `port` não numérico).

```json
{
  "detail": [
    {
      "type": "missing",
      "loc": ["body", "hostname"],
      "msg": "Field required"
    }
  ]
}
```

---

## Modelos de dados

Definidos em `scanner/models/schemas.py`.

### `ScanInput`

| Campo      | Tipo   | Padrão | Descrição          |
|------------|--------|--------|--------------------|
| `hostname` | string | —      | Host a auditar     |
| `port`     | int    | `443`  | Porta TLS do alvo  |

### `ScanResponse`

| Campo            | Tipo                  | Descrição                                                        |
|------------------|-----------------------|-----------------------------------------------------------------|
| `target`         | string                | `hostname:port` auditado                                        |
| `scanned_at`     | string (ISO-8601 UTC) | Instante da varredura                                           |
| `reachable`      | bool                  | Sempre `true` neste schema                                      |
| `summary`        | objeto `{sev: int}`   | Contagem de achados por severidade                              |
| `total_findings` | int                   | Total de achados (= `len(findings)`)                            |
| `findings`       | lista de [`Finding`](#finding) | Achados de segurança detectados                        |

### `ScanError`

| Campo       | Tipo   | Descrição                                |
|-------------|--------|------------------------------------------|
| `target`    | string | `hostname:port` que se tentou auditar    |
| `reachable` | bool   | Sempre `false` neste schema              |
| `error`     | string | Mensagem legível do motivo da falha      |
| `findings`  | lista  | Sempre vazia (`[]`)                      |

> O endpoint `/scan` declara `response_model = ScanResponse | ScanError`: a resposta é **uma das
> duas** formas. Distinga-as pelo campo `reachable` (ou pela presença de `summary`).

### `Finding`

| Campo           | Tipo                                                    | Descrição                              |
|-----------------|---------------------------------------------------------|----------------------------------------|
| `id`            | string                                                  | Identificador estável do achado        |
| `category`      | `protocol` \| `cipher` \| `certificate` \| `configuration` | Família do achado                  |
| `title`         | string                                                  | Título curto (PT-BR)                   |
| `detail`        | string                                                  | Descrição do problema (PT-BR)          |
| `severity_hint` | `critical` \| `high` \| `medium` \| `low` \| `info`     | Severidade sugerida pela detecção      |

> `severity_hint` é uma **dica** da camada determinística. A classificação de risco final é
> responsabilidade do dashboard/Gemini, que pode reordenar ou contextualizar.

---

## Catálogo de achados

Lista completa do que o scanner detecta. Os IDs marcados com `*` recebem o nome da cipher suite
como sufixo (ex.: `cipher_rc4_TLS_RSA_WITH_RC4_128_SHA`).

### `protocol`

| `id`                            | Título                              | `severity_hint` |
|---------------------------------|-------------------------------------|-----------------|
| `proto_ssl_2_0_cipher_suites`   | Protocolo obsoleto habilitado: SSLv2 | `critical`     |
| `proto_ssl_3_0_cipher_suites`   | Protocolo obsoleto habilitado: SSLv3 | `critical`     |
| `proto_tls_1_0_cipher_suites`   | Protocolo obsoleto habilitado: TLS 1.0 | `high`       |
| `proto_tls_1_1_cipher_suites`   | Protocolo obsoleto habilitado: TLS 1.1 | `high`       |
| `proto_no_modern`               | Ausência de TLS 1.2/1.3             | `high`          |

### `cipher`

| `id`               | Título                                      | `severity_hint` |
|--------------------|---------------------------------------------|-----------------|
| `cipher_null_*`    | Cipher sem criptografia/autenticação (NULL/anônima) | `critical` |
| `cipher_rc4_*`     | Cipher fraca (RC4)                          | `high`          |
| `cipher_export_*`  | Cipher de exportação                        | `high`          |
| `cipher_3des_*`    | Cipher legada (3DES, Sweet32)               | `medium`        |
| `cipher_md5_*`     | Cipher com MD5                              | `medium`        |
| `cipher_keysize_*` | Chave simétrica fraca (< 128 bits)          | `high`          |

### `certificate`

| `id`                  | Título                          | `severity_hint` |
|-----------------------|---------------------------------|-----------------|
| `cert_expired`        | Certificado expirado            | `critical`      |
| `cert_not_yet_valid`  | Certificado ainda não válido    | `high`          |
| `cert_self_signed`    | Certificado autoassinado        | `high`          |
| `cert_untrusted`      | Certificado não confiável       | `high`          |
| `cert_sha1`           | Assinatura SHA-1 na cadeia      | `medium`        |

### `configuration`

| `id`              | Título                                 | `severity_hint` |
|-------------------|----------------------------------------|-----------------|
| `vuln_heartbleed` | Vulnerável a Heartbleed (CVE-2014-0160) | `critical`     |
| `vuln_ccs`        | Vulnerável a CCS Injection (CVE-2014-0224) | `critical`  |
| `vuln_robot`      | Vulnerável a ROBOT                     | `high`          |
| `vuln_crime`      | Compressão TLS habilitada (CRIME)      | `medium`        |
| `cfg_no_hsts`     | Cabeçalho HSTS ausente                 | `low`           |

---

## Severidades

Ordem decrescente de gravidade:

`critical` › `high` › `medium` › `low` › `info`

Os mesmos cinco valores aparecem em `severity_hint` (por achado) e nas chaves de `summary`
(contagem agregada).

---

## Tratamento de erros

| Situação                              | Status HTTP | Corpo                                  | Como o cliente trata            |
|---------------------------------------|-------------|----------------------------------------|---------------------------------|
| Varredura concluída                   | `200`       | [`ScanResponse`](#scanresponse) (`reachable: true`) | Processar `findings`  |
| Alvo inacessível (sem conectividade TLS) | `200`    | [`ScanError`](#scanerror) (`reachable: false`) | Exibir `error`; não há achados |
| Entrada inválida                      | `422`       | `{ "detail": [...] }`                   | Corrigir o corpo da requisição  |
| Falha interna inesperada              | `500`       | `{ "detail": "Internal Server Error" }` | Reportar/registrar              |

> **Importante:** "alvo inacessível" **não** é `4xx`/`5xx` — é uma resposta `200` de negócio.
> Sempre ramifique pelo campo `reachable` antes de assumir que há `summary`/`findings`.

---

## Exemplos de integração

### cURL

```bash
curl -s -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"hostname": "expired.badssl.com"}'
```

### Python (`requests`)

```python
import requests

resp = requests.post(
    "http://localhost:8000/scan",
    json={"hostname": "expired.badssl.com", "port": 443},
    timeout=120,
)
data = resp.json()

if not data.get("reachable"):
    print("Inacessível:", data["error"])
else:
    print(f"{data['total_findings']} achados — {data['summary']}")
    for f in data["findings"]:
        print(f"[{f['severity_hint'].upper()}] {f['title']}")
```

### Alvos de teste (badssl.com)

Ambiente controlado, somente para validação:

| Alvo                       | Porta | Achado esperado          |
|----------------------------|-------|--------------------------|
| `expired.badssl.com`       | 443   | `cert_expired`           |
| `self-signed.badssl.com`   | 443   | `cert_self_signed`       |
| `rc4.badssl.com`           | 443   | `cipher_rc4_*`           |
| `tls-v1-0.badssl.com`      | 1010  | `proto_tls_1_0_cipher_suites` |

---

## Como as regras são definidas

A detecção de **protocolo** e **cipher** é declarativa, em `scanner/core/rules.yaml` — uma
tabela única e auditável (protocolos inseguros, protocolos modernos exigidos, classes de cipher
fraca por palavra-chave e tamanho mínimo de chave). Para adicionar/ajustar uma regra dessas
famílias, edite o YAML; nenhuma mudança de código é necessária.

A detecção de **certificado** e **vulnerabilidades** (`configuration`) permanece como código
explícito em `scanner/core/normalizer.py`, pois envolve lógica imperativa (datas, cadeia de
confiança, enums do sslyze).

Pipeline interno: `core/scanner.py` (executa o sslyze) → `core/normalizer.py` (extrai achados)
→ `api/routes.py` (monta a resposta).

---

## Cuidados conhecidos

- **Falso "certificado não confiável" atrás de proxy.** Proxies que interceptam TLS (ou a
  ausência do certificado intermediário) podem fazer o sslyze reportar `cert_untrusted`
  incorretamente, e podem até impedir a conectividade (resposta `reachable: false`). Em alvos
  reais acessados diretamente, o comportamento é correto.
- **Somente testes não destrutivos.** A varredura TLS é passiva; não há exploração ativa.
- **Versões fixadas.** Não atualizar o `sslyze` sem testar — APIs de resultado mudam entre
  versões e quebram o `normalizer`.
