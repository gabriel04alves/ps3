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
    - [Filosofia: detecção determinística e auditável](#filosofia-detecção-determinística-e-auditável)
    - [Onde fica cada família de regra](#onde-fica-cada-família-de-regra)
    - [Critérios para uma regra existir](#critérios-para-uma-regra-existir)
    - [Como as regras atuais foram selecionadas](#como-as-regras-atuais-foram-selecionadas)
    - [Anatomia do `rules.yaml`](#anatomia-do-rulesyaml)
    - [Como adicionar uma regra (passo a passo)](#como-adicionar-uma-regra-passo-a-passo)
    - [Armadilhas do YAML](#armadilhas-do-yaml)
    - [Como testar uma regra nova](#como-testar-uma-regra-nova)
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
| `reachable` | bool   | `false` se o alvo está inacessível; `true` se o alvo foi alcançado, mas a normalização do resultado falhou |
| `error`     | string | Mensagem legível do motivo da falha      |
| `findings`  | lista  | Sempre vazia (`[]`)                      |

> `ScanError` cobre **dois** cenários, distinguíveis por `reachable`:
> 1. **`reachable: false`** — o sslyze não conseguiu conectividade TLS com o alvo (host fora do
>    ar, porta fechada/filtrada, DNS falhando, porta sem TLS, timeout).
> 2. **`reachable: true`** — o alvo foi varrido com sucesso, mas a etapa de normalização lançou
>    uma exceção ao traduzir o resultado bruto em achados. É uma salvaguarda: em vez de um
>    `500` opaco, o cliente recebe a mensagem do erro.

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

> Esta família é **declarativa** em `rules.yaml` (seção `vulnerabilidades`). Veja
> [Como as regras são definidas](#como-as-regras-são-definidas) para adicionar uma nova.

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
| Falha ao normalizar o resultado       | `200`       | [`ScanError`](#scanerror) (`reachable: true`) | Exibir `error`; alvo foi alcançado, mas o resultado não pôde ser processado |
| Entrada inválida                      | `422`       | `{ "detail": [...] }`                   | Corrigir o corpo da requisição  |
| Falha interna inesperada              | `500`       | `{ "detail": "Internal Server Error" }` | Reportar/registrar              |

> **Importante:** "alvo inacessível" e "falha ao normalizar" **não** são `4xx`/`5xx` — são
> respostas `200` de negócio. Sempre ramifique pelo campo `reachable` antes de assumir que há
> `summary`/`findings`.

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

Esta é a parte mais importante para quem vai **manter ou estender** a detecção. Leia antes de
adicionar qualquer achado novo.

### Filosofia: detecção determinística e auditável

O scanner separa duas responsabilidades que nunca se misturam:

| Camada | Onde | O que faz |
|--------|------|-----------|
| **Varredura** | `core/scanner.py` (sslyze) | Conecta no alvo, negocia TLS, enumera protocolos e ciphers, roda os testes de vulnerabilidade e valida o certificado. Produz um **resultado bruto**. |
| **Interpretação** | `core/normalizer.py` + `core/rules.yaml` | Lê o resultado bruto e o traduz em **achados** (`Finding`) legíveis, com severidade. |

> O `rules.yaml` **não varre nada**. Ele só decide *como interpretar* o que o sslyze já
> coletou. Toda regra aponta para um campo do objeto de resultado do sslyze. Trocar o sslyze
> por outra ferramenta exigiria reescrever esses campos.

Princípio inegociável: **o scanner nunca usa IA e nunca "adivinha".** Todo achado vem de uma
regra explícita e auditável. A classificação de risco final (com IA) é feita a jusante, pelo
dashboard/Gemini — aqui só há detecção determinística.

### Onde fica cada família de regra

| Família (`category`) | Definição | Por quê |
|----------------------|-----------|---------|
| `protocol`           | **YAML** — `protocolos_inseguros`, `protocolos_modernos` | Padrão simples: "atributo X tem ciphers aceitas?" |
| `cipher`             | **YAML** — `cipher_classes`, `cipher_origem`, `cipher_key_size_minimo` | Casamento de palavra-chave no nome + limite numérico |
| `configuration` (vulns) | **YAML** — `vulnerabilidades` | Navegar até um resultado e checar um booleano/None/enum |
| `certificate`        | **Código** — `_check_certificate` em `normalizer.py` | Lógica imperativa: aritmética de datas, comparação de campos, agregação de cadeia de confiança. Generalizar para YAML deixaria a regra *mais* difícil de auditar do que o Python explícito. |

**Regra de bolso:** se a checagem couber em "olhe este campo e compare com um valor/lista",
ela pertence ao YAML. Se exigir lógica condicional encadeada (datas, travessia de objetos
aninhados), mantenha em Python.

### Critérios para uma regra existir

Antes de adicionar um achado, ele deve atender a **todos** os critérios abaixo:

1. **Determinístico.** A presença do problema é decidível a partir do resultado do sslyze, sem
   julgamento subjetivo nem IA.
2. **Acionável.** Há uma recomendação concreta para o operador do servidor (desabilitar um
   protocolo, trocar uma cipher, renovar um certificado).
3. **Não destrutivo.** Deriva apenas de dados que o sslyze já coleta passivamente. O scanner
   **não** faz exploração ativa.
4. **Severidade defensável.** A `severity_hint` segue um consenso reconhecível (ex.: SSLv2/v3 e
   Heartbleed são `critical`; HSTS ausente é `low`). Lembre que é uma **dica** — o dashboard
   pode recontextualizar.
5. **ID estável.** O `id` é um contrato consumido a jusante; uma vez publicado, **não muda**.

### Como as regras atuais foram selecionadas

O conjunto inicial cobre os problemas TLS clássicos e amplamente consensuais, alinhados a guias
como o SSL Labs / Mozilla TLS:

- **Protocolos** — SSLv2 e SSLv3 são `critical` (criptografia quebrada: DROWN, POODLE); TLS 1.0
  e 1.1 são `high` (depreciados pela IETF em 2021). A ausência de TLS 1.2/1.3 é `high` porque
  indica um servidor incapaz de negociar criptografia atual.
- **Ciphers** — selecionadas por classe de fraqueza conhecida: `NULL`/anônima (sem
  confidencialidade), `RC4` (quebrada), `EXPORT` (chaves curtas propositais — FREAK/Logjam),
  `3DES` (Sweet32), `MD5` (hash quebrado), e qualquer chave simétrica `< 128 bits`.
- **Vulnerabilidades** — CVEs/ataques que o próprio sslyze já testa nativamente: Heartbleed,
  CCS Injection, ROBOT, CRIME (compressão TLS). HSTS ausente entra como higiene de
  configuração `low`.
- **Certificado** — os estados que invalidam a confiança: expirado, ainda-não-válido,
  autoassinado, cadeia não confiável e assinatura SHA-1.

A escolha foi deliberadamente **conservadora**: só entram achados de alto consenso e baixo
falso-positivo. Isso mantém o YAML auditável "numa só visão" e a saída confiável para a camada
de IA a jusante.

### Anatomia do `rules.yaml`

O arquivo tem quatro blocos. Os textos aceitam placeholders `{nome}` (nome do protocolo ou da
cipher) e `{key_size}` (tamanho da chave), preenchidos em tempo de execução.

**1. Protocolos** — `protocolos_inseguros` gera um achado se o atributo tiver ciphers aceitas;
`protocolos_modernos` lista os atributos cuja ausência total dispara `proto_no_modern`.

```yaml
protocolos_inseguros:
  - attr: ssl_3_0_cipher_suites   # atributo no objeto de scan do sslyze
    nome: SSLv3                    # rótulo exibido em {nome}
    severity: critical

protocolos_modernos:
  - tls_1_2_cipher_suites
  - tls_1_3_cipher_suites
```

**2. Ciphers** — `cipher_origem` diz de quais protocolos enumerar as ciphers; `cipher_classes`
é avaliado **em ordem** (a primeira classe que casa vence, como um `elif`); `cipher_key_size_minimo`
é avaliado à parte.

```yaml
cipher_classes:
  - id: rc4
    keywords: [RC4]          # casa por substring no nome da cipher (MAIÚSCULAS)
    severity: high
    title: "Cipher fraca (RC4): {nome}"
    detail: "RC4 é vulnerável e não deve ser utilizada."
  - id: "null"
    keywords: ["NULL"]       # veja "Armadilhas do YAML" abaixo
    anonymous: true          # também casa quando cs.is_anonymous for verdadeiro
    severity: critical
    title: "Cipher sem criptografia/autenticação: {nome}"
    detail: "Cipher anônima ou NULL não oferece confidencialidade."
```

**3. Tamanho mínimo de chave** — `cipher_key_size_minimo`: dispara quando `key_size < bits`.

**4. Vulnerabilidades** — cada regra navega até um `result` (atributo do scan), lê um `attr` e
aplica um operador `op`. Se o comando de scan não tiver **completado**, a regra é ignorada.

| `op`      | Dispara quando…                              | Campo extra |
|-----------|----------------------------------------------|-------------|
| `is_true` | o atributo é verdadeiro (flag booleana)      | —           |
| `is_none` | o atributo é `None` (ex.: cabeçalho ausente) | —           |
| `in_enum` | o `.name` do atributo está em `values`       | `values:`   |

```yaml
vulnerabilidades:
  - id: vuln_heartbleed
    result: heartbleed                  # scan.heartbleed
    attr: is_vulnerable_to_heartbleed   # campo preenchido pelo sslyze
    op: is_true
    severity: critical
    title: "Vulnerável a Heartbleed"
    detail: "Permite leitura de memória do servidor (CVE-2014-0160)."
  - id: vuln_robot
    result: robot
    attr: robot_result
    op: in_enum
    values: [VULNERABLE_STRONG_ORACLE, VULNERABLE_WEAK_ORACLE]
    severity: high
    title: "Vulnerável a ROBOT"
    detail: "Ataque de oráculo Bleichenbacher contra RSA."
```

Toda regra de `vulnerabilidades` produz um achado da categoria `configuration`.

### Como adicionar uma regra (passo a passo)

Exemplo: sinalizar uma nova vulnerabilidade que o sslyze já testa.

1. **Confirme o campo no sslyze.** Descubra o atributo do resultado e o campo a ler (ex.:
   `scan.<result>.<attr>`). Os nomes do YAML têm que bater **exatamente** com a API do sslyze.
2. **Escolha o operador** (`is_true` / `is_none` / `in_enum`) conforme o tipo do campo.
3. **Defina um `id` estável** e único (será contrato a jusante).
4. **Escreva `title`/`detail` em PT-BR** e atribua `severity` segundo os
   [critérios](#critérios-para-uma-regra-existir).
5. **Adicione o bloco no `rules.yaml`.** Nenhuma mudança em `normalizer.py` é necessária para
   protocolo/cipher/vulnerabilidade.
6. **Atualize esta documentação** — a tabela no [Catálogo de achados](#catálogo-de-achados).
7. **Teste** (veja abaixo).

> Para um achado de **certificado**, é diferente: ele exige editar `_check_certificate` em
> `normalizer.py`, pois não é coberto pelo motor declarativo.

### Armadilhas do YAML

- **`NULL`, `Null`, `null`, `~`, `yes`/`no`, `on`/`off` têm significado especial em YAML.**
  `keywords: [NULL]` é interpretado como `[None]` (não como a string `"NULL"`) e quebra o
  casamento de ciphers com `TypeError`. **Sempre coloque entre aspas** valores que devem ser
  texto literal: `keywords: ["NULL"]`.
- **A ordem em `cipher_classes` importa** — a primeira classe que casa interrompe a avaliação.
  Coloque as classes mais específicas/graves primeiro.
- **`attr`/`result`/`values` precisam refletir a versão fixada do sslyze** (`6.3.1`). Atualizar
  o sslyze pode renomear campos e silenciosamente desativar regras.

### Como testar uma regra nova

A varredura real leva ~30–90 s; para iterar rápido, exercite o normalizador com um resultado
**falso** (sem rede), validando a regra de forma isolada:

```python
from types import SimpleNamespace as NS
from sslyze import ScanCommandAttemptStatusEnum as S
from core import normalizer

def attempt(result):           # simula um comando de scan COMPLETADO
    return NS(status=S.COMPLETED, result=result)

scan = NS(
    heartbleed=attempt(NS(is_vulnerable_to_heartbleed=True)),
    # ... demais resultados que sua regra consulta ...
)
findings = []
normalizer._check_vulnerabilities(scan, findings)
print([f["id"] for f in findings])   # deve conter o id da sua regra nova
```

Para um teste ponta a ponta, use os [alvos de teste do badssl.com](#alvos-de-teste-badsslcom).

Pipeline interno completo: `core/scanner.py` (executa o sslyze) → `core/normalizer.py` +
`core/rules.yaml` (extrai achados) → `api/routes.py` (monta a resposta).

---

## Cuidados conhecidos

- **Falso "certificado não confiável" atrás de proxy.** Proxies que interceptam TLS (ou a
  ausência do certificado intermediário) podem fazer o sslyze reportar `cert_untrusted`
  incorretamente, e podem até impedir a conectividade (resposta `reachable: false`). Em alvos
  reais acessados diretamente, o comportamento é correto.
- **Somente testes não destrutivos.** A varredura TLS é passiva; não há exploração ativa.
- **Versões fixadas.** Não atualizar o `sslyze` sem testar — APIs de resultado mudam entre
  versões e quebram o `normalizer`.
