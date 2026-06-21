from datetime import datetime, timezone

from sslyze import ScanCommandAttemptStatusEnum, RobotScanResultEnum


def _completed(attempt):
    if attempt is not None and attempt.status == ScanCommandAttemptStatusEnum.COMPLETED:
        return attempt.result
    return None


def _add(findings: list, fid: str, category: str, title: str, detail: str, severity_hint: str):
    findings.append({
        "id": fid,
        "category": category,
        "title": title,
        "detail": detail,
        "severity_hint": severity_hint,
    })


def normalize(scan) -> list:
    """Extrai achados de segurança do resultado bruto do sslyze."""
    findings = []

    _check_protocols(scan, findings)
    _check_ciphers(scan, findings)
    _check_certificate(scan, findings)
    _check_vulnerabilities(scan, findings)

    return findings


def _check_protocols(scan, findings: list):
    protocolos_inseguros = [
        ("ssl_2_0_cipher_suites", "SSLv2", "critical"),
        ("ssl_3_0_cipher_suites", "SSLv3", "critical"),
        ("tls_1_0_cipher_suites", "TLS 1.0", "high"),
        ("tls_1_1_cipher_suites", "TLS 1.1", "high"),
    ]
    for attr, nome, sev in protocolos_inseguros:
        res = _completed(getattr(scan, attr))
        if res and res.accepted_cipher_suites:
            _add(findings, f"proto_{attr}", "protocol",
                 f"Protocolo obsoleto habilitado: {nome}",
                 f"O servidor aceita conexões via {nome}, um protocolo "
                 f"considerado inseguro e que deveria ser desativado.", sev)

    tem_moderno = any(
        (_completed(getattr(scan, a)) and _completed(getattr(scan, a)).accepted_cipher_suites)
        for a in ("tls_1_2_cipher_suites", "tls_1_3_cipher_suites")
    )
    if not tem_moderno:
        _add(findings, "proto_no_modern", "protocol",
             "Ausência de TLS 1.2/1.3",
             "O servidor não oferece TLS 1.2 nem TLS 1.3, os protocolos atuais recomendados.",
             "high")


def _check_ciphers(scan, findings: list):
    cipher_attrs = [
        "ssl_2_0_cipher_suites", "ssl_3_0_cipher_suites",
        "tls_1_0_cipher_suites", "tls_1_1_cipher_suites", "tls_1_2_cipher_suites",
    ]
    ciphers_vistas = set()

    for attr in cipher_attrs:
        res = _completed(getattr(scan, attr))
        if not res:
            continue
        for accepted in res.accepted_cipher_suites:
            cs = accepted.cipher_suite
            nome = cs.name
            if nome in ciphers_vistas:
                continue
            ciphers_vistas.add(nome)
            n = nome.upper()

            if "NULL" in n or cs.is_anonymous:
                _add(findings, f"cipher_null_{nome}", "cipher",
                     f"Cipher sem criptografia/autenticação: {nome}",
                     "Cipher anônima ou NULL não oferece confidencialidade.", "critical")
            elif "RC4" in n:
                _add(findings, f"cipher_rc4_{nome}", "cipher",
                     f"Cipher fraca (RC4): {nome}",
                     "RC4 é vulnerável e não deve ser utilizada.", "high")
            elif "EXPORT" in n:
                _add(findings, f"cipher_export_{nome}", "cipher",
                     f"Cipher de exportação: {nome}",
                     "Ciphers 'export' usam chaves curtas e são quebráveis.", "high")
            elif "3DES" in n or "DES-CBC3" in n:
                _add(findings, f"cipher_3des_{nome}", "cipher",
                     f"Cipher legada (3DES): {nome}",
                     "3DES é lenta e vulnerável (Sweet32).", "medium")
            elif "MD5" in n:
                _add(findings, f"cipher_md5_{nome}", "cipher",
                     f"Cipher com MD5: {nome}",
                     "MD5 é um algoritmo de hash quebrado.", "medium")

            if cs.key_size and cs.key_size < 128:
                _add(findings, f"cipher_keysize_{nome}", "cipher",
                     f"Chave simétrica fraca ({cs.key_size} bits): {nome}",
                     "Tamanho de chave abaixo do recomendado (128 bits).", "high")


def _check_certificate(scan, findings: list):
    cert_res = _completed(scan.certificate_info)
    if not cert_res or not cert_res.certificate_deployments:
        return

    dep = cert_res.certificate_deployments[0]
    chain = dep.received_certificate_chain

    if chain:
        leaf = chain[0]
        agora = datetime.now(timezone.utc)

        try:
            not_after = leaf.not_valid_after_utc
            not_before = leaf.not_valid_before_utc
            if not_after < agora:
                _add(findings, "cert_expired", "certificate",
                     "Certificado expirado",
                     f"O certificado venceu em {not_after.date()}.", "critical")
            elif not_before > agora:
                _add(findings, "cert_not_yet_valid", "certificate",
                     "Certificado ainda não válido",
                     f"O certificado só é válido a partir de {not_before.date()}.", "high")
        except Exception:
            pass

        try:
            if leaf.subject == leaf.issuer:
                _add(findings, "cert_self_signed", "certificate",
                     "Certificado autoassinado",
                     "Emissor e titular são iguais; não há cadeia de confiança.", "high")
        except Exception:
            pass

    problemas_validacao = [
        pv.validation_error for pv in dep.path_validation_results
        if pv.validation_error is not None
    ]
    if problemas_validacao and len(problemas_validacao) == len(dep.path_validation_results):
        _add(findings, "cert_untrusted", "certificate",
             "Certificado não confiável",
             f"A cadeia não validou em nenhuma trust store. Detalhe: {problemas_validacao[0]}",
             "high")

    if dep.verified_chain_has_sha1_signature:
        _add(findings, "cert_sha1", "certificate",
             "Assinatura SHA-1 na cadeia",
             "SHA-1 está obsoleto para assinatura de certificados.", "medium")


def _check_vulnerabilities(scan, findings: list):
    hb = _completed(scan.heartbleed)
    if hb and hb.is_vulnerable_to_heartbleed:
        _add(findings, "vuln_heartbleed", "configuration", "Vulnerável a Heartbleed",
             "Permite leitura de memória do servidor (CVE-2014-0160).", "critical")

    ccs = _completed(scan.openssl_ccs_injection)
    if ccs and ccs.is_vulnerable_to_ccs_injection:
        _add(findings, "vuln_ccs", "configuration", "Vulnerável a CCS Injection",
             "Permite interceptação da comunicação (CVE-2014-0224).", "critical")

    robot = _completed(scan.robot)
    if robot and robot.robot_result in (
        RobotScanResultEnum.VULNERABLE_STRONG_ORACLE,
        RobotScanResultEnum.VULNERABLE_WEAK_ORACLE,
    ):
        _add(findings, "vuln_robot", "configuration", "Vulnerável a ROBOT",
             "Ataque de oráculo Bleichenbacher contra RSA.", "high")

    comp = _completed(scan.tls_compression)
    if comp and comp.supports_compression:
        _add(findings, "vuln_crime", "configuration", "Compressão TLS habilitada (CRIME)",
             "Compressão TLS permite o ataque CRIME.", "medium")

    headers = _completed(scan.http_headers)
    if headers is not None and headers.strict_transport_security_header is None:
        _add(findings, "cfg_no_hsts", "configuration", "Cabeçalho HSTS ausente",
             "Sem Strict-Transport-Security, o cliente pode ser rebaixado para HTTP.", "low")
