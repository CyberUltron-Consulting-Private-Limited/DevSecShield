"""Inline nginx, Apache, and OpenSSH posture facts, plus DH prime sizes."""

from __future__ import annotations

from aibom.cbom.posture.dhparam import _prime_bits, prime_bits
from aibom.cbom.posture.extract_common import listener_reader
from aibom.cbom.posture.extract_servers import extract_servers, server_facts
from aibom.cbom.posture.model import BasisEntry, EncryptionFact


def _basis(fact: EncryptionFact) -> dict[str, str | None]:
    return {item.name: item.value for item in fact.basis}


def _der_len(length: int) -> bytes:
    if length < 0x80:
        return bytes((length,))
    body = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes((0x80 | len(body),)) + body


def _der_integer(value: int) -> bytes:
    width = max(1, (value.bit_length() + 7) // 8)
    raw = value.to_bytes(width, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return b"\x02" + _der_len(len(raw)) + raw


def _pkcs3(bits: int) -> bytes:
    """SEQUENCE of two INTEGERs: a prime of ``bits`` and base 2."""
    prime = (1 << (bits - 1)) | 1
    body = _der_integer(prime) + _der_integer(2)
    return b"\x30" + _der_len(len(body)) + body


def test_nginx_include_is_not_a_second_entry() -> None:
    files = {
        "nginx.conf": "http {\n  include conf.d/x.conf;\n}\n",
        "conf.d/x.conf": "server {\n  listen 443 ssl;\n}\n",
    }
    facts = server_facts(files)
    assert len(facts) == 1
    assert facts[0].path == "nginx.conf"
    assert _basis(facts[0])["listen"] == "443"


def test_apache_sslprotocol_keeps_the_floor_and_later_tokens() -> None:
    text = "<VirtualHost *:443>\nSSLProtocol TLSv1.2 TLSv1.3\n</VirtualHost>\n"
    fact = extract_servers(text, "httpd.conf")[0]
    assert _basis(fact)["protocols"] == "TLSv1.2,TLSv1.3"
    assert _basis(fact)["protocol_min"] == "TLSv1.2"


def test_ssl_on_makes_the_listen_encrypted(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443;\n  ssl on;\n}\n",
        encoding="utf-8",
    )
    enabled = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in enabled.flags}
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in enabled.flags}
    fact = next(
        comp
        for comp in enabled.components
        if (comp.properties or {}).get("crypto:factNativeType") == "nginx"
    )
    assert (fact.properties or {}).get("crypto:factVerdict") == "ENCRYPTED_DECLARED"
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 80;\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    mixed = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in mixed.flags}


def test_nginx_listen_keeps_the_bind_address() -> None:
    text = "server {\n  listen 443 ssl;\n  listen [::]:80;\n}\n"
    fact = extract_servers(text, "nginx.conf")[0]
    assert _basis(fact)["listen"] == "443,[::]:80"
    bound = "server {\n  listen 0.0.0.0:443 ssl;\n  listen [::]:80;\n}\n"
    both = extract_servers(bound, "nginx.conf")[0]
    assert _basis(both)["listen"] == "0.0.0.0:443,[::]:80"


def test_proxy_verify_off_disables_tls_checks(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  proxy_ssl_verify off;\n}\n",
        encoding="utf-8",
    )
    alone = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in alone.flags}
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  proxy_pass https://backend.example;\n"
        "  proxy_ssl_verify off;\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" in {flag.code for flag in result.flags}
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLProxyVerify none\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    missing = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in missing.flags}
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLProxyEngine on\n"
        "SSLProxyVerify none\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" in {flag.code for flag in apache.flags}


def test_http_redirect_stays_unencrypted_in_transit(tmp_path) -> None:
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 80;\n"
        "  return 301 http://example.com$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    run = normalize_crypto(result, duration_of_scan=0.0)
    fact = next(
        row for row in run["cbom_posture"]["facts"] if row["kind"] == "tls_endpoint"
    )
    assert fact["verdict"] == "NOT_ENCRYPTED"
    assert "UNENCRYPTED_IN_TRANSIT" in fact["finding_codes"]


def test_apache_http_redirect_is_not_declared_encrypted(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "Redirect / http://example.com/\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    fact = next(comp for comp in result.components if comp.kind == "infra")
    props = fact.properties or {}
    assert props["crypto:factVerdict"] == "UNKNOWN"
    assert "UNENCRYPTED_IN_TRANSIT" not in {
        flag.code for flag in result.flags
    }


def test_https_redirect_is_not_an_unencrypted_listener(tmp_path) -> None:
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 80;\n"
        "  return 301 https://example.com$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    run = normalize_crypto(result, duration_of_scan=0.0)
    fact = next(
        row for row in run["cbom_posture"]["facts"] if row["kind"] == "tls_endpoint"
    )
    assert fact["verdict"] == "ENCRYPTED_DECLARED"
    assert fact["finding_codes"] == []
    assert result.flags == []
    assert "PLAINTEXT_LISTENER" not in fact["finding_codes"]


def test_apache_listen_80_is_a_plaintext_listener(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text("Listen 80\n", encoding="utf-8")
    result = scan_crypto(tmp_path)
    codes = {flag.code for flag in result.flags}
    assert "PLAINTEXT_LISTENER" in codes
    assert "UNENCRYPTED_IN_TRANSIT" in codes


def test_apache_sslengine_on_is_not_plaintext(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "Listen 443\nSSLEngine on\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in result.flags}
    fact = next(comp for comp in result.components if comp.kind == "infra")
    assert (fact.properties or {})["crypto:factVerdict"] == "ENCRYPTED_DECLARED"


def test_plaintext_nginx_listener_is_unencrypted_in_transit(tmp_path) -> None:
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 80;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    run = normalize_crypto(result, duration_of_scan=0.0)
    fact = next(
        row for row in run["cbom_posture"]["facts"] if row["kind"] == "tls_endpoint"
    )
    assert fact["verdict"] == "NOT_ENCRYPTED"
    assert "UNENCRYPTED_IN_TRANSIT" in fact["finding_codes"]
    assert "PLAINTEXT_LISTENER" in fact["finding_codes"]


def test_nginx_tls_10_is_a_weak_protocol(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props["crypto:protocolVersion"] == "TLSv1"
    assert props["crypto:strength"] == "weak"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_apache_tls_10_is_a_weak_protocol(tmp_path) -> None:
    from aibom.cbom.normalize import normalize_crypto
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "SSLEngine on\nSSLProtocol TLSv1\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}
    run = normalize_crypto(result, duration_of_scan=0.0)
    fact = next(
        row for row in run["cbom_posture"]["facts"] if row["kind"] == "tls_endpoint"
    )
    assert fact["net"]["protocols"]["1.0"] == "offered"


def test_nginx_tls_12_is_not_a_weak_protocol(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.2 TLSv1.3;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props["crypto:protocolVersion"] == "TLSv1.2"
    assert "crypto:strength" not in props
    assert "WEAK_PROTOCOL" not in {flag.code for flag in result.flags}


def test_weak_nginx_cipher_is_a_protocol_finding(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_ciphers DES-CBC3-SHA;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in result.flags}


def test_strong_nginx_cipher_is_not_a_weak_suite(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n"
        "}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in result.flags}
    from aibom.cbom.normalize import normalize_crypto

    run = normalize_crypto(result, duration_of_scan=0.0)
    fact = next(
        row for row in run["cbom_posture"]["facts"] if row["kind"] == "tls_endpoint"
    )
    # Strong suites must not produce weak_suites; listen may still appear in net.
    assert "weak_suites" not in fact.get("net", {})


def test_weak_apache_cipher_is_a_protocol_finding(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "SSLEngine on\nSSLCipherSuite DES-CBC3-SHA\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in result.flags}


def _linked_cert(result, native: str, source: str) -> bool:
    fact = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == native
    )
    src = f"crypto-cfg_{(fact.properties or {}).get('crypto:factId')}"
    certs = {
        comp.bom_ref
        for comp in result.components
        if (comp.properties or {}).get("crypto:assetType") == "certificate"
        and (comp.properties or {}).get("discovery:source") == source
    }
    return any(
        edge.src == src and edge.rel == "depends_on" and edge.dst in certs
        for edge in result.edges
    )


def test_envoy_client_certificate_is_not_disabled_verification(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - filter_chains:\n"
        "        - transport_socket:\n"
        "            typed_config:\n"
        "              require_client_certificate: true\n",
        encoding="utf-8",
    )
    required = scan_crypto(tmp_path)
    assert "required" in _recorded(required, "envoy")
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in required.flags}
    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - filter_chains:\n"
        "        - transport_socket:\n"
        "            typed_config:\n"
        "              require_client_certificate: false\n",
        encoding="utf-8",
    )
    optional = scan_crypto(tmp_path)
    assert '"client_auth"' in _recorded(optional, "envoy")
    assert "none" in _recorded(optional, "envoy")
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in optional.flags}


def test_database_certificate_files_link_the_scanned_pem(tmp_path) -> None:
    from pathlib import Path

    from aibom.cbom.pipeline import scan_crypto

    pem = (
        Path(__file__).parent / "fixtures" / "synthetic-crypto-certs" / "strong.pem"
    )
    (tmp_path / "server.pem").write_bytes(pem.read_bytes())
    (tmp_path / "my.cnf").write_text(
        "[mysqld]\nssl_cert = server.pem\n",
        encoding="utf-8",
    )
    mysql = scan_crypto(tmp_path)
    assert _linked_cert(mysql, "mysql", "server.pem")
    (tmp_path / "my.cnf").unlink()
    (tmp_path / "mongod.conf").write_text(
        "net:\n  tls:\n    certificateKeyFile: server.pem\n",
        encoding="utf-8",
    )
    mongo = scan_crypto(tmp_path)
    assert _linked_cert(mongo, "mongodb", "server.pem")


def test_compose_long_bind_pins_the_httpd_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: httpd:2.4.58\n"
        "    volumes:\n"
        "      - type: bind\n"
        "        source: ./httpd.conf\n"
        "        target: /usr/local/apache2/conf/httpd.conf\n",
        encoding="utf-8",
    )
    pinned = scan_crypto(tmp_path)
    protocol = next(comp for comp in pinned.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in pinned.flags}
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: httpd:2.4.16\n"
        "    volumes:\n"
        "      - type: bind\n"
        "        source: ./other.conf\n"
        "        target: /usr/local/apache2/conf/httpd.conf\n",
        encoding="utf-8",
    )
    other = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(other, "apache_httpd")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in other.flags}


def test_httpd_image_pin_sets_the_default_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text("FROM httpd:2.4.16\n", encoding="utf-8")
    old = scan_crypto(tmp_path)
    protocol = next(comp for comp in old.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "SSLv3"
    assert "WEAK_PROTOCOL" in {flag.code for flag in old.flags}
    (tmp_path / "Dockerfile").write_text("FROM httpd:2.4.58\n", encoding="utf-8")
    current = scan_crypto(tmp_path)
    later = next(comp for comp in current.components if comp.name == "TLS")
    assert (later.properties or {}).get("crypto:protocolVersion") == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in current.flags}
    (tmp_path / "Dockerfile").write_text("FROM nginx:1.27.3\n", encoding="utf-8")
    other = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(other, "apache_httpd")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in other.flags}


def test_compose_bind_mount_sets_the_nginx_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27.3\n"
        "    volumes:\n"
        "      - ./nginx.conf:/etc/nginx/nginx.conf\n",
        encoding="utf-8",
    )
    mounted = scan_crypto(tmp_path)
    protocol = next(comp for comp in mounted.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "TLSv1.2"
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.25\n"
        "    volumes:\n"
        "      - ./other.conf:/etc/nginx/nginx.conf\n",
        encoding="utf-8",
    )
    other = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(other, "nginx")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in other.flags}


def test_nginx_pin_uses_the_last_image_and_the_same_directory(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM nginx:1.25 AS build\nFROM nginx:1.27.3-alpine\n",
        encoding="utf-8",
    )
    last = scan_crypto(tmp_path)
    protocol = next(comp for comp in last.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "TLSv1.2"
    (tmp_path / "Dockerfile").write_text(
        "FROM nginx:1.25-alpine\n",
        encoding="utf-8",
    )
    variant = scan_crypto(tmp_path)
    older = next(comp for comp in variant.components if comp.name == "TLS")
    assert (older.properties or {}).get("crypto:protocolVersion") == "TLSv1"
    (tmp_path / "Dockerfile").unlink()
    nested = tmp_path / "images"
    nested.mkdir()
    (nested / "Dockerfile").write_text("FROM nginx:1.27.3\n", encoding="utf-8")
    missed = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(missed, "nginx")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in missed.flags}


def test_nginx_image_pin_sets_the_default_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (tmp_path / "Dockerfile").write_text(
        "FROM nginx:1.27.3-alpine\n",
        encoding="utf-8",
    )
    modern = scan_crypto(tmp_path)
    protocol = next(comp for comp in modern.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in modern.flags}
    (tmp_path / "Dockerfile").write_text("FROM nginx:1.25\n", encoding="utf-8")
    older = scan_crypto(tmp_path)
    weak = next(comp for comp in older.components if comp.name == "TLS")
    assert (weak.properties or {}).get("crypto:protocolVersion") == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in older.flags}
    (tmp_path / "Dockerfile").write_text("FROM nginx:latest\n", encoding="utf-8")
    floating = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(floating, "nginx")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in floating.flags}


def test_nginx_http_protocol_applies_when_the_server_omits_it(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "http {\n"
        "  ssl_protocols TLSv1;\n"
        "  server {\n"
        "    listen 443 ssl;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    inherited = scan_crypto(tmp_path)
    protocol = next(comp for comp in inherited.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in inherited.flags}
    (tmp_path / "nginx.conf").write_text(
        "http {\n"
        "  ssl_protocols TLSv1;\n"
        "  server {\n"
        "    listen 443 ssl;\n"
        "    ssl_protocols TLSv1.2;\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    closer = scan_crypto(tmp_path)
    chosen = next(comp for comp in closer.components if comp.name == "TLS")
    assert (chosen.properties or {}).get("crypto:protocolVersion") == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in closer.flags}


def test_missing_protocol_directive_is_version_dependent(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(apache, "apache_httpd")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in apache.flags}
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert "provider_version_dependent" in _recorded(nginx, "nginx")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in nginx.flags}
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1.2;\n}\n",
        encoding="utf-8",
    )
    pinned = scan_crypto(tmp_path)
    assert "provider_version_dependent" not in _recorded(pinned, "nginx")


def test_apache_conditionals_do_not_set_the_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "<If \"%{HTTPS} == 'on'\">\n"
        "SSLProtocol TLSv1\n"
        "</If>\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    hidden = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {flag.code for flag in hidden.flags}
    assert "unresolved_expression" in _recorded(hidden, "apache_httpd")
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLProtocol TLSv1.2\n"
        "<If \"%{HTTPS} == 'on'\">\n"
        "SSLProtocol TLSv1\n"
        "</If>\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    kept = scan_crypto(tmp_path)
    protocol = next(comp for comp in kept.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:protocolVersion") == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in kept.flags}
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "<IfModule ssl_module>\n"
        "SSLProtocol TLSv1\n"
        "</IfModule>\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    module = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" in {flag.code for flag in module.flags}


def test_apache_cipher_suite_ignores_a_leading_protocol_word(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLCipherSuite TLSv1.2 DES-CBC3-SHA\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    suite = (protocol.properties or {}).get("crypto:cipherSuite", "")
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in result.flags}


def test_apache_protocol_arithmetic(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def version(text: str) -> tuple[str | None, set[str]]:
        (tmp_path / "httpd.conf").write_text(
            "<VirtualHost *:443>\n"
            "SSLEngine on\n"
            f"SSLProtocol {text}\n"
            "</VirtualHost>\n",
            encoding="utf-8",
        )
        result = scan_crypto(tmp_path)
        codes = {flag.code for flag in result.flags}
        asset = next(
            (
                comp
                for comp in result.components
                if comp.name == "TLS"
                and (comp.properties or {}).get("crypto:policyName") is None
            ),
            None,
        )
        found = None if asset is None else (asset.properties or {}).get(
            "crypto:protocolVersion"
        )
        return found, codes

    assert version("all -SSLv3") == ("TLSv1", {"WEAK_PROTOCOL"})
    assert version("-all +TLSv1.2") == ("TLSv1.2", set())
    assert version("-all +TLSv1.2 +TLSv1.3") == ("TLSv1.2", set())
    assert version("all -SSLv3 -TLSv1 -TLSv1.1") == ("TLSv1.2", set())
    assert version("all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1") == ("TLSv1.2", set())
    assert version("all all -SSLv2 -SSLv3 -TLSv1 -TLSv1.1") == ("TLSv1.2", set())
    assert version("TLSv1") == ("TLSv1", {"WEAK_PROTOCOL"})
    assert version("+SSLv2") == (None, set())
    assert version("${PROTO}") == (None, set())
    assert version("TLSv1.2 +TLSv1.3") == ("TLSv1.2", set())
    bounded, codes = version("TLSv1.2 TLSv1.3")
    assert bounded == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in codes
    assert "floor_is_bound" in _recorded(scan_crypto(tmp_path), "apache_httpd")
    assert version("TLSv1 TLSv1.2") == (None, set())
    assert version("-all") == (None, set())


def test_required_rsa_size_is_recorded(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "sshd_config").write_text(
        "Port 22\nRequiredRSASize 1024\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    recorded = _recorded(result, "sshd_config")
    assert "required_rsa_size" in recorded
    assert "1024" in recorded
    assert "WEAK_KEY_SIZE" not in {flag.code for flag in result.flags}


def test_cipher_order_and_compression_raise_no_finding(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_prefer_server_ciphers on;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert "prefer_server_ciphers" in _recorded(nginx, "nginx")
    assert '"on"' in _recorded(nginx, "nginx")
    assert not {flag.code for flag in nginx.flags}
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLHonorCipherOrder on\n"
        "SSLCompression off\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    recorded = _recorded(apache, "apache_httpd")
    assert "prefer_server_ciphers" in recorded
    assert "compression" in recorded
    assert '"off"' in recorded
    assert not {flag.code for flag in apache.flags}


def test_ssh_and_traefik_listen_tokens_are_capped(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "sshd_config").write_text(
        "ListenAddress 0.0.0.0\nListenAddress 192.0.2.10\nPort 22\n",
        encoding="utf-8",
    )
    ssh = scan_crypto(tmp_path)
    recorded = _recorded(ssh, "sshd_config")
    assert "0.0.0.0" in recorded
    assert "192.0.2.10" in recorded
    assert "listen_declared" in recorded
    (tmp_path / "sshd_config").write_text("Port 22\nPort 2222\n", encoding="utf-8")
    ports = scan_crypto(tmp_path)
    assert "22,2222" in _recorded(ports, "sshd_config")
    (tmp_path / "sshd_config").unlink()
    lines = [
        "entryPoints:",
        "  websecure:",
        "    address: ':443'",
        "    http:",
        "      tls: {}",
    ]
    for number in range(4431, 4440):
        lines.extend(
            [
                f"  p{number}:",
                f"    address: ':{number}'",
                "    http:",
                "      tls: {}",
            ]
        )
    (tmp_path / "traefik.yml").write_text("\n".join(lines) + "\n", encoding="utf-8")
    traefik = scan_crypto(tmp_path)
    kept = ":443,:4431,:4432,:4433,:4434,:4435,:4436,:4437"
    assert kept in _recorded(traefik, "traefik")
    assert ":4438" not in _recorded(traefik, "traefik")
    assert ":4439" not in _recorded(traefik, "traefik")


def test_tomcat_and_jetty_literal_addresses_are_endpoints(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "server.xml").write_text(
        "<Server><Service><Engine><Host name=\"app.example.test\">"
        "<Connector port=\"8443\" SSLEnabled=\"true\" "
        "sslEnabledProtocols=\"TLSv1.2\"/>"
        "</Host></Engine></Service></Server>\n",
        encoding="utf-8",
    )
    tomcat = scan_crypto(tmp_path)
    connector = next(comp for comp in tomcat.components if comp.name == "TLS")
    host_endpoint = (connector.properties or {}).get("crypto:endpoint")
    assert host_endpoint == "app.example.test:8443"
    assert (connector.properties or {}).get("crypto:listen") == "8443"
    (tmp_path / "server.xml").write_text(
        "<Server><Service><Connector port=\"8443\" address=\"192.0.2.10\" "
        "SSLEnabled=\"true\" sslEnabledProtocols=\"TLSv1.2\"/>"
        "</Service></Server>\n",
        encoding="utf-8",
    )
    literal = scan_crypto(tmp_path)
    bound = next(comp for comp in literal.components if comp.name == "TLS")
    assert (bound.properties or {}).get("crypto:endpoint") == "192.0.2.10:8443"
    assert (bound.properties or {}).get("crypto:listen") == "192.0.2.10:8443"
    (tmp_path / "server.xml").unlink()
    (tmp_path / "ssl.ini").write_text(
        "jetty.ssl.host=app.example.test\n",
        encoding="utf-8",
    )
    jetty = scan_crypto(tmp_path)
    assert "app.example.test:8443" in _recorded(jetty, "jetty")
    assert "port_default" in _recorded(jetty, "jetty")
    assert "listen_declared" not in _recorded(jetty, "jetty")


def test_envoy_and_spring_literal_addresses_are_endpoints(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - address:\n"
        "        socket_address:\n"
        "          address: 0.0.0.0\n"
        "          port_value: 443\n"
        "      filter_chains:\n"
        "        - filter_chain_match:\n"
        "            server_names:\n"
        "              - app.example.test\n"
        "              - '*.example.test'\n"
        "          transport_socket:\n"
        "            typed_config:\n"
        "              tls_minimum_protocol_version: TLSv1_2\n",
        encoding="utf-8",
    )
    envoy = scan_crypto(tmp_path)
    envoy_tls = next(comp for comp in envoy.components if comp.name == "TLS")
    props = envoy_tls.properties or {}
    assert props.get("crypto:endpoint") == "app.example.test:443"
    assert props.get("crypto:listen") == "0.0.0.0:443"
    (tmp_path / "envoy.yaml").unlink()
    (tmp_path / "application.properties").write_text(
        "server.address=app.example.test\n"
        "server.port=8443\n"
        "server.ssl.enabled=true\n"
        "server.ssl.enabled-protocols=TLSv1.2\n",
        encoding="utf-8",
    )
    spring = scan_crypto(tmp_path)
    spring_tls = next(comp for comp in spring.components if comp.name == "TLS")
    spring_endpoint = (spring_tls.properties or {}).get("crypto:endpoint")
    assert spring_endpoint == "app.example.test:8443"
    (tmp_path / "application.properties").write_text(
        "server.address=app.example.test\n"
        "server.ssl.enabled=true\n"
        "server.ssl.enabled-protocols=TLSv1.2\n",
        encoding="utf-8",
    )
    omitted = scan_crypto(tmp_path)
    omitted_tls = next(comp for comp in omitted.components if comp.name == "TLS")
    omitted_endpoint = (omitted_tls.properties or {}).get("crypto:endpoint")
    assert omitted_endpoint == "app.example.test:8080"
    assert "8080" in _recorded(omitted, "spring_boot")
    assert (omitted_tls.properties or {}).get("crypto:listen") is None


def test_named_hosts_become_endpoint_candidates(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  server_name www.example.com example.com *.example.com _;\n"
        "  ssl_protocols TLSv1.2;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    protocol = next(comp for comp in nginx.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props.get("crypto:endpoint") == "example.com:443"
    recorded = _recorded(nginx, "nginx")
    assert "example.com:443" in recorded
    assert "www.example.com:443" in recorded
    assert "*.example.com" not in recorded
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "ServerName https://App.Example.com:8443\n"
        "SSLProtocol TLSv1.2\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    apache_tls = next(comp for comp in apache.components if comp.name == "TLS")
    assert (apache_tls.properties or {}).get("crypto:endpoint") == "app.example.com:443"
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "haproxy.cfg").write_text(
        "frontend web\n  bind 192.0.2.10:443 ssl\n",
        encoding="utf-8",
    )
    proxy = scan_crypto(tmp_path)
    assert "192.0.2.10:443" in _recorded(proxy, "haproxy")


def test_tls_listen_tokens_are_declared(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  listen [::]:443 ssl;\n"
        "  listen 80;\n"
        "  listen $port ssl;\n"
        "  ssl_protocols TLSv1.2;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    protocol = next(comp for comp in nginx.components if comp.name == "TLS")
    assert (protocol.properties or {}).get("crypto:listen") == "443,[::]:443"
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert "*:443" in _recorded(apache, "apache_httpd")
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "haproxy.cfg").write_text(
        "frontend web\n  bind *:443 ssl\n",
        encoding="utf-8",
    )
    proxy = scan_crypto(tmp_path)
    assert "*:443" in _recorded(proxy, "haproxy")


def test_apache_proxy_protocol_is_a_separate_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLProtocol TLSv1.2\n"
        "SSLProxyEngine on\n"
        "SSLProxyProtocol TLSv1\n"
        "SSLSessionTickets off\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    listener = next(
        comp
        for comp in result.components
        if comp.name == "TLS"
        and (comp.properties or {}).get("crypto:policyName") is None
    )
    outbound = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:policyName") == "SSLProxyProtocol"
    )
    assert (listener.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "crypto:strength" not in (listener.properties or {})
    assert (outbound.properties or {})["crypto:protocolVersion"] == "TLSv1"
    assert (outbound.properties or {})["crypto:strength"] == "weak"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}
    assert "off" in _recorded(result, "apache_httpd")
    assert "session_tickets" in _recorded(result, "apache_httpd")
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_session_tickets on;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert "session_tickets" in _recorded(nginx, "nginx")
    assert "WEAK_PROTOCOL" not in {flag.code for flag in nginx.flags}


def test_key_file_is_declared_and_not_linked(tmp_path) -> None:
    from pathlib import Path

    from aibom.cbom.pipeline import scan_crypto

    pem = (
        Path(__file__).parent / "fixtures" / "synthetic-crypto-certs" / "strong.pem"
    )
    (tmp_path / "server.pem").write_bytes(pem.read_bytes())
    (tmp_path / "server.key").write_text(
        "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_certificate server.pem;\n"
        "  ssl_certificate_key server.key;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert _linked_cert(nginx, "nginx", "server.pem")
    assert not _linked_cert(nginx, "nginx", "server.key")
    recorded = _recorded(nginx, "nginx")
    assert "key_file_declared" in recorded
    assert "server.key" in recorded
    rendered = " ".join(str(comp.properties) for comp in nginx.components)
    assert "SECRETKEYMATERIAL" not in rendered
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLCertificateFile server.pem\n"
        "SSLCertificateKeyFile server.key\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert _linked_cert(apache, "apache_httpd", "server.pem")
    assert not _linked_cert(apache, "apache_httpd", "server.key")
    assert "server.key" in _recorded(apache, "apache_httpd")
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_key_file = 'server.pem'\n",
        encoding="utf-8",
    )
    postgres = scan_crypto(tmp_path)
    assert "key_file_declared" in _recorded(postgres, "postgresql")
    assert not _linked_cert(postgres, "postgresql", "server.pem")
    (tmp_path / "postgresql.conf").unlink()
    (tmp_path / "my.cnf").write_text(
        "[mysqld]\nssl_key = server.key\n",
        encoding="utf-8",
    )
    mysql = scan_crypto(tmp_path)
    assert "server.key" in _recorded(mysql, "mysql")
    assert not _linked_cert(mysql, "mysql", "server.key")


def test_declared_certificate_links_the_scanned_file(tmp_path) -> None:
    from pathlib import Path

    from aibom.cbom.pipeline import scan_crypto

    pem = (
        Path(__file__).parent / "fixtures" / "synthetic-crypto-certs" / "strong.pem"
    )
    (tmp_path / "server.pem").write_bytes(pem.read_bytes())
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_certificate server.pem;\n}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert _linked_cert(nginx, "nginx", "server.pem")
    assert "strong-control.test" in _recorded(nginx, "nginx")
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_certificate missing.pem;\n}\n",
        encoding="utf-8",
    )
    missing = scan_crypto(tmp_path)
    assert not _linked_cert(missing, "nginx", "server.pem")
    assert "unresolved_reference" in _recorded(missing, "nginx")
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLCertificateFile server.pem\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert _linked_cert(apache, "apache_httpd", "server.pem")
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "haproxy.cfg").write_text(
        "frontend web\n  bind :443 ssl crt server.pem\n",
        encoding="utf-8",
    )
    proxy = scan_crypto(tmp_path)
    assert _linked_cert(proxy, "haproxy", "server.pem")
    (tmp_path / "haproxy.cfg").unlink()
    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - filter_chains:\n"
        "        - transport_socket:\n"
        "            typed_config:\n"
        "              tls_certificates:\n"
        "                - certificate_chain:\n"
        "                    filename: server.pem\n",
        encoding="utf-8",
    )
    envoy = scan_crypto(tmp_path)
    assert _linked_cert(envoy, "envoy", "server.pem")
    (tmp_path / "envoy.yaml").unlink()
    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_cert_file = 'server.pem'\n",
        encoding="utf-8",
    )
    postgres = scan_crypto(tmp_path)
    assert _linked_cert(postgres, "postgresql", "server.pem")


def _recorded(result, native: str) -> str:
    fact = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == native
    )
    return str((fact.properties or {}).get("crypto:factBasis"))


def test_hsts_is_recorded_and_raises_no_finding(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        '  add_header Strict-Transport-Security "max-age=31536000" always;\n'
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert '"hsts"' in _recorded(nginx, "nginx")
    assert "31536000" in _recorded(nginx, "nginx")
    assert "HSTS" not in {flag.code for flag in nginx.flags}
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    quiet = scan_crypto(tmp_path)
    assert "hsts" not in _recorded(quiet, "nginx")
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        'Header always set Strict-Transport-Security "max-age=63072000"\n'
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert "63072000" in _recorded(apache, "apache_httpd")
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "haproxy.cfg").write_text(
        "frontend web\n"
        "  bind :443 ssl\n"
        "  http-response set-header Strict-Transport-Security max-age=60\n",
        encoding="utf-8",
    )
    proxy = scan_crypto(tmp_path)
    assert "60" in _recorded(proxy, "haproxy")
    assert '"hsts"' in _recorded(proxy, "haproxy")
    (tmp_path / "haproxy.cfg").unlink()
    (tmp_path / "traefik.yml").write_text(
        "entryPoints:\n"
        "  web:\n"
        "    address: ':80'\n"
        "http:\n"
        "  middlewares:\n"
        "    sec:\n"
        "      headers:\n"
        "        stsSeconds: 31536000\n",
        encoding="utf-8",
    )
    traefik = scan_crypto(tmp_path)
    fact = next(
        comp
        for comp in traefik.components
        if (comp.properties or {}).get("crypto:factNativeType") == "traefik"
    )
    props = fact.properties or {}
    assert props.get("crypto:factVerdict") == "UNKNOWN"
    assert "31536000" in str(props.get("crypto:factBasis"))
    assert "HSTS" not in {flag.code for flag in traefik.flags}


def _curve_names(result) -> list[str | None]:
    return [
        (comp.properties or {}).get("crypto:curve")
        for comp in result.components
        if comp.name == "ECDH"
    ]


def test_proxy_curves_below_224_bits_are_weak(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "haproxy.cfg").write_text(
        "frontend web\n"
        "  bind :443 ssl curves P-192:prime256v1\n",
        encoding="utf-8",
    )
    proxy = scan_crypto(tmp_path)
    assert _curve_names(proxy) == ["P-192"]
    (tmp_path / "haproxy.cfg").unlink()
    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - filter_chains:\n"
        "        - transport_socket:\n"
        "            name: envoy.transport_sockets.tls\n"
        "            typed_config:\n"
        "              ecdh_curves:\n"
        "                - P-192\n"
        "                - X25519\n",
        encoding="utf-8",
    )
    envoy = scan_crypto(tmp_path)
    assert _curve_names(envoy) == ["P-192"]
    (tmp_path / "envoy.yaml").unlink()
    (tmp_path / "traefik.yml").write_text(
        "tls:\n"
        "  options:\n"
        "    default:\n"
        "      curvePreferences:\n"
        "        - secp192r1\n"
        "        - CurveP256\n",
        encoding="utf-8",
    )
    traefik = scan_crypto(tmp_path)
    assert _curve_names(traefik) == ["secp192r1"]


def test_curves_below_224_bits_are_weak_ecdh_assets(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_ecdh_curve prime192v1:prime256v1;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    curves = [
        (comp.properties or {}).get("crypto:curve")
        for comp in nginx.components
        if comp.name == "ECDH"
    ]
    assert curves == ["prime192v1"]
    asset = next(comp for comp in nginx.components if comp.name == "ECDH")
    props = asset.properties or {}
    assert props["crypto:primitive"] == "key-agree"
    assert props["crypto:strength"] == "weak"
    assert "crypto:keySize" not in props
    assert "WEAK_ALGORITHM" in {flag.code for flag in nginx.flags}
    assert "WEAK_KEY_SIZE" not in {flag.code for flag in nginx.flags}
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLOpenSSLConfCmd Curves P-192\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    written = next(comp for comp in apache.components if comp.name == "ECDH")
    assert (written.properties or {})["crypto:curve"] == "P-192"
    (tmp_path / "httpd.conf").unlink()
    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_ecdh_curve = 'prime192v1'\n",
        encoding="utf-8",
    )
    postgres = scan_crypto(tmp_path)
    stored = [
        (comp.properties or {}).get("crypto:curve")
        for comp in postgres.components
        if comp.name == "ECDH"
    ]
    assert stored == ["prime192v1"]
    (tmp_path / "postgresql.conf").write_text(
        "ssl = on\nssl_ecdh_curve = 'prime256v1'\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    assert not any(comp.name == "ECDH" for comp in strong.components)


def test_client_authentication_none_is_not_disabled_verification(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_verify_client off;\n"
        "}\n",
        encoding="utf-8",
    )
    nginx = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in nginx.flags}
    fact = next(
        comp
        for comp in nginx.components
        if (comp.properties or {}).get("crypto:factNativeType") == "nginx"
    )
    assert "client_auth" in str((fact.properties or {}).get("crypto:factBasis"))
    (tmp_path / "nginx.conf").unlink()
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLVerifyClient none\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    apache = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in apache.flags}
    host = next(
        comp
        for comp in apache.components
        if (comp.properties or {}).get("crypto:factNativeType") == "apache_httpd"
    )
    assert '"client_auth"' in str((host.properties or {}).get("crypto:factBasis"))
    assert "none" in str((host.properties or {}).get("crypto:factBasis"))


def test_nginx_listen_without_tls_is_not_encrypted(monkeypatch) -> None:
    seen: list[tuple[bool, bool]] = []
    real = listener_reader

    def spy(*, plaintext: bool, redirect: bool):
        seen.append((plaintext, redirect))
        return real(plaintext=plaintext, redirect=redirect)

    monkeypatch.setattr(
        "aibom.cbom.posture.extract_servers.listener_reader", spy
    )
    text = "server {\n  listen 80;\n}\n"
    fact = extract_servers(text, "nginx.conf")[0]
    assert isinstance(fact, EncryptionFact)
    assert fact.layers["transport"] == "NOT_ENCRYPTED"
    assert fact.verdict == "NOT_ENCRYPTED"
    assert fact.finding_codes == ("PLAINTEXT_LISTENER",)
    assert seen == [(True, False)]


def test_nginx_redirect_is_encrypted_declared(monkeypatch) -> None:
    seen: list[tuple[bool, bool]] = []
    real = listener_reader

    def spy(*, plaintext: bool, redirect: bool):
        seen.append((plaintext, redirect))
        return real(plaintext=plaintext, redirect=redirect)

    monkeypatch.setattr(
        "aibom.cbom.posture.extract_servers.listener_reader", spy
    )
    text = "server {\n  listen 80;\n  return 301 https://example.com$request_uri;\n}\n"
    fact = extract_servers(text, "nginx.conf")[0]
    direct = listener_reader(plaintext=True, redirect=True)
    assert fact.verdict == "ENCRYPTED_DECLARED"
    assert fact.verdict == direct.verdict
    assert fact.layers["transport"] == "ENCRYPTED_DECLARED"
    assert fact.verdict != "NOT_ENCRYPTED"
    assert fact.finding_codes == ()
    assert seen == [(True, True)]
    assert _basis(fact)["redirect"] == "https"


def test_openssh_password_yes_is_disabling_and_first_wins() -> None:
    text = "PasswordAuthentication yes\nPasswordAuthentication no\n"
    fact = extract_servers(text, "sshd_config")[0]
    assert fact.kind == "ssh_service"
    assert fact.verdict == "ENCRYPTED_DECLARED"
    assert _basis(fact)["PasswordAuthentication"] == "yes"
    assert _basis(fact)["signal"] == "disabling"
    assert _basis(fact)["duplicate_key"] == "first"
    later = "PasswordAuthentication no\nPasswordAuthentication yes\n"
    kept = extract_servers(later, "sshd_config")[0]
    assert _basis(kept)["PasswordAuthentication"] == "no"
    assert "signal" not in _basis(kept)
    noisy = extract_servers("PasswordAuthentication yes\n" * 40, "sshd_config")
    assert len(noisy) == 1
    assert _basis(noisy[0])["signal"] == "disabling"
    assert _basis(noisy[0])["PasswordAuthentication"] == "yes"


def test_stream_and_tcp_passthrough_stay_unknown(monkeypatch) -> None:
    def boom(*, plaintext: bool, redirect: bool):
        raise AssertionError((plaintext, redirect))

    monkeypatch.setattr(
        "aibom.cbom.posture.extract_servers.listener_reader", boom
    )
    empty = extract_servers("stream {\n}\n", "nginx.conf")
    assert len(empty) == 1
    assert empty[0].verdict == "UNKNOWN"
    assert empty[0].layers["transport"] == "UNKNOWN"
    assert empty[0].unknown_reason == "layer_not_observable"
    assert _basis(empty[0])["context"] == "stream"
    passed = (
        "stream {\n"
        "  server {\n"
        "    listen 443;\n"
        "    ssl_preread on;\n"
        "    proxy_pass 192.0.2.10:443;\n"
        "  }\n"
        "}\n"
    )
    fact = extract_servers(passed, "nginx.conf")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.layers["transport"] == "UNKNOWN"
    assert fact.unknown_reason == "layer_not_observable"
    assert fact.finding_codes == ()
    assert _basis(fact)["passthrough"] == "tcp"
    assert _basis(fact)["listen"] == "443"


def test_detail_stays_on_basis_entries() -> None:
    fact = extract_servers("server {\n  listen 80;\n}\n", "nginx.conf")[0]
    assert type(fact) is EncryptionFact
    assert fact.basis
    assert all(type(item) is BasisEntry for item in fact.basis)
    assert _basis(fact)["listen"] == "80"
    assert not hasattr(fact, "listen")
    ssh = extract_servers("PasswordAuthentication yes\n", "sshd_config")[0]
    assert type(ssh) is EncryptionFact
    assert not hasattr(ssh, "signal")
    assert all(type(item) is BasisEntry for item in ssh.basis)


def test_apache_redirect_uses_the_listener_reader() -> None:
    plain = "<VirtualHost *:80>\nServerName example.com\n</VirtualHost>\n"
    fact = extract_servers(plain, "httpd.conf")[0]
    assert fact.verdict == "NOT_ENCRYPTED"
    redirected = (
        "<VirtualHost *:80>\n"
        "Redirect permanent / https://example.com/\n"
        "</VirtualHost>\n"
    )
    secured = extract_servers(redirected, "httpd.conf")[0]
    assert secured.verdict == listener_reader(plaintext=True, redirect=True).verdict
    assert secured.verdict == "ENCRYPTED_DECLARED"


def test_dh_prime_bits_for_512_1024_and_2048() -> None:
    for bits in (512, 1024, 2048):
        blob = _pkcs3(bits)
        assert prime_bits(blob) == bits
        assert _prime_bits(blob) == bits


def test_nginx_dh_file_becomes_a_weak_diffie_hellman_asset(tmp_path) -> None:
    import binascii

    from aibom.cbom.pipeline import scan_crypto

    prime = _pkcs3(1024)
    body = binascii.b2a_base64(prime).decode("ascii")
    (tmp_path / "dhparam.pem").write_text(
        "-----BEGIN DH PARAMETERS-----\n" + body + "-----END DH PARAMETERS-----\n",
        encoding="utf-8",
    )
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_dhparam dhparam.pem;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "Diffie-Hellman")
    props = asset.properties or {}
    assert props["crypto:keySize"] == "1024"
    assert props["crypto:primitive"] == "key-agree"
    assert props["crypto:quantumVulnerable"] == "true"
    codes = {flag.code for flag in result.flags}
    assert "WEAK_KEY_SIZE" in codes
    assert "QUANTUM_VULNERABLE" in codes
    assert any(
        edge.rel == "depends_on" and edge.dst == asset.bom_ref for edge in result.edges
    )


def test_a_2048_bit_dh_file_is_not_an_undersized_key(tmp_path) -> None:
    import binascii

    from aibom.cbom.pipeline import scan_crypto

    body = binascii.b2a_base64(_pkcs3(2048)).decode("ascii")
    (tmp_path / "dhparam.pem").write_text(
        "-----BEGIN DH PARAMETERS-----\n" + body + "-----END DH PARAMETERS-----\n",
        encoding="utf-8",
    )
    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_dhparam dhparam.pem;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "Diffie-Hellman")
    assert (asset.properties or {})["crypto:keySize"] == "2048"
    codes = {flag.code for flag in result.flags if flag.target == asset.bom_ref}
    assert "WEAK_KEY_SIZE" not in codes
    assert "QUANTUM_VULNERABLE" in codes


def test_openssh_weak_kex_and_protocol_1(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "sshd_config").write_text(
        "Ciphers aes128-ctr,blowfish-cbc\n"
        "KexAlgorithms diffie-hellman-group1-sha1\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "SSH")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "blowfish-cbc" in suite
    assert "diffie-hellman-group1-sha1" in suite
    assert (protocol.properties or {})["crypto:protocolType"] == "ssh"
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    (tmp_path / "sshd_config").write_text(
        "Protocol 1\nCiphers aes256-gcm@openssh.com\n",
        encoding="utf-8",
    )
    legacy = scan_crypto(tmp_path)
    ssh = next(comp for comp in legacy.components if comp.name == "SSH")
    assert (ssh.properties or {})["crypto:protocolVersion"] == "SSH-1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in legacy.flags}


def test_jetty_exclude_protocols_raise_the_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "jetty-ssl.xml").write_text(
        "<Configure>\n"
        '  <Set name="IncludeProtocols">\n'
        "    <Item>TLSv1</Item>\n"
        "    <Item>TLSv1.2</Item>\n"
        "  </Set>\n"
        '  <Set name="ExcludeProtocols">\n'
        "    <Item>TLSv1</Item>\n"
        "  </Set>\n"
        '  <Set name="IncludeCipherSuites">\n'
        "    <Item>TLS_RSA_WITH_3DES_EDE_CBC_SHA</Item>\n"
        "    <Item>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</Item>\n"
        "  </Set>\n"
        '  <Set name="ExcludeCipherSuites">\n'
        "    <Item>TLS_RSA_WITH_3DES_EDE_CBC_SHA</Item>\n"
        "  </Set>\n"
        "</Configure>\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props["crypto:protocolVersion"] == "TLSv1.2"
    assert "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" in props["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" not in props["crypto:cipherSuite"]
    codes = {flag.code for flag in result.flags}
    assert "WEAK_PROTOCOL" not in codes
    assert "WEAK_CIPHER_SUITE" not in codes


def test_jetty_include_protocols_and_ciphers(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "jetty-ssl.xml").write_text(
        "<Configure>\n"
        '  <Set name="IncludeProtocols">\n'
        '    <Array type="String">\n'
        "      <Item>TLSv1</Item>\n"
        "      <Item>TLSv1.2</Item>\n"
        "    </Array>\n"
        "  </Set>\n"
        "</Configure>\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in weak.flags}
    (tmp_path / "jetty-ssl.xml").write_text(
        "<Configure>\n"
        '  <Set name="IncludeCipherSuites">\n'
        "    <Item>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</Item>\n"
        "  </Set>\n"
        "</Configure>\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    kept = next(comp for comp in strong.components if comp.name == "TLS")
    suite = (kept.properties or {})["crypto:cipherSuite"]
    assert "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" in suite
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}
    assert "WEAK_PROTOCOL" not in {flag.code for flag in strong.flags}


def test_spring_yaml_sets_the_floor_and_client_auth(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "application.yml").write_text(
        "server:\n"
        "  ssl:\n"
        "    enabled: true\n"
        "    client-auth: none\n"
        "    enabled-protocols:\n"
        "      - TLSv1\n"
        "      - TLSv1.2\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1"
    codes = {flag.code for flag in result.flags}
    assert "WEAK_PROTOCOL" in codes
    assert "TLS_VERIFICATION_DISABLED" not in codes
    server = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factAddress") == "spring.server[1]"
    )
    assert "client_auth" in str((server.properties or {}).get("crypto:factBasis"))


def test_spring_cipher_list_is_evaluated(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "application.properties").write_text(
        "server.ssl.enabled=true\n"
        "server.ssl.ciphers=TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    (tmp_path / "application.properties").write_text(
        "server.ssl.enabled=true\n"
        "server.ssl.ciphers=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}


def test_spring_ssl_disabled_is_plaintext_and_protocols_set_the_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "application.properties").write_text(
        "server.ssl.enabled=false\n"
        "management.server.ssl.enabled=true\n"
        "management.server.ssl.enabled-protocols=TLSv1,TLSv1.2\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    codes = {flag.code for flag in result.flags}
    assert "UNENCRYPTED_IN_TRANSIT" in codes
    assert "PLAINTEXT_LISTENER" in codes
    assert "WEAK_PROTOCOL" in codes
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1"


def test_tomcat_ssl_host_config_sets_floor_and_client_auth(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8443" SSLEnabled="true">\n'
        '      <SSLHostConfig protocols="TLSv1,TLSv1.2"\n'
        '                     ciphers="TLS_RSA_WITH_3DES_EDE_CBC_SHA"\n'
        '                     certificateVerification="none"/>\n'
        "    </Connector>\n"
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    props = protocol.properties or {}
    assert props["crypto:protocolVersion"] == "TLSv1"
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in props["crypto:cipherSuite"]
    codes = {flag.code for flag in result.flags}
    assert "WEAK_PROTOCOL" in codes
    assert "WEAK_CIPHER_SUITE" in codes
    assert "TLS_VERIFICATION_DISABLED" not in codes
    connector = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factAddress") == "tomcat.connector[1]"
    )
    assert "client_auth" in str((connector.properties or {}).get("crypto:factBasis"))


def test_tomcat_ciphers_are_evaluated(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8443" SSLEnabled="true"\n'
        '               ciphers="TLS_RSA_WITH_3DES_EDE_CBC_SHA"/>\n'
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    (tmp_path / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8443" SSLEnabled="true"\n'
        '               ciphers="ECDHE-RSA-AES256-GCM-SHA384"/>\n'
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}


def test_tomcat_connector_without_ssl_is_plaintext(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8080" protocol="HTTP/1.1"/>\n'
        '    <Connector port="8443" SSLEnabled="true"\n'
        '               sslEnabledProtocols="TLSv1,TLSv1.2"/>\n'
        '    <Connector port="8009" protocol="AJP/1.3"/>\n'
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    codes = {flag.code for flag in result.flags}
    assert "UNENCRYPTED_IN_TRANSIT" in codes
    assert "PLAINTEXT_LISTENER" in codes
    assert "WEAK_PROTOCOL" in codes
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1"
    addresses = {
        (comp.properties or {}).get("crypto:factAddress")
        for comp in result.components
        if comp.kind == "infra"
    }
    assert "tomcat.connector[1]" in addresses
    assert "tomcat.connector[2]" in addresses
    assert all("8009" not in str(comp.properties) for comp in result.components)


def test_traefik_insecure_skip_verify_disables_verification(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "traefik.yml").write_text(
        "entryPoints:\n"
        "  web:\n"
        "    address: \":443\"\n"
        "serversTransport:\n"
        "  insecureSkipVerify: true\n",
        encoding="utf-8",
    )
    disabled = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" in {flag.code for flag in disabled.flags}
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in disabled.flags}
    (tmp_path / "traefik.yml").write_text(
        "entryPoints:\n"
        "  web:\n"
        "    address: \":443\"\n"
        "serversTransport:\n"
        "  insecureSkipVerify: false\n",
        encoding="utf-8",
    )
    checked = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in checked.flags}


def test_traefik_cipher_suites_are_evaluated(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "traefik.yml").write_text(
        "tls:\n"
        "  options:\n"
        "    default:\n"
        "      cipherSuites:\n"
        "        - TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    (tmp_path / "traefik.yml").write_text(
        "tls:\n"
        "  options:\n"
        "    default:\n"
        "      cipherSuites:\n"
        "        - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}


def test_traefik_min_version_is_the_protocol_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "traefik.yml").write_text(
        "tls:\n  options:\n    default:\n      minVersion: VersionTLS10\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in weak.flags}
    (tmp_path / "traefik.yml").write_text(
        "tls:\n  options:\n    default:\n      minVersion: VersionTLS12\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    kept = next(comp for comp in strong.components if comp.name == "TLS")
    assert (kept.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in strong.flags}


def test_envoy_cipher_suite_list_is_evaluated(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "  - filter_chains:\n"
        "    - transport_socket:\n"
        "        typed_config:\n"
        "          cipher_suites:\n"
        "          - TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "  - filter_chains:\n"
        "    - transport_socket:\n"
        "        typed_config:\n"
        "          cipher_suites:\n"
        "          - TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}


def test_envoy_minimum_version_is_the_protocol_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "  - name: listener_0\n"
        "    filter_chains:\n"
        "    - transport_socket:\n"
        "        typed_config:\n"
        "          tls_minimum_protocol_version: TLSv1_0\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in weak.flags}
    (tmp_path / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "  - name: listener_0\n"
        "    filter_chains:\n"
        "    - transport_socket:\n"
        "        typed_config:\n"
        "          tls_minimum_protocol_version: TLSv1_2\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    kept = next(comp for comp in strong.components if comp.name == "TLS")
    assert (kept.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in strong.flags}


def test_haproxy_tls_floor_uses_the_bind_then_the_default(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "haproxy.cfg").write_text(
        "frontend www\n  bind :443 ssl ssl-min-ver TLSv1.0\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in weak.flags}
    (tmp_path / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11\n"
        "frontend www\n"
        "  bind :443 ssl\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    kept = next(comp for comp in strong.components if comp.name == "TLS")
    assert (kept.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in strong.flags}


def test_haproxy_verify_none_is_disabled_verification(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "haproxy.cfg").write_text(
        "backend api\n  server app 10.0.0.1:443 ssl verify none\n",
        encoding="utf-8",
    )
    disabled = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" in {flag.code for flag in disabled.flags}
    (tmp_path / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-default-server-options ssl verify none\n"
        "backend api\n"
        "  server app 10.0.0.1:443 ssl verify required\n",
        encoding="utf-8",
    )
    required = scan_crypto(tmp_path)
    assert "TLS_VERIFICATION_DISABLED" not in {flag.code for flag in required.flags}


def test_haproxy_default_cipher_is_overridden_by_the_bind(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-default-bind-ciphers DES-CBC3-SHA\n"
        "frontend www\n"
        "  bind :443 ssl\n",
        encoding="utf-8",
    )
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    (tmp_path / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-default-bind-ciphers DES-CBC3-SHA\n"
        "frontend www\n"
        "  bind :443 ssl ciphers ECDHE-RSA-AES256-GCM-SHA384\n",
        encoding="utf-8",
    )
    strong = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}


def test_haproxy_https_redirect_is_not_plaintext(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "haproxy.cfg").write_text(
        "frontend www\n  bind :80\n  redirect scheme https\n",
        encoding="utf-8",
    )
    secured = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in secured.flags}
    (tmp_path / "haproxy.cfg").write_text(
        "frontend www\n  bind :80\n  redirect scheme http\n",
        encoding="utf-8",
    )
    opened = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" in {flag.code for flag in opened.flags}
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in opened.flags}


def test_haproxy_dh_param_file_links_the_frontend(tmp_path) -> None:
    import binascii

    from aibom.cbom.pipeline import scan_crypto

    body = binascii.b2a_base64(_pkcs3(1024)).decode("ascii")
    (tmp_path / "dhparam.pem").write_text(
        "-----BEGIN DH PARAMETERS-----\n" + body + "-----END DH PARAMETERS-----\n",
        encoding="utf-8",
    )
    (tmp_path / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-dh-param-file dhparam.pem\n"
        "frontend www\n"
        "  bind :443 ssl\n"
        "frontend plain\n"
        "  bind :80\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "Diffie-Hellman")
    assert (asset.properties or {})["crypto:keySize"] == "1024"
    assert "UNENCRYPTED_IN_TRANSIT" in {flag.code for flag in result.flags}
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in result.flags}


def test_apache_dh_parameters_command_links_the_file(tmp_path) -> None:
    import binascii

    from aibom.cbom.pipeline import scan_crypto

    body = binascii.b2a_base64(_pkcs3(1024)).decode("ascii")
    (tmp_path / "dhparam.pem").write_text(
        "-----BEGIN DH PARAMETERS-----\n" + body + "-----END DH PARAMETERS-----\n",
        encoding="utf-8",
    )
    (tmp_path / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLOpenSSLConfCmd DHParameters dhparam.pem\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    asset = next(comp for comp in result.components if comp.name == "Diffie-Hellman")
    assert (asset.properties or {})["crypto:keySize"] == "1024"
    assert any(
        edge.rel == "depends_on" and edge.dst == asset.bom_ref for edge in result.edges
    )


def test_missing_dh_file_is_unresolved(tmp_path) -> None:
    import json

    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_dhparam missing.pem;\n}\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert all(comp.name != "Diffie-Hellman" for comp in result.components)
    fact = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == "nginx"
    )
    basis = json.loads(str((fact.properties or {})["crypto:factBasis"]))
    row = next(item for item in basis if item["name"] == "dh_file")
    assert row["unknown_reason"] == "unresolved_reference"


def test_dh_reader_rejects_short_and_garbage() -> None:
    short = (1 << 62) | 1
    body = _der_integer(short) + _der_integer(2)
    tiny = b"\x30" + _der_len(len(body)) + body
    assert _prime_bits(tiny) is None
    assert prime_bits(b"") is None
    assert prime_bits(b"\xff") is None
    assert prime_bits(b"\x02\x01\x02") is None
