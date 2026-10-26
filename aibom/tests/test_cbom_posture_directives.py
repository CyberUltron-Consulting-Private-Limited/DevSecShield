"""Directive dialects record includes and honour each precedence rule."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.diagnostics import DiagnosticSink
from aibom.cbom.posture.directives import (
    load_directives,
    parse_apache,
    parse_crypttab,
    parse_haproxy,
    parse_mysql_cnf,
    parse_nginx,
    parse_openssh,
    parse_pg_hba,
    parse_postgresql,
    parse_properties,
    parse_redis,
)
from support.generators import mutate_bytes


def test_openssh_keeps_the_first_password_authentication() -> None:
    text = "PasswordAuthentication yes\nPasswordAuthentication no\n"
    sink = DiagnosticSink()
    doc = parse_openssh(text, path="sshd_config", sink=sink)
    assert doc is not None
    assert doc.lookup("PasswordAuthentication") == ("yes",)
    assert [item.code for item in sink.stored()] == ["duplicate_key"]


def test_openssh_match_does_not_replace_the_global_value() -> None:
    text = "PasswordAuthentication yes\nMatch User bob\nPasswordAuthentication no\n"
    doc = parse_openssh(text, path="sshd_config", sink=DiagnosticSink())
    assert doc is not None
    assert doc.lookup("PasswordAuthentication") == ("yes",)
    matched = [entry for entry in doc.entries if entry.parent]
    assert matched[0].args == ("no",)
    assert matched[0].marker == "unresolved_expression"


def test_nginx_records_include_and_does_not_read_it() -> None:
    text = "http {\n  include conf.d/*.conf;\n  server { listen 443 ssl; }\n}\n"
    doc = parse_nginx(text, path="nginx.conf", sink=DiagnosticSink())
    assert doc is not None
    assert doc.includes == ("conf.d/*.conf",)
    listen = doc.lookup("listen", "http.server")
    assert listen == ("443", "ssl")


def test_other_dialects_parse_their_records() -> None:
    apache = parse_apache(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        path="httpd.conf",
        sink=DiagnosticSink(),
    )
    assert apache is not None
    assert apache.lookup("SSLEngine", "virtualhost *:443") == ("on",)
    haproxy = parse_haproxy(
        "frontend www\n  bind :443 ssl\n",
        path="haproxy.cfg",
        sink=DiagnosticSink(),
    )
    assert haproxy is not None
    assert haproxy.lookup("bind", "frontend www") == (":443", "ssl")
    mysql = parse_mysql_cnf(
        "[mysqld]\nssl-ca=/etc/ca.pem\n!include /extra.cnf\n",
        path="my.cnf",
        sink=DiagnosticSink(),
    )
    assert mysql is not None
    assert mysql.lookup("ssl_ca", "mysqld") == ("/etc/ca.pem",)
    assert mysql.includes == ("/extra.cnf",)
    postgres = parse_postgresql(
        "ssl = on\ninclude 'extra.conf'\n",
        path="postgresql.conf",
        sink=DiagnosticSink(),
    )
    assert postgres is not None
    assert postgres.lookup("ssl") == ("on",)
    assert postgres.includes == ("extra.conf",)
    redis = parse_redis(
        "include /etc/redis/extra.conf\n",
        path="redis.conf",
        sink=DiagnosticSink(),
    )
    assert redis is not None
    assert redis.includes == ("/etc/redis/extra.conf",)
    crypt = parse_crypttab(
        "crypt /dev/sda2 none luks\n",
        path="crypttab",
        sink=DiagnosticSink(),
    )
    assert crypt is not None
    assert crypt.lookup("crypt") == ("/dev/sda2", "none", "luks")
    hba = parse_pg_hba(
        "host all all 0.0.0.0/0 md5\n",
        path="pg_hba.conf",
        sink=DiagnosticSink(),
    )
    assert hba is not None
    assert hba.lookup("host") == ("all", "all", "0.0.0.0/0", "md5")


def test_properties_keep_the_last_value_and_decode_unicode() -> None:
    sink = DiagnosticSink()
    doc = parse_properties(
        "server.port = 8080\nname=caf\\u00e9\nserver.port=9090\n",
        path="app.properties",
        sink=sink,
    )
    assert doc is not None
    assert doc.lookup("server.port") == ("9090",)
    assert doc.lookup("name") == ("café",)
    assert [item.code for item in sink.stored()] == ["duplicate_key"]


def test_bytes_return_a_result_or_one_diagnostic() -> None:
    seen: list[str] = []
    result = load_directives(b"\xff", seen.append, kind="nginx")
    assert result is not None or seen == ["parse_error"]
    assert len(seen) <= 1


@pytest.mark.parametrize("seed", range(1, 21))
def test_mutated_bytes_never_raise(seed: int) -> None:
    base = b"PasswordAuthentication yes\nPasswordAuthentication no\n"
    for payload in mutate_bytes(seed, base=base):
        load_directives(payload, lambda _code: None, kind="openssh")
