"""Service environments, crypto overrides, openssl CLI uses and web TLS directives, from what the AWS lab's
Ubuntu target returned to the unprivileged zs-cbom user (2026-11-01)."""
from __future__ import annotations

import json

from zs_scan_node import linux_parsers as P

HEX = "9f" * 32  # stands in for the planted AES-256 key
SYSTEMCTL = f"""ExecStart={{ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -c import ssl, time; time.sleep(10**9) ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}
Environment=AES_KEY={HEX} OPENSSL_CONF=/opt/payments/openssl.cnf
Id=zs-payments.service
FragmentPath=/etc/systemd/system/zs-payments.service

ExecStart={{ path=/usr/bin/java ; argv[]=/usr/bin/java -Djava.security.properties=/opt/legacy-app/java.security.override /opt/legacy-app/Sleep.java ; ignore_errors=no ; start_time=[Sun 2026-11-01 06:46:55 UTC] ; stop_time=[n/a] ; pid=7216 ; code=(null) ; status=0/0 }}
Environment=
Id=zs-legacy-java.service
FragmentPath=/etc/systemd/system/zs-legacy-java.service

ExecStart={{ path=/lib/systemd/systemd-logind ; argv[]=/lib/systemd/systemd-logind ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }}
Environment=KEY_FILE=/etc/x.key API_TOKEN_URL=https://example API_PASSWORD=${{FROM_VAULT}} LANG=C
Id=systemd-logind.service
FragmentPath=/lib/systemd/system/systemd-logind.service
"""


def test_service_secrets_keep_only_name_length_and_encoding():
    svcs = P.systemd_services(SYSTEMCTL)
    assert [s["unit"] for s in svcs] == ["zs-payments.service", "zs-legacy-java.service"]
    pay = svcs[0]
    assert pay["secrets"] == [{"name": "AES_KEY", "encoding": "hex", "length": 64, "key_bits": 256}]
    assert pay["openssl_conf"] == "/opt/payments/openssl.cnf" and pay["fragment"] == "/etc/systemd/system/zs-payments.service"
    assert svcs[1]["java_security"] == "/opt/legacy-app/java.security.override" and not svcs[1]["java_override_replaces"]
    assert HEX not in json.dumps(svcs)  # the value never leaves the parser


def test_secret_shape_rejects_references_and_non_secrets():
    assert P.secret_shape("KEY_FILE", "/etc/x.key") is None
    assert P.secret_shape("API_PASSWORD", "${FROM_VAULT}") is None
    assert P.secret_shape("LANG", "C") is None
    assert P.secret_shape("DB_PASSWORD", "hunter2hunter2")["encoding"] == "text"
    assert P.secret_shape("JWT_SECRET", "c2VjcmV0LXNpZ25pbmcta2V5LWZvci1qd3Q=")["encoding"] == "base64"


def test_crypto_directives_from_grep_n():
    d = P.crypto_directives("12:MinProtocol = TLSv1\n13:CipherString = DEFAULT@SECLEVEL=0\n")
    assert d["minprotocol"]["value"] == "TLSv1" and d["cipherstring"]["line"] == 13
    j = P.crypto_directives("1:jdk.tls.disabledAlgorithms=\n")
    assert j["jdk.tls.disabledalgorithms"]["value"] == ""


def test_openssl_cli_uses_drop_the_passphrase():
    out = ("/etc/cron.d/zs-payments-backup:2:0 3 1 1 * root /usr/bin/tar -czf - /opt/payments/conf 2>/dev/null | "
           "/usr/bin/openssl enc -aes-128-cbc -md md5 -k S3cretPassw0rd -out /var/backups/p.tgz.enc\n"
           "/usr/local/bin/legacy-encrypt.sh:5:/usr/bin/openssl enc -des3 -salt -k Legacy-Pass-1 -in \"$in\" -out \"$in.enc\"\n"
           "/usr/local/bin/good.sh:3:openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -pass file:/etc/app/pass -in a -out b\n"
           "/usr/local/bin/doc.sh:1:# openssl enc -des is bad\n")
    uses = P.openssl_cli_uses(out)
    assert [(u["file"], u["line"], u["cipher"], u["md"], u["pbkdf2"], u["hardcoded_passphrase"]) for u in uses] == [
        ("/etc/cron.d/zs-payments-backup", 2, "aes-128-cbc", "md5", False, True),
        ("/usr/local/bin/legacy-encrypt.sh", 5, "des3", None, False, True),
        ("/usr/local/bin/good.sh", 3, "aes-256-cbc", None, True, False)]
    assert "S3cret" not in json.dumps(uses) and "Legacy-Pass" not in json.dumps(uses)


def test_web_tls_directives():
    out = ("/etc/nginx/conf.d/zs-payments-8443.conf:6:    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
           "/etc/nginx/conf.d/zs-payments-8443.conf:7:    ssl_ciphers 'ALL:@SECLEVEL=0';\n"
           "/etc/nginx/nginx.conf:32:\tssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3; # Dropping SSLv3, ref: POODLE\n"
           "/etc/httpd/conf.d/ssl.conf:40:SSLProtocol all -SSLv3 -TLSv1\n")
    w = P.web_tls(out)
    ng = w["/etc/nginx/conf.d/zs-payments-8443.conf"]
    assert ng["server"] == "nginx" and ng["protocols"] == ["TLSv1", "TLSv1.1", "TLSv1.2"] and ng["ciphers"] == "ALL:@SECLEVEL=0"
    assert w["/etc/httpd/conf.d/ssl.conf"]["protocols"] == ["TLSv1.1", "TLSv1.2", "TLSv1.3"]
    # Ubuntu's stock nginx.conf, with its trailing comment
    assert w["/etc/nginx/nginx.conf"]["protocols"] == ["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"]
