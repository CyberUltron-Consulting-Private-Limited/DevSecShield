"""Round 5 WP3a: infrastructure-as-code, configuration, dependency and data gaps found by the lab corpus.

Each case writes a small tree modelled on a planted lab item (crypto-zoo) and runs it through ``scan_crypto``; each
has a negative twin (a clean policy, ``validate_certs: yes``, a supported base image, a declared key...). Key
material is synthetic DER built here (a structurally valid key header with filler bytes), never a real key.
"""

from __future__ import annotations

import base64
import json
from datetime import date
from pathlib import Path

import pytest

from aibom.cbom.advisories import (
    compare_versions,
    find_vulnerable,
    group_by_pin,
    parse_specifier,
)
from aibom.cbom.pipeline import scan_crypto
from aibom.cbom.posture.dockerfile import (
    crypto_package_pins,
    extract_dockerfile_images,
    match_release,
)
from aibom.cbom.posture.tls_policy import (
    _NAMED_FLOOR,
    _rows,
    policy_floor_note,
    protocol_for_policy,
)
from aibom.cbom.rules import source_language
from aibom.cbom.x509 import parse_private_key
from aibom.emit.cyclonedx import emit_cyclonedx


def _write(root: Path, files: dict[str, str | bytes]) -> None:
    for rel, body in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(body, bytes):
            path.write_bytes(body)
        else:
            path.write_text(body, encoding="utf-8")


def _rows_by_source(result) -> list[tuple[str, str, str, str, list[str]]]:
    """(kind, name, path, line, codes) for every component."""
    out = []
    for comp in result.components:
        props = comp.properties or {}
        src = props.get("crypto:factPath") or props.get("discovery:source") or ""
        line = props.get("crypto:factLine") or props.get("crypto:line") or ""
        if ":" in src and src.rsplit(":", 1)[1].isdigit():
            src, line = src.rsplit(":", 1)
        out.append((comp.kind, comp.name, src, str(line), sorted({f.code for f in result.flags_for(comp.bom_ref)})))
    return out


def _codes_at(result, path: str) -> set[str]:
    return {code for _k, _n, src, _l, codes in _rows_by_source(result) if src == path for code in codes}


def _diagnostics(result, code: str) -> list[tuple[str, int]]:
    return [(d.path, d.line) for d in result.posture.diagnostics if d.code == code]


# --------------------------------------------------------------------------- #
# COD-072 — ELB / ALB / NLB / CloudFront security-policy catalogue
# --------------------------------------------------------------------------- #

_LISTENER = (
    'resource "aws_lb_listener" "https" {{\n'
    "  load_balancer_arn = aws_lb.main.arn\n"
    "  port              = 443\n"
    '  protocol          = "HTTPS"\n'
    '  ssl_policy        = "{policy}"\n'
    "}}\n"
)


def test_catalogue_holds_every_published_policy_family() -> None:
    rows = _rows()
    families = {family for family, _name in rows}
    assert {"aws-elbv2", "aws-elb", "aws-cloudfront"} <= families
    assert rows[("aws-elbv2", "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09")][0] == "1.2"
    assert rows[("aws-elbv2", "ELBSecurityPolicy-FS-1-2-Res-2020-10")][0] == "1.2"
    assert rows[("aws-elbv2", "ELBSecurityPolicy-TLS13-1-0-2021-06")][0] == "1.0"
    assert rows[("aws-cloudfront", "TLSv1.2_2025")][0] == "1.2"
    assert rows[("aws-cloudfront", "SSLv3")][0] == "SSLv3"
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in rows[("aws-elb", "ELBSecurityPolicy-2015-05")][1]
    assert protocol_for_policy("SSLv3") == "SSLv3"


def test_name_convention_matches_every_catalogued_aws_policy() -> None:
    """The floor read from an unknown name is only trusted because every published name follows it."""
    checked = 0
    for (family, name), (minimum, _suites) in _rows().items():
        matched = _NAMED_FLOOR.match(name)
        if family.startswith("aws-elb") and matched:
            assert f"1.{matched.group(1)}" == minimum, name
            checked += 1
    assert checked >= 30


def test_retired_policy_name_is_judged_by_its_name_and_noted(tmp_path: Path) -> None:
    _write(tmp_path, {"infra/alb.tf": _LISTENER.format(policy="ELBSecurityPolicy-TLS-1-0-2015-04")})
    result = scan_crypto(tmp_path)
    protocol = next(c for c in result.components if c.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {f.code for f in result.flags_for(protocol.bom_ref)}
    fact = next(c for c in result.components if c.kind == "infra")
    assert (fact.properties or {})["crypto:factLine"] == "5"  # the ssl_policy line, not the protocol line
    assert "inferred_from_name" in (fact.properties or {})["crypto:factBasis"]
    assert _diagnostics(result, "tls_policy_not_in_catalog") == [("infra/alb.tf", 5)]
    assert policy_floor_note("ELBSecurityPolicy-TLS13-1-2-2021-06") is None


def test_modern_and_unauthored_policies(tmp_path: Path) -> None:
    _write(tmp_path, {"infra/alb.tf": _LISTENER.format(policy="ELBSecurityPolicy-TLS13-1-2-2021-06")})
    clean = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {f.code for f in clean.flags}
    assert _diagnostics(clean, "tls_policy_not_in_catalog") == []
    _write(tmp_path, {"infra/alb.tf": _LISTENER.format(policy="ELBSecurityPolicy-NOT-AUTHORED")})
    unknown = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {f.code for f in unknown.flags}
    assert _diagnostics(unknown, "tls_policy_not_in_catalog") == [("infra/alb.tf", 5)]


# --------------------------------------------------------------------------- #
# COD-075 — provider-managed key (no key declared)
# --------------------------------------------------------------------------- #


def test_bucket_on_the_provider_default_key_is_low(tmp_path: Path) -> None:
    _write(tmp_path, {
        "s3.tf": 'resource "aws_s3_bucket" "b" {\n  bucket = "acme-data"\n}\n',
        "rds.tf": 'resource "aws_db_instance" "db" {\n  storage_encrypted = true\n}\n',
    })
    result = scan_crypto(tmp_path)
    assert _codes_at(result, "s3.tf") == {"PROVIDER_MANAGED_KEY"}
    flag = next(f for f in result.flags if f.code == "PROVIDER_MANAGED_KEY")
    assert flag.severity == "note"
    assert "PROVIDER_MANAGED_KEY" not in _codes_at(result, "rds.tf")  # declared encryption is not the default


# --------------------------------------------------------------------------- #
# COD-080 — Dockerfile: end-of-life base image, pinned crypto packages, verification switches
# --------------------------------------------------------------------------- #

_DOCKERFILE = (
    "FROM ubuntu:16.04\n"
    "RUN apt-get update && apt-get install -y openssl=1.0.2g-1ubuntu4\n"
    "COPY . /app\n"
)


def test_eol_base_image_and_pinned_openssl(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": _DOCKERFILE})
    result = scan_crypto(tmp_path)
    rows = _rows_by_source(result)
    image = next(r for r in rows if r[0] == "infra")
    assert image[1] == "container_image:ubuntu:16.04" and image[3] == "1" and image[4] == ["EOL_BASE_IMAGE"]
    package = next(r for r in rows if r[1] == "openssl@1.0.2g-1ubuntu4")
    assert package[0] == "framework" and package[3] == "2" and package[4] == []
    pins = crypto_package_pins("RUN apk add --no-cache \\\n    libssl1.1=1.1.1k-r0 curl\n", "Dockerfile")
    assert [(p.name, p.version, p.ecosystem, p.line) for p in pins] == [("libssl1.1", "1.1.1k-r0", "apk", 2)]


def test_base_image_release_matching() -> None:
    assert match_release("ubuntu:16.04").release == "16.04"
    assert match_release("docker.io/library/debian:buster-slim").release == "10"
    assert match_release("python:3.8-slim-buster").distro == "debian"
    assert match_release("node:14-alpine3.12").release == "3.12"
    assert match_release("alpine:3.12.3").release == "3.12"
    assert match_release("centos:7").release == "7"
    assert match_release("amazonlinux:1").release == "2018.03"
    for unjudged in ("ubuntu", "ubuntu:latest", "ubuntu@sha256:abc", "${BASE}", "scratch", "postgres:15"):
        assert match_release(unjudged) is None


def test_supported_base_image_is_clean_and_the_date_decides() -> None:
    assert extract_dockerfile_images("FROM ubuntu:26.04\n", "Dockerfile", today=date(2026, 11, 2)) == ()
    assert extract_dockerfile_images(_DOCKERFILE, "Dockerfile", today=date(2021, 1, 1)) == ()
    (fact,) = extract_dockerfile_images(_DOCKERFILE, "Dockerfile", today=date(2026, 11, 2))
    basis = {item.name: item.value for item in fact.basis}
    assert basis["end_of_life"] == "2021-04-02" and basis["signal"] == "EOL_BASE_IMAGE"
    multi = extract_dockerfile_images("FROM --platform=$BUILDPLATFORM debian:9 AS build\nFROM debian:13\n", "D",
                                      today=date(2026, 11, 2))
    assert [f.address for f in multi] == ["debian:9 AS build"]


def test_dockerfile_verification_switches(tmp_path: Path) -> None:
    _write(tmp_path, {"Dockerfile": (
        "FROM debian:13\n"
        "ENV PYTHONHTTPSVERIFY=0\n"
        "RUN pip install --trusted-host pypi.internal -r requirements.txt\n"
        "ENV GIT_SSL_NO_VERIFY=true\n"
        "RUN npm config set strict-ssl false\n"
    )})
    kinds = {r[1] for r in _rows_by_source(scan_crypto(tmp_path)) if "TLS_VERIFICATION_DISABLED" in r[4]}
    assert kinds == {
        "tls_endpoint:python.https_verify_env", "tls_endpoint:pip.trusted_host",
        "tls_endpoint:git.ssl_no_verify_env", "tls_endpoint:npm.strict_ssl_false",
    }
    _write(tmp_path, {"Dockerfile": "FROM debian:13\nENV PYTHONHTTPSVERIFY=1\nENV GIT_SSL_NO_VERIFY=false\n"})
    assert "TLS_VERIFICATION_DISABLED" not in {f.code for f in scan_crypto(tmp_path).flags}


# --------------------------------------------------------------------------- #
# COD-077 — key material inside a Kubernetes Secret
# --------------------------------------------------------------------------- #


def _der(tag: int, body: bytes) -> bytes:
    n = len(body)
    if n < 0x80:
        return bytes([tag, n]) + body
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(raw)]) + raw + body


def _fake_rsa_pkcs1(bits: int = 2048) -> bytes:
    modulus = b"\x00\xc5" + b"\x5a" * (bits // 8 - 1)
    return _der(0x30, _der(0x02, b"\x00") + _der(0x02, modulus) + _der(0x02, b"\x01\x00\x01"))


def _fake_ec_sec1_p256() -> bytes:
    p256 = bytes.fromhex("2a8648ce3d030107")
    return _der(0x30, _der(0x02, b"\x01") + _der(0x04, b"\x11" * 32) + _der(0xA0, _der(0x06, p256)))


def _pem(label: str, der: bytes) -> str:
    return f"-----BEGIN {label}-----\n" + base64.encodebytes(der).decode() + f"-----END {label}-----\n"


def test_private_key_parser_reads_type_and_size_only() -> None:
    rsa = parse_private_key(_fake_rsa_pkcs1(), "RSA PRIVATE KEY")
    assert (rsa.algorithm, rsa.key_size, rsa.curve) == ("RSA", 2048, None)
    ec = parse_private_key(_fake_ec_sec1_p256(), "EC PRIVATE KEY")
    assert (ec.algorithm, ec.curve) == ("EC", "P-256")
    rsa_oid = _der(0x30, _der(0x06, bytes.fromhex("2a864886f70d010101")) + b"\x05\x00")
    pkcs8 = _der(0x30, _der(0x02, b"\x00") + rsa_oid + _der(0x04, _fake_rsa_pkcs1(3072)))
    assert parse_private_key(pkcs8, "PRIVATE KEY").key_size == 3072
    assert parse_private_key(b"garbage", "PRIVATE KEY") is None
    assert parse_private_key(_fake_rsa_pkcs1(), "ENCRYPTED PRIVATE KEY") is None


def test_secret_tls_key_is_a_hardcoded_key_and_is_never_stored(tmp_path: Path) -> None:
    key_b64 = base64.b64encode(_pem("RSA PRIVATE KEY", _fake_rsa_pkcs1()).encode()).decode()
    bad_cert = base64.b64encode(b"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n").decode()
    _write(tmp_path, {"deploy/k8s/tls-secret.yaml": (
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: app-tls\ntype: kubernetes.io/tls\ndata:\n"
        f"  tls.key: {key_b64}\n  tls.crt: {bad_cert}\n"
        "---\napiVersion: v1\nkind: Secret\nmetadata:\n  name: db\ndata:\n"
        f"  password: {base64.b64encode(b'hunter2-not-a-key').decode()}\n"
    )})
    result = scan_crypto(tmp_path)
    keys = [r for r in _rows_by_source(result) if r[1].startswith("private-key")]
    assert keys == [("crypto_asset", "private-key (app-tls/tls.key)", "deploy/k8s/tls-secret.yaml", "7",
                     ["HARDCODED_KEY"])]
    props = next(c.properties for c in result.components if c.name == "private-key (app-tls/tls.key)")
    assert (props["crypto:algorithm"], props["crypto:keySize"]) == ("RSA", "2048")
    assert _diagnostics(result, "key_material_unparsed") == [("deploy/k8s/tls-secret.yaml", 8)]
    exported = json.dumps(emit_cyclonedx(result)) + json.dumps([c.properties for c in result.components])
    assert key_b64[:40] not in exported and key_b64[-40:] not in exported
    body = "".join(_pem("RSA PRIVATE KEY", _fake_rsa_pkcs1()).splitlines()[1:-1])
    assert body[:40] not in exported


# --------------------------------------------------------------------------- #
# COD-079 — Ansible validate_certs
# --------------------------------------------------------------------------- #

_PLAY = (
    "- hosts: web\n  tasks:\n    - name: fetch config\n      get_url:\n        url: https://internal/cfg\n"
    "        validate_certs: {value}\n        dest: /etc/app/cfg\n"
)


@pytest.mark.parametrize("value", ["no", "false", "False", '"no"'])
def test_ansible_validate_certs_off(tmp_path: Path, value: str) -> None:
    _write(tmp_path, {"deploy/ansible/site.yml": _PLAY.format(value=value)})
    rows = _rows_by_source(scan_crypto(tmp_path))
    hit = [r for r in rows if "TLS_VERIFICATION_DISABLED" in r[4]]
    want = [("tls_endpoint:ansible.validate_certs", "deploy/ansible/site.yml", "6")]
    assert [(r[1], r[2], r[3]) for r in hit] == want


def test_ansible_negative_twins_and_role_tasks(tmp_path: Path) -> None:
    _write(tmp_path, {"deploy/ansible/site.yml": _PLAY.format(value="yes")})
    assert "TLS_VERIFICATION_DISABLED" not in {f.code for f in scan_crypto(tmp_path).flags}
    _write(tmp_path, {
        "deploy/ansible/site.yml": _PLAY.format(value="yes"),
        "roles/web/tasks/main.yml": "- name: call\n  uri:\n    url: https://x\n    validate_certs=no\n",
    })
    assert _codes_at(scan_crypto(tmp_path), "roles/web/tasks/main.yml") == {"TLS_VERIFICATION_DISABLED"}


# --------------------------------------------------------------------------- #
# COD-078 — Helm values (and chart templates that cannot be rendered)
# --------------------------------------------------------------------------- #


def test_helm_values_tls_disabled(tmp_path: Path) -> None:
    _write(tmp_path, {"deploy/helm/values.yaml": "service:\n  name: app\ntls:\n  enabled: false\nreplicas: 2\n"})
    rows = _rows_by_source(scan_crypto(tmp_path))
    hit = next(r for r in rows if r[2] == "deploy/helm/values.yaml")
    assert (hit[1], hit[3]) == ("tls_endpoint:tls.enabled", "4")
    assert "PLAINTEXT_LISTENER" in hit[4]
    _write(tmp_path, {"deploy/helm/values.yaml": "tls:\n  enabled: true\n"})
    assert _codes_at(scan_crypto(tmp_path), "deploy/helm/values.yaml") == set()


def test_helm_chart_templates_are_reported_not_parsed(tmp_path: Path) -> None:
    _write(tmp_path, {
        "chart/Chart.yaml": "apiVersion: v2\nname: app\nversion: 0.1.0\n",
        "chart/values.yaml": "ingress:\n  tls:\n    enabled: false\nclient:\n  insecureSkipVerify: true\n",
        "chart/templates/ingress.yaml": (
            "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: {{ .Release.Name }}\n"
            "spec:\n  {{- if .Values.ingress.tls.enabled }}\n  tls: []\n  {{- end }}\n"
        ),
    })
    result = scan_crypto(tmp_path)
    assert _diagnostics(result, "helm_template_skipped") == [("chart/templates/ingress.yaml", 0)]
    codes = {r[1]: r[4] for r in _rows_by_source(result) if r[2] == "chart/values.yaml"}
    assert "UNENCRYPTED_IN_TRANSIT" in codes["tls_endpoint:ingress.tls.enabled"]
    assert codes["tls_endpoint:client.insecureSkipVerify"] == ["TLS_VERIFICATION_DISABLED"]
    fact = next(c for c in result.components if c.name == "tls_endpoint:ingress.tls.enabled")
    assert "chart/templates/ingress.yaml" in (fact.properties or {})["crypto:factBasis"]
    # an ordinary YAML file named values.yaml outside any chart is not Helm
    _write(tmp_path / "other", {"app/values.yaml": "tls:\n  enabled: false\n"})
    assert _codes_at(scan_crypto(tmp_path / "other"), "app/values.yaml") == set()


# --------------------------------------------------------------------------- #
# COD-084/085/086 — dependency advisories
# --------------------------------------------------------------------------- #


def test_requirements_constraints_and_go_pseudo_versions(tmp_path: Path) -> None:
    _write(tmp_path, {
        "requirements.txt": "flask==2.0.1\npycrypto==2.6.1\n",
        "requirements-extra.txt": "# pinned transitive set\ncryptography==3.2 ; python_version < '3.9'\n",
        "constraints.txt": "pyjwt==2.0.0 --hash=sha256:abcd\n",
        "go.mod": "module x\n\ngo 1.19\n\nrequire (\n\tgolang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2\n)\n",
    })
    rows = {(r.pin.path, r.pin.line, r.pin.name): r for r in group_by_pin(find_vulnerable(tmp_path))}
    pycrypto = rows[("requirements.txt", 2, "pycrypto")]
    assert {a.id for a in pycrypto.advisories} == {"CVE-2013-7459", "CVE-2018-6594"}
    assert pycrypto.upgrade_to is None  # no fixed release: replace the library
    assert ("requirements-extra.txt", 2, "cryptography") in rows
    assert ("constraints.txt", 1, "pyjwt") in rows
    xcrypto = rows[("go.mod", 6, "golang.org/x/crypto")]
    assert "CVE-2019-11840" in {a.id for a in xcrypto.advisories}
    result = scan_crypto(tmp_path)
    libs = [r for r in _rows_by_source(result) if "VULNERABLE_CRYPTO_LIBRARY" in r[4]]
    assert {(r[1], r[2], r[3]) for r in libs} == {
        ("pycrypto@2.6.1", "requirements.txt", "2"),
        ("cryptography@3.2", "requirements-extra.txt", "2"),
        ("pyjwt@2.0.0", "constraints.txt", "1"),
        ("golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2", "go.mod", "6"),
    }
    assert len([r for r in libs if r[1].startswith("pycrypto")]) == 1  # one row per pin, not per CVE


def test_version_ordering_and_clean_pins(tmp_path: Path) -> None:
    assert parse_specifier("v0.0.0-20190308221718-c2843e01d9a2")[0] == "0.0.0-20190308221718-c2843e01d9a2"
    assert parse_specifier("v2.0.0+incompatible")[0] == "2.0.0+incompatible"
    early, fix = "0.0.0-20190308221718-c2843e01d9a2", "0.0.0-20190320223903-b7391e95e576"
    assert compare_versions(early, fix) == -1 and compare_versions(fix, early) == 1
    assert compare_versions("1.0.0-beta.2", "1.0.0-beta.10") == -1  # numeric identifiers compare as numbers
    assert compare_versions("0.1.0", fix) == 1
    _write(tmp_path, {
        "requirements.txt": "cryptography==49.0.0\npycryptodome==3.20.0\n",
        "go.mod": "module x\n\nrequire golang.org/x/crypto v0.56.0\n",
    })
    assert find_vulnerable(tmp_path) == ()


# --------------------------------------------------------------------------- #
# COD-167 — SQL Server EncryptByKey resolved to the key's algorithm
# --------------------------------------------------------------------------- #


def test_mssql_key_resolved_across_files(tmp_path: Path) -> None:
    _write(tmp_path, {
        "db/schema.sql": "CREATE SYMMETRIC KEY sk\n  WITH ALGORITHM = TRIPLE_DES\n  ENCRYPTION BY CERTIFICATE c;\n"
                         "CREATE SYMMETRIC KEY [ak] WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE c;\n",
        "db/use.sql": "-- EncryptByKey(Key_GUID('ak'), x) in a comment\n"
                      "OPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c;\n"
                      "UPDATE users SET ssn = EncryptByKey(Key_GUID('sk'), ssn);\n"
                      "SELECT DecryptByKey(ssn) FROM users;\n"
                      "UPDATE t SET v = EncryptByKey(Key_GUID('ak'), v);\n",
    })
    rows = _rows_by_source(scan_crypto(tmp_path))
    use = {(r[1], r[3]): r[4] for r in rows if r[2] == "db/use.sql"}
    assert "WEAK_ALGORITHM" in use[("3DES", "3")]
    assert "WEAK_ALGORITHM" not in use[("AES-256", "5")]
    schema = {(r[1], r[3]) for r in rows if r[2] == "db/schema.sql"}
    assert ("3DES", "2") in schema  # the declaration keeps its own row (algorithm lane)


def test_mssql_undeclared_key_is_inventoried_without_an_algorithm(tmp_path: Path) -> None:
    _write(tmp_path, {"db/mssql_enc.sql": "-- column encryption\nOPEN SYMMETRIC KEY sk DECRYPTION BY CERTIFICATE c;\n"
                                         "UPDATE users SET ssn = EncryptByKey(Key_GUID('sk'), ssn);\n"})
    result = scan_crypto(tmp_path)
    (row,) = [r for r in _rows_by_source(result) if r[2] == "db/mssql_enc.sql"]
    assert row[:2] == ("crypto_asset", "secret-key (sk, mssql_enc.sql)") and row[3] == "3" and row[4] == []
    comp = next(c for c in result.components if c.name == "secret-key (sk, mssql_enc.sql)")
    assert "crypto:algorithm" not in (comp.properties or {})


# --------------------------------------------------------------------------- #
# COD-149 — PowerShell
# --------------------------------------------------------------------------- #

_PROTECT = (
    "param([string]$In)\n"
    "$key = [byte[]](1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16)\n"
    "$sec = ConvertTo-SecureString -String $In -Key $key\n"
    "Write-Output $sec\n"
)


def test_powershell_securestring_key(tmp_path: Path) -> None:
    _write(tmp_path, {"scripts/Protect.ps1": _PROTECT})
    rows = _rows_by_source(scan_crypto(tmp_path))
    ps = {(r[1], r[3]): r[4] for r in rows if r[2] == "scripts/Protect.ps1"}
    assert ps[("AES", "3")] == []
    assert ps[("secret-key (key, Protect.ps1)", "2")] == ["HARDCODED_KEY"]


def test_powershell_negative_twins_and_utf16(tmp_path: Path) -> None:
    _write(tmp_path, {"a.ps1": "$k = Get-Content key.bin -AsByteStream\n"
                               "$s = ConvertFrom-SecureString $p -Key $k\n"
                               "# $x = ConvertTo-SecureString $y -Key (1..16)\n"})
    rows = _rows_by_source(scan_crypto(tmp_path))
    assert {(r[1], r[3]) for r in rows if r[2] == "a.ps1"} == {("AES", "2")}
    src = "$md5 = [System.Security.Cryptography.MD5]::Create()\n$s = ConvertTo-SecureString $y -Key (1..16)\n"
    _write(tmp_path / "u", {"b.ps1": b"\xff\xfe" + src.encode("utf-16-le")})
    rows = _rows_by_source(scan_crypto(tmp_path / "u"))
    found = {(r[1], r[3]): r[4] for r in rows if r[2] == "b.ps1"}
    assert "WEAK_ALGORITHM" in found[("MD5", "1")]
    assert found[("AES", "2")] == []
    assert found[("secret-key (inline, b.ps1)", "2")] == ["HARDCODED_KEY"]  # an inline -Key (1..16) range


# --------------------------------------------------------------------------- #
# COD-137 — code saved with a .txt extension
# --------------------------------------------------------------------------- #


def test_double_extension_and_sniffed_text(tmp_path: Path) -> None:
    java = "package legacy;\nimport javax.crypto.Cipher;\npublic class Payments {\n" \
           "  public Cipher c() throws Exception {\n    return Cipher.getInstance(\"DES\");\n  }\n}\n"
    _write(tmp_path, {
        "legacy/Payments.java.txt": java,
        "legacy/old_payments.txt": java,
        "CMakeLists.txt": "project(x)\n# uses DES for legacy reasons\n",
        "requirements.txt": "pycryptodome==3.20.0\n",
        "notes.txt": "We moved off DES and MD5 last year.\n",
    })
    assert source_language(tmp_path / "legacy/Payments.java.txt") == "java"
    assert source_language(tmp_path / "legacy/old_payments.txt") == "java"
    for plain in ("CMakeLists.txt", "requirements.txt", "notes.txt"):
        assert source_language(tmp_path / plain) is None
    rows = _rows_by_source(scan_crypto(tmp_path))
    des = {(r[2], r[3]) for r in rows if r[1] == "DES"}
    assert des == {("legacy/Payments.java.txt", "5"), ("legacy/old_payments.txt", "5")}


# --------------------------------------------------------------------------- #
# COD-187/188 — submodules not checked out, Git LFS pointers
# --------------------------------------------------------------------------- #


def test_submodules_and_lfs_pointers_are_coverage_notes(tmp_path: Path) -> None:
    pointer = "version https://git-lfs.github.com/spec/v1\noid sha256:" + "a" * 64 + "\nsize 2048\n"
    _write(tmp_path, {
        ".gitmodules": '[submodule "crypto-legacy"]\n\tpath = crypto-legacy\n\turl = https://example.com/x.git\n'
                       '[submodule "vendor-ok"]\n\tpath = libs/ok\n\turl = https://example.com/y.git\n',
        "libs/ok/des.c": "int x;\n",
        ".gitattributes": "models/*.py filter=lfs diff=lfs merge=lfs -text\n",
        "models/weak_crypto.py": pointer,
        "app.py": "print('hi')\n",
    })
    (tmp_path / "crypto-legacy").mkdir()
    result = scan_crypto(tmp_path)
    assert _diagnostics(result, "submodule_not_scanned") == [("crypto-legacy", 0)]
    assert _diagnostics(result, "lfs_object_not_scanned") == [("models/weak_crypto.py", 0)]
    assert result.properties["crypto:coverage:submodulesNotScanned"] == "1"
    assert result.properties["crypto:coverage:lfsObjectsNotScanned"] == "1"


def test_pointer_shaped_file_without_lfs_attributes_is_not_reported(tmp_path: Path) -> None:
    _write(tmp_path, {"notes.md": "version https://git-lfs.github.com/spec/v1\n"})
    result = scan_crypto(tmp_path)
    assert _diagnostics(result, "lfs_object_not_scanned") == []
    assert "crypto:coverage:lfsObjectsNotScanned" not in result.properties
