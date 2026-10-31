"""The committed Terraform fixture reaches the three posture PDFs."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
if str(_REPO) not in sys.path:
    sys.path.insert(0, str(_REPO))

from backend.tests.support.pdf_text import pdf_text
from backend.utilities.dashboard import cbom_team_rollup as roll
from backend.utilities.pdf.cbom_data_at_rest_pdf import (
    build_pdf as data_pdf,
)
from backend.utilities.pdf.cbom_infra_posture_pdf import (
    build_pdf as infra_pdf,
)
from backend.utilities.pdf.cbom_network_tls_pdf import (
    build_pdf as network_pdf,
)

_TREE = _REPO / "aibom" / "tests" / "fixtures" / "synthetic-config-aws-tf"
_PYTHON = _REPO / "aibom" / ".venv" / "bin" / "python"
_NOW = datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc)
_SCAN = r"""
import json
import sys
from pathlib import Path

from aibom.cbom.normalize import normalize_crypto
from aibom.cbom.pipeline import scan_crypto

tree = Path(sys.argv[1])
dest = Path(sys.argv[2])
run = normalize_crypto(scan_crypto(tree), duration_of_scan=0.0)
dest.write_text(json.dumps(run), encoding="utf-8")
"""


def _scan(dest: Path, tree: Path = _TREE) -> dict:
    subprocess.run(
        [str(_PYTHON), "-c", _SCAN, str(tree), str(dest)],
        cwd=_REPO / "aibom",
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(dest.read_text(encoding="utf-8"))


def _view(blob: dict) -> roll.TeamCbomView:
    created = _NOW - timedelta(days=1)
    head = roll.ScanHead(
        id=501,
        team_id=1,
        scan_type="cbom",
        title="synthetic-config-aws-tf",
        status="success",
        created_at=created,
        last_updated=created + timedelta(minutes=2),
        scan_metadata={
            "zip_file_used": False,
            "repo_url": "https://example.invalid/synthetic-config-aws-tf",
            "branch": "main",
        },
    )

    def load(ids: list[int]) -> dict[int, dict]:
        return {scan_id: blob for scan_id in ids}

    return roll.fold_scans(
        [head],
        load,
        team_id=1,
        team_name="Fixture Team",
        now=_NOW,
    )


def test_fixture_scan_is_printed_by_the_three_posture_pdfs(tmp_path: Path) -> None:
    blob = _scan(tmp_path / "run.json")
    block = blob["cbom_posture"]
    assert block["lanes"]
    addresses = {fact["address"] for fact in block["facts"]}
    assert "aws_db_instance.plain" in addresses
    assert "aws_s3_bucket.logs" in addresses
    view = _view(blob)
    documents = {
        "infra": infra_pdf(view),
        "network": network_pdf(view),
        "data": data_pdf(view),
    }
    texts = {name: pdf_text(raw) for name, raw in documents.items()}
    for raw in documents.values():
        assert raw.startswith(b"%PDF-")
        assert len(raw) > 3000
    infra = texts["infra"]
    assert "aws_db_instance.plain" in infra
    assert "aws_s3_bucket.logs" in infra
    assert "Not encrypted" in infra
    assert "Encrypted (provider default)" in infra
    assert "declared configuration is not proof of operation" in infra
    assert "The platform did not probe any endpoint" in texts["network"]
    data = texts["data"]
    assert "aws_db_instance.plain" in data
    assert "aws_s3_bucket.logs" in data
    assert "stored data was not inspected" in data


def test_omitted_aws_rotation_reaches_the_infra_pdf(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "main.tf").write_text(
        'resource "aws_kms_key" "key" {\n}\n', encoding="utf-8"
    )
    blob = _scan(tmp_path / "run.json", tree)
    fact = next(
        row
        for row in blob["cbom_posture"]["facts"]
        if row["address"] == "aws_kms_key.key"
    )
    assert "KMS_KEY_ROTATION_DISABLED" in fact["finding_codes"]
    text = pdf_text(infra_pdf(_view(blob)))
    assert "aws_kms_key.key" in text
    assert "Key rotation disabled" in text


def test_weak_nginx_suite_is_printed_in_the_network_pdf(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_ciphers DES-CBC3-SHA;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "Weak cipher suites" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_haproxy_default_cipher_is_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-default-bind-ciphers DES-CBC3-SHA\n"
        "frontend www\n"
        "  bind :443 ssl\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "haproxy.cfg" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_strong_nginx_suite_is_not_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" not in text


def test_a_different_imported_host_is_not_a_discrepancy(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  server_name example.com;\n"
        "  ssl_protocols TLSv1.2;\n"
        "}\n",
        encoding="utf-8",
    )
    (tree / "result.json").write_text(
        '{"scanResult":[{"targetHost":"example.org","port":"443",'
        '"protocols":["TLSv1"]}]}',
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "example.com:443" in text
    assert "discrepancy" not in text


def test_spring_and_import_discrepancy_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "application.properties").write_text(
        "server.address=app.example.test\n"
        "server.port=8443\n"
        "server.ssl.enabled=true\n"
        "server.ssl.enabled-protocols=TLSv1.2\n",
        encoding="utf-8",
    )
    (tree / "result.json").write_text(
        '{"scanResult":[{"targetHost":"app.example.test","port":"8443",'
        '"protocols":["TLSv1"]}]}',
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "app.example.test:8443 discrepancy" in text


def test_static_floor_above_the_import_is_a_discrepancy(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  server_name example.com;\n"
        "  ssl_protocols TLSv1.2;\n"
        "}\n",
        encoding="utf-8",
    )
    (tree / "result.json").write_text(
        '{"scanResult":[{"targetHost":"example.com","port":"443",'
        '"protocols":["TLSv1"]}]}',
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "example.com:443 discrepancy" in text
    matched = tmp_path / "matched"
    matched.mkdir()
    (matched / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  server_name example.com;\n"
        "  ssl_protocols TLSv1.2;\n"
        "}\n",
        encoding="utf-8",
    )
    (matched / "result.json").write_text(
        '{"scanResult":[{"targetHost":"example.com","port":"443",'
        '"protocols":["TLSv1.2"]}]}',
        encoding="utf-8",
    )
    same = _scan(tmp_path / "same.json", matched)
    same_text = pdf_text(network_pdf(_view(same)))
    assert "example.com:443" in same_text
    assert "discrepancy" not in same_text


def test_ssh_port_is_printed_as_a_listen(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "sshd_config").write_text("Port 22\n", encoding="utf-8")
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "listen 22" in text


def test_tomcat_host_name_is_printed_as_the_endpoint(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "server.xml").write_text(
        "<Server><Service><Engine><Host name=\"app.example.test\">"
        "<Connector port=\"8443\" SSLEnabled=\"true\"/>"
        "</Host></Engine></Service></Server>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "app.example.test:8443" in text


def test_envoy_server_name_is_printed_as_the_endpoint(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "    - address:\n"
        "        socket_address:\n"
        "          address: 0.0.0.0\n"
        "          port_value: 443\n"
        "      filter_chains:\n"
        "        - filter_chain_match:\n"
        "            server_names: ['app.example.test']\n"
        "          transport_socket:\n"
        "            typed_config:\n"
        "              tls_minimum_protocol_version: TLSv1_2\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "app.example.test:443" in text


def test_nginx_server_name_is_printed_as_the_endpoint(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  server_name www.example.com example.com;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "example.com:443" in text


def test_nginx_listen_port_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  server_name _;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "listen 443" in text


def test_nginx_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_protocols TLSv1 TLSv1.2;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "listen 443" in text
    assert "offered" in text


def test_plaintext_nginx_listener_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 80;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "nginx.server[1]" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed
    assert "PLAINTEXT_LISTENER" in collapsed


def test_apache_listen_80_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text("Listen 80\n", encoding="utf-8")
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "apache.main[1]" in collapsed
    assert "PLAINTEXT_LISTENER" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_ingress_without_tls_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  rules:\n"
        "  - host: example.com\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "ingress.yaml" in collapsed
    assert "PLAINTEXT_LISTENER" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_istio_permissive_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "peer.yaml").write_text(
        "apiVersion: security.istio.io/v1beta1\n"
        "kind: PeerAuthentication\n"
        "metadata:\n"
        "  name: mesh\n"
        "spec:\n"
        "  mtls:\n"
        "    mode: PERMISSIVE\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "peer.yaml" in collapsed
    assert "PLAINTEXT_LISTENER" in collapsed


def test_identity_provider_is_printed_as_not_encrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: enc\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - identity: {}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(data_pdf(_view(blob))).split())
    assert "enc.yaml" in collapsed
    assert "Notencrypted" in collapsed


def test_apiserver_without_flag_is_printed_as_not_encrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "pod.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: apiserver\n"
        "spec:\n"
        "  containers:\n"
        "  - name: kube-apiserver\n"
        "    image: registry.k8s.io/kube-apiserver:v1.29.0\n"
        "    command: [kube-apiserver]\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(data_pdf(_view(blob))).split())
    assert "pod.yaml" in collapsed
    assert "Notencrypted" in collapsed


def test_linked_apiserver_is_not_printed_as_unencrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: enc\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - kms:\n"
        "      name: vault\n"
        "      endpoint: unix:///tmp/kms.sock\n",
        encoding="utf-8",
    )
    (tree / "pod.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Pod\n"
        "metadata:\n"
        "  name: apiserver\n"
        "spec:\n"
        "  containers:\n"
        "  - name: kube-apiserver\n"
        "    image: registry.k8s.io/kube-apiserver:v1.29.0\n"
        "    command:\n"
        "    - kube-apiserver\n"
        "    - --encryption-provider-config=/etc/kubernetes/enc.yaml\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(data_pdf(_view(blob))).split())
    assert "pod.yaml" in collapsed
    assert "Encrypted(declared)" in collapsed
    assert "Notencrypted" not in collapsed


def test_configmaps_only_are_printed_as_not_encrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: enc\n"
        "resources:\n"
        "- resources: [configmaps]\n"
        "  providers:\n"
        "  - kms:\n"
        "      name: vault\n"
        "      endpoint: unix:///tmp/kms.sock\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(data_pdf(_view(blob))).split())
    assert "enc.yaml" in collapsed
    assert "Notencrypted" in collapsed


def test_https_redirect_is_not_printed_as_unencrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 80;\n"
        "  return 301 https://example.com$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "nginx.server[1]" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" not in collapsed


def test_http_redirect_is_printed_as_unencrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 80;\n"
        "  return 301 http://example.com$request_uri;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "nginx.server[1]" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_postgres_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "postgresql.conf").write_text(
        "ssl = on\nssl_min_protocol_version = 'TLSv1'\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "postgresql.conf" in text
    assert "offered" in text


def test_postgres_ssl_off_is_printed_as_not_encrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "postgresql.conf").write_text("ssl = off\n", encoding="utf-8")
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "SSH and database transport" in text
    assert "postgresql.conf" in text
    assert "Not encrypted" in text


def test_elasticsearch_client_auth_is_not_printed_as_disabled(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "elasticsearch.yml").write_text(
        "xpack:\n"
        "  security:\n"
        "    http.ssl.client_authentication: none\n"
        "    http.ssl.supported_protocols: [TLSv1, TLSv1.2]\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "elasticsearch.yml" in text
    assert "TLS_VERIFICATION_DISABLED" not in collapsed


def test_mysql_certificate_subject_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    pem = (
        _REPO
        / "aibom"
        / "tests"
        / "fixtures"
        / "synthetic-crypto-certs"
        / "strong.pem"
    )
    (tree / "server.pem").write_bytes(pem.read_bytes())
    (tree / "my.cnf").write_text(
        "[mysqld]\nssl_cert = server.pem\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "my.cnf" in text
    assert "strong-control.test" in text


def test_compose_httpd_floor_is_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    (tree / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: httpd:2.4.58\n"
        "    volumes:\n"
        "      - type: bind\n"
        "        source: ./httpd.conf\n"
        "        target: /usr/local/apache2/conf/httpd.conf\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "WEAK_PROTOCOL" in collapsed


def test_httpd_2_4_16_is_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    (tree / "Dockerfile").write_text("FROM httpd:2.4.16\n", encoding="utf-8")
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "WEAK_PROTOCOL" in collapsed


def test_compose_mounted_nginx_floor_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (tree / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    image: nginx:1.27.3\n"
        "    volumes:\n"
        "      - ./nginx.conf:/etc/nginx/nginx.conf\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen 443" in text
    assert "WEAK_PROTOCOL" not in collapsed


def test_ssl_on_is_not_printed_as_plaintext(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443;\n  ssl on;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen 443" in text
    assert "PLAINTEXT_LISTENER" not in collapsed
    mixed = tmp_path / "mixed"
    mixed.mkdir()
    (mixed / "nginx.conf").write_text(
        "server {\n  listen 80;\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    mixed_blob = _scan(tmp_path / "mixed.json", mixed)
    mixed_text = "".join(pdf_text(network_pdf(_view(mixed_blob))).split())
    assert "PLAINTEXT_LISTENER" in mixed_text


def test_last_nginx_stage_floor_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (tree / "Dockerfile").write_text(
        "FROM nginx:1.25 AS build\nFROM nginx:1.27.3-alpine\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen 443" in text
    assert "WEAK_PROTOCOL" not in collapsed


def test_nginx_image_floor_is_printed(tmp_path: Path) -> None:
    modern = tmp_path / "modern"
    modern.mkdir()
    (modern / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (modern / "Dockerfile").write_text(
        "FROM nginx:1.27.3-alpine\n",
        encoding="utf-8",
    )
    modern_blob = _scan(tmp_path / "modern.json", modern)
    modern_text = pdf_text(network_pdf(_view(modern_blob)))
    assert "listen 443" in modern_text
    assert "WEAK_PROTOCOL" not in "".join(modern_text.split())
    older = tmp_path / "older"
    older.mkdir()
    (older / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n}\n",
        encoding="utf-8",
    )
    (older / "Dockerfile").write_text("FROM nginx:1.25\n", encoding="utf-8")
    older_blob = _scan(tmp_path / "older.json", older)
    older_text = "".join(pdf_text(network_pdf(_view(older_blob))).split())
    assert "WEAK_PROTOCOL" in older_text


def test_nginx_http_protocol_is_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "http {\n"
        "  ssl_protocols TLSv1;\n"
        "  server { listen 443 ssl; }\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen 443" in text
    assert "WEAK_PROTOCOL" in collapsed


def test_apache_without_a_protocol_is_not_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\nSSLEngine on\n</VirtualHost>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "WEAK_PROTOCOL" not in collapsed


def test_apache_protocol_inside_if_is_not_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "<If \"%{HTTPS} == 'on'\">\n"
        "SSLProtocol TLSv1\n"
        "</If>\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "WEAK_PROTOCOL" not in collapsed


def test_apache_cipher_with_a_protocol_word_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLCipherSuite TLSv1.2 DES-CBC3-SHA\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in collapsed


def test_apache_all_minus_sslv3_is_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLProtocol all -SSLv3\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "WEAK_PROTOCOL" in collapsed


def test_apache_proxy_tls_10_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "httpd.conf").write_text(
        "<VirtualHost *:443>\n"
        "SSLEngine on\n"
        "SSLProtocol TLSv1.2\n"
        "SSLProxyProtocol TLSv1\n"
        "</VirtualHost>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen *:443" in text
    assert "WEAK_PROTOCOL" in collapsed


def test_private_key_material_is_not_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    pem = (
        _REPO
        / "aibom"
        / "tests"
        / "fixtures"
        / "synthetic-crypto-certs"
        / "strong.pem"
    )
    (tree / "server.pem").write_bytes(pem.read_bytes())
    (tree / "server.key").write_text(
        "-----BEGIN PRIVATE KEY-----\nSECRETKEYMATERIAL\n-----END PRIVATE KEY-----\n",
        encoding="utf-8",
    )
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_certificate server.pem;\n"
        "  ssl_certificate_key server.key;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "listen 443" in text
    assert "strong-control.test" in text
    assert "SECRETKEYMATERIAL" not in text


def test_nginx_certificate_subject_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    pem = (
        _REPO
        / "aibom"
        / "tests"
        / "fixtures"
        / "synthetic-crypto-certs"
        / "strong.pem"
    )
    (tree / "server.pem").write_bytes(pem.read_bytes())
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_certificate server.pem;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "listen 443" in text
    assert "strong-control.test" in text


def test_nginx_hsts_max_age_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        '  add_header Strict-Transport-Security "max-age=31536000" always;\n'
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "listen 443" in text
    assert "31536000" in text


def test_haproxy_weak_curve_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "haproxy.cfg").write_text(
        "frontend web\n  bind :443 ssl curves P-192\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "haproxy.frontend[1]" in text
    assert "P-192" in text
    assert "WEAK_ALGORITHM" in collapsed


def test_weak_curve_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  ssl_ecdh_curve prime192v1;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen 443" in text
    assert "prime192v1" in text
    assert "WEAK_ALGORITHM" in collapsed


def test_client_auth_off_is_not_printed_as_disabled_verification(
    tmp_path: Path,
) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_verify_client off;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "listen 443" in text
    assert "TLS_VERIFICATION_DISABLED" not in collapsed


def test_proxy_verify_off_is_printed_as_disabled(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "nginx.conf").write_text(
        "server {\n"
        "  listen 443 ssl;\n"
        "  proxy_pass https://backend.example;\n"
        "  proxy_ssl_verify off;\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "nginx.conf" in text
    assert "TLS_VERIFICATION_DISABLED" in collapsed


def test_istio_passthrough_is_not_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "gateway.yaml").write_text(
        "apiVersion: networking.istio.io/v1beta1\n"
        "kind: Gateway\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  servers:\n"
        "  - port:\n"
        "      number: 443\n"
        "      protocol: HTTPS\n"
        "    tls:\n"
        "      mode: PASSTHROUGH\n"
        "      minProtocolVersion: TLSV1_0\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "default/web" in collapsed
    assert "WEAK_PROTOCOL" not in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" not in collapsed


def test_istio_gateway_weak_suite_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "gateway.yaml").write_text(
        "apiVersion: networking.istio.io/v1beta1\n"
        "kind: Gateway\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  servers:\n"
        "  - port:\n"
        "      number: 443\n"
        "      protocol: HTTPS\n"
        "    tls:\n"
        "      mode: SIMPLE\n"
        "      cipherSuites:\n"
        "      - TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "default/web" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_istio_gateway_http_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "gateway.yaml").write_text(
        "apiVersion: networking.istio.io/v1beta1\n"
        "kind: Gateway\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  servers:\n"
        "  - port:\n"
        "      number: 80\n"
        "      protocol: HTTP\n"
        "  - port:\n"
        "      number: 443\n"
        "      protocol: HTTPS\n"
        "    tls:\n"
        "      mode: SIMPLE\n"
        "      minProtocolVersion: TLSV1_0\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "default/web" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed
    assert "offered" in collapsed


def test_destination_rule_disable_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "rule.yaml").write_text(
        "apiVersion: networking.istio.io/v1beta1\n"
        "kind: DestinationRule\n"
        "metadata:\n"
        "  name: api\n"
        "spec:\n"
        "  trafficPolicy:\n"
        "    tls:\n"
        "      mode: DISABLE\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "default/api" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_cloudformation_ref_policy_is_not_printed_as_weak(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "stack.yaml").write_text(
        "Resources:\n"
        "  Https:\n"
        "    Type: AWS::ElasticLoadBalancingV2::Listener\n"
        "    Properties:\n"
        "      Protocol: HTTPS\n"
        "      SslPolicy: !Ref PolicyName\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "Https" in collapsed
    assert "WEAK_PROTOCOL" not in collapsed


def test_variable_listener_policy_is_not_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "main.tf").write_text(
        'resource "aws_lb_listener" "https" {\n'
        '  protocol   = "HTTPS"\n'
        "  ssl_policy = var.policy\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    collapsed = "".join(text.split())
    assert "aws_lb_listener.https" in text
    assert "WEAK_PROTOCOL" not in collapsed


def test_https_listener_default_policy_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "main.tf").write_text(
        'resource "aws_lb_listener" "https" {\n'
        '  protocol = "HTTPS"\n'
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "aws_lb_listener.https" in text
    assert "offered" in text


def test_cloudformation_tlsv1_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "stack.yaml").write_text(
        "Resources:\n"
        "  Web:\n"
        "    Type: AWS::CloudFront::Distribution\n"
        "    Properties:\n"
        "      DistributionConfig:\n"
        "        ViewerCertificate:\n"
        "          MinimumProtocolVersion: TLSv1\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "Web" in text
    assert "offered" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_azure_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "main.tf").write_text(
        'resource "azurerm_linux_web_app" "old" {\n'
        "  https_only = true\n"
        "  site_config {\n"
        '    minimum_tls_version = "1.0"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "azurerm_linux_web_app.old" in text
    assert "offered" in text


def test_gcp_compatible_ssl_policy_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "main.tf").write_text(
        'resource "google_compute_ssl_policy" "old" {\n'
        '  profile         = "COMPATIBLE"\n'
        '  min_tls_version = "TLS_1_0"\n'
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "google_compute_ssl_policy.old" in text
    assert "offered" in text


def test_cloudfront_tlsv1_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "main.tf").write_text(
        'resource "aws_cloudfront_distribution" "web" {\n'
        "  viewer_certificate {\n"
        '    minimum_protocol_version = "TLSv1"\n'
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "aws_cloudfront_distribution.web" in text
    assert "offered" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_service_negotiation_policy_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "svc.yaml").write_text(
        "apiVersion: v1\n"
        "kind: Service\n"
        "metadata:\n"
        "  name: lb\n"
        "  annotations:\n"
        "    service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy:\n"
        "      ELBSecurityPolicy-2016-08\n"
        "spec:\n"
        "  type: LoadBalancer\n"
        "  ports:\n"
        "  - port: 443\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "default/lb" in text
    assert "offered" in text


def test_frontend_config_compatible_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "front.yaml").write_text(
        "apiVersion: networking.gke.io/v1beta1\n"
        "kind: FrontendConfig\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  sslPolicy: COMPATIBLE\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "default/web" in text
    assert "offered" in text


def test_alb_old_ssl_policy_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        '    alb.ingress.kubernetes.io/ssl-policy: "ELBSecurityPolicy-2016-08"\n'
        "spec:\n"
        "  rules:\n"
        "  - host: app.example.com\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "default/web" in text
    assert "offered" in text


def test_certificate_arn_is_not_printed_as_unencrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        '    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:us-east-1:1:certificate/abc"\n'
        "spec:\n"
        "  rules:\n"
        "  - host: app.example.com\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "default/web" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" not in collapsed


def test_alb_http_and_https_ports_are_printed_as_unencrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    ports = '[{"HTTP":80},{"HTTPS":443}]'
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        f"    alb.ingress.kubernetes.io/listen-ports: '{ports}'\n"
        "spec:\n"
        "  rules:\n"
        "  - host: app.example.com\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "default/web" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_alb_http_listen_port_is_printed_as_unencrypted(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        "    alb.ingress.kubernetes.io/listen-ports: '[{\"HTTP\":80}]'\n"
        "spec:\n"
        "  rules:\n"
        "  - host: app.example.com\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "default/web" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_ingress_rc4_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        '    nginx.ingress.kubernetes.io/ssl-ciphers: "RC4-SHA"\n'
        "spec:\n"
        "  tls:\n"
        "  - secretName: edge-tls\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "default/web" in text
    assert "TLS_RSA_WITH_RC4_128_SHA" in text


def test_ingress_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        "    nginx.ingress.kubernetes.io/ssl-protocols: TLSv1 TLSv1.2\n"
        "spec:\n"
        "  tls:\n"
        "  - secretName: edge-tls\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "default/web" in text
    assert "offered" in text


def test_openssh_weak_kex_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "sshd_config").write_text(
        "Ciphers aes128-ctr,blowfish-cbc\n"
        "KexAlgorithms diffie-hellman-group1-sha1\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "sshd_config[1]" in text
    assert "blowfish-cbc" in text
    assert "diffie-hellman-group1-sha1" in text


def test_jetty_excluded_suite_is_not_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "jetty-ssl.xml").write_text(
        "<Configure>\n"
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
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "jetty.ssl[1]" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" not in text
    assert "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" not in text


def test_jetty_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "jetty-ssl.xml").write_text(
        "<Configure>\n"
        '  <Set name="IncludeProtocols">\n'
        "    <Item>TLSv1</Item>\n"
        "    <Item>TLSv1.2</Item>\n"
        "  </Set>\n"
        "</Configure>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "jetty.ssl[1]" in text
    assert "offered" in text


def test_spring_yaml_tls_10_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "application.yml").write_text(
        "server:\n"
        "  ssl:\n"
        "    enabled: true\n"
        "    client-auth: none\n"
        "    enabled-protocols:\n"
        "      - TLSv1\n"
        "      - TLSv1.2\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "spring.server[1]" in text


def test_spring_weak_cipher_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "application.properties").write_text(
        "server.ssl.enabled=true\n"
        "server.ssl.ciphers=TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "spring.server[1]" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_spring_disabled_ssl_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "application.properties").write_text(
        "server.ssl.enabled=false\n"
        "management.server.ssl.enabled=true\n"
        "management.server.ssl.enabled-protocols=TLSv1,TLSv1.2\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "application.properties" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed
    assert "offered" in collapsed


def test_tomcat_host_config_cipher_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8443" SSLEnabled="true">\n'
        '      <SSLHostConfig ciphers="TLS_RSA_WITH_3DES_EDE_CBC_SHA"/>\n'
        "    </Connector>\n"
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "tomcat.connector[1]" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_tomcat_weak_cipher_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8443" SSLEnabled="true"\n'
        '               ciphers="TLS_RSA_WITH_3DES_EDE_CBC_SHA"/>\n'
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "tomcat.connector[1]" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_tomcat_plaintext_connector_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "server.xml").write_text(
        "<Server>\n"
        "  <Service>\n"
        '    <Connector port="8080" protocol="HTTP/1.1"/>\n'
        '    <Connector port="8443" SSLEnabled="true"\n'
        '               sslEnabledProtocols="TLSv1,TLSv1.2"/>\n'
        "  </Service>\n"
        "</Server>\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "server.xml" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed
    assert "offered" in collapsed


def test_traefik_skip_verify_is_printed_as_disabled(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "traefik.yml").write_text(
        "entryPoints:\n"
        "  web:\n"
        "    address: \":443\"\n"
        "serversTransport:\n"
        "  insecureSkipVerify: true\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "traefik.tls[1]" in text
    assert "Disabled certificate verification" in text


def test_traefik_weak_suite_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "traefik.yml").write_text(
        "tls:\n"
        "  options:\n"
        "    default:\n"
        "      cipherSuites:\n"
        "        - TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "traefik.yml" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_traefik_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "traefik.yml").write_text(
        "tls:\n  options:\n    default:\n      minVersion: VersionTLS10\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "traefik.tls[1]" in text
    assert "offered" in text


def test_envoy_weak_suite_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "  - filter_chains:\n"
        "    - transport_socket:\n"
        "        typed_config:\n"
        "          cipher_suites:\n"
        "          - TLS_RSA_WITH_3DES_EDE_CBC_SHA\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "envoy.yaml" in text
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in text


def test_envoy_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "envoy.yaml").write_text(
        "static_resources:\n"
        "  listeners:\n"
        "  - name: listener_0\n"
        "    filter_chains:\n"
        "    - transport_socket:\n"
        "        typed_config:\n"
        "          tls_minimum_protocol_version: TLSv1_0\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "envoy.listener[1]" in text
    assert "offered" in text


def test_haproxy_tls_10_is_printed_as_offered(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "haproxy.cfg").write_text(
        "frontend www\n  bind :443 ssl ssl-min-ver TLSv1.0\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "haproxy.frontend[1]" in text
    assert "offered" in text


def test_haproxy_verify_none_is_printed_as_disabled(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "haproxy.cfg").write_text(
        "backend api\n  server app 10.0.0.1:443 ssl verify none\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "Disabled certificate verification" in text
    assert "haproxy.cfg" in text


def test_requests_verify_false_is_printed_as_disabled(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "client.py").write_text(
        "requests.get(url, verify=False)\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    text = pdf_text(network_pdf(_view(blob)))
    assert "Disabled certificate verification" in text
    assert "client.py" in text


def test_file_keyring_is_printed_as_weak_at_rest(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "my.cnf").write_text(
        "[mysqld]\nearly-plugin-load=keyring_file.so\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(infra_pdf(_view(blob))).split())
    assert "my.cnf" in collapsed
    assert "AT_REST_ENCRYPTION_WEAK" in collapsed


def test_aescbc_is_printed_without_the_secret(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    secret = "AAAAAAAAAAAAAAAAAAAAAA=="
    (tree / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: enc\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - aescbc:\n"
        "      keys:\n"
        "      - name: key1\n"
        f"        secret: {secret}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(infra_pdf(_view(blob))).split())
    assert "enc.yaml" in collapsed
    assert "AT_REST_ENCRYPTION_WEAK" in collapsed
    assert secret not in collapsed
    assert secret not in json.dumps(blob)


def test_heartbleed_import_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "result.json").write_text(
        '{"scanResult":[{"targetHost":"example.com","port":"443","findings":['
        '{"id":"HEARTBLEED","severity":"HIGH"},{"id":"BEAST","severity":"LOW"}]}]}',
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "example.com:443" in collapsed
    assert "HEARTBLEED" in collapsed
    assert "BEAST" in collapsed


def test_fallback_scsv_is_printed(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "result.json").write_text(
        '{"scanResult":[{"targetHost":"example.com","port":"443",'
        '"protocols":["TLSv1"],"findings":['
        '{"id":"TLS_FALLBACK_SCSV","severity":"LOW"}]}]}',
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "example.com:443" in collapsed
    assert "TLS_FALLBACK_SCSV" in collapsed
    assert "missing" in collapsed


def _dh_pem() -> str:
    import binascii

    def der_len(length: int) -> bytes:
        if length < 0x80:
            return bytes((length,))
        body = length.to_bytes((length.bit_length() + 7) // 8, "big")
        return bytes((0x80 | len(body),)) + body

    def der_integer(value: int) -> bytes:
        width = max(1, (value.bit_length() + 7) // 8)
        raw = value.to_bytes(width, "big")
        if raw[0] & 0x80:
            raw = b"\x00" + raw
        return b"\x02" + der_len(len(raw)) + raw

    prime = (1 << 1023) | 1
    sequence = der_integer(prime) + der_integer(2)
    der = b"\x30" + der_len(len(sequence)) + sequence
    body = binascii.b2a_base64(der).decode("ascii")
    return (
        "-----BEGIN DH PARAMETERS-----\n"
        + body
        + "-----END DH PARAMETERS-----\n"
    )


def test_dh_1024_is_printed_on_the_nginx_endpoint(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "dhparam.pem").write_text(_dh_pem(), encoding="utf-8")
    (tree / "nginx.conf").write_text(
        "server {\n  listen 443 ssl;\n  ssl_dhparam dhparam.pem;\n}\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "nginx.conf" in collapsed
    assert "DH1024" in collapsed
    assert "WEAK_KEY_SIZE" in collapsed


def test_haproxy_https_redirect_is_not_printed_as_unencrypted(tmp_path: Path) -> None:
    def render(name: str, body: str) -> str:
        tree = tmp_path / name
        tree.mkdir()
        (tree / "haproxy.cfg").write_text(body, encoding="utf-8")
        blob = _scan(tmp_path / f"{name}.json", tree)
        return "".join(pdf_text(network_pdf(_view(blob))).split())

    https = render("https", "frontend www\n  bind :80\n  redirect scheme https\n")
    http = render("http", "frontend www\n  bind :80\n  redirect scheme http\n")
    assert "haproxy.cfg" in https
    assert "UNENCRYPTED_IN_TRANSIT" not in https
    assert "UNENCRYPTED_IN_TRANSIT" in http


def test_haproxy_dh_file_is_printed_on_the_network_pdf(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "dhparam.pem").write_text(_dh_pem(), encoding="utf-8")
    (tree / "haproxy.cfg").write_text(
        "global\n"
        "  ssl-dh-param-file dhparam.pem\n"
        "frontend www\n"
        "  bind :443 ssl\n"
        "frontend plain\n"
        "  bind :80\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "haproxy.cfg" in collapsed
    assert "DH1024" in collapsed
    assert "WEAK_KEY_SIZE" in collapsed
    assert "UNENCRYPTED_IN_TRANSIT" in collapsed


def test_postgres_dh_file_is_printed_on_the_network_pdf(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    tree.mkdir()
    (tree / "dhparam.pem").write_text(_dh_pem(), encoding="utf-8")
    (tree / "postgresql.conf").write_text(
        "ssl = on\nssl_dh_params_file = 'dhparam.pem'\n",
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(network_pdf(_view(blob))).split())
    assert "postgresql.conf" in collapsed
    assert "DH1024" in collapsed
    assert "WEAK_KEY_SIZE" in collapsed


def test_mapping_file_is_printed_as_declared(tmp_path: Path) -> None:
    tree = tmp_path / "tree"
    nested = tree / ".devsecshield"
    nested.mkdir(parents=True)
    (nested / "cbom-mapping.yaml").write_text(
        "version: 1\ndefaults:\n  system: billing\n",
        encoding="utf-8",
    )
    (tree / "main.tf").write_text(
        'resource "aws_s3_bucket" "logs" {\n  bucket = "logs"\n}\n',
        encoding="utf-8",
    )
    blob = _scan(tmp_path / "run.json", tree)
    collapsed = "".join(pdf_text(data_pdf(_view(blob))).split())
    assert "declared:billing" in collapsed
