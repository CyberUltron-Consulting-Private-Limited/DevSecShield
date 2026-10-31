"""Kubernetes posture extraction. Inline YAML and JSON, no fixture trees."""

from __future__ import annotations

import pytest

from aibom.cbom.posture.extract_kubernetes import extract_kubernetes
from aibom.cbom.posture.model import EncryptionFact

_CANARY = "CANARY-KEY-MATERIAL"
_ROW = "k8s.apiserver.encryption_flag"


def _config(first: str, second: str, *, secret: str = _CANARY) -> str:
    return f"""
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
metadata:
  name: enc
resources:
  - resources: ["configmaps"]
    providers:
      - aescbc:
          keys:
            - name: other
              secret: {secret}
  - resources: ["secrets"]
    providers:
      - {first}:
          apiVersion: v2
          name: first
          keys:
            - name: key1
              secret: {secret}
      - {second}:
          apiVersion: v1
          name: second
          keys:
            - name: key2
              secret: {secret}
"""


def _pod(command: str, *, flag: str | None = None) -> str:
    lines = [command]
    if flag is not None:
        lines.append(flag)
    body = "\n".join(f"        - {line}" for line in lines)
    return f"""
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
  namespace: kube-system
spec:
  containers:
    - name: kube-apiserver
      command:
{body}
"""


def test_first_provider_wins_over_a_later_provider() -> None:
    identity = extract_kubernetes(_config("identity", "kms"), "enc.yaml")[0]
    kms = extract_kubernetes(_config("kms", "identity"), "enc.yaml")[0]
    assert identity.verdict == "NOT_ENCRYPTED"
    assert identity.key_management == "unspecified"
    assert identity.layers["database"] == "NOT_ENCRYPTED"
    assert kms.verdict == "ENCRYPTED_DECLARED"
    assert kms.key_management == "customer_managed"
    assert any(item.name == "kms_api" and item.value == "v2" for item in kms.basis)
    assert _CANARY not in repr(identity)
    assert _CANARY not in repr(kms)


def test_first_provider_wins_in_json() -> None:
    text = """
    {
      "apiVersion": "apiserver.config.k8s.io/v1",
      "kind": "EncryptionConfiguration",
      "resources": [{
        "resources": ["secrets"],
        "providers": [{"identity": {}}, {"aescbc": {"keys": [{"secret": "CANARY"}]}}]
      }]
    }
    """
    fact = extract_kubernetes(text, "enc.json")[0]
    assert fact.verdict == "NOT_ENCRYPTED"
    assert fact.layers["database"] == "NOT_ENCRYPTED"
    assert "CANARY" not in repr(fact)


def test_wildcard_provider_is_the_writer_and_the_secret_is_unread() -> None:
    text = """
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["*.*"]
    providers:
      - secretbox:
          keys:
            - name: box
              secret: CANARY-SECRETBOX
      - identity: {}
"""
    fact = extract_kubernetes(text, "enc.yaml")[0]
    assert fact.verdict == "ENCRYPTED_DECLARED"
    assert fact.key_management == "local_file"
    assert "CANARY-SECRETBOX" not in repr(fact)


def test_no_secrets_entry_is_not_encrypted() -> None:
    text = """
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources: ["configmaps"]
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: CANARY-ONLY
"""
    fact = extract_kubernetes(text, "enc.yaml")[0]
    assert fact.verdict == "NOT_ENCRYPTED"
    assert any(
        item.value == "no resources entry includes secrets" for item in fact.basis
    )
    assert "CANARY-ONLY" not in repr(fact)


@pytest.mark.parametrize(
    "command",
    [
        "kube-apiserver",
        "/usr/local/bin/kube-apiserver",
    ],
)
def test_apiserver_without_flag_uses_the_default_row(command: str) -> None:
    fact = extract_kubernetes(_pod(command), "kube-apiserver.yaml")[0]
    assert fact.kind == "k8s_secrets_etcd"
    assert fact.native_type == "Pod"
    assert fact.verdict == "NOT_ENCRYPTED"
    assert fact.layers["database"] == "NOT_ENCRYPTED"
    assert fact.default_row == _ROW
    assert fact.unknown_reason is None
    assert any(item.value == _ROW for item in fact.basis)


def test_apiserver_args_without_flag_uses_the_default_row() -> None:
    text = """
apiVersion: v1
kind: Pod
metadata:
  name: kube-apiserver
spec:
  containers:
    - name: kube-apiserver
      args: ["kube-apiserver", "--secure-port=6443"]
"""
    fact = extract_kubernetes(text, "pod.yaml")[0]
    assert fact.verdict == "NOT_ENCRYPTED"
    assert fact.default_row == _ROW


@pytest.mark.parametrize(
    "flag",
    [
        "--encryption-provider-config=/etc/kubernetes/encryption-config.yaml",
        "--encryption-provider-config /etc/kubernetes/encryption-config.yaml",
    ],
)
def test_apiserver_flag_without_a_file_is_unresolved(flag: str) -> None:
    fact = extract_kubernetes(_pod("kube-apiserver", flag=flag), "pod.yaml")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.layers["database"] == "UNKNOWN"
    assert fact.unknown_reason == "unresolved_reference"
    assert fact.default_row is None


def test_apiserver_flag_without_a_file_is_unresolved_in_json() -> None:
    text = """
    {
      "apiVersion": "v1",
      "kind": "Pod",
      "metadata": {"name": "kube-apiserver"},
      "spec": {"containers": [{
        "name": "kube-apiserver",
        "command": ["kube-apiserver", "--encryption-provider-config=/missing.yaml"]
      }]}
    }
    """
    fact = extract_kubernetes(text, "pod.json")[0]
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "unresolved_reference"


def test_linked_flag_keeps_the_first_provider() -> None:
    pod = _pod(
        "kube-apiserver",
        flag="--encryption-provider-config=/etc/kubernetes/encryption-config.yaml",
    )
    facts = extract_kubernetes(
        pod,
        "pod.yaml",
        files={"encryption-config.yaml": _config("identity", "kms")},
    )
    by_type = {fact.native_type: fact for fact in facts}
    config = by_type["EncryptionConfiguration"]
    server = by_type["Pod"]
    assert config.verdict == "NOT_ENCRYPTED"
    assert server.verdict == "NOT_ENCRYPTED"
    assert server.default_row is None
    assert server.unknown_reason is None
    assert any(
        item.name == "via --encryption-provider-config" for item in server.basis
    )
    assert _CANARY not in repr(server)


def test_two_config_paths_with_the_same_suffix_stay_unresolved() -> None:
    pod = _pod(
        "kube-apiserver",
        flag="--encryption-provider-config=/etc/kubernetes/enc.yaml",
    )
    facts = extract_kubernetes(
        pod,
        "pod.yaml",
        files={
            "a/enc.yaml": _config("kms", "identity"),
            "b/enc.yaml": _config("identity", "kms"),
        },
    )
    server = next(fact for fact in facts if fact.native_type == "Pod")
    assert server.verdict == "UNKNOWN"
    assert server.unknown_reason == "unresolved_reference"


def test_ingress_secret_name_is_only_a_basis_ref() -> None:
    text = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
spec:
  tls:
    - hosts: ["example.com"]
      secretName: edge-tls
"""
    fact = extract_kubernetes(text, "ingress.yaml")[0]
    assert "secret" not in EncryptionFact.__dataclass_fields__
    assert not hasattr(fact, "secret")
    assert fact.key_ref is None
    refs = [item.value for item in fact.basis if item.name == "ref"]
    assert refs == ["edge-tls"]
    assert fact.kind == "tls_endpoint"
    assert fact.verdict == "ENCRYPTED_DECLARED"


def test_non_identifier_secret_name_is_omitted() -> None:
    text = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
spec:
  tls:
    - secretName: "not a name!"
"""
    fact = extract_kubernetes(text, "ingress.yaml")[0]
    assert "not a name!" not in repr(fact)
    assert all(item.name != "secret" for item in fact.basis)
    assert fact.key_ref is None


def test_secret_data_and_string_data_are_not_read() -> None:
    text = """
apiVersion: v1
kind: Secret
metadata:
  name: db
type: Opaque
data:
  password: CANARYDATA
stringData:
  token: CANARYTOKEN
"""
    fact = extract_kubernetes(text, "secret.yaml")[0]
    assert fact.kind == "secret_store"
    assert fact.layers == {"service": "UNKNOWN"}
    assert fact.unknown_reason == "layer_not_observable"
    blob = repr(fact)
    assert "CANARYDATA" not in blob
    assert "CANARYTOKEN" not in blob
    assert any(item.name == "type" and item.value == "Opaque" for item in fact.basis)


def test_istio_gateway_passthrough_is_not_a_terminated_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "gateway.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {flag.code for flag in result.flags}
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in result.flags}
    gateway = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == "Gateway"
    )
    assert (gateway.properties or {}).get("crypto:factVerdict") == "UNKNOWN"


def test_istio_gateway_cipher_suites(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def write(suite: str) -> None:
        (tmp_path / "gateway.yaml").write_text(
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
            f"      - {suite}\n",
            encoding="utf-8",
        )

    write("TLS_RSA_WITH_3DES_EDE_CBC_SHA")
    weak = scan_crypto(tmp_path)
    protocol = next(comp for comp in weak.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_3DES_EDE_CBC_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in weak.flags}
    write("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
    strong = scan_crypto(tmp_path)
    assert "WEAK_CIPHER_SUITE" not in {flag.code for flag in strong.flags}


def test_istio_gateway_http_and_tls_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "gateway.yaml").write_text(
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
    opened = scan_crypto(tmp_path)
    protocol = next(comp for comp in opened.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    codes = {flag.code for flag in opened.flags}
    assert "UNENCRYPTED_IN_TRANSIT" in codes
    assert "WEAK_PROTOCOL" in codes
    (tmp_path / "gateway.yaml").write_text(
        "apiVersion: networking.istio.io/v1beta1\n"
        "kind: Gateway\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  servers:\n"
        "  - port:\n"
        "      number: 80\n"
        "      protocol: HTTP\n"
        "    tls:\n"
        "      httpsRedirect: true\n"
        "  - port:\n"
        "      number: 443\n"
        "      protocol: HTTPS\n"
        "    tls:\n"
        "      mode: SIMPLE\n"
        "      minProtocolVersion: TLSV1_2\n",
        encoding="utf-8",
    )
    secured = scan_crypto(tmp_path)
    kept = next(comp for comp in secured.components if comp.name == "TLS")
    assert (kept.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in secured.flags}
    assert "WEAK_PROTOCOL" not in {flag.code for flag in secured.flags}


def test_destination_rule_disable_and_skipped_verify(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def write(body: str) -> None:
        (tmp_path / "rule.yaml").write_text(
            "apiVersion: networking.istio.io/v1beta1\n"
            "kind: DestinationRule\n"
            "metadata:\n"
            "  name: api\n"
            "spec:\n"
            "  trafficPolicy:\n"
            "    tls:\n"
            f"{body}",
            encoding="utf-8",
        )

    write("      mode: DISABLE\n")
    disabled = scan_crypto(tmp_path)
    codes = {flag.code for flag in disabled.flags}
    assert "UNENCRYPTED_IN_TRANSIT" in codes
    assert "PLAINTEXT_LISTENER" in codes
    write("      mode: SIMPLE\n      insecureSkipVerify: true\n")
    skipped = scan_crypto(tmp_path)
    skipped_codes = {flag.code for flag in skipped.flags}
    assert "TLS_VERIFICATION_DISABLED" in skipped_codes
    assert "UNENCRYPTED_IN_TRANSIT" not in skipped_codes


def test_service_negotiation_policy_sets_the_tls_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "svc.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in result.flags}


def test_frontend_config_ssl_policy_uses_the_gcp_profile(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def write(policy: str) -> None:
        (tmp_path / "front.yaml").write_text(
            "apiVersion: networking.gke.io/v1beta1\n"
            "kind: FrontendConfig\n"
            "metadata:\n"
            "  name: web\n"
            "spec:\n"
            f"  sslPolicy: {policy}\n",
            encoding="utf-8",
        )

    write("COMPATIBLE")
    compatible = scan_crypto(tmp_path)
    old = next(comp for comp in compatible.components if comp.name == "TLS")
    assert (old.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in compatible.flags}
    write("RESTRICTED")
    restricted = scan_crypto(tmp_path)
    kept = next(comp for comp in restricted.components if comp.name == "TLS")
    assert (kept.properties or {})["crypto:protocolVersion"] == "TLSv1.2"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in restricted.flags}


def test_alb_ssl_policy_sets_the_tls_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def write(policy: str) -> None:
        (tmp_path / "ingress.yaml").write_text(
            "apiVersion: networking.k8s.io/v1\n"
            "kind: Ingress\n"
            "metadata:\n"
            "  name: web\n"
            "  annotations:\n"
            f'    alb.ingress.kubernetes.io/ssl-policy: "{policy}"\n'
            "spec:\n"
            "  rules:\n"
            "  - host: app.example.com\n",
            encoding="utf-8",
        )

    write("ELBSecurityPolicy-2016-08")
    old = scan_crypto(tmp_path)
    protocol = next(comp for comp in old.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1.0"
    assert "WEAK_PROTOCOL" in {flag.code for flag in old.flags}
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in old.flags}
    write("ELBSecurityPolicy-TLS13-1-3-2021-06")
    modern = scan_crypto(tmp_path)
    kept = next(comp for comp in modern.components if comp.name == "TLS")
    assert (kept.properties or {})["crypto:protocolVersion"] == "TLSv1.3"
    assert "WEAK_PROTOCOL" not in {flag.code for flag in modern.flags}
    write("ELBSecurityPolicy-NOT-AUTHORED")
    unknown = scan_crypto(tmp_path)
    assert "WEAK_PROTOCOL" not in {flag.code for flag in unknown.flags}
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in unknown.flags}


def test_certificate_arn_is_tls_until_redirect_is_disabled(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def write(extra: str) -> None:
        (tmp_path / "ingress.yaml").write_text(
            "apiVersion: networking.k8s.io/v1\n"
            "kind: Ingress\n"
            "metadata:\n"
            "  name: web\n"
            "  annotations:\n"
            f"{extra}"
            "spec:\n"
            "  rules:\n"
            "  - host: app.example.com\n",
            encoding="utf-8",
        )

    arn = '    alb.ingress.kubernetes.io/certificate-arn: "arn:aws:acm:cert/abc"\n'
    write(arn)
    secured = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in secured.flags}
    write(arn + '    nginx.ingress.kubernetes.io/ssl-redirect: "false"\n')
    opened = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" in {flag.code for flag in opened.flags}
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in opened.flags}


def test_allow_http_false_removes_plaintext(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    ports = '[{"HTTP":80},{"HTTPS":443}]'
    (tmp_path / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        '    kubernetes.io/ingress.allow-http: "false"\n'
        f"    alb.ingress.kubernetes.io/listen-ports: '{ports}'\n"
        "spec:\n"
        "  rules:\n"
        "  - host: app.example.com\n",
        encoding="utf-8",
    )
    blocked = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in blocked.flags}
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in blocked.flags}
    (tmp_path / "ingress.yaml").write_text(
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
    opened = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" in {flag.code for flag in opened.flags}
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in opened.flags}


def test_alb_listen_ports_distinguish_http_from_https(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def ingress(ports: str) -> str:
        return (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: Ingress\n"
            "metadata:\n"
            "  name: web\n"
            "  annotations:\n"
            f"    alb.ingress.kubernetes.io/listen-ports: '{ports}'\n"
            "spec:\n"
            "  rules:\n"
            "  - host: app.example.com\n"
        )

    (tmp_path / "ingress.yaml").write_text(
        ingress('[{"HTTP":80}]'),
        encoding="utf-8",
    )
    opened = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" in {flag.code for flag in opened.flags}
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in opened.flags}
    (tmp_path / "ingress.yaml").write_text(
        ingress('[{"HTTPS":443}]'),
        encoding="utf-8",
    )
    secured = scan_crypto(tmp_path)
    assert "UNENCRYPTED_IN_TRANSIT" not in {flag.code for flag in secured.flags}
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in secured.flags}


def test_ingress_rc4_cipher_is_a_weak_suite(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "ingress.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    suite = (protocol.properties or {})["crypto:cipherSuite"]
    assert "TLS_RSA_WITH_RC4_128_SHA" in suite
    assert "WEAK_CIPHER_SUITE" in {flag.code for flag in result.flags}


def test_ingress_ssl_protocols_set_the_floor(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "ingress.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    protocol = next(comp for comp in result.components if comp.name == "TLS")
    assert (protocol.properties or {})["crypto:protocolVersion"] == "TLSv1"
    assert "WEAK_PROTOCOL" in {flag.code for flag in result.flags}


def test_ssl_ciphers_go_through_the_evaluator() -> None:
    text = """
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: web
  annotations:
    nginx.ingress.kubernetes.io/ssl-ciphers: "RC4-SHA"
spec:
  tls:
    - secretName: edge-tls
"""
    fact = extract_kubernetes(text, "ingress.yaml")[0]
    names = [item.value for item in fact.basis if item.name == "cipher_suite"]
    assert names == ["TLS_RSA_WITH_RC4_128_SHA"]


def test_datastore_image_on_a_deployment_keeps_three_layers() -> None:
    text = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mq
spec:
  template:
    spec:
      containers:
        - name: mq
          image: rabbitmq:3
          env:
            - name: RABBITMQ_DEFAULT_PASS
              value: CANARYPASS
"""
    fact = extract_kubernetes(text, "deploy.yaml")[0]
    assert fact.provider == "kubernetes"
    assert fact.kind == "message_queue"
    assert fact.native_type == "rabbitmq"
    assert fact.verdict == "UNKNOWN"
    assert fact.unknown_reason == "layer_not_observable"
    for layer in ("database", "volume", "transport"):
        assert fact.layers[layer] == "UNKNOWN"
        assert any(
            item.name == layer and item.unknown_reason == "layer_not_observable"
            for item in fact.basis
        )
    assert "CANARYPASS" not in repr(fact)


def test_kustomization_and_typeless_documents_are_not_resources() -> None:
    text = """
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - deploy.yaml
---
hello: world
"""
    assert extract_kubernetes(text, "kustomization.yaml") == ()


def test_the_longer_encryption_path_wins(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    specific = tmp_path / "etc" / "kubernetes"
    other = tmp_path / "other"
    specific.mkdir(parents=True)
    other.mkdir()
    (specific / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: locked\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - kms:\n"
        "      name: vault\n"
        "      endpoint: unix:///tmp/kms.sock\n",
        encoding="utf-8",
    )
    (other / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: plain\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - identity: {}\n",
        encoding="utf-8",
    )
    (tmp_path / "pod.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    pod = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == "Pod"
    )
    props = pod.properties or {}
    assert props["crypto:factVerdict"] == "ENCRYPTED_DECLARED"
    assert "UNENCRYPTED_AT_REST" not in props["crypto:factFindingCodes"]


def test_two_matching_encryption_files_are_not_chosen(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    left = tmp_path / "a"
    right = tmp_path / "b"
    left.mkdir()
    right.mkdir()
    (left / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: plain\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - identity: {}\n",
        encoding="utf-8",
    )
    (right / "enc.yaml").write_text(
        "apiVersion: apiserver.config.k8s.io/v1\n"
        "kind: EncryptionConfiguration\n"
        "metadata:\n"
        "  name: locked\n"
        "resources:\n"
        "- resources: [secrets]\n"
        "  providers:\n"
        "  - kms:\n"
        "      name: vault\n"
        "      endpoint: unix:///tmp/kms.sock\n",
        encoding="utf-8",
    )
    (tmp_path / "pod.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    pod = next(
        comp
        for comp in result.components
        if (comp.properties or {}).get("crypto:factNativeType") == "Pod"
    )
    props = pod.properties or {}
    assert props["crypto:factVerdict"] == "UNKNOWN"
    assert "UNENCRYPTED_AT_REST" not in props["crypto:factFindingCodes"]


def test_apiserver_flag_uses_the_linked_configuration(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "enc.yaml").write_text(
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
    (tmp_path / "pod.yaml").write_text(
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
    linked = scan_crypto(tmp_path)
    pod = next(
        comp
        for comp in linked.components
        if (comp.properties or {}).get("crypto:factNativeType") == "Pod"
    )
    assert (pod.properties or {})["crypto:factVerdict"] == "ENCRYPTED_DECLARED"
    assert "UNENCRYPTED_AT_REST" not in {flag.code for flag in linked.flags}
    (tmp_path / "pod.yaml").write_text(
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
        "    - --encryption-provider-config=/etc/kubernetes/missing.yaml\n",
        encoding="utf-8",
    )
    missing = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" not in {flag.code for flag in missing.flags}


def test_apiserver_without_encryption_flag_is_unencrypted(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "pod.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" in {flag.code for flag in result.flags}


def test_secrets_omitted_from_resources_are_unencrypted(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "enc.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" in {flag.code for flag in result.flags}


def test_a_wildcard_before_secrets_hides_the_later_provider(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def entry(resources: str, provider: str) -> str:
        if provider == "identity":
            body = "  - identity: {}\n"
        else:
            body = (
                "  - kms:\n"
                "      name: vault\n"
                "      endpoint: unix:///tmp/kms.sock\n"
            )
        return f"- resources: [{resources}]\n  providers:\n{body}"

    def config(first: str, second: str) -> str:
        return (
            "apiVersion: apiserver.config.k8s.io/v1\n"
            "kind: EncryptionConfiguration\n"
            "metadata:\n"
            "  name: enc\n"
            "resources:\n"
            + first
            + second
        )

    (tmp_path / "enc.yaml").write_text(
        config(entry('"*.*"', "identity"), entry("secrets", "kms")),
        encoding="utf-8",
    )
    hidden = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" in {flag.code for flag in hidden.flags}
    (tmp_path / "enc.yaml").write_text(
        config(entry("secrets", "kms"), entry('"*.*"', "identity")),
        encoding="utf-8",
    )
    specific = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" not in {flag.code for flag in specific.flags}


def test_aescbc_is_weak_and_secretbox_is_not(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def config(provider: str) -> str:
        return (
            "apiVersion: apiserver.config.k8s.io/v1\n"
            "kind: EncryptionConfiguration\n"
            "metadata:\n"
            "  name: enc\n"
            "resources:\n"
            "- resources: [secrets]\n"
            "  providers:\n"
            f"  - {provider}:\n"
            "      keys:\n"
            "      - name: key1\n"
            "        secret: AAAAAAAAAAAAAAAAAAAAAA==\n"
        )

    (tmp_path / "enc.yaml").write_text(config("aescbc"), encoding="utf-8")
    weak = scan_crypto(tmp_path)
    assert "AT_REST_ENCRYPTION_WEAK" in {flag.code for flag in weak.flags}
    aes = next(comp for comp in weak.components if comp.name == "AES")
    assert (aes.properties or {})["crypto:mode"] == "CBC"
    assert "crypto:keySize" not in (aes.properties or {})
    material = next(comp for comp in weak.components if comp.name == "secret-key")
    assert (material.properties or {})["crypto:hardcoded"] == "true"
    assert "AAAAAAAAAAAAAAAAAAAAAA==" not in repr(weak)
    (tmp_path / "enc.yaml").write_text(config("aesgcm"), encoding="utf-8")
    gcm = scan_crypto(tmp_path)
    assert "AT_REST_ENCRYPTION_WEAK" in {flag.code for flag in gcm.flags}
    assert "HARDCODED_KEY" in {flag.code for flag in gcm.flags}
    gcm_aes = next(comp for comp in gcm.components if comp.name == "AES")
    assert (gcm_aes.properties or {})["crypto:mode"] == "GCM"
    (tmp_path / "enc.yaml").write_text(config("secretbox"), encoding="utf-8")
    strong = scan_crypto(tmp_path)
    assert "AT_REST_ENCRYPTION_WEAK" not in {flag.code for flag in strong.flags}
    assert all(comp.name != "AES" for comp in strong.components)


def test_only_the_first_encryption_provider_is_used(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def config(first: str, second: str) -> str:
        return (
            "apiVersion: apiserver.config.k8s.io/v1\n"
            "kind: EncryptionConfiguration\n"
            "metadata:\n"
            "  name: enc\n"
            "resources:\n"
            "- resources: [secrets]\n"
            "  providers:\n"
            f"  - {first}: {{}}\n"
            f"  - {second}:\n"
            "      name: vault\n"
            "      endpoint: unix:///tmp/kms.sock\n"
        )

    (tmp_path / "enc.yaml").write_text(config("kms", "identity"), encoding="utf-8")
    kms_first = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" not in {flag.code for flag in kms_first.flags}
    (tmp_path / "enc.yaml").write_text(
        config("identity", "kms"), encoding="utf-8"
    )
    identity_first = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" in {flag.code for flag in identity_first.flags}


def test_identity_provider_is_unencrypted_at_rest(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "enc.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" in {flag.code for flag in result.flags}


def test_kms_provider_is_not_unencrypted_at_rest(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "enc.yaml").write_text(
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
    result = scan_crypto(tmp_path)
    assert "UNENCRYPTED_AT_REST" not in {flag.code for flag in result.flags}


def test_istio_permissive_is_a_plaintext_listener(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    def policy(mode: str) -> str:
        return (
            "apiVersion: security.istio.io/v1beta1\n"
            "kind: PeerAuthentication\n"
            "metadata:\n"
            "  name: mesh\n"
            "spec:\n"
            "  mtls:\n"
            f"    mode: {mode}\n"
        )

    (tmp_path / "peer.yaml").write_text(policy("PERMISSIVE"), encoding="utf-8")
    permissive = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in permissive.flags}
    (tmp_path / "peer.yaml").write_text(policy("STRICT"), encoding="utf-8")
    strict = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in strict.flags}
    (tmp_path / "peer.yaml").write_text(policy("DISABLE"), encoding="utf-8")
    disabled = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in disabled.flags}


def test_ingress_without_tls_is_a_plaintext_listener(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  rules:\n"
        "  - host: example.com\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    codes = {flag.code for flag in result.flags}
    assert "PLAINTEXT_LISTENER" in codes
    assert "UNENCRYPTED_IN_TRANSIT" in codes


def test_ssl_redirect_false_stays_plaintext_with_a_secret(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        '    nginx.ingress.kubernetes.io/ssl-redirect: "false"\n'
        "spec:\n"
        "  tls:\n"
        "  - secretName: web-tls\n"
        "  rules:\n"
        "  - host: example.com\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" in {flag.code for flag in result.flags}


def test_force_ssl_redirect_is_not_plaintext(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "  annotations:\n"
        '    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"\n'
        "spec:\n"
        "  rules:\n"
        "  - host: example.com\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in result.flags}


def test_ingress_with_tls_is_not_plaintext(tmp_path) -> None:
    from aibom.cbom.pipeline import scan_crypto

    (tmp_path / "ingress.yaml").write_text(
        "apiVersion: networking.k8s.io/v1\n"
        "kind: Ingress\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  tls:\n"
        "  - secretName: web-tls\n"
        "  rules:\n"
        "  - host: example.com\n",
        encoding="utf-8",
    )
    result = scan_crypto(tmp_path)
    assert "PLAINTEXT_LISTENER" not in {flag.code for flag in result.flags}
