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
