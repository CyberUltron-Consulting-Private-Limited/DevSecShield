"""Kubernetes cluster sources (staging, 14 Nov 2026), through the real API (test_cbom_sources_api.py harness).

* #207: the Tier 1 and Tier 2 templates create what their binding names (namespace zs-cbom, service account zs-cbom)
  and a long-lived service-account token Secret; the kubeconfig steps build a kubeconfig from that Secret and say why
  not ``kubectl create token`` (it expires, 1 hour by default).
* #208: a context that is not in the kubeconfig is refused at save, naming the contexts it has.
* #209: ``insecure-skip-tls-verify`` is refused at save with the scan node's own words; ``proxy-url`` is refused too
  (the node connects to the API server directly and would silently ignore it).
"""
from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest
import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_node_keys import _ca_cert  # noqa: E402
from test_cbom_sources_api import api, enroll_node, world  # noqa: E402,F401

from backend.utilities.cbom_sources import kinds, templates  # noqa: E402

ITEMS = "/1/cbom/sources/items"


def _kubeconfig(contexts=("prod",), current="prod", cluster_extra: dict | None = None) -> str:
    ca = base64.b64encode(_ca_cert().encode()).decode()
    data = {
        "apiVersion": "v1", "kind": "Config", "current-context": current,
        "clusters": [{"name": f"c-{c}", "cluster": {"server": f"https://k8s-{c}.bank.local:6443",
                                                    "certificate-authority-data": ca, **(cluster_extra or {})}}
                     for c in contexts],
        "users": [{"name": "zs-cbom", "user": {"token": "zs-test-token-not-real"}}],
        "contexts": [{"name": c, "context": {"cluster": f"c-{c}", "user": "zs-cbom"}} for c in contexts],
    }
    return yaml.safe_dump(data)


def _cluster(node_id, kubeconfig, name="prod", **cfg):
    return {"kind": "kubernetes", "name": name, "node_id": node_id,
            "config": {"api_url": "https://k8s-prod.bank.local:6443", **cfg}, "secrets": {"kubeconfig": kubeconfig}}


# ----------------------------------------------------------------------------- #207
@pytest.mark.parametrize("text", [templates.K8S_TIER1, templates.K8S_TIER2])
def test_each_template_creates_the_namespace_service_account_and_a_lasting_token(text):
    docs = {d["kind"]: d for d in yaml.safe_load_all(text)}
    assert docs["Namespace"]["metadata"]["name"] == "zs-cbom"
    assert docs["ServiceAccount"]["metadata"] == {"name": "zs-cbom", "namespace": "zs-cbom"}
    secret = docs["Secret"]
    assert secret["type"] == "kubernetes.io/service-account-token"
    assert secret["metadata"]["namespace"] == "zs-cbom"
    assert secret["metadata"]["annotations"] == {"kubernetes.io/service-account.name": "zs-cbom"}
    subject = docs["ClusterRoleBinding"]["subjects"][0]
    assert (subject["kind"], subject["name"], subject["namespace"]) == ("ServiceAccount", "zs-cbom", "zs-cbom")
    order = [d["kind"] for d in yaml.safe_load_all(text)]
    assert order.index("Namespace") < order.index("ServiceAccount") < order.index("Secret")


def test_the_kubeconfig_steps_use_the_secret_and_warn_about_expiring_tokens():
    steps = templates.template_text("k8s-kubeconfig")
    secret = next(d for d in yaml.safe_load_all(templates.K8S_TIER1) if d["kind"] == "Secret")["metadata"]["name"]
    assert f"get secret {secret}" in steps and "{.data.token}" in steps and "ca\\.crt" in steps
    for cmd in ("set-cluster", "--embed-certs=true", "set-credentials", "set-context", "use-context"):
        assert cmd in steps, cmd
    assert "kubectl create token" in steps and "expire" in steps


def test_the_template_endpoint_serves_the_kubeconfig_steps(api, world):  # noqa: F811
    r = api("GET", "/1/cbom/sources/templates/k8s-kubeconfig")
    assert r.status_code == 200 and "set-credentials" in r.text


# ----------------------------------------------------------------------------- #208
def test_a_context_that_is_not_in_the_kubeconfig_is_refused(api, world):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    kc = _kubeconfig(contexts=("prod", "staging"))
    r = api("POST", ITEMS, json=_cluster(node_id, kc, context="no-such-context"))
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == ("context: 'no-such-context' is not in the kubeconfig; its contexts are prod, staging "
                                  "(blank uses its current-context, prod)")
    ok = api("POST", ITEMS, json=_cluster(node_id, kc, context="staging"))
    assert ok.status_code == 201, ok.text
    # an edit of the context alone is checked against the stored kubeconfig
    src = ok.json()["source"]
    r = api("PATCH", f"{ITEMS}/{src['id']}", json={"config": {**src["config"], "context": "nope"},
                                                   "secrets": {"kubeconfig": kc}, "expected_version": src["row_version"]})
    assert r.status_code == 400 and "'nope' is not in the kubeconfig" in r.json()["detail"]
    assert api("POST", ITEMS, json=_cluster(node_id, kc, name="blank-context")).status_code == 201


def test_check_kubeconfig_reports_contexts_and_their_servers():
    summary = kinds.check_kubeconfig(_kubeconfig(contexts=("prod", "staging"), current="staging"))
    assert summary["contexts"] == ["prod", "staging"] and summary["current_context"] == "staging"
    assert summary["servers"] == {"prod": "https://k8s-prod.bank.local:6443",
                                  "staging": "https://k8s-staging.bank.local:6443"}


# ----------------------------------------------------------------------------- #209
@pytest.mark.parametrize("extra,message", [
    ({"insecure-skip-tls-verify": True},
     "kubeconfig disables certificate checks (insecure-skip-tls-verify); remove it"),
    ({"proxy-url": "http://10.232.0.69:3128"},
     "kubeconfig sets proxy-url, which the scan node does not use (it connects to the API server directly); remove it"),
])
def test_unsafe_or_ignored_kubeconfig_settings_are_refused_at_save(api, world, extra, message):  # noqa: F811
    node_id, _token, _ = enroll_node(api)
    r = api("POST", ITEMS, json=_cluster(node_id, _kubeconfig(cluster_extra=extra)))
    assert r.status_code == 400 and r.json()["detail"] == f"secrets.{message}", r.text


def test_insecure_skip_tls_verify_false_is_fine():
    kinds.check_kubeconfig(_kubeconfig(cluster_extra={"insecure-skip-tls-verify": False}))
