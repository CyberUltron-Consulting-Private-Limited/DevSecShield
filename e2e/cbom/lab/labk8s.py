"""kind wave for issue #93: one-node cluster, TLS secrets, a private-key ConfigMap, an ingress, two accounts.

gen.py up --wave k8s applies the manifests this module builds. The self-check compares kubectl's JSON with
labfollow.k8s_mismatches. kind is a host tool; unit tests never start a cluster.
"""
from __future__ import annotations

import base64
import json
import shutil
import subprocess
from pathlib import Path

import labspec as S

CLUSTER = "cb02-k8s"
NAMESPACE = "cb02"
CONTEXT = f"kind-{CLUSTER}"


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


def manifests(expect: dict, crt: dict[str, str], key: dict[str, str], config_pem: str) -> dict:
    """A Kubernetes List. `crt`/`key` map a secret name to PEM text."""
    items: list[dict] = [{"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": NAMESPACE}}]
    for exp in expect["secrets"]:
        items.append({"apiVersion": "v1", "kind": "Secret",
                      "metadata": {"name": exp["name"], "namespace": NAMESPACE},
                      "type": "kubernetes.io/tls",
                      "data": {"tls.crt": _b64(crt[exp["name"]]), "tls.key": _b64(key[exp["name"]])}})
    items.append({"apiVersion": "v1", "kind": "ConfigMap",
                  "metadata": {"name": expect["configmap"]["name"], "namespace": NAMESPACE},
                  "data": {"app.key": config_pem}})
    items.append({"apiVersion": "networking.k8s.io/v1", "kind": "Ingress",
                  "metadata": {"name": "web", "namespace": NAMESPACE},
                  "spec": {"tls": [{"hosts": ["web.lab"], "secretName": expect["ingress_secret"]}],
                           "rules": [{"host": "web.lab", "http": {"paths": [
                               {"path": "/", "pathType": "Prefix",
                                "backend": {"service": {"name": "web", "port": {"number": 443}}}}]}}]}})
    for name, rules in (
            ("zs-cbom-tier1", [{"apiGroups": [""], "resources": ["pods", "configmaps"], "verbs": ["get", "list"]}]),
            ("zs-cbom-tier2", [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}])):
        items.append({"apiVersion": "v1", "kind": "ServiceAccount",
                      "metadata": {"name": name, "namespace": NAMESPACE}})
        items.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "Role",
                      "metadata": {"name": name, "namespace": NAMESPACE}, "rules": rules})
        items.append({"apiVersion": "rbac.authorization.k8s.io/v1", "kind": "RoleBinding",
                      "metadata": {"name": name, "namespace": NAMESPACE},
                      "subjects": [{"kind": "ServiceAccount", "name": name, "namespace": NAMESPACE}],
                      "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": "Role", "name": name}})
    return {"apiVersion": "v1", "kind": "List", "items": items}


def _run(cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def up(run_dir: Path) -> None:
    """Create the kind cluster, attach its node to the lab network, and apply the generated manifests."""
    if shutil.which("kind") is None or shutil.which("kubectl") is None:
        raise SystemExit("gen: the k8s wave needs kind and kubectl on the host")
    manifest = run_dir / "lab" / "targets" / "k8s" / "manifests.json"
    if not manifest.is_file():
        raise SystemExit("gen: k8s manifests were not generated")
    cfg = run_dir / "lab" / "targets" / "k8s" / "kind.yaml"
    cfg.write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\nnodes:\n- role: control-plane\n")
    created = _run(["kind", "create", "cluster", "--name", CLUSTER, "--config", str(cfg), "--wait", "180s"])
    if created.returncode != 0 and "already exists" not in (created.stderr + created.stdout):
        raise SystemExit(f"gen: kind create failed: {(created.stderr or created.stdout)[-800:]}")
    _run(["docker", "network", "connect", S.NETWORK["name"], f"{CLUSTER}-control-plane"])
    applied = _run(["kubectl", "--context", CONTEXT, "apply", "-f", str(manifest)])
    if applied.returncode != 0:
        raise SystemExit(f"gen: kubectl apply failed: {(applied.stderr or applied.stdout)[-800:]}")


def down() -> None:
    if shutil.which("kind") is None:
        return
    clusters = _run(["kind", "get", "clusters"])
    if CLUSTER in clusters.stdout.split():
        _run(["kind", "delete", "cluster", "--name", CLUSTER])


def kubectl_json(*args: str) -> dict:
    res = _run(["kubectl", "--context", CONTEXT, *args, "-o", "json"])
    if res.returncode != 0:
        raise SystemExit(f"selfcheck: kubectl {' '.join(args)} failed: {(res.stderr or res.stdout)[-500:]}")
    return json.loads(res.stdout)
