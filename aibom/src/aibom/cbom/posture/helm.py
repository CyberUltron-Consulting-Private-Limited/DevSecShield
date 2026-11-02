"""Helm charts and Ansible playbooks: which files they are, and the TLS switches Helm values declare.

A Helm chart is a directory with a ``Chart.yaml``. Its ``values*.yaml`` files are plain YAML and are read here; a
values file outside a chart counts when its path says Helm (a ``helm`` / ``charts`` / ``chart`` directory). The
chart's ``templates/`` are Go templates: they are not rendered (no Helm binary in the scan), so each one that holds
template actions is reported as a ``helm_template_skipped`` diagnostic instead of being parsed as Kubernetes YAML,
and a values fact lists the templates that read its key (``.Values.tls.enabled``).

TLS switches in values: a ``tls`` / ``ssl`` / ``https`` mapping with ``enabled: false``, or ``tlsEnabled`` /
``sslEnabled`` / ``useTLS`` style booleans set to false -> a plaintext endpoint (the same verdict a Kubernetes Ingress
without TLS gets); ``insecureSkipVerify`` / ``skipTLSVerify`` style booleans set to true -> certificate
verification disabled.
"""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from pathlib import PurePosixPath

from aibom.cbom.posture.codec import make_fact_id
from aibom.cbom.posture.extract_compose import load_documents
from aibom.cbom.posture.model import BasisEntry, EncryptionFact, path_context
from aibom.cbom.posture.verdict import resource_verdict

_HELM_DIRS = frozenset({"helm", "charts", "chart"})
_VALUES = re.compile(r"^values(?:[._-][A-Za-z0-9._-]{0,64})?\.ya?ml$")
_TLS_BLOCKS = frozenset({"tls", "ssl", "https", "mtls"})
_TLS_FLAGS = frozenset({"tlsenabled", "sslenabled", "usetls", "usessl", "enabletls", "enablessl", "httpsenabled"})
_SKIP_VERIFY = frozenset(
    {"insecureskipverify", "skiptlsverify", "tlsinsecureskipverify", "tlsskipverify", "skipverify", "insecuretls"}
)
_MAX_DEPTH = 12
_MAX_FACTS = 64
_MAX_REFS = 10


def _chart_root(root: str, rel: str) -> str | None:
    """The chart directory (relative) that holds ``rel``, if a ``Chart.yaml`` sits there."""
    parts = PurePosixPath(rel).parts[:-1]
    for depth in range(len(parts), -1, -1):
        base = "/".join(parts[:depth])
        if os.path.isfile(os.path.join(root, base, "Chart.yaml")) and not os.path.islink(
            os.path.join(root, base, "Chart.yaml")
        ):
            return base
    return None


def helm_class(root: str, rel: str) -> str | None:
    """``helm-values``, ``helm-template`` or None for a file at ``rel`` under the scan root."""
    path = PurePosixPath(rel)
    name = path.name
    lowered = {part.casefold() for part in path.parts[:-1]}
    chart = None
    if _VALUES.match(name) or "templates" in lowered:
        chart = _chart_root(root, rel)
    if _VALUES.match(name) and (chart is not None or lowered & _HELM_DIRS):
        return "helm-values"
    in_templates = chart is not None and rel.startswith(f"{chart}/templates/" if chart else "templates/")
    if in_templates and name.endswith((".yaml", ".yml", ".tpl", ".txt")):
        return "helm-template"
    return None


_ANSIBLE_HEAD = re.compile(r"^-\s{1,8}(?:hosts|import_playbook)\s{0,8}:", re.MULTILINE)
_ANSIBLE_TASK_DIRS = frozenset({"tasks", "handlers"})


def is_ansible(rel: str, head: bytes) -> bool:
    """A playbook (a play list starting ``- hosts:``) or a role's ``tasks`` / ``handlers`` file."""
    path = PurePosixPath(rel)
    if not path.name.endswith((".yml", ".yaml")):
        return False
    parts = [part.casefold() for part in path.parts]
    if "roles" in parts and len(parts) >= 2 and parts[-2] in _ANSIBLE_TASK_DIRS:
        return True
    text = head.decode("utf-8", errors="ignore")
    return bool(_ANSIBLE_HEAD.search(text)) or "ansible.builtin." in text


def _walk(node: object, trail: tuple[str, ...], depth: int, out: list[tuple[tuple[str, ...], str, int]]) -> None:
    """(dotted path, finding kind, line) for every TLS switch under ``node``."""
    if depth > _MAX_DEPTH or len(out) >= _MAX_FACTS or not isinstance(node, Mapping):
        return
    lines = getattr(node, "key_lines", {}) or {}
    default = getattr(node, "line", 1)
    for key, value in node.items():
        if not isinstance(key, str):
            continue
        folded = key.casefold().replace("_", "").replace("-", "")
        here = (*trail, key)
        line = int(lines.get(key, default) or default)
        if folded in _TLS_BLOCKS and isinstance(value, Mapping):
            enabled = value.get("enabled")
            if enabled is False:
                inner = getattr(value, "key_lines", {}) or {}
                out.append(((*here, "enabled"), "plaintext", int(inner.get("enabled", line) or line)))
        elif (folded in _TLS_FLAGS or folded in _TLS_BLOCKS) and value is False:
            out.append((here, "plaintext", line))
        elif folded in _SKIP_VERIFY and value is True:
            out.append((here, "verify_off", line))
        if isinstance(value, Mapping):
            _walk(value, here, depth + 1, out)
        elif isinstance(value, list):
            for item in value[:64]:
                _walk(item, here, depth + 1, out)


def extract_helm_values(
    text: str, path: str, templates: Mapping[str, str] | None = None
) -> tuple[EncryptionFact, ...]:
    """One ``tls_endpoint`` fact per TLS switch the values file turns off."""
    found: list[tuple[tuple[str, ...], str, int]] = []
    for doc in load_documents(text):
        _walk(doc, (), 0, found)
    facts: list[EncryptionFact] = []
    for trail, kind, line in found:
        dotted = ".".join(trail)[:200]
        basis = [BasisEntry("value", dotted)]
        refs = sorted(rel for rel, body in (templates or {}).items() if f".Values.{dotted}" in body)[:_MAX_REFS]
        if refs:
            basis.append(BasisEntry("referenced_by", ",".join(refs)))
        if kind == "plaintext":
            layers = {"transport": "NOT_ENCRYPTED"}
            basis.append(BasisEntry("listener", "plaintext"))
        else:
            layers = {"transport": "UNKNOWN"}
            basis.append(BasisEntry("verification", "disabled"))
        rolled = resource_verdict(dict(layers), transport_only=True)
        facts.append(
            EncryptionFact(
                id=make_fact_id("tls_endpoint", "helm", "helm_values", dotted, path),
                kind="tls_endpoint",
                provider="helm",
                native_type="helm_values",
                address=dotted,
                path=path,
                line=line if line > 0 else 1,
                format="helm",
                layers=layers,
                verdict=rolled or "UNKNOWN",
                basis=tuple(basis),
                unknown_reason=None if kind == "plaintext" else "attribute_not_modeled",
                path_context=path_context(path),
            )
        )
    facts.sort(key=lambda item: (item.path, item.line, item.address))
    return tuple(facts)


def has_template_actions(text: str) -> bool:
    return "{{" in text


__all__ = ["extract_helm_values", "has_template_actions", "helm_class", "is_ansible"]
