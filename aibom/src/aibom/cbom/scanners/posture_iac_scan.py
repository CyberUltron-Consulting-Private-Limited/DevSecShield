"""CBOM scanner: encryption facts in infrastructure-as-code files."""

from __future__ import annotations

from pathlib import PurePosixPath

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.ciphers import protocol_asset
from aibom.cbom.posture.context import PostureSink, posture_sink
from aibom.cbom.posture.dockerfile import crypto_package_pins
from aibom.cbom.posture.extract_cloudformation import extract_cloudformation
from aibom.cbom.posture.extract_compose import extract_compose, extract_dockerfile
from aibom.cbom.posture.extract_kubernetes import (
    config_algorithm,
    config_material,
    extract_kubernetes,
)
from aibom.cbom.posture.extract_terraform import extract_terraform
from aibom.cbom.posture.helm import extract_helm_values, has_template_actions
from aibom.cbom.posture.k8s_material import secret_material
from aibom.cbom.posture.keyspec import algorithm_for_fact, material_for_fact
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.posture.safeio import DecodedFile
from aibom.cbom.posture.tls_policy import INFERRED
from aibom.cbom.registry import cbom_register
from aibom.model.component import FrameworkComponent
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset(
    {"terraform", "cloudformation", "kubernetes", "compose", "dockerfile", "helm-values", "helm-template"}
)


def _facts(decoded: DecodedFile) -> tuple[EncryptionFact, ...]:
    text, rel = decoded.text, decoded.rel
    if decoded.cls == "terraform":
        return extract_terraform(text, rel)
    if decoded.cls == "cloudformation":
        return extract_cloudformation(text, rel)
    if decoded.cls == "kubernetes":
        return extract_kubernetes(text, rel)
    if decoded.cls == "compose":
        return extract_compose(text, rel)
    if decoded.cls == "dockerfile":
        return extract_dockerfile(text, rel)
    return ()


def _policy_notes(sink: PostureSink, facts: tuple) -> None:
    """A named TLS policy the catalogue does not know is a coverage note, never silence."""
    for fact in facts:
        for item in fact.basis:
            unknown = item.name == "ssl_policy" and item.unknown_reason == "default_unknown"
            inferred = item.name == "policy_floor" and item.value == INFERRED
            if unknown or inferred:
                sink.diagnostics.add("tls_policy_not_in_catalog", fact.path, fact.line)
                break


def _emit(ctx: ScanContext, facts: tuple) -> None:
    add_facts(ctx, facts)
    _policy_notes(posture_sink(ctx), facts)
    for fact in facts:
        for asset in (
            algorithm_for_fact(fact),
            material_for_fact(fact),
            config_algorithm(fact),
            config_material(fact),
            protocol_asset(fact),
        ):
            if asset is not None and not ctx.has_ref(asset.bom_ref):
                ctx.add_component(asset)


def _packages(ctx: ScanContext, decoded: DecodedFile) -> None:
    """Crypto OS packages a Dockerfile pins (inventory rows; the base image carries the end-of-life finding)."""
    for pin in crypto_package_pins(decoded.text, decoded.rel):
        ref = f"crypto-pkg-{pin.ecosystem}-{pin.name}-{pin.version}-{pin.path}".lower()
        ref = "".join(ch if ch.isalnum() or ch == "-" else "-" for ch in ref)[:180]
        if ctx.has_ref(ref):
            continue
        ctx.add_component(
            FrameworkComponent(
                bom_ref=ref,
                name=f"{pin.name}@{pin.version}",
                properties={
                    "crypto:role": "library",
                    "crypto:version": pin.version,
                    "crypto:ecosystem": pin.ecosystem,
                    "crypto:line": str(pin.line),
                    "discovery:source": pin.path,
                },
            )
        )


def _material(ctx: ScanContext, sink: PostureSink, text: str, rel: str) -> None:
    assets, notes = secret_material(text, rel)
    for asset in assets:
        if not ctx.has_ref(asset.bom_ref):
            ctx.add_component(asset)
    for note in notes:
        sink.diagnostics.add(note.code, note.path, note.line)


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    kubernetes: dict[str, str] = {}
    values: dict[str, str] = {}
    templates: dict[str, str] = {}
    for decoded in iter_class(sink, _CLASSES):
        if decoded.cls == "kubernetes":
            kubernetes[decoded.rel] = decoded.text
            continue
        if decoded.cls == "helm-values":
            values[decoded.rel] = decoded.text
            continue
        if decoded.cls == "helm-template":
            templates[decoded.rel] = decoded.text
            if has_template_actions(decoded.text):
                sink.diagnostics.add("helm_template_skipped", decoded.rel, 0)
            continue
        _emit(ctx, _facts(decoded))
        if decoded.cls == "dockerfile":
            _packages(ctx, decoded)
    for rel in sorted(values):
        parent = str(PurePosixPath(rel).parent)
        prefix = "templates/" if parent == "." else f"{parent}/templates/"
        own = {path: body for path, body in templates.items() if path.startswith(prefix)}
        _emit(ctx, extract_helm_values(values[rel], rel, own))
    if kubernetes:
        first = sorted(kubernetes)[0]
        _emit(
            ctx,
            extract_kubernetes(kubernetes[first], first, files=kubernetes),
        )
        for rel in sorted(kubernetes):
            _material(ctx, sink, kubernetes[rel], rel)


@cbom_register
class PostureIacScanner(Scanner):
    """Terraform, CloudFormation, Kubernetes, compose, Dockerfile and Helm values facts."""

    name = "posture_iac"
    order = 31
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
