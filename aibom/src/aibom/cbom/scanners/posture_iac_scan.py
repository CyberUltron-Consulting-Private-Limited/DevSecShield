"""CBOM scanner: encryption facts in infrastructure-as-code files."""

from __future__ import annotations

from aibom.cbom.posture.assemble import add_facts, iter_class
from aibom.cbom.posture.context import posture_sink
from aibom.cbom.posture.extract_cloudformation import extract_cloudformation
from aibom.cbom.posture.extract_compose import extract_compose, extract_dockerfile
from aibom.cbom.posture.extract_kubernetes import extract_kubernetes
from aibom.cbom.posture.extract_terraform import extract_terraform
from aibom.cbom.posture.model import EncryptionFact
from aibom.cbom.posture.safeio import DecodedFile
from aibom.cbom.registry import cbom_register
from aibom.scan.registry import ScanContext, Scanner

_CLASSES = frozenset(
    {"terraform", "cloudformation", "kubernetes", "compose", "dockerfile"}
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


def _collect(ctx: ScanContext) -> None:
    sink = posture_sink(ctx)
    for decoded in iter_class(sink, _CLASSES):
        add_facts(ctx, _facts(decoded))


@cbom_register
class PostureIacScanner(Scanner):
    """Terraform, CloudFormation, Kubernetes, compose, and Dockerfile facts."""

    name = "posture_iac"
    order = 31
    level = 1
    posture_role = "extractor"

    def scan(self, ctx: ScanContext) -> None:
        posture_sink(ctx).enter(self.name)
        with posture_sink(ctx).guard(self.name):
            _collect(ctx)
