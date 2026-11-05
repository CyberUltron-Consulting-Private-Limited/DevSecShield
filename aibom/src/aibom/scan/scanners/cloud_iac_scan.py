"""Level-4 scanner: cloud IaC -> managed cloud AI services.

Detects Bedrock / SageMaker / Vertex AI / Azure OpenAI declared in Terraform
(``*.tf``) or CloudFormation (``*.yaml``/``*.json``) and emits ``cloud_service``
components. A registry entry.
"""

from __future__ import annotations

from pathlib import Path

from aibom.model.component import CloudServiceComponent
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import read_text, walk_files

# IaC resource/type substring -> (display name, vendor)
_SERVICES = {
    "aws_bedrock": ("AWS Bedrock", "AWS"),
    "bedrock": ("AWS Bedrock", "AWS"),
    "aws_sagemaker": ("AWS SageMaker", "AWS"),
    "sagemaker": ("AWS SageMaker", "AWS"),
    "google_vertex": ("Google Vertex AI", "Google"),
    "aiplatform": ("Google Vertex AI", "Google"),
    "vertex": ("Google Vertex AI", "Google"),
    "azurerm_cognitive": ("Azure OpenAI", "Microsoft"),
    "azurerm_machine_learning": ("Azure ML", "Microsoft"),
    "azure_openai": ("Azure OpenAI", "Microsoft"),
}

_SUFFIXES = {".tf", ".tf.json", ".yaml", ".yml", ".json", ".hcl"}


def _iac_files(root: Path) -> list[Path]:
    return walk_files(
        root,
        keep=lambda p: p.suffix.lower() in _SUFFIXES or p.name.endswith(".tf.json"),
    )


@register
class CloudIacScanner(Scanner):
    name = "cloud-iac"
    level = 4
    order = 32

    def matches(self, root: Path) -> bool:
        return bool(_iac_files(root))

    def scan(self, ctx: ScanContext) -> None:
        seen: set[str] = set()
        for path in _iac_files(ctx.root):
            text = read_text(path)
            if text is None:
                continue
            text = text.lower()
            for needle, (label, vendor) in _SERVICES.items():
                if needle in text:
                    ref = "cloud_service-" + label.lower().replace(" ", "-")
                    if ref in seen:
                        continue
                    seen.add(ref)
                    ctx.add_component(
                        CloudServiceComponent(
                            bom_ref=ref,
                            name=label,
                            publisher=vendor,
                            properties={
                                "discovery:source": path.name,
                                "discovery:iac": needle,
                            },
                        )
                    )


__all__ = ["CloudIacScanner"]
