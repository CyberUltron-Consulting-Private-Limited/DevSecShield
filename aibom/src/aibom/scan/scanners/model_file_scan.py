"""Scanner: serialized model WEIGHT FILES -> one component per artifact.

A complete model-file SBOM lists every weight/serialization artifact a repo ships
(``.safetensors`` / ``.onnx`` / ``.bin`` / ``.h5`` / ``.pt`` + ONNX/OpenVINO
quantization variants), each with its own integrity hash — not just the logical
model. Card-independent (an HF model repo whose README is not a parseable model
card still ships weights), so it runs as its own scanner and the model-repo
scanner links the model to these files via ``depends_on``.

Lanes (``aibom/contract/lanes``): emits components only, never scores.
"""

from __future__ import annotations

from pathlib import Path

from aibom.model.component import ModelFileComponent
from aibom.scan.parsers.model_file import find_model_files, sha256_hash
from aibom.scan.registry import ScanContext, Scanner, register


@register
class ModelFileScanner(Scanner):
    name = "model-file"
    order = 15  # before model-repo (20) so the model can depends_on the files
    level = 1

    def matches(self, root: Path) -> bool:
        return bool(find_model_files(root))

    def scan(self, ctx: ScanContext) -> None:
        for wf in find_model_files(ctx.root):
            ref = f"modelfile-{wf.name.lower()}"
            if ctx.has_ref(ref):  # de-dup same filename across subdirs
                continue
            # Relative path so the adapter can populate finding.location
            # (discovery:source → location). Without this, hash-named .bin
            # weight files land in Shadow AI with an empty Location field.
            rel = wf.relative_to(ctx.root).as_posix()
            ctx.add_component(
                ModelFileComponent(
                    bom_ref=ref,
                    name=wf.name,
                    hashes=[sha256_hash(wf)],
                    properties={
                        "model:weight_file": "true",
                        "discovery:source": rel,
                    },
                )
            )


__all__ = ["ModelFileScanner"]
