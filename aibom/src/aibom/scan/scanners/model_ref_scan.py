"""Scanner: inline model REFERENCES in source -> model components.

Walks the repo's code / config / doc files and recognizes model identifiers via
the known-model dictionary (:mod:`aibom.scan.parsers.model_refs`) — the half of
AI inventory that lives in application code (``model="gpt-4o"``) rather than in a
model card. Each distinct reference becomes a ``model`` component (kind=model)
with its vendor as publisher.

Deterministic by default. An OPTIONAL LLM enrichment pass (``enrich`` class
attribute, a callable; ``None`` = disabled) can add fuzzy/uncatalogued model
references — kept off by default and out of the golden path so scans stay
byte-reproducible.

Bounded for big repos: only an extension allowlist is read, files over
``_MAX_BYTES`` are skipped, and build/vendor/VCS directories are pruned.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path

from aibom.model.component import ModelCard, ModelComponent, PedigreeAncestor
from aibom.scan.parsers import model_card_enrich, model_kb
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.parsers.model_refs import find_model_refs_ctx
from aibom.scan.registry import ScanContext, Scanner, register


def _apply_card(card: ModelCard, fields: dict) -> None:
    """Populate ModelCard modelParameters + lineage from a KB/LLM field dict.

    Only the four ``modelParameters`` fields + ``lineage`` (pedigree) are touched;
    unrelated keys (e.g. ``license``) are ignored. No-op for an empty dict so the
    card degrades to "—" gracefully.
    """
    if not fields:
        return
    if fields.get("approach_type"):
        card.approach_type = fields["approach_type"]
    if fields.get("task"):
        card.task = fields["task"]
    if fields.get("architecture_family"):
        card.architecture_family = fields["architecture_family"]
    if fields.get("model_architecture"):
        card.model_architecture = fields["model_architecture"]
    for ancestor in fields.get("lineage") or []:
        card.pedigree_ancestors.append(PedigreeAncestor(name=ancestor))


# Small known-model licensing map, keyed by vendor. Hosted/commercial models are
# licensed (proprietary terms), NOT "unlicensed"; common OSS embedding families
# carry their real OSS license. A model whose vendor isn't here gets a SOFT
# MODEL_LICENSE_UNKNOWN flag — never the library "unlicensed" treatment.
_MODEL_LICENSE_BY_VENDOR: dict[str, str] = {
    "OpenAI": "LicenseRef-proprietary",
    "Anthropic": "LicenseRef-proprietary",
    "Google": "LicenseRef-proprietary",
    "Cohere": "LicenseRef-proprietary",
    "Mistral": "Apache-2.0",
    "Meta": "LicenseRef-llama-community",
    "sentence-transformers": "Apache-2.0",
    "HuggingFace": "Apache-2.0",
    "Nomic": "Apache-2.0",
    "Jina": "Apache-2.0",
}

_EXTS = {
    ".py",
    ".pyi",
    ".ipynb",
    ".ts",
    ".tsx",
    ".js",
    ".jsx",
    ".mjs",
    ".cjs",
    ".json",
    ".jsonl",
    ".yaml",
    ".yml",
    ".toml",
    ".tf",
    ".md",
    ".mdx",
    ".txt",
    ".env",
}
_SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "target",
    ".venv",
    "venv",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".tox",
    ".next",
    "out",
    ".idea",
    ".gradle",
    "vendor",
    "site-packages",
    ".ruff_cache",
    "coverage",
}
_MAX_BYTES = 256 * 1024
_SLUG = re.compile(r"[^a-z0-9]+")


def _slug(name: str) -> str:
    return _SLUG.sub("-", name.lower()).strip("-")


def _walk(root: Path) -> Iterator[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in _EXTS:
                yield p


@register
class ModelRefScanner(Scanner):
    name = "model-ref"
    order = 25  # after model-repo (20): its carded model (if any) wins the bom_ref
    level = 1

    #: Optional LLM enrichment: ``Callable[[str], dict[str, str]]`` mapping text
    #: to ``{model_name: vendor}``. ``None`` keeps the scan deterministic.
    enrich: Callable[[str], dict[str, str]] | None = None

    #: Optional LLM hook for model-CARD inference of models NOT in the KB
    #: (``Callable[..., str | None]``, the Bedrock provider signature). ``None``
    #: keeps the scan deterministic (KB only); tests inject a fake/real provider.
    card_llm: Callable[..., str | None] | None = None

    def scan(self, ctx: ScanContext) -> None:
        # normalized name -> [display name, vendor, reference_type]. usage wins.
        seen: dict[str, list[str]] = {}
        for path in _walk(ctx.root):
            try:
                if path.stat().st_size > _MAX_BYTES:
                    continue
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            refs = dict(find_model_refs_ctx(text))  # name -> (vendor, reference_type)
            if self.enrich is not None:
                # Enrichment augments, never overrides; fuzzy hits default to catalog.
                for name, vendor in self.enrich(text).items():
                    refs.setdefault(name, (vendor, "catalog"))
            for name, (vendor, rtype) in refs.items():
                low = name.lower()
                if low not in seen:
                    seen[low] = [name, vendor, rtype]
                elif rtype == "usage" and seen[low][2] != "usage":
                    seen[low][2] = "usage"  # real use seen elsewhere -> promote

        for key in sorted(seen):
            name, vendor, rtype = seen[key]
            bom_ref = f"modelref-{_slug(name)}"
            if ctx.has_ref(bom_ref):
                continue  # a carded model already owns this ref — don't double-add
            # Card fields: KB first (deterministic), else optional LLM enrich
            # (off the golden path), else nothing -> the card stays "—".
            kb = model_kb.lookup(name)
            card_fields = (
                kb
                if kb is not None
                else (
                    model_card_enrich.infer_card(name, llm=self.card_llm)
                    if self.card_llm is not None
                    else {}
                )
            )
            # License: KB (model-specific) wins, else the vendor map.
            spdx = (kb.get("license") if kb else None) or _MODEL_LICENSE_BY_VENDOR.get(
                vendor
            )
            comp = ModelComponent(
                bom_ref=bom_ref,
                name=name,
                publisher=vendor,
                licenses=[license_choice(spdx)] if spdx else None,
                # usage = the code loads/calls it; catalog = listed in a
                # supported-model registry (catalog is NOT real inventory).
                properties={"model:reference_type": rtype},
            )
            _apply_card(comp.model_card, card_fields)
            ctx.add_component(comp)
            if spdx is None:
                # SOFT finding — a model with no known license is NOT a library
                # "unlicensed"; it needs manual model-licensing classification.
                ctx.add_flag(
                    "MODEL_LICENSE_UNKNOWN",
                    bom_ref,
                    severity="note",
                    message=(
                        f"Model {name!r} ({vendor}) has no known license mapping; "
                        "classify its model licensing manually (distinct from a "
                        "library with an unresolved license)."
                    ),
                )


__all__ = ["ModelRefScanner"]
