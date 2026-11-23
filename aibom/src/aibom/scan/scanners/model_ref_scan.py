"""Scanner: inline model REFERENCES in source -> model components.

Walks the repo's code / config / doc files and recognizes model identifiers via
the known-model dictionary (:mod:`aibom.scan.parsers.model_refs`) — the half of
AI inventory that lives in application code (``model="gpt-4o"``) rather than in a
model card. Each distinct reference becomes a ``model`` component (kind=model)
with its vendor as publisher.

Deterministic: known-model KB only. No network / no LLM.

Bounded for big repos: only an extension allowlist is read, files over
``_MAX_BYTES`` are skipped, and build/vendor/VCS directories are pruned.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from aibom.model.component import ModelCard, ModelComponent, PedigreeAncestor
from aibom.scan.parsers import model_kb
from aibom.scan.parsers.licenses import license_choice
from aibom.scan.parsers.model_refs import find_model_refs_ctx
from aibom.scan.path_roles import (
    evidence_rank,
    is_doc_path,
    is_env_file,
    is_example_path,
    is_test_path,
)
from aibom.scan.registry import ScanContext, Scanner, register
from aibom.scan.safe_files import read_text, walk_files


def _apply_card(card: ModelCard, fields: dict) -> None:
    """Populate ModelCard modelParameters + lineage from a KB field dict.

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


# A reference's type, strongest first: the code uses it, a catalog / doc / example
# lists it, only test code names it.
_TYPE_RANK = {"usage": 0, "catalog": 1, "test": 2}


def _walk(root: Path) -> Iterator[Path]:
    # ``.env`` / ``.env.example`` have no usable suffix: matched by name
    yield from walk_files(
        root, _SKIP_DIRS, lambda p: p.suffix.lower() in _EXTS or is_env_file(p)
    )


@register
class ModelRefScanner(Scanner):
    name = "model-ref"
    order = 25  # after model-repo (20): its carded model (if any) wins the bom_ref
    level = 1

    def scan(self, ctx: ScanContext) -> None:
        # normalized name -> {name, vendor, type, source, rank}; the strongest type
        # wins. A reference the application USES is a model of this system. A name
        # only in a supported-model table / pricing catalog / docs / example file
        # ("catalog") or only in test code ("test") stays in the BOM, tagged with
        # its ``model:reference_type``, but is not counted: the findings, the score,
        # the compliance checks and the PDF count only models in use (SmarterRouter
        # listed 71 "models", 6 real). Dropping them instead turned every gap in the
        # usage patterns into data loss (review of #487 M1).
        seen: dict[str, dict[str, Any]] = {}
        for path in _walk(ctx.root):
            # None: a link, not a regular file, or over the limit
            text = read_text(path, _MAX_BYTES)
            if text is None:
                continue
            if is_test_path(path, ctx.root):
                role = "test"
            elif is_doc_path(path) or is_example_path(path, ctx.root):
                role = "catalog"  # prose and sample data mention, never use
            else:
                role = None
            try:
                source = path.relative_to(ctx.root).as_posix()
            except ValueError:
                source = path.name
            rank = evidence_rank(path)
            refs = dict(find_model_refs_ctx(text))  # name -> (vendor, reference_type)
            for name, (vendor, rtype) in refs.items():
                kind = role or rtype
                low = name.lower()
                entry = seen.get(low)
                if entry is None or _TYPE_RANK[kind] < _TYPE_RANK[entry["type"]] or (
                    kind == entry["type"] == "usage" and rank < entry["rank"]
                ):
                    # usage evidenced by application code outranks configuration
                    # (m11): discovery:source names the strongest evidence
                    seen[low] = {"name": name, "vendor": vendor, "type": kind,
                                 "source": source, "rank": rank}
        for kind in ("catalog", "test"):
            n = sum(1 for v in seen.values() if v["type"] == kind)
            if n:
                ctx.properties[f"aibom:model_mentions_{kind}"] = str(n)

        for key in sorted(seen):
            entry = seen[key]
            name, vendor, rtype, source = (
                entry["name"], entry["vendor"], entry["type"], entry["source"]
            )
            bom_ref = f"modelref-{_slug(name)}"
            if ctx.has_ref(bom_ref):
                continue  # a carded model already owns this ref — don't double-add
            # Card fields: known-model KB only. Unknown models stay "—".
            kb = model_kb.lookup(name)
            card_fields = kb if kb is not None else {}
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
                # supported-model registry / doc / example; test = test code only
                # (catalog and test are NOT models in use).
                properties={"model:reference_type": rtype, "discovery:source": source},
            )
            _apply_card(comp.model_card, card_fields)
            ctx.add_component(comp)
            if spdx is None and rtype == "usage":
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
