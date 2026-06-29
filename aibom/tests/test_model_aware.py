"""Keystone: the pipeline is MODEL-AWARE — real pipeline, no mocks.

The model-ref scanner's models are now first-class graph citizens the
compliance/graph layers read: licensed (or softly model-license-unknown, never
library-"unlicensed"), usage/catalog tagged, and linked into the graph (zero
orphans). Libraries resolve to real licenses; unlicensed = genuine library
unknowns only.
"""
from __future__ import annotations

import os

from aibom.scan.pipeline import scan_repo

_HERE = os.path.dirname(os.path.abspath(__file__))


def _fx(name: str) -> str:
    return os.path.join(_HERE, "fixtures", name)


def test_synthetic_libs_resolve_and_zero_library_unlicensed() -> None:
    r = scan_repo(_fx("synthetic-ai-app"), level=4)
    fw = {c.name.lower(): c for c in r.components if c.kind == "framework"}
    for lib in ("numpy", "torch", "requests", "pydantic", "chromadb"):
        assert lib in fw, f"library {lib} not detected"
        assert fw[lib].licenses, f"library {lib} should resolve to a known license"
    library_unlicensed = [c for c in r.components if c.kind == "framework" and not c.licenses]
    assert library_unlicensed == [], (
        f"library-unlicensed must be 0 on synthetic: {[c.name for c in library_unlicensed]}"
    )


def test_models_never_count_as_library_unlicensed() -> None:
    r = scan_repo(_fx("synthetic-ai-app"), level=4)
    models = [c for c in r.components if c.kind == "model"]
    assert models, "model references must be detected"
    mlu = {f.target for f in r.flags if f.code == "MODEL_LICENSE_UNKNOWN"}
    for m in models:
        # Every model is either licensed (known map) or softly model-license-unknown
        # — NEVER the library "MODEL_NO_LICENSE"/unlicensed treatment.
        assert m.licenses or m.bom_ref in mlu, (
            f"model {m.name} is neither licensed nor model-license-unknown"
        )
    assert not [f for f in r.flags if f.code == "MODEL_NO_LICENSE"], (
        "models must not raise the library MODEL_NO_LICENSE flag"
    )


def test_models_seen_by_graph_query_zero_orphans() -> None:
    for fx in ("synthetic-ai-app", "chroma"):
        path = _fx(fx)
        if not os.path.isdir(path):
            continue  # chroma clone is gitignored; skip in CI
        r = scan_repo(path, level=4)
        models = [c for c in r.components if c.kind == "model"]
        assert models, f"{fx}: NO model component visible to a graph query (the keystone defect)"
        endpoints = {e.src for e in r.edges} | {e.dst for e in r.edges}
        orphans = [m for m in models if m.bom_ref not in endpoints]
        assert orphans == [], f"{fx}: orphan model nodes: {[m.name for m in orphans][:10]}"


def test_usage_vs_catalog_tagged() -> None:
    r = scan_repo(_fx("synthetic-ai-app"), level=4)
    models = [c for c in r.components if c.kind == "model"]
    for m in models:
        rt = (m.properties or {}).get("model:reference_type")
        assert rt in ("usage", "catalog"), f"model {m.name} missing usage/catalog tag: {rt}"
    # synthetic app actually USES its models -> all usage
    assert all((m.properties or {}).get("model:reference_type") == "usage" for m in models)
