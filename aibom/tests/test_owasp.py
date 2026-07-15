"""OWASP LLM Top 10 (2025) mapper — pure-function mapping + scan distribution.

Asserts the required mappings on hand-crafted finding/flag types (ChromaDB→LLM08,
hardcoded key→LLM02, unpinned/unlicensed dep→LLM03) and that a real chroma scan
yields a non-empty ``ScanResult.owasp`` distribution containing LLM08 + LLM03.
"""

from __future__ import annotations

import pathlib

import pytest

from aibom import owasp
from aibom.model.component import FrameworkComponent, ModelComponent, SecretComponent
from aibom.model.result import Flag
from aibom.scan.pipeline import scan_repo

_FIX = pathlib.Path(__file__).resolve().parent / "fixtures"


# ── the three required pure-function mappings ────────────────────────────────
def test_chromadb_maps_to_llm08() -> None:
    chromadb = FrameworkComponent(
        bom_ref="lib-chromadb", name="chromadb", version="0.5.0"
    )
    assert owasp.categories_for_component(chromadb) == {"LLM08"}


def test_hardcoded_key_maps_to_llm02() -> None:
    secret = SecretComponent(bom_ref="secret-openai", name="OPENAI_API_KEY")
    assert owasp.categories_for_component(secret) == {"LLM02"}


def test_unpinned_dependency_maps_to_llm03() -> None:
    unpinned = FrameworkComponent(bom_ref="lib-foo", name="foo")  # version=None
    assert "LLM03" in owasp.categories_for_component(unpinned)


def test_unlicensed_dependency_maps_to_llm03() -> None:
    # Pinned but unlicensed: the supply-chain signal comes from the flag.
    pinned = FrameworkComponent(bom_ref="lib-bar", name="bar", version="1.0.0")
    flag = Flag(code="FRAMEWORK_NO_LICENSE", target="lib-bar", severity="note")
    assert "LLM03" in owasp.categories_for_component(pinned, [flag])


# ── flag-type mapping (the finding/flag-type half) ───────────────────────────
def test_flag_type_mapping() -> None:
    assert owasp.categories_for_flag("FRAMEWORK_NO_LICENSE") == {"LLM03"}
    assert owasp.categories_for_flag("MODEL_NO_LICENSE") == {"LLM03"}
    assert owasp.categories_for_flag("MODEL_PHI_AT_INFERENCE") == {"LLM02"}
    assert owasp.categories_for_flag("DATASET_NO_DEIDENT") == {"LLM02"}
    # An unmapped/irrelevant code maps to nothing — conservative, never guessed.
    assert owasp.categories_for_flag("SERVICE_REF_COLLISION") == frozenset()
    assert owasp.categories_for_flag("NONEXISTENT_CODE") == frozenset()


def test_embedding_model_maps_to_llm08_generation_model_does_not() -> None:
    emb = ModelComponent(bom_ref="m-embed", name="text-embedding-ada-002")
    gen = ModelComponent(bom_ref="m-gpt", name="gpt-4o")
    assert owasp.categories_for_component(emb) == {"LLM08"}
    assert owasp.categories_for_component(gen) == set()


# ── aggregate distribution on a real scan (the DONE) ─────────────────────────
def test_synthetic_distribution_has_llm08() -> None:
    # synthetic has chromadb (vector store) + embed-english-v3.0 (embedding).
    result = scan_repo(_FIX / "synthetic", level=4)
    assert "LLM08" in result.owasp


def test_chroma_distribution_non_empty_llm08_and_llm03() -> None:
    if not (_FIX / "chroma").is_dir():
        pytest.skip("chroma clone absent (see tests/fixtures/CHROMA.md)")
    result = scan_repo(_FIX / "chroma", level=4)
    assert result.owasp, "owasp distribution must be non-empty on chroma"
    assert "LLM08" in result.owasp  # embedding models / vector store
    assert "LLM03" in result.owasp  # unpinned (>=) + unlicensed deps
    # counts are positive integers
    assert all(isinstance(v, int) and v > 0 for v in result.owasp.values())


def test_distribution_keys_are_ordered_canonical_codes() -> None:
    result = scan_repo(_FIX / "synthetic", level=4)
    codes = list(result.owasp)
    assert codes == sorted(codes)  # ordered by OWASP code
    assert all(c in owasp.OWASP_LLM_LABELS for c in codes)
