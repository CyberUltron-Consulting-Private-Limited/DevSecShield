"""Pre-Phase-3 hardening: PHI-as-graph-fact + served_by/BAA, deployment graph,
the no-PHI NA path, multi-site deployed_at, and the locked risk-score scale.
"""

from __future__ import annotations

import json
import pathlib

from aibom.emit.cyclonedx import emit_and_validate, emit_cyclonedx
from aibom.emit.spdx import emit_and_validate_spdx, emit_spdx
from aibom.emit.validate import validate_cyclonedx, validate_spdx
from aibom.model.result import REL_DEPLOYED_AT, REL_SERVED_BY
from aibom.scan.pipeline import scan_repo
from aibom.score.scorer import normalize_score, risk_band

_EX = pathlib.Path(__file__).resolve().parent.parent / "examples"
_CLINICAL = _EX / "clinical-imaging"
_NO_PHI = _EX / "no-phi-model"
_MULTI = _EX / "multi-site"


# --------------------------------------------------------------------------- #
# A) PHI is a GRAPH FACT (node property + served_by/BAA edge), not flag-only
# --------------------------------------------------------------------------- #


def test_phi_is_a_node_property_not_only_a_flag() -> None:
    result = scan_repo(_CLINICAL)
    model = next(c for c in result.components if c.kind == "model")
    # Authoritative graph fact lives on the node, decided WITHOUT reading flags.
    assert model.properties and model.properties.get("clinical:processes_phi") == "true"
    # The flag still exists as the scoring echo (parallel, not the source).
    assert "MODEL_PHI_AT_INFERENCE" in {f.code for f in result.flags}


def test_served_by_edge_to_baa_service() -> None:
    result = scan_repo(_CLINICAL)
    served = result.neighbors("model-chestxr-cnn", REL_SERVED_BY)
    assert len(served) == 1
    service = served[0]
    assert service.kind == "service"
    assert service.properties and service.properties["service:baa"] == "true"


def test_phi_and_served_by_in_cyclonedx_and_spdx() -> None:
    result = scan_repo(_CLINICAL)
    cdx = emit_cyclonedx(result)
    model = next(c for c in cdx["components"] if c["type"] == "machine-learning-model")
    assert {"name": "clinical:processes_phi", "value": "true"} in model["properties"]
    dep = next(d for d in cdx["dependencies"] if d["ref"] == "model-chestxr-cnn")
    assert "service-acme-cloud" in dep["dependsOn"]

    spdx = emit_spdx(result)
    served = [
        r
        for r in spdx["@graph"]
        if r.get("type") == "Relationship" and r.get("comment") == "served_by"
    ]
    assert len(served) == 1
    assert any(t.endswith("service-acme-cloud") for t in served[0]["to"])


def test_clinical_goldens_still_valid_after_hardening() -> None:
    result = scan_repo(_CLINICAL)
    assert emit_and_validate(result) == json.loads(
        (_CLINICAL / "expected" / "chestxr.cdx.json").read_text()
    )
    assert emit_and_validate_spdx(result) == json.loads(
        (_CLINICAL / "expected" / "chestxr.spdx.json").read_text()
    )


# --------------------------------------------------------------------------- #
# C1) No-PHI fixture: the HIPAA NA path is exercisable (absence reflected)
# --------------------------------------------------------------------------- #


def test_no_phi_fixture_has_no_phi_graph_fact() -> None:
    result = scan_repo(_NO_PHI)
    model = next(c for c in result.components if c.kind == "model")
    assert not (model.properties and "clinical:processes_phi" in model.properties)
    # No served_by edge, and no service component at all.
    assert result.out_edges("model-bone-age", REL_SERVED_BY) == []
    assert not any(c.kind == "service" for c in result.components)
    # CycloneDX carries no processes_phi property anywhere.
    cdx = emit_and_validate(result)
    assert "clinical:processes_phi" not in json.dumps(cdx)


def test_no_phi_goldens_valid() -> None:
    result = scan_repo(_NO_PHI)
    assert validate_cyclonedx(emit_cyclonedx(result)) == []
    assert emit_and_validate(result) == json.loads(
        (_NO_PHI / "expected" / "bom.cdx.json").read_text()
    )


# --------------------------------------------------------------------------- #
# C2) Multi-site fixture: deployed_at edges in the graph AND the BOM
# --------------------------------------------------------------------------- #


def test_multi_site_deployed_at_edges() -> None:
    result = scan_repo(_MULTI)
    sites = result.neighbors("model-chestxr-multisite", REL_DEPLOYED_AT)
    assert {s.bom_ref for s in sites} == {
        "site-mercy-general",
        "site-lakeside-regional",
    }
    # Each site node carries governance properties.
    lakeside = result.by_ref("site-lakeside-regional")
    assert lakeside and lakeside.properties
    assert lakeside.properties["site:drift_status"] == "drift-detected"
    assert lakeside.properties["site:version"] == "2.0.3"

    # deployed_at targets appear in the BOM dependency section.
    cdx = emit_and_validate(result)
    dep = next(d for d in cdx["dependencies"] if d["ref"] == "model-chestxr-multisite")
    assert {"site-mercy-general", "site-lakeside-regional"} <= set(dep["dependsOn"])


def test_multi_site_deployed_at_in_spdx() -> None:
    spdx = emit_and_validate_spdx(scan_repo(_MULTI))
    deployed = [
        r
        for r in spdx["@graph"]
        if r.get("type") == "Relationship" and r.get("comment") == "deployed_at"
    ]
    assert deployed and len(deployed[0]["to"]) == 2
    assert validate_spdx(spdx) == []


def test_multi_site_golden_valid() -> None:
    result = scan_repo(_MULTI)
    assert emit_and_validate(result) == json.loads(
        (_MULTI / "expected" / "bom.cdx.json").read_text()
    )


# --------------------------------------------------------------------------- #
# D) Risk-score scale: 0-100 normalization + low/med/high bands
# --------------------------------------------------------------------------- #


def test_scores_carry_normalized_and_band() -> None:
    scores = scan_repo(_CLINICAL).scores
    assert scores["risk_total"] == 9.0  # raw internal sum preserved
    assert scores["risk_normalized"] == 33.3  # 9 / 27 * 100
    assert scores["risk_band"] == "medium"


def test_no_phi_scores_low_band() -> None:
    scores = scan_repo(_NO_PHI).scores
    assert scores["risk_total"] == 0.0
    assert scores["risk_normalized"] == 0.0
    assert scores["risk_band"] == "low"


def test_normalize_score_caps_at_100() -> None:
    assert normalize_score(0) == 0.0
    assert normalize_score(27) == 100.0  # every defined flag once
    assert normalize_score(1000) == 100.0  # capped
    assert risk_band(0.0) == "low"
    assert risk_band(50.0) == "medium"
    assert risk_band(90.0) == "high"


def test_custom_scale_changes_band(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "w.yaml"
    cfg.write_text(
        "default: 1\nflags:\n  X: 10\nscale:\n  max_raw: 10\n  bands:\n"
        "    low: 10\n    medium: 20\n"
    )
    # raw 10 -> 100 normalized under max_raw=10; band high (>20).
    assert normalize_score(10, weights_path=str(cfg)) == 100.0
    assert risk_band(100.0, weights_path=str(cfg)) == "high"


def test_weights_cache_is_not_stale_on_edit(tmp_path: pathlib.Path) -> None:
    """SCORE-1: rewriting the SAME path's YAML is picked up (cache keyed by mtime)."""
    cfg = tmp_path / "w.yaml"
    cfg.write_text("flags:\n  X: 10\nscale:\n  max_raw: 10\n")
    assert normalize_score(10, weights_path=str(cfg)) == 100.0  # 10/10*100
    # Mutate the same path; a path-only cache would return the stale 100.0.
    import os
    import time

    os.utime(cfg, (time.time() + 1, time.time() + 1))  # bump mtime deterministically
    cfg.write_text("flags:\n  X: 10\nscale:\n  max_raw: 100\n")
    os.utime(cfg, (time.time() + 2, time.time() + 2))
    assert normalize_score(10, weights_path=str(cfg)) == 10.0  # 10/100*100


# --------------------------------------------------------------------------- #
# PHI-1 / PHI-2: bom_ref collision guards on served_by / deployed_at
# --------------------------------------------------------------------------- #


def _write_card(root: pathlib.Path, frontmatter: str) -> None:
    (root / "MODEL_CARD.md").write_text(f"---\n{frontmatter}---\n")


def test_served_by_ref_colliding_with_model_is_rejected(tmp_path: pathlib.Path) -> None:
    # served_by.bom_ref == the model's own ref would make neighbors() resolve to
    # the MODEL (service:baa absent), corrupting the HIPAA check. Must be refused.
    _write_card(
        tmp_path,
        "name: m\nbom_ref: model-m\nclinical:\n"
        "  uses_sensitive_personal_information: \"yes\"\n"
        "served_by:\n  name: bad\n  bom_ref: model-m\n  baa: true\n",
    )
    result = scan_repo(tmp_path)
    assert [c.bom_ref for c in result.components].count("model-m") == 1
    assert result.by_ref("model-m").kind == "model"  # type: ignore[union-attr]
    assert result.out_edges("model-m", REL_SERVED_BY) == []
    assert "SERVICE_REF_COLLISION" in {f.code for f in result.flags}


def test_duplicate_deployed_at_site_is_flagged_not_merged(
    tmp_path: pathlib.Path,
) -> None:
    # Two deployed_at sites sharing one bom_ref would silently drop the second
    # site's drift_status; the collision must be flagged and skipped.
    _write_card(
        tmp_path,
        "name: m\nbom_ref: model-m\ndeployed_at:\n"
        "  - name: Site A\n    bom_ref: site-x\n    drift_status: stable\n"
        "  - name: Site B\n    bom_ref: site-x\n    drift_status: drift-detected\n",
    )
    result = scan_repo(tmp_path)
    sites = [c for c in result.components if c.bom_ref == "site-x"]
    assert len(sites) == 1  # no two components share a bom_ref
    assert len(result.out_edges("model-m", REL_DEPLOYED_AT)) == 1
    assert "SITE_REF_COLLISION" in {f.code for f in result.flags}


def test_no_two_components_share_a_bom_ref_in_fixtures() -> None:
    """Defense-in-depth: every shipped fixture emits unique component bom_refs."""
    for fx in (_CLINICAL, _NO_PHI, _MULTI):
        refs = [c.bom_ref for c in scan_repo(fx).components]
        assert len(refs) == len(set(refs)), f"duplicate bom_ref in {fx.name}"
