"""Review 6032108510 (PR #489, second review) M-1: licence-risk checks on an SBOM built
offline.

With the package registries unreachable, an SBOM keeps fewer licences; the GPL-family
packages lost theirs and SEBI CSCRF ``CSCRF-GV.SC.S5-lic-risk`` and RBI FREE-AI
``FREEAI-SUPPLY-4`` flipped from fail (online) to pass (offline). A component without a
resolved licence now makes them partial (not BOM-evidenceable), never a pass.
"""

from __future__ import annotations

from aibom.sbom.compliance import run_sbom_compliance

ROOT = "pkg:github/acme/app@1"
CHECKS = (
    ("sebi_cscrf_sbom", "CSCRF-GV.SC.S5-lic-risk"),
    ("rbi_free_ai_supply", "FREEAI-SUPPLY-4"),
)


def _bom(licences: dict[str, str | None]) -> dict:
    comps = []
    for name, lic in licences.items():
        comp = {
            "bom-ref": f"pkg:pypi/{name}@1",
            "name": name,
            "version": "1",
            "purl": f"pkg:pypi/{name}@1",
        }
        if lic:
            comp["licenses"] = [{"license": {"id": lic}}]
        comps.append(comp)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "metadata": {
            "timestamp": "2026-11-24T00:00:00Z",
            "component": {"type": "application", "name": "acme/app", "bom-ref": ROOT},
        },
        "components": comps,
    }


def _rows(licences: dict[str, str | None], kinds: dict[str, str]) -> list[dict]:
    return [
        {
            "dependency": f"{n}==1",
            "purl": f"pkg:pypi/{n}@1",
            "impact": "Low",
            "inventory_only": True,
            "vuln_assessed": True,
            "license": lic or "LicenseRef-not-declared",
            "license_type": kinds.get(n, "not_declared"),
        }
        for n, lic in licences.items()
    ]


def _verdicts(licences: dict[str, str | None], kinds: dict[str, str]) -> dict:
    result = run_sbom_compliance(_rows(licences, kinds), sbom_json=_bom(licences))
    out = {}
    for fw, rid in CHECKS:
        out[rid] = next(q for q in result[fw]["requirements"] if q["id"] == rid)
    return out


def test_online_gpl_package_fails():
    licences = {"mysql-python": "GPL-2.0-only", "flask": "BSD-3-Clause"}
    kinds = {"mysql-python": "strong_copyleft", "flask": "permissive"}
    for q in _verdicts(licences, kinds).values():
        assert q["verdict"] == "fail"


def test_offline_unknown_licences_are_partial_not_pass():
    licences = {"mysql-python": None, "chardet": None, "flask": "BSD-3-Clause"}
    kinds = {"flask": "permissive"}
    for q in _verdicts(licences, kinds).values():
        assert q["verdict"] == "not_bom_evidenceable", q
        partial = "partial: 2/3 component(s) have no resolved licence"
        assert q["evidence"].startswith(partial)
        assert sorted(q["refs"]) == ["pkg:pypi/chardet@1", "pkg:pypi/mysql-python@1"]


def test_every_licence_known_and_permissive_passes():
    licences = {"flask": "BSD-3-Clause", "click": "BSD-3-Clause"}
    kinds = {"flask": "permissive", "click": "permissive"}
    for q in _verdicts(licences, kinds).values():
        assert q["verdict"] == "pass"
