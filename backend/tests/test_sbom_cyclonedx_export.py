"""Industry-ready SBOM CycloneDX: real names + one Pass/Fail property.

The downloadable document must look like CycloneDX/bom-examples (standard
component fields, optional vulnerabilities[]) with a single advisory
``dss:compliance`` property. Per-framework RBI/SEBI/CERT-In stays on the
dashboard and PDF — not dumped into the JSON.
"""
from __future__ import annotations

import os
import sys
import types

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data  # noqa: E402
from backend.utilities.dashboard.scan_metadata import get_scan_metadata  # noqa: E402


def _scan(scan_data, *, repo_url=None):
    return types.SimpleNamespace(
        scan_metadata={"repo_url": repo_url} if repo_url else {},
        scan_data=scan_data,
    )


def _prop_names(bom: dict) -> set[str]:
    props = (bom.get("metadata") or {}).get("properties") or []
    return {str(p.get("name")) for p in props if isinstance(p, dict)}


def _all_component_prop_names(bom: dict) -> set[str]:
    names: set[str] = set()
    for c in bom.get("components") or []:
        if not isinstance(c, dict):
            continue
        for p in c.get("properties") or []:
            if isinstance(p, dict) and p.get("name"):
                names.add(str(p["name"]))
    return names


def test_bom_dict_prefers_persisted_sbom_json_over_stub() -> None:
    real = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "requests",
                "version": "2.31.0",
                "purl": "pkg:pypi/requests@2.31.0",
                "type": "library",
            }
        ],
    }
    data = {
        "sbom_json": real,
        "results": [{"dependency": "ignored==0", "title": "x"}],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data)
    assert bom is not None
    names = [c.get("name") for c in bom["components"]]
    assert "requests" in names
    refs = [str(c.get("bom-ref") or "") for c in bom["components"]]
    assert not any(r.startswith("sbom-dep-") for r in refs)
    assert bom["components"][0].get("version") == "2.31.0"


def test_stub_sbom_uses_package_names_not_sbom_dep_placeholders() -> None:
    data = {
        "results": [
            {
                "dependency": "flask==3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
                "title": "Inventory: flask",
            },
            {
                "dependency": "click@8.1.0",
                "title": "Inventory: click",
            },
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data)
    assert bom["bomFormat"] == "CycloneDX"
    names = [c["name"] for c in bom["components"]]
    assert names == ["flask", "click"]
    for c in bom["components"]:
        ref = str(c.get("bom-ref") or "")
        assert "sbom-dep" not in ref.lower()
        assert "sbom dependency" not in str(c.get("name") or "").lower()
        assert c["name"] in ref or (c.get("purl") and c["name"] in str(c["purl"]))


def test_scan_metadata_surfaces_single_compliance_property() -> None:
    data = {
        "sbom_json": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [{"name": "urllib3", "version": "2.0.0", "type": "library"}],
        },
        "sbom_compliance": {
            "disclaimer": "advisory only — see dashboard",
            "cert_in_sbom": {
                "pass": 2,
                "fail": 1,
                "not_bom_evidenceable": 0,
                "out_of_scope": 0,
                "na": 0,
                "coverage": 0.67,
                "requirements": [],
            },
            "rbi_free_ai_supply": {
                "pass": 4,
                "fail": 0,
                "coverage": 1.0,
                "requirements": [],
            },
        },
        "results": [{"dependency": "urllib3==2.0.0"}],
    }
    meta = get_scan_metadata("sbom_sca", _scan(data))
    bom = meta.get("sbom_json")
    assert isinstance(bom, dict)
    assert bom["bomFormat"] == "CycloneDX"
    assert bom["specVersion"] in {"1.5", "1.6", "1.7"}
    assert bom["components"][0]["name"] == "urllib3"
    names = _prop_names(bom)
    assert "dss:compliance" in names
    assert names == {"dss:compliance"}
    values = {
        p.get("value")
        for p in (bom.get("metadata") or {}).get("properties") or []
        if isinstance(p, dict) and p.get("name") == "dss:compliance"
    }
    assert values == {"fail"}
    assert not any(n.startswith("dss:compliance.") for n in names)
    assert "dss:compliance.cert_in_sbom" not in {n.split(".verdict")[0] for n in names}
    assert meta.get("sbom_compliance", {}).get("cert_in_sbom", {}).get("fail") == 1


def test_industry_sbom_strips_syft_and_per_framework_noise() -> None:
    data = {
        "sbom_json": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.7",
            "serialNumber": "urn:uuid:760aa8a1-d775-475b-99b9-26bc0d52d490",
            "metadata": {
                "timestamp": "2026-08-10T06:22:34Z",
                "component": {"type": "application", "name": "/tmp/repo__fls8k2d"},
                "properties": [
                    {"name": "dss:compliance.rbi_free_ai_supply.verdict", "value": "fail"},
                    {"name": "dss:compliance.disclaimer", "value": "long disclaimer"},
                ],
            },
            "components": [
                {
                    "bom-ref": "pkg:pypi/flask@3.0.0",
                    "type": "library",
                    "name": "flask",
                    "version": "3.0.0",
                    "purl": "pkg:pypi/flask@3.0.0",
                    "properties": [
                        {"name": "syft:package:foundBy", "value": "python-package-cataloger"},
                        {"name": "syft:location:0:path", "value": "/requirements.txt"},
                        {"name": "dss:compliant", "value": "true"},
                        {"name": "dss:impact", "value": "Low"},
                        {"name": "dss:license_type", "value": "permissive"},
                    ],
                },
                {
                    "type": "file",
                    "name": "/tmp/repo__fls8k2d/requirements.txt",
                    "hashes": [{"alg": "SHA-256", "content": "abc"}],
                },
            ],
        },
        "sbom_compliance": {
            "cert_in_sbom": {"pass": 1, "fail": 0, "coverage": 1.0, "requirements": []},
        },
        "results": [
            {
                "dependency": "flask==3.0.0",
                "purl": "pkg:pypi/flask@3.0.0",
                "license": "BSD-3-Clause",
                "license_type": "permissive",
                "impact": "Low",
                "cves": {},
            }
        ],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="juice-shop")
    assert bom is not None
    assert bom["bomFormat"] == "CycloneDX"
    names = [c["name"] for c in bom["components"]]
    assert names == ["flask"]
    flask = bom["components"][0]
    assert flask.get("licenses") == [{"license": {"id": "BSD-3-Clause"}}]
    assert flask.get("purl") == "pkg:pypi/flask@3.0.0"
    assert flask.get("supplier", {}).get("name")
    assert flask.get("evidence", {}).get("occurrences") == [
        {"location": "/requirements.txt"}
    ]
    assert not flask.get("author")
    comp_props = _all_component_prop_names(bom)
    assert comp_props == {"dss:compliance"}
    assert not any(n.startswith("syft:") for n in comp_props)
    meta_names = _prop_names(bom)
    assert meta_names == {"dss:compliance"}
    meta_comp = (bom.get("metadata") or {}).get("component") or {}
    assert "/tmp/" not in str(meta_comp.get("name") or "")
    assert meta_comp.get("name") == "juice-shop"


def test_industry_sbom_emits_vulnerabilities_from_cves() -> None:
    data = {
        "sbom_json": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "jackson-databind",
                    "version": "2.13.0",
                    "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
                }
            ],
        },
        "sbom_compliance": {
            "ntia_minimum_elements": {"pass": 0, "fail": 1, "coverage": 0.0, "requirements": []},
        },
        "results": [
            {
                "dependency": "jackson-databind==2.13.0",
                "purl": "pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.13.0",
                "impact": "High",
                "license": "Apache-2.0",
                "license_type": "permissive",
                "cves": {"CVE-2023-35116": {"severity": "high"}},
                "hash": "SHA-256:deadbeef",
            }
        ],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data)
    assert bom is not None
    vulns = bom.get("vulnerabilities") or []
    assert len(vulns) == 1
    assert vulns[0]["id"] == "CVE-2023-35116"
    assert vulns[0]["source"]["name"] == "NVD"
    refs = [a.get("ref") for a in vulns[0].get("affects") or []]
    assert any("jackson-databind" in str(r) for r in refs)
    hashes = bom["components"][0].get("hashes") or []
    assert hashes[0]["alg"] == "SHA-256"
    assert hashes[0]["content"] == "deadbeef"
    assert bom["components"][0]["properties"] == [{"name": "dss:compliance", "value": "fail"}]


def test_scan_metadata_synthesizes_named_sbom_when_json_missing() -> None:
    data = {
        "results": [
            {"dependency": "numpy==1.26.0", "purl": "pkg:pypi/numpy@1.26.0"},
        ],
        "sbom_compliance": {
            "cert_in_sbom": {"pass": 1, "fail": 0, "coverage": 1.0, "requirements": []}
        },
    }
    meta = get_scan_metadata("sbom_sca", _scan(data))
    bom = meta["sbom_json"]
    assert bom["components"][0]["name"] == "numpy"
    assert "sbom-dep" not in str(bom["components"][0].get("bom-ref") or "")
    assert _prop_names(bom) == {"dss:compliance"}


def test_industry_sbom_dedupes_same_action_version_and_keeps_locations() -> None:
    data = {
        "sbom_json": {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "components": [
                {
                    "type": "library",
                    "name": "actions/checkout",
                    "version": "v7.0.0",
                    "purl": "pkg:github/actions/checkout@v7.0.0?package-id=aaa",
                    "bom-ref": "pkg:github/actions/checkout@v7.0.0?package-id=aaa",
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/.github/workflows/lint.yml"},
                    ],
                },
                {
                    "type": "library",
                    "name": "actions/checkout",
                    "version": "v7.0.0",
                    "purl": "pkg:github/actions/checkout@v7.0.0?package-id=bbb",
                    "bom-ref": "pkg:github/actions/checkout@v7.0.0?package-id=bbb",
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/.github/workflows/codeql-analysis.yml"},
                    ],
                },
                {
                    "type": "library",
                    "name": "actions/checkout",
                    "version": "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0",
                    "purl": "pkg:github/actions/checkout@9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0?package-id=ccc",
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/.github/workflows/run-tests.yml"},
                    ],
                },
                {
                    "type": "library",
                    "name": "sphinx",
                    "version": "7.2.6",
                    "purl": "pkg:pypi/sphinx@7.2.6",
                },
            ],
        },
        "sbom_compliance": {"ntia_minimum_elements": {"pass": 1, "fail": 0, "coverage": 1.0}},
        "results": [],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data)
    assert bom is not None
    by_nv = {(c["name"], c["version"]): c for c in bom["components"]}
    assert len(bom["components"]) == 3
    tag = by_nv[("actions/checkout", "v7.0.0")]
    assert tag["purl"] == "pkg:github/actions/checkout@v7.0.0"
    assert "package-id" not in str(tag["purl"])
    locs = {o["location"] for o in tag["evidence"]["occurrences"]}
    assert locs == {
        "/.github/workflows/lint.yml",
        "/.github/workflows/codeql-analysis.yml",
    }
    assert tag["supplier"]["name"] == "GitHub"
    assert tag["author"] == "actions"
    assert tag["licenses"] == [{"license": {"id": "MIT"}}]
    sha = by_nv[("actions/checkout", "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0")]
    assert sha["hashes"][0]["alg"] == "SHA-1"
    assert sha["hashes"][0]["content"] == "9c091bb21b7c1c1d1991bb908d89e4e9dddfe3e0"
    sphinx = by_nv[("sphinx", "7.2.6")]
    assert sphinx["licenses"] == [{"license": {"id": "BSD-2-Clause"}}]
    assert sphinx["supplier"]["name"] == "PyPI"
