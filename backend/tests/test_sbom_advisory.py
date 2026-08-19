"""OSV + NVD advisories attach to CycloneDX vulnerabilities[] (hermetic)."""
from __future__ import annotations

import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data
from backend.utilities.compliance.sbom_cyclonedx import sanitize_industry_sbom


def test_osv_batch_attaches_cve_to_matching_purl(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_advisory, sbom_registry

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(
        sbom_registry,
        "lookup_package",
        lambda eco, name, version: {
            "author": "A",
            "license": "MIT",
            "hash": ("SHA-256", "aa" * 32),
            "depends": [],
        },
    )

    def fake_post(url: str, body: dict):
        assert "osv.dev" in url
        queries = body.get("queries") or []
        results = []
        for q in queries:
            pkg = (q.get("package") or {})
            purl = str(pkg.get("purl") or "")
            if "urllib3" in purl:
                results.append({"vulns": [{"id": "CVE-2025-50181"}]})
            else:
                results.append({"vulns": []})
        return {"results": results}

    monkeypatch.setattr(sbom_advisory, "_post_json", fake_post)
    monkeypatch.setattr(sbom_advisory, "_get_json", lambda url: None)
    data = {
        "results": [
            {"dependency": "urllib3@2.5.0 (python)", "cves": {}, "impact": "Low"},
            {"dependency": "idna@3.18 (python)", "cves": {}, "impact": "Low"},
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="flask")
    vulns = bom.get("vulnerabilities") or []
    ids = {v["id"] for v in vulns}
    assert "CVE-2025-50181" in ids
    urllib = next(v for v in vulns if v["id"] == "CVE-2025-50181")
    refs = [a["ref"] for a in urllib.get("affects") or []]
    assert any("urllib3" in r for r in refs)
    idna = next(c for c in bom["components"] if c["name"] == "idna")
    idna_ref = idna.get("bom-ref")
    assert idna_ref not in refs


def test_nvd_second_pass_only_when_osv_empty_and_mentions_package(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_advisory, sbom_registry

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(
        sbom_registry,
        "lookup_package",
        lambda eco, name, version: {
            "author": "A",
            "license": "MIT",
            "hash": ("SHA-256", "aa" * 32),
            "depends": [],
        },
    )
    monkeypatch.setattr(
        sbom_advisory,
        "_post_json",
        lambda url, body: {"results": [{"vulns": []} for _ in (body.get("queries") or [])]},
    )

    def fake_get(url: str):
        if "nvd.nist.gov" not in url:
            return None
        if "redis" in url.lower():
            return {
                "vulnerabilities": [
                    {
                        "cve": {
                            "id": "CVE-2023-28856",
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "Redis is a Python package providing a client for the Redis in-memory database.",
                                }
                            ],
                        }
                    },
                    {
                        "cve": {
                            "id": "CVE-2025-21622",
                            "descriptions": [
                                {
                                    "lang": "en",
                                    "value": "ClipBucket V5 provides open source video hosting with PHP.",
                                }
                            ],
                        }
                    },
                ]
            }
        return {"vulnerabilities": []}

    monkeypatch.setattr(sbom_advisory, "_get_json", fake_get)
    data = {
        "results": [
            {"dependency": "redis@4.5.4 (python)", "cves": {}, "impact": "Low"},
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="flask")
    ids = {v["id"] for v in (bom.get("vulnerabilities") or [])}
    assert "CVE-2023-28856" in ids
    assert "CVE-2025-21622" not in ids


def test_polluted_finding_cve_still_dropped_when_osv_off() -> None:
    data = {
        "results": [
            {
                "dependency": "azure-core@1.36.0 (python)",
                "cves": {"CVE-2025-21622": "ClipBucket V5 video hosting PHP avatar"},
                "impact": "High",
            },
            {
                "dependency": "starlette@0.48.0 (python)",
                "cves": {"CVE-2025-21622": "ClipBucket V5 video hosting PHP avatar"},
                "impact": "High",
            },
            {
                "dependency": "axios@1.12.2 (npm)",
                "cves": {"CVE-2025-21622": "ClipBucket V5 video hosting PHP avatar"},
                "impact": "High",
            },
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="RiskPilot")
    ids = {v["id"] for v in (bom.get("vulnerabilities") or [])}
    assert "CVE-2025-21622" not in ids


def test_nvd_drops_unrelated_protocol_cves_for_short_pypi_names(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_advisory, sbom_registry

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(
        sbom_registry,
        "lookup_package",
        lambda eco, name, version: {
            "author": "A",
            "license": "MIT",
            "hash": ("SHA-256", "aa" * 32),
            "depends": [],
        },
    )
    monkeypatch.setattr(
        sbom_advisory,
        "_post_json",
        lambda url, body: {"results": [{"vulns": []} for _ in (body.get("queries") or [])]},
    )

    def fake_get(url: str):
        if "nvd.nist.gov" not in url:
            return None
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2015-5240",
                        "descriptions": [
                            {
                                "lang": "en",
                                "value": "Apache Qpid Java AMQP client mishandles authentication.",
                            }
                        ],
                    }
                }
            ]
        }

    monkeypatch.setattr(sbom_advisory, "_get_json", fake_get)
    data = {
        "results": [
            {"dependency": "amqp@5.1.1 (python)", "cves": {}, "impact": "Low"},
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="flask")
    ids = {v["id"] for v in (bom.get("vulnerabilities") or [])}
    assert "CVE-2015-5240" not in ids


def test_nvd_skips_github_actions_keyword_false_positives(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_advisory, sbom_registry

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(
        sbom_registry,
        "lookup_package",
        lambda eco, name, version: {
            "author": "actions",
            "license": "MIT",
            "hash": ("SHA-1", "b" * 40),
            "depends": [],
        },
    )
    monkeypatch.setattr(
        sbom_advisory,
        "_post_json",
        lambda url, body: {"results": [{"vulns": []} for _ in (body.get("queries") or [])]},
    )

    def fake_get(url: str):
        raise AssertionError("NVD must not be queried for GitHub Actions")

    monkeypatch.setattr(sbom_advisory, "_get_json", fake_get)
    data = {
        "sbom_json": {
            "components": [
                {
                    "name": "actions/checkout",
                    "version": "v7.0.0",
                    "purl": "pkg:github/actions/checkout@v7.0.0",
                    "type": "library",
                }
            ]
        },
        "results": [],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="requests")
    ids = {v["id"] for v in (bom.get("vulnerabilities") or [])}
    assert "CVE-2025-32111" not in ids


def test_merge_advisories_prefers_cve_alias() -> None:
    from backend.utilities.compliance.sbom_advisory import _vuln_id

    assert _vuln_id({"id": "GHSA-xxxx", "aliases": ["CVE-2023-1"]}) == "CVE-2023-1"
    assert _vuln_id({"id": "CVE-2024-9"}) == "CVE-2024-9"
    assert _vuln_id({"id": "GHSA-only"}) == "GHSA-only"
