"""Findings-only SBOMs must recover identity and drop polluted CVEs."""
from __future__ import annotations

import os
import sys

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from backend.utilities.compliance.certin_attest import bom_dict_from_scan_data
from backend.utilities.compliance.sbom_identity import parse_pkg


def test_parse_ecosystem_dependency_string() -> None:
    azure = parse_pkg(dependency="azure-core@1.36.0 (python)")
    assert azure.name == "azure-core"
    assert azure.version == "1.36.0"
    assert azure.ecosystem == "pypi"
    assert azure.purl == "pkg:pypi/azure-core@1.36.0"

    axios = parse_pkg(dependency="axios@1.12.2 (npm)")
    assert axios.purl == "pkg:npm/axios@1.12.2"
    assert axios.ecosystem == "npm"

    crypto = parse_pkg(dependency="cryptography@46.0.2/46.0.3 (python)")
    assert crypto.version == "46.0.2"

    flask = parse_pkg(dependency="flask==3.0.0", purl="pkg:pypi/flask@3.0.0")
    assert flask.purl == "pkg:pypi/flask@3.0.0"
    assert flask.version == "3.0.0"


CLIPBUCKET = (
    "ClipBucket V5 provides open source video hosting with PHP. "
    "During the user avatar upload workflow, a user can choose to upload "
    "and change their avatar at any time."
)


def test_findings_only_riskpilot_fills_identity_and_drops_polluted_cve() -> None:
    data = {
        "results": [
            {
                "dependency": "azure-core@1.36.0 (python)",
                "title": "azure-core 1.36.0 (Python)",
                "license_type": "unknown",
                "cves": {"CVE-2025-21622": CLIPBUCKET},
                "impact": "High",
            },
            {
                "dependency": "starlette@0.48.0 (python)",
                "title": "starlette 0.48.0 (Python)",
                "license_type": "unknown",
                "cves": {"CVE-2025-21622": CLIPBUCKET},
                "impact": "High",
            },
            {
                "dependency": "axios@1.12.2 (npm)",
                "title": "axios 1.12.2 (NPM)",
                "license_type": "unknown",
                "cves": {"CVE-2025-21622": CLIPBUCKET},
                "impact": "High",
            },
            {
                "dependency": "urllib3@2.5.0 (python)",
                "title": "urllib3 2.5.0 (Python)",
                "license_type": "unknown",
                "cves": {
                    "CVE-2025-50181": "urllib3 is a user-friendly HTTP client for Python."
                },
                "impact": "High",
            },
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="RiskPilot")
    assert bom is not None
    by = {c["name"]: c for c in bom["components"]}
    azure = by["azure-core"]
    assert azure["version"] == "1.36.0"
    assert azure["purl"] == "pkg:pypi/azure-core@1.36.0"
    assert azure["supplier"]["name"] == "PyPI"
    assert azure["licenses"] == [{"license": {"id": "MIT"}}]
    axios = by["axios"]
    assert axios["purl"] == "pkg:npm/axios@1.12.2"
    assert axios["supplier"]["name"] == "npm"
    assert axios["licenses"] == [{"license": {"id": "MIT"}}]
    assert by["starlette"]["licenses"] == [{"license": {"id": "BSD-3-Clause"}}]
    vulns = bom.get("vulnerabilities") or []
    ids = {v["id"] for v in vulns}
    assert "CVE-2025-21622" not in ids
    assert "CVE-2025-50181" in ids
    urllib = next(v for v in vulns if v["id"] == "CVE-2025-50181")
    refs = [a["ref"] for a in urllib.get("affects") or []]
    assert refs == ["pkg:pypi/urllib3@2.5.0"]


def test_registry_lookup_fills_author_hash_and_declared_deps(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake(eco: str, name: str, version: str):
        if name == "azure-core":
            return {
                "author": "Microsoft Corporation",
                "license": "MIT",
                "hash": ("SHA-256", "fee9923a3a753e94a259563429f3644aaf05c486"),
                "depends": ["requests", "typing-extensions"],
            }
        return None

    monkeypatch.setattr(sbom_registry, "lookup_package", fake)
    data = {
        "results": [
            {
                "dependency": "azure-core@1.36.0 (python)",
                "title": "azure-core 1.36.0 (Python)",
                "cves": {},
                "impact": "Low",
            },
            {
                "dependency": "requests@2.31.0 (python)",
                "title": "requests 2.31.0 (Python)",
                "cves": {},
                "impact": "Low",
            },
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="RiskPilot")
    azure = next(c for c in bom["components"] if c["name"] == "azure-core")
    assert azure["author"] == "Microsoft Corporation"
    assert azure["hashes"][0]["alg"] == "SHA-256"
    props = {p["name"]: p["value"] for p in azure.get("properties") or []}
    assert "requests" in props.get("declared:depends", "")
    deps = bom.get("dependencies") or []
    azure_dep = next((d for d in deps if d.get("ref") == azure["bom-ref"]), None)
    assert azure_dep is not None
    assert any("requests" in str(x) for x in azure_dep.get("dependsOn") or [])


def test_registry_skips_extras_and_uses_github_org_author(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    payloads = {
        "pillow": {
            "info": {
                "author": "Jeffrey A. Clark",
                "license": "MIT-CMU",
                "requires_dist": [
                    'furo; extra == "docs"',
                    'olefile; extra == "tests"',
                    'typing-extensions; python_version < "3.10" and extra == "typing"',
                ],
            },
            "urls": [{"digests": {"sha256": "aa" * 32}}],
        },
        "fschat": {
            "info": {
                "author": "",
                "author_email": "",
                "license": "Apache-2.0",
                "project_urls": {"Homepage": "https://github.com/lm-sys/fastchat"},
                "requires_dist": ["aiohttp", "black ==23.3.0 ; extra == 'dev'"],
            },
            "urls": [{"digests": {"sha256": "bb" * 32}}],
        },
    }

    def fake_json(url: str):
        for name, body in payloads.items():
            if f"/{name}/" in url:
                return body
        return None

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(sbom_registry, "_get_json", fake_json)
    sbom_registry._fetch.cache_clear()
    pillow = sbom_registry.lookup_package("pypi", "pillow", "11.3.0")
    assert pillow is not None
    assert pillow.get("depends") == []
    fschat = sbom_registry.lookup_package("pypi", "fschat", "0.2.36")
    assert fschat is not None
    assert fschat["author"] == "lm-sys"
    assert fschat["depends"] == ["aiohttp"]


def test_fifty_five_packages_all_get_registry_hash(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake(eco: str, name: str, version: str):
        return {
            "author": "A",
            "license": "MIT",
            "hash": ("SHA-256", "ab" * 32),
            "depends": [],
        }

    monkeypatch.setattr(sbom_registry, "lookup_package", fake)
    data = {
        "results": [
            {
                "dependency": f"pkg-{i:02d}@1.0.0 (python)",
                "cves": {},
                "impact": "Low",
            }
            for i in range(55)
        ]
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="flask")
    comps = bom["components"]
    assert len(comps) == 55
    assert all(c.get("hashes") for c in comps)


def test_complete_row_does_not_call_registry_http(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry
    from backend.utilities.compliance.sbom_cyclonedx import sanitize_industry_sbom

    calls: list[str] = []

    def fake_json(url: str):
        calls.append(url)
        return None

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(sbom_registry, "_get_json", fake_json)
    from backend.utilities.compliance import sbom_advisory

    monkeypatch.setattr(sbom_advisory, "attach_advisories", lambda comps: [])
    sbom_registry._fetch.cache_clear()
    sanitize_industry_sbom(
        {
            "components": [
                {
                    "name": "click",
                    "version": "8.1.3",
                    "purl": "pkg:pypi/click@8.1.3",
                    "author": "Pallets",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    "hashes": [{"alg": "SHA-256", "content": "aa" * 32}],
                    "properties": [{"name": "declared:depends", "value": "colorama"}],
                }
            ]
        }
    )
    assert calls == []


def test_classifier_license_when_license_field_empty(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake_json(url: str):
        if "alabaster" in url:
            return {
                "info": {
                    "author": "Adam Turner",
                    "license": "",
                    "classifiers": ["License :: OSI Approved :: BSD License"],
                    "requires_dist": [],
                },
                "urls": [{"digests": {"sha256": "cc" * 32}}],
            }
        return None

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(sbom_registry, "_get_json", fake_json)
    sbom_registry._fetch.cache_clear()
    meta = sbom_registry.lookup_package("pypi", "alabaster", "1.0.0")
    assert meta is not None
    assert meta["license"] in {"BSD-2-Clause", "BSD-3-Clause", "BSD"}
    assert meta["author"] == "Adam Turner"


def test_github_tag_resolves_commit_and_license(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake_json(url: str):
        if "api.github.com" in url and "/commits/" in url:
            return {"sha": "a" * 40}
        if "api.github.com" in url and url.endswith("/license"):
            return {"license": {"spdx_id": "MIT"}}
        return None

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(sbom_registry, "_get_json", fake_json)
    sbom_registry._fetch.cache_clear()
    meta = sbom_registry.lookup_package("github", "astral-sh/setup-uv", "v9.0.0")
    assert meta is not None
    assert meta["hash"] == ("SHA-1", "a" * 40)
    assert meta["license"] == "MIT"
    assert meta["depends"] == []
    assert meta["author"] == "astral-sh"


def test_deps_dev_fills_license_only_after_native_miss(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    urls: list[str] = []

    def fake_json(url: str):
        urls.append(url)
        if "deps.dev" in url:
            return {"licenses": ["MIT"]}
        if "pypi.org" in url:
            return {
                "info": {"author": "Tom", "license": "", "classifiers": [], "requires_dist": []},
                "urls": [{"digests": {"sha256": "dd" * 32}}],
            }
        return None

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(sbom_registry, "_get_json", fake_json)
    sbom_registry._fetch.cache_clear()
    miss = sbom_registry.lookup_package("pypi", "pathspec", "1.1.1")
    assert miss is not None
    assert miss["license"] == "MIT"
    assert any("deps.dev" in u for u in urls)

    urls.clear()
    sbom_registry._fetch.cache_clear()

    def native_hit(url: str):
        urls.append(url)
        if "deps.dev" in url:
            raise AssertionError("deps.dev should not run on native hit")
        return {
            "info": {
                "author": "Pallets",
                "license": "BSD-3-Clause",
                "requires_dist": [],
            },
            "urls": [{"digests": {"sha256": "ee" * 32}}],
        }

    monkeypatch.setattr(sbom_registry, "_get_json", native_hit)
    hit = sbom_registry.lookup_package("pypi", "click", "8.1.3")
    assert hit["license"] == "BSD-3-Clause"
    assert hit["author"] == "Pallets"
    assert not any("deps.dev" in u for u in urls)


def test_existing_author_not_replaced(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake(eco: str, name: str, version: str):
        return {"author": "Intruder", "license": "MIT", "hash": ("SHA-256", "ff" * 32), "depends": []}

    monkeypatch.setattr(sbom_registry, "lookup_package", fake)
    data = {
        "sbom_json": {
            "components": [
                {
                    "name": "flask",
                    "version": "2.3.2",
                    "purl": "pkg:pypi/flask@2.3.2",
                    "author": "Pallets",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                }
            ]
        },
        "results": [],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="flask")
    flask = next(c for c in bom["components"] if c["name"] == "flask")
    assert flask["author"] == "Pallets"


def test_github_action_row_gets_hash_via_sanitize(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake(eco: str, name: str, version: str):
        if eco == "github":
            return {
                "author": "astral-sh",
                "license": "Apache-2.0",
                "hash": ("SHA-1", "b" * 40),
                "depends": [],
            }
        return None

    monkeypatch.setattr(sbom_registry, "lookup_package", fake)
    data = {
        "sbom_json": {
            "components": [
                {
                    "name": "astral-sh/setup-uv",
                    "version": "v9.0.0",
                    "purl": "pkg:github/astral-sh/setup-uv@v9.0.0",
                    "type": "library",
                }
            ]
        },
        "results": [],
    }
    bom = bom_dict_from_scan_data("sbom_sca", data, subject_name="flask")
    row = bom["components"][0]
    assert row["hashes"][0]["content"] == "b" * 40
    assert row["licenses"][0]["license"]["id"] == "Apache-2.0"
    props = {p["name"]: p["value"] for p in row.get("properties") or []}
    assert "declared:depends" in props
    assert props["declared:depends"] == ""


def test_slash_version_keeps_first_existing_on_pypi(monkeypatch) -> None:
    from backend.utilities.compliance import sbom_registry

    def fake_json(url: str):
        if "/cryptography/46.0.2/" in url:
            return None
        if "/cryptography/46.0.3/" in url:
            return {
                "info": {
                    "author": "The Python Cryptographic Authority",
                    "license": "Apache-2.0 OR BSD-3-Clause",
                    "license_expression": "Apache-2.0 OR BSD-3-Clause",
                    "requires_dist": [],
                },
                "urls": [{"digests": {"sha256": "11" * 32}}],
            }
        if "deps.dev" in url:
            raise AssertionError("deps.dev should not run after native hit")
        return None

    monkeypatch.setenv("DSS_SBOM_REGISTRY", "1")
    monkeypatch.setattr(sbom_registry, "_get_json", fake_json)
    sbom_registry._fetch.cache_clear()
    meta = sbom_registry.lookup_package("pypi", "cryptography", "46.0.2/46.0.3")
    assert meta is not None
    assert meta["version"] == "46.0.3"
    assert meta["author"] == "The Python Cryptographic Authority"
