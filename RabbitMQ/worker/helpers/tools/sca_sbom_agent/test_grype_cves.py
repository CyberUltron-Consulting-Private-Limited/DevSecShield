"""Grype CVE ids must survive onto finding rows when the LLM list is empty."""

from helpers.tools.sca_sbom_agent.parser import apply_grype_cves


def test_apply_grype_cves_fills_empty_llm_list():
    document = {
        "matches": [
            {
                "vulnerability": {
                    "id": "GHSA-xxxx",
                    "description": "advisory",
                },
                "relatedVulnerabilities": [
                    {"id": "CVE-2024-26130", "description": "Bleichenbacher oracle"},
                ],
                "artifact": {
                    "name": "cryptography",
                    "version": "48.0.0",
                    "purl": "pkg:pypi/cryptography@48.0.0",
                },
            }
        ]
    }
    rows = [
        {"dependency": "cryptography@48.0.0", "cves": {}},
        {"dependency": "unrelated@1.0.0", "cves": {}},
        {"dependency": "kept@1", "cves": {"CVE-2020-0001": "already set"}},
    ]
    apply_grype_cves(rows, document)
    assert "CVE-2024-26130" in rows[0]["cves"]
    assert rows[1]["cves"] == {}
    assert rows[2]["cves"] == {"CVE-2020-0001": "already set"}


def test_apply_grype_cves_does_not_mix_versions():
    document = {
        "matches": [
            {
                "vulnerability": {"id": "CVE-2023-1111", "description": "old"},
                "artifact": {"name": "tar", "version": "6.0.0"},
            },
            {
                "vulnerability": {"id": "CVE-2024-2222", "description": "new"},
                "artifact": {"name": "tar", "version": "7.5.15"},
            },
        ]
    }
    rows = [{"dependency": "tar@7.5.15", "cves": {}}]
    apply_grype_cves(rows, document)
    assert list(rows[0]["cves"]) == ["CVE-2024-2222"]
