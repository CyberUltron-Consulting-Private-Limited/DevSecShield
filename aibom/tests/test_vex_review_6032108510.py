"""Review 6032108510 (PR #489, second review) m1 and m3: CERT-In VEX.

m1: an AI BOM's VEX is #487's: the ids its BOM records are merged with the affects
its findings add, and every id is kept as given (a GHSA id with no digit,
``AI-SUPPLY-CHAIN``). Only an SBOM's own Grype statements are authoritative.

m3: a version read from a manifest range is not known to be installed, so its
affects entry gives the range with status unknown, not the lower bound "affected".
"""

from __future__ import annotations

from aibom.compliance.cert_in.vex import build_vex, normalise_advisory_id

NOW = "2026-11-24T00:00:00Z"
SERIAL = "urn:uuid:11111111-1111-4111-8111-111111111111"


def _statements(doc: dict) -> dict:
    return {
        v["id"]: sorted(a["ref"] for a in v.get("affects") or [])
        for v in doc["vulnerabilities"]
    }


def test_ai_bom_merges_its_findings_affects_into_a_recorded_id():
    bom = {
        "serialNumber": SERIAL,
        "components": [
            {"bom-ref": "model-a", "name": "model-a"},
            {
                "bom-ref": "pkg:pypi/torch@2.0",
                "name": "torch",
                "version": "2.0",
                "purl": "pkg:pypi/torch@2.0",
            },
        ],
        "vulnerabilities": [{"id": "CVE-2024-0001", "affects": [{"ref": "model-a"}]}],
    }
    findings = [
        {"cves": ["CVE-2024-0001"], "purl": "pkg:pypi/torch@2.0", "dependency": "torch"}
    ]
    doc = build_vex(scan_type="ai_bom", bom=bom, findings=findings, now=NOW)
    assert _statements(doc) == {"CVE-2024-0001": ["model-a", "pkg:pypi/torch@2.0"]}


def test_ai_bom_keeps_digitless_ghsa_and_non_advisory_ids():
    bom = {
        "components": [{"bom-ref": "m", "name": "m"}],
        "vulnerabilities": [{"id": "ghsa-AAAA-bbbb-cccc", "affects": [{"ref": "m"}]}],
    }
    findings = [
        {"cves": ["GHSA-aaaa-bbbb-cccc"], "dependency": "x", "version": "1"},
        {"vulnerability_id": "AI-SUPPLY-CHAIN", "dependency": "y"},
    ]
    doc = build_vex(scan_type="ai_bom", bom=bom, findings=findings, now=NOW)
    assert _statements(doc) == {
        "AI-SUPPLY-CHAIN": ["y"],
        "GHSA-aaaa-bbbb-cccc": ["x"],
        "ghsa-AAAA-bbbb-cccc": ["m"],
    }


def test_a_digitless_ghsa_id_is_an_advisory_id():
    assert normalise_advisory_id("GHSA-wxwx-xxwx-hjwh") == "GHSA-wxwx-xxwx-hjwh"
    assert normalise_advisory_id("ghsa-WXWX-xxwx-hjwh") == "GHSA-wxwx-xxwx-hjwh"
    assert normalise_advisory_id("AI-SUPPLY-CHAIN") is None


def _guessed_sbom(constraint: str) -> dict:
    ref = "pkg:pypi/pillow@10.0"
    return {
        "serialNumber": SERIAL,
        "version": 1,
        "components": [
            {"bom-ref": ref, "name": "pillow", "version": "10.0", "purl": ref}
        ],
        "vulnerabilities": [
            {
                "id": "GHSA-3f63-hfp8-52jq",
                "affects": [{"ref": ref}],
                "properties": [
                    {"name": "dss:detected_by", "value": "grype"},
                    {"name": "dss:version_guessed_from", "value": constraint},
                ],
            }
        ],
    }


def test_a_guessed_version_is_stated_as_its_range_with_status_unknown():
    doc = build_vex(scan_type="sbom_sca", bom=_guessed_sbom(">=10.0,<13.0"), now=NOW)
    (stmt,) = doc["vulnerabilities"]
    assert stmt["analysis"]["state"] == "in_triage"
    (aff,) = stmt["affects"]
    assert aff["versions"] == [{"range": "vers:pypi/>=10.0|<13.0", "status": "unknown"}]


def test_compatible_release_and_unwritable_ranges():
    def versions(constraint: str) -> list:
        doc = build_vex(scan_type="sbom_sca", bom=_guessed_sbom(constraint), now=NOW)
        return doc["vulnerabilities"][0]["affects"][0]["versions"]

    assert versions("~=10.0") == [
        {"range": "vers:pypi/>=10.0|<11", "status": "unknown"}
    ]
    assert versions("<13, >= 10.0") == [
        {"range": "vers:pypi/>=10.0|<13", "status": "unknown"}
    ]
    assert versions("===10.0-custom") == [{"version": "10.0", "status": "unknown"}]


def test_a_pinned_version_is_still_affected():
    bom = _guessed_sbom("")
    bom["vulnerabilities"][0]["properties"] = [
        {"name": "dss:detected_by", "value": "grype"}
    ]
    doc = build_vex(scan_type="sbom_sca", bom=bom, now=NOW)
    aff = doc["vulnerabilities"][0]["affects"][0]
    assert aff["versions"] == [{"version": "10.0", "status": "affected"}]
