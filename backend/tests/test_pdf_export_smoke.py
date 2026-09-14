"""Runtime smoke: every scan-type PDF generator actually builds a file.

Catches ReportLab TableStyle/Paragraph markup errors, missing imports, and
broken empty/sparse payloads. Hermetic — reportlab only, no DB/network.
"""

from __future__ import annotations

import base64
import json
import os
import re
import sys
import zlib

import pytest
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

from backend.utilities.pdf.combined import (  # noqa: E402
    UnsupportedPdfExport,
    generate_pdf_for_type,
    prepare_pdf_export_payload,
    write_scan_pdf,
)

_FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
_SCAN_TYPES = ("sast", "sbom_sca", "dast", "iac", "mcp", "llm", "cbom", "ai_bom")


def _assert_valid_pdf(path: str) -> None:
    with open(path, "rb") as fh:
        head = fh.read(5)
    size = os.path.getsize(path)
    assert head == b"%PDF-", f"not a PDF (magic {head!r})"
    assert size > 1000, f"PDF suspiciously small ({size} bytes)"


def _pdf_haystack(path: str) -> str:
    """Flatten PDF page text from ASCII85+Flate content streams."""
    with open(path, "rb") as fh:
        raw = fh.read()
    chunks = [raw]
    # ReportLab writes `stream\\n<ascii85>~>endstream` (no newline before endstream).
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        decoded = None
        try:
            decoded = base64.a85decode(data, adobe=True)
        except (ValueError, OverflowError):
            decoded = None
        if decoded is not None:
            try:
                chunks.append(zlib.decompress(decoded))
                continue
            except zlib.error:
                chunks.append(decoded)
                continue
        for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
            try:
                chunks.append(zlib.decompress(data, wbits))
                break
            except zlib.error:
                continue
    text = b"\n".join(chunks).decode("latin-1", errors="ignore")
    literals = []
    for match in re.findall(r"\((?:\\.|[^\\)])*\)", text):
        inner = match[1:-1]
        inner = (
            inner.replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\(", "(")
            .replace("\\)", ")")
            .replace("\\\\", "\\")
        )
        literals.append(inner)
    return text + "\n" + "\n".join(literals)


def _load_fixture(name: str) -> dict:
    with open(os.path.join(_FIXTURES, name), encoding="utf-8") as fh:
        return json.load(fh)


def _empty_payload(scan_type: str):
    if scan_type == "mcp":
        return {}
    if scan_type == "sast":
        return {}
    return []


def _sparse_payload(scan_type: str):
    if scan_type == "mcp":
        return {"final_issues": [{"title": "bare finding"}]}
    if scan_type == "sast":
        return {
            "results": [
                {
                    "check_id": "rule.bare",
                    "path": "app.py",
                    "severity": "WARNING",
                    "extra": {"severity": "WARNING", "message": "bare finding"},
                }
            ]
        }
    return [{"title": "bare finding"}]


def _typical_payload(scan_type: str):
    if scan_type == "sast":
        return [
            {
                "logical_component_title": "web-app",
                "scan_duration": "12s",
                "vulnerabilities": [
                    {
                        "title": "SQL injection",
                        "impact": "High",
                        "description": "Unparameterized query",
                        "location": "app.py:42",
                        "owasp_top_10": {"A03:2021": "Injection"},
                        "compliance_controls": {"PCI-DSS": "6.5.1"},
                        "cves": {"CVE-2024-0001": "nvd"},
                        "snippet": "cursor.execute(f\"SELECT {q}\")",
                        "suggested_fix": "Use parameterized queries",
                    }
                ],
            }
        ]
    if scan_type == "sbom_sca":
        return [
            {
                "title": "Vulnerable package",
                "impact": "High",
                "description": "Known CVE in dependency",
                "dependencies": ["demo@1.0.0"],
                "cves": {"CVE-2024-0001": "https://nvd.nist.gov"},
                "suggested_fix": "upgrade demo to 1.1.0",
            }
        ]
    if scan_type == "dast":
        return [
            {
                "title": "Reflected XSS",
                "impact": "High",
                "confidence": "High",
                "category": "xss",
                "url": "https://example.test/search",
                "description": "Unescaped query parameter",
                "suggested_fix": "Encode output",
            }
        ]
    if scan_type == "iac":
        return [
            {
                "title": "Public S3 bucket",
                "impact": "Critical",
                "description": "Bucket ACL allows public read",
                "owasp_top_10": {"A01:2021": "Broken Access Control"},
                "compliance_controls": {"CIS": "2.1.5"},
                "location": "infra/s3.tf",
                "suggested_fix": "Block public access",
            }
        ]
    if scan_type == "mcp":
        return {
            "final_issues": [
                {
                    "issue_severity": "high",
                    "issue_code": "MCP001",
                    "server": "demo-mcp",
                    "issue_text": "Tool exposes secrets",
                    "tool": {"name": "fetch"},
                }
            ],
            "error_messages": [],
        }
    if scan_type == "llm":
        return {
            "vulnerabilities": [
                {
                    "title": "Prompt injection",
                    "impact": "Medium",
                    "description": "Model followed injected instructions",
                    "owasp_top_10_llm": {"LLM01": "Prompt Injection"},
                    "suggested_fix": "Add input isolation",
                }
            ]
        }
    if scan_type == "cbom":
        return _load_fixture("cbom_export_scandata.json")
    if scan_type == "ai_bom":
        return _load_fixture("ai_bom_export_scandata.json")
    raise AssertionError(f"no typical payload for {scan_type}")


def test_pdf_generator_modules_import():
    import backend.utilities.pdf.ai_bom_pdf  # noqa: F401
    import backend.utilities.pdf.cbom_pdf  # noqa: F401
    import backend.utilities.pdf.dast_pdf  # noqa: F401
    import backend.utilities.pdf.iac_pdf  # noqa: F401
    import backend.utilities.pdf.llm_pdf  # noqa: F401
    import backend.utilities.pdf.mcp_pdf  # noqa: F401
    import backend.utilities.pdf.report_branding  # noqa: F401
    import backend.utilities.pdf.sast_pdf  # noqa: F401
    import backend.utilities.pdf.sbom_sca_pdf  # noqa: F401


def test_roundedcorners_tablestyle_builds_pdf(tmp_path):
    """ReportLab >=4.4.7 supports ROUNDEDCORNERS — Copilot's crash claim is false."""
    out = tmp_path / "rounded.pdf"
    table = Table([["rounded"]])
    table.setStyle(TableStyle([("ROUNDEDCORNERS", [6, 6, 6, 6])]))
    doc = SimpleDocTemplate(str(out), pagesize=letter)
    doc.build([table])
    _assert_valid_pdf(str(out))


@pytest.mark.parametrize("scan_type", _SCAN_TYPES)
def test_export_pdf_empty_payload(scan_type, tmp_path):
    out = tmp_path / f"{scan_type}_empty.pdf"
    generate_pdf_for_type(scan_type, _empty_payload(scan_type), str(out))
    _assert_valid_pdf(str(out))


@pytest.mark.parametrize("scan_type", _SCAN_TYPES)
def test_export_pdf_sparse_payload(scan_type, tmp_path):
    out = tmp_path / f"{scan_type}_sparse.pdf"
    generate_pdf_for_type(scan_type, _sparse_payload(scan_type), str(out))
    _assert_valid_pdf(str(out))


@pytest.mark.parametrize("scan_type", _SCAN_TYPES)
def test_export_pdf_typical_payload(scan_type, tmp_path):
    out = tmp_path / f"{scan_type}_typical.pdf"
    generate_pdf_for_type(scan_type, _typical_payload(scan_type), str(out))
    _assert_valid_pdf(str(out))


def test_sbom_inventory_and_cve_fields_from_scan_data(tmp_path):
    payload = {
        "duration_of_scan": 134,
        "results": [
            {
                "title": "Inventory: core-js",
                "dependency": "core-js==3.6.5",
                "impact": "Low",
                "inventory_only": True,
                "suggested_fix": "n/a — inventory row",
                "owasp_top_10": {},
            },
            {
                "title": "ReDoS in lodash-es",
                "dependency": "lodash-es==4.17.15",
                "impact": "Medium",
                "owasp_top_10": {"A03:2021": "Injection"},
                "suggested_fix": "Upgrade lodash-es",
                "cves": {"CVE-2019-10744": "nvd"},
            },
        ],
    }
    out = tmp_path / "sbom_sample_shape.pdf"
    generate_pdf_for_type("sbom_sca", payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    assert "2m 14s" in haystack
    assert "core-js==3.6.5" in haystack
    assert "lodash-es==4.17.15" in haystack
    assert "Upgrade lodash-es" in haystack
    assert "A03:2021" in haystack
    assert "No CVE recorded for this component" in haystack
    assert "inventory row" not in haystack.lower()
    # Catalog Location for both rows is the package, not an empty em-dash.
    assert haystack.count("core-js==3.6.5") >= 1
    assert haystack.count("lodash-es==4.17.15") >= 1


def test_wrapped_scan_data_fills_scan_time(tmp_path):
    payload = {"duration_of_scan": 45, "results": _typical_payload("iac")}
    out = tmp_path / "iac_wrapped_duration.pdf"
    generate_pdf_for_type("iac", payload, str(out))
    _assert_valid_pdf(str(out))
    assert "45s" in _pdf_haystack(str(out))


def _worker_persist_payload(scan_type: str) -> dict:
    """Shape the Celery worker actually stores on Scan.scan_data."""
    if scan_type == "sast":
        return {
            "duration_of_scan": 134,
            "metadata": {"engine": "agent"},
            "results": [
                {
                    "logical_component_title": "web-app",
                    "vulnerabilities": [
                        {
                            "title": "Exposed Database URL in logs",
                            "impact": "High",
                            "description": "Prints DATABASE_URL",
                            "location": "/tmp/repo_42_abc/backup.py:12",
                            "owasp_top_10": {"A05:2021": "Security Misconfiguration"},
                            "suggested_fix": "Redact DATABASE_URL in logs",
                            "snippet": "print(db_url)",
                            "cves": {},
                        }
                    ],
                }
            ],
        }
    if scan_type == "sbom_sca":
        return {
            "duration_of_scan": 134,
            "sbom_compliance": {"disclaimer": "advisory"},
            "results": [
                {
                    "title": "Inventory: core-js",
                    "dependency": "core-js==3.6.5",
                    "impact": "Low",
                    "inventory_only": True,
                    "suggested_fix": "n/a — inventory row",
                    "owasp_top_10": {},
                },
                {
                    "title": "ReDoS in lodash-es",
                    "dependency": "lodash-es==4.17.15",
                    "impact": "Medium",
                    "owasp_top_10": {"A03:2021": "Injection"},
                    "suggested_fix": "Upgrade lodash-es",
                    "cves": {"CVE-2019-10744": "nvd"},
                },
            ],
        }
    if scan_type == "dast":
        return {
            "duration_of_scan": 134,
            "metadata": {
                "urls_included": ["https://example.test"],
                "aws_secret_access_key": "AKIA_SHOULD_NOT_APPEAR_IN_PDF",
            },
            "results": [
                {
                    "title": "Reflected XSS",
                    "impact": "High",
                    "confidence": "High",
                    "category": "xss",
                    "url": "https://example.test/search",
                    "description": "Unescaped query",
                    "suggested_fix": "Encode output",
                    "owasp_top_10": {"A03:2021": "Injection"},
                }
            ],
        }
    if scan_type == "iac":
        return {
            "duration_of_scan": 134,
            "metadata": {},
            "dependency_diagram": {},
            "results": [
                {
                    "title": "Public S3 bucket",
                    "impact": "Critical",
                    "description": "ACL allows public write",
                    "owasp_top_10": {"A05:2021": "Security Misconfiguration"},
                    "location": "/tmp/repo_99_xyz/terraform/main.tf",
                    "suggested_fix": "Set ACL to private",
                    "snippet": 'acl = "public-read-write"',
                }
            ],
        }
    if scan_type == "mcp":
        return {
            "duration_of_scan": 134,
            "results": {
                "tools": [
                    {
                        "tool_name": "read_wiki_structure",
                        "vulnerabilities": [
                            {
                                "title": "Tool exposes secrets",
                                "impact": "High",
                                "description": "Token in tool output",
                                "owasp_top_10": {"A07:2021": "Identification Failures"},
                                "suggested_fix": "Redact secrets",
                            }
                        ],
                    }
                ]
            },
        }
    if scan_type == "llm":
        return {
            "duration_of_scan": 134,
            "metadata": {},
            "results": {
                "vulnerabilities": [
                    {
                        "title": "Malware Evasion vulnerability",
                        "impact": "High",
                        "description": "Evasion probe hits",
                        "owasp_top_10_llm": {"LLM01": "Prompt Injection"},
                        "suggested_fix": "Add jailbreak detection",
                    }
                ],
                "model_vulnerabilities": {},
            },
        }
    if scan_type == "cbom":
        payload = _load_fixture("cbom_export_scandata.json")
        payload["duration_of_scan"] = 134
        payload["metadata"] = {"source": "adapter"}
        return payload
    if scan_type == "ai_bom":
        payload = _load_fixture("ai_bom_export_scandata.json")
        payload["duration_of_scan"] = 134
        return payload
    raise AssertionError(f"no worker persist payload for {scan_type}")


_WORKER_EXPECT = {
    "sast": ("2m 14s", "Exposed Database URL in logs", "backup.py:12", "Redact DATABASE_URL in logs", "A05:2021"),
    "sbom_sca": ("2m 14s", "core-js==3.6.5", "Upgrade lodash-es", "A03:2021", "No CVE recorded for this component"),
    "dast": ("2m 14s", "Reflected XSS", "https://example.test/search", "Encode output", "A03:2021", "URLs included"),
    "iac": ("2m 14s", "Public S3 bucket", "terraform/main.tf", "Set ACL to private", "A05:2021"),
    "mcp": ("2m 14s", "Tool exposes secrets", "read_wiki_structure", "Redact secrets"),
    "llm": ("2m 14s", "Malware Evasion vulnerability", "Add jailbreak detection", "LLM01"),
    "cbom": ("2m 14s", "3DES-CBC", "crypto_app.py"),
    "ai_bom": ("2m 14s", "openai_api_key", "app.py"),
}


@pytest.mark.parametrize("scan_type", _SCAN_TYPES)
def test_worker_persist_pdf_fields(scan_type, tmp_path):
    payload = prepare_pdf_export_payload(scan_type, _worker_persist_payload(scan_type))
    out = tmp_path / f"{scan_type}_worker_persist.pdf"
    generate_pdf_for_type(scan_type, payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    for needle in _WORKER_EXPECT[scan_type]:
        assert needle in haystack, f"{scan_type} missing {needle!r}"
    if scan_type == "sast":
        assert "/tmp/repo_" not in haystack
        assert "repo_42_abc" not in haystack
        assert not re.search(r"\d+ U\b", haystack), haystack
    if scan_type == "iac":
        assert "/tmp/repo_" not in haystack
        assert "repo_99_xyz" not in haystack
        assert not re.search(r"\d+ U\b", haystack), haystack
    if scan_type == "sbom_sca":
        assert "inventory row" not in haystack.lower()
    if scan_type in ("dast", "mcp", "llm"):
        assert not re.search(r"\d+ U\b", haystack), haystack
    if scan_type == "dast":
        assert "AKIA_SHOULD_NOT_APPEAR_IN_PDF" not in haystack


def test_full_scan_data_does_not_leak_non_finding_secrets(tmp_path):
    """Passing full scan_data must not dump metadata / secret side-channels into PDF text."""
    secret_markers = (
        "AKIA_SHOULD_NOT_APPEAR_IN_PDF",
        "supersecret_password_xyz",
        "LEAK_MARKER_SHOULD_NOT_APPEAR",
        "BEGIN RSA PRIVATE KEY",
    )
    payload = {
        "duration_of_scan": 12,
        "metadata": {
            "aws_secret_access_key": secret_markers[0],
            "password": secret_markers[1],
            "debug_blob": secret_markers[2],
        },
        "cbom_json": {"raw": secret_markers[3]},
        "internal_debug_dump": secret_markers[2],
        "results": [
            {
                "logical_component_title": "payments-api",
                "vulnerabilities": [
                    {
                        "title": "SQL injection",
                        "impact": "High",
                        "description": "Unparameterized query",
                        "location": "app.py:42",
                        "owasp_top_10": {"A03:2021": "Injection"},
                        "suggested_fix": "Use parameterized queries",
                    }
                ],
            }
        ],
    }
    out = tmp_path / "sast_no_secret_leak.pdf"
    generate_pdf_for_type("sast", payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    assert "SQL injection" in haystack
    assert "A03:2021" in haystack
    for marker in secret_markers:
        assert marker not in haystack, f"leaked {marker!r} into PDF"


def test_large_sast_payload_completes(tmp_path):
    """Regression guard: a dense findings list must still produce a valid PDF."""
    vulns = [
        {
            "title": f"Finding {i}",
            "impact": ("Critical", "High", "Medium", "Low")[i % 4],
            "description": f"Synthetic finding body {i}",
            "location": f"src/module_{i % 20}.py:{10 + i}",
            "owasp_top_10": {"A03:2021": "Injection"} if i % 3 == 0 else {},
            "suggested_fix": f"Remediate finding {i}",
        }
        for i in range(120)
    ]
    payload = {
        "duration_of_scan": 90,
        "results": [{"logical_component_title": "payments-api", "vulnerabilities": vulns}],
    }
    out = tmp_path / "sast_large.pdf"
    generate_pdf_for_type("sast", payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    assert "Finding 0" in haystack
    assert "Finding 119" in haystack
    assert "payments-api" in haystack


def test_missing_logo_still_builds_all_scan_types(tmp_path, monkeypatch):
    """Every generator must keep working when the Zero Shield logo file is missing."""
    from backend.utilities.pdf import report_branding as branding

    monkeypatch.setattr(branding, "logo_path", lambda: str(tmp_path / "missing-logo.png"))
    for scan_type in _SCAN_TYPES:
        out = tmp_path / f"{scan_type}_nologo.pdf"
        generate_pdf_for_type(scan_type, _typical_payload(scan_type), str(out))
        _assert_valid_pdf(str(out))


def test_prepare_export_payload_allowlists_dast_urls_not_secrets():
    raw = {
        "results": [{"title": "xss"}],
        "duration_of_scan": 12,
        "metadata": {
            "urls_included": ["https://example.test"],
            "urls_excluded": ["https://skip.test"],
            "aws_secret_access_key": "AKIA_SHOULD_NOT_APPEAR_IN_PDF",
        },
    }
    dast = prepare_pdf_export_payload("dast", raw)
    assert dast["results"] == [{"title": "xss"}]
    assert dast["duration_of_scan"] == 12
    assert dast["metadata"]["urls_included"] == ["https://example.test"]
    assert dast["metadata"]["urls_excluded"] == ["https://skip.test"]
    assert "aws_secret_access_key" not in dast["metadata"]

    sast = prepare_pdf_export_payload("sast", raw)
    assert "metadata" not in sast
    assert sast["duration_of_scan"] == 12


def test_sbom_legacy_list_cves_and_license_list(tmp_path):
    payload = {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2024-9999",
                    "description": "legacy match",
                    "severity": "HIGH",
                    "cves": [{"CVE-2024-9999": "nvd"}],
                    "owasp_top_10": [{"A06:2021": "Vulnerable Components"}],
                },
                "artifact": {
                    "name": "left-pad",
                    "version": "1.0.0",
                    "licenses": ["MIT", "Apache-2.0"],
                },
            }
        ]
    }
    out = tmp_path / "sbom_legacy_list.pdf"
    generate_pdf_for_type("sbom_sca", payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    assert "CVE-2024-9999" in haystack
    assert "A06:2021" in haystack
    assert "MIT" in haystack
    assert "Apache-2.0" in haystack
    assert "['MIT'" not in haystack


def test_llm_skips_non_dict_rows(tmp_path):
    payload = {
        "vulnerabilities": [
            None,
            "garbage",
            {
                "title": "Prompt injection",
                "impact": "High",
                "description": "Injected instructions",
                "suggested_fix": "Isolate untrusted input",
            },
        ]
    }
    out = tmp_path / "llm_mixed.pdf"
    generate_pdf_for_type("llm", payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    assert "Prompt injection" in haystack
    assert "Isolate untrusted input" in haystack
    assert "garbage" not in haystack


def test_unsupported_scan_types_raise():
    with pytest.raises(UnsupportedPdfExport, match="leakage"):
        generate_pdf_for_type("leakage", [], "/tmp/unused-leakage.pdf")
    with pytest.raises(UnsupportedPdfExport, match="agent_discovery"):
        generate_pdf_for_type("agent_discovery", [], "/tmp/unused-agent.pdf")


def test_write_scan_pdf_unlinks_output_on_failure(tmp_path, monkeypatch):
    out = tmp_path / "failed.pdf"
    out.write_bytes(b"%PDF-placeholder")

    def _boom(*_args, **_kwargs):
        raise RuntimeError("renderer exploded")

    monkeypatch.setattr(
        "backend.utilities.pdf.combined.generate_pdf_for_sast",
        _boom,
    )
    with pytest.raises(RuntimeError, match="renderer exploded"):
        write_scan_pdf("sast", [{"title": "x"}], str(out))
    assert not out.exists()


def test_typical_payloads_do_not_invent_unknown_severity(tmp_path):
    for scan_type in _SCAN_TYPES:
        out = tmp_path / f"{scan_type}_no_unknown.pdf"
        generate_pdf_for_type(scan_type, _typical_payload(scan_type), str(out))
        haystack = _pdf_haystack(str(out))
        assert not re.search(r"\d+ U\b", haystack), f"{scan_type} phantom Unknown KPI: {haystack[-500:]}"

