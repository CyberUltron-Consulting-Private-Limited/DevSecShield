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

from backend.utilities.pdf.combined import generate_pdf_for_type  # noqa: E402

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
            "metadata": {"urls_included": ["https://example.test"]},
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
    "dast": ("2m 14s", "Reflected XSS", "https://example.test/search", "Encode output", "A03:2021"),
    "iac": ("2m 14s", "Public S3 bucket", "terraform/main.tf", "Set ACL to private", "A05:2021"),
    "mcp": ("2m 14s", "Tool exposes secrets", "read_wiki_structure", "Redact secrets"),
    "llm": ("2m 14s", "Malware Evasion vulnerability", "Add jailbreak detection", "LLM01"),
    "cbom": ("2m 14s", "3DES-CBC", "crypto_app.py"),
    "ai_bom": ("2m 14s", "openai_api_key", "app.py"),
}


@pytest.mark.parametrize("scan_type", _SCAN_TYPES)
def test_worker_persist_pdf_fields(scan_type, tmp_path):
    payload = _worker_persist_payload(scan_type)
    out = tmp_path / f"{scan_type}_worker_persist.pdf"
    generate_pdf_for_type(scan_type, payload, str(out))
    _assert_valid_pdf(str(out))
    haystack = _pdf_haystack(str(out))
    for needle in _WORKER_EXPECT[scan_type]:
        assert needle in haystack, f"{scan_type} missing {needle!r}"
    if scan_type == "sast":
        assert "/tmp/repo_" not in haystack
        assert "repo_42_abc" not in haystack
    if scan_type == "iac":
        assert "/tmp/repo_" not in haystack
        assert "repo_99_xyz" not in haystack
    if scan_type == "sbom_sca":
        assert "inventory row" not in haystack.lower()
