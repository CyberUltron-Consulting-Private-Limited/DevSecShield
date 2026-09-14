"""Production-path PDF export E2E.

Mirrors authenticated GET /{team}/{type}/scan/{id}/export:
  full Scan.scan_data dict → generate_pdf_for_type → FileResponse(application/pdf)

No DB/network. Writes sample reports under ~/Downloads/ZeroShield_PDF_E2E/.
"""
from __future__ import annotations

import base64
import json
import os
import re
import shutil
import sys
import zlib
from pathlib import Path

_REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_REPO))

from backend.utilities.pdf.combined import (  # noqa: E402
    generate_pdf_for_type,
    prepare_pdf_export_payload,
)

_FIXTURES = _REPO / "backend" / "tests" / "fixtures"
_OUT = Path(os.environ.get("PDF_E2E_OUT", str(Path.home() / "Downloads" / "ZeroShield_PDF_E2E")))
_SCAN_TYPES = ("sast", "sbom_sca", "dast", "iac", "mcp", "llm", "cbom", "ai_bom")


def _haystack(path: Path) -> str:
    raw = path.read_bytes()
    chunks = [raw]
    for match in re.finditer(rb"stream\r?\n(.*?)endstream", raw, re.S):
        data = match.group(1).strip()
        try:
            decoded = base64.a85decode(data, adobe=True)
            try:
                chunks.append(zlib.decompress(decoded))
            except zlib.error:
                chunks.append(decoded)
            continue
        except (ValueError, OverflowError):
            pass
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


def _assert_pdf(path: Path) -> None:
    head = path.read_bytes()[:5]
    size = path.stat().st_size
    assert head == b"%PDF-", f"{path.name}: bad magic {head!r}"
    assert size > 1000, f"{path.name}: too small ({size})"


def _load(name: str) -> dict:
    with open(_FIXTURES / name, encoding="utf-8") as fh:
        return json.load(fh)


def worker_payload(scan_type: str) -> dict:
    """Shape Celery persists on Scan.scan_data — same object export_scan now passes."""
    if scan_type == "sast":
        # Rich sample matching ZeroShield_SAST_Report_Sample.pdf project cue.
        return {
            "duration_of_scan": 134,
            "metadata": {"engine": "agent", "source": "production-export-e2e"},
            "results": [
                {
                    "logical_component_title": "payments-api",
                    "scan_duration": "2m 14s",
                    "vulnerabilities": [
                        {
                            "title": "SQL Injection in checkout handler",
                            "impact": "Critical",
                            "description": (
                                "User-controlled input is concatenated into a SQL query in the "
                                "checkout path, allowing data exfiltration from the payments DB."
                            ),
                            "location": "/tmp/repo_42_abc/src/checkout/handler.py:118",
                            "snippet": 'cursor.execute(f"SELECT * FROM orders WHERE id = {order_id}")',
                            "suggested_fix": "Use parameterized queries / ORM bind parameters.",
                            "owasp_top_10": {"A03:2021": "Injection"},
                            "compliance_controls": {"PCI-DSS": "6.5.1", "OWASP ASVS": "5.3.4"},
                            "cves": {"CWE-89": "SQL Injection"},
                        },
                        {
                            "title": "Hardcoded payment gateway API key",
                            "impact": "Critical",
                            "description": "A live gateway secret is committed in source.",
                            "location": "/tmp/repo_42_abc/src/config/secrets.py:22",
                            "snippet": 'GATEWAY_API_KEY = "sk_live_51Hz..."',
                            "suggested_fix": "Move secrets to a vault / env; rotate the exposed key.",
                            "owasp_top_10": {"A07:2021": "Identification and Authentication Failures"},
                            "compliance_controls": {"PCI-DSS": "3.5.1"},
                        },
                        {
                            "title": "Exposed DATABASE_URL in application logs",
                            "impact": "High",
                            "description": "Prints DATABASE_URL including credentials to stdout.",
                            "location": "/tmp/repo_42_abc/src/backup.py:12",
                            "snippet": "print(db_url)",
                            "suggested_fix": "Redact DATABASE_URL in logs.",
                            "owasp_top_10": {"A05:2021": "Security Misconfiguration"},
                        },
                        {
                            "title": "Insecure random used for session tokens",
                            "impact": "Medium",
                            "description": "random.random() is used to mint session identifiers.",
                            "location": "/tmp/repo_42_abc/src/auth/session.py:44",
                            "snippet": "token = str(random.random())",
                            "suggested_fix": "Use secrets.token_urlsafe() / os.urandom.",
                            "owasp_top_10": {"A02:2021": "Cryptographic Failures"},
                        },
                        {
                            "title": "Verbose stack traces returned to clients",
                            "impact": "Low",
                            "description": "Unhandled exceptions dump stack traces in API responses.",
                            "location": "/tmp/repo_42_abc/src/api/middleware.py:77",
                            "snippet": "return JSONResponse(traceback.format_exc())",
                            "suggested_fix": "Return generic errors; log details server-side.",
                            "owasp_top_10": {"A04:2021": "Insecure Design"},
                        },
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
                "urls_excluded": ["https://skip.test"],
                "aws_secret_access_key": "AKIA_SHOULD_NOT_APPEAR_IN_PDF",
            },
            "results": [
                {
                    "title": "Reflected XSS",
                    "impact": "High",
                    "confidence": "High",
                    "category": "xss",
                    "url": "https://example.test/search",
                    "description": "Unescaped query parameter reflected in HTML.",
                    "suggested_fix": "Encode output",
                    "owasp_top_10": {"A03:2021": "Injection"},
                    "compliance_controls": {"PCI-DSS": "6.5.7"},
                }
            ],
        }
    if scan_type == "iac":
        return {
            "duration_of_scan": 134,
            "results": [
                {
                    "title": "Public S3 bucket",
                    "impact": "Critical",
                    "description": "Bucket ACL allows public read.",
                    "location": "/tmp/repo_99_xyz/terraform/main.tf:40",
                    "owasp_top_10": {"A05:2021": "Security Misconfiguration"},
                    "compliance_controls": {"CIS": "2.1.5"},
                    "suggested_fix": "Set ACL to private",
                    "snippet": 'acl = "public-read"',
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
                ],
                "prompts": [],
                "resources": [],
                "error_messages": [],
            },
        }
    if scan_type == "llm":
        return {
            "duration_of_scan": 134,
            "results": {
                "vulnerabilities": [
                    {
                        "title": "Malware Evasion vulnerability",
                        "impact": "High",
                        "description": "Model followed injected jailbreak instructions.",
                        "owasp_top_10_llm": {"LLM01": "Prompt Injection"},
                        "suggested_fix": "Add jailbreak detection",
                    }
                ],
                "model_vulnerabilities": {},
            },
        }
    if scan_type == "cbom":
        payload = _load("cbom_export_scandata.json")
        payload["duration_of_scan"] = 134
        payload["metadata"] = {"source": "production-export-e2e"}
        return payload
    if scan_type == "ai_bom":
        payload = _load("ai_bom_export_scandata.json")
        payload["duration_of_scan"] = 134
        return payload
    raise AssertionError(scan_type)


_EXPECT = {
    "sast": ("2m 14s", "SQL Injection in checkout handler", "A03:2021", "payments-api", "ZERO SHIELD"),
    "sbom_sca": ("2m 14s", "lodash-es==4.17.15", "A03:2021", "ZERO SHIELD"),
    "dast": ("2m 14s", "Reflected XSS", "A03:2021", "URLs included", "ZERO SHIELD"),
    "iac": ("2m 14s", "Public S3 bucket", "A05:2021", "ZERO SHIELD"),
    "mcp": ("2m 14s", "Tool exposes secrets", "ZERO SHIELD"),
    "llm": ("2m 14s", "Malware Evasion vulnerability", "LLM01", "ZERO SHIELD"),
    "cbom": ("2m 14s", "ZERO SHIELD"),
    "ai_bom": ("2m 14s", "ZERO SHIELD"),
}


def main() -> int:
    if _OUT.exists():
        shutil.rmtree(_OUT)
    _OUT.mkdir(parents=True)

    print(f"OUT {_OUT}")
    print("Simulating production export_scan -> generate_pdf_for_type(full scan_data)\n")

    failures = 0
    for scan_type in _SCAN_TYPES:
        raw = worker_payload(scan_type)
        # Production contract: export_scan allowlists then generate_pdf_for_type.
        assert isinstance(raw, dict) and "results" in raw, scan_type
        payload = prepare_pdf_export_payload(scan_type, raw)
        out = _OUT / f"ZeroShield_{scan_type.upper()}_Report.pdf"
        generate_pdf_for_type(scan_type, payload, str(out))
        _assert_pdf(out)
        hay = _haystack(out)
        missing = [n for n in _EXPECT[scan_type] if n not in hay]
        invented_unknown = bool(re.search(r"\d+ U\b", hay))
        leaked_clone = "/tmp/repo_" in hay
        leaked_secret = "AKIA_SHOULD_NOT_APPEAR_IN_PDF" in hay
        status = "PASS"
        if missing or invented_unknown or leaked_clone or leaked_secret:
            status = "FAIL"
            failures += 1
        print(f"  [{status}] {scan_type:8}  {out.name}  ({out.stat().st_size:,} bytes)")
        if missing:
            print(f"         missing: {missing}")
        if invented_unknown:
            print("         invented Unknown KPI (N U)")
        if leaked_clone:
            print("         leaked /tmp/repo_ clone prefix")
        if leaked_secret:
            print("         leaked DAST metadata secret")

    # Primary sample copy for quick open (matches sample PDF naming).
    sast_src = _OUT / "ZeroShield_SAST_Report.pdf"
    downloads = Path.home() / "Downloads"
    if downloads.is_dir():
        sast_copy = downloads / "ZeroShield_SAST_Report_E2E.pdf"
        shutil.copy2(sast_src, sast_copy)
        print(f"\nPrimary sample -> {sast_copy}")
    print(f"All 8 reports -> {_OUT}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
