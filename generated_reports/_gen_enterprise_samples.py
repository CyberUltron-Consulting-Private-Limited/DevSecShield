"""Generate shareable enterprise PDF samples for feedback."""
from __future__ import annotations

import os
import sys
import types
import importlib.util

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)


def _stub_pkg(name: str) -> None:
    if name not in sys.modules:
        m = types.ModuleType(name)
        m.__path__ = [os.path.join(ROOT, *name.split("."))]
        sys.modules[name] = m


def _load(name: str, rel: str):
    path = os.path.join(ROOT, rel)
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


for pkg in ("backend", "backend.utilities", "backend.utilities.pdf"):
    _stub_pkg(pkg)

_load("backend.utilities.pdf.report_branding", "backend/utilities/pdf/report_branding.py")
sast = _load("backend.utilities.pdf.sast_pdf", "backend/utilities/pdf/sast_pdf.py")
sbom = _load("backend.utilities.pdf.sbom_sca_pdf", "backend/utilities/pdf/sbom_sca_pdf.py")

out_dir = os.path.join(ROOT, "generated_reports")
os.makedirs(out_dir, exist_ok=True)

sast_mock = [
    {
        "logical_component_title": "payments-api",
        "scan_duration": "2m 14s",
        "vulnerabilities": [
            {
                "title": "SQL injection via string-concatenated query",
                "impact": "Critical",
                "location": "services/query_builder.py:87",
                "description": (
                    "User-controlled input is concatenated into a SQL statement, "
                    "allowing an attacker to alter the query logic and exfiltrate or modify data."
                ),
                "snippet": 'cursor.execute("SELECT * FROM users WHERE id=" + user_id)',
                "suggested_fix": (
                    "Use parameterized queries / bound parameters. "
                    "Never concatenate user input into SQL."
                ),
                "owasp_top_10": {"A03:2021": "Injection"},
                "cves": {},
            },
            {
                "title": "Exposed database URL written to stdout",
                "impact": "High",
                "location": "backup.py:42",
                "description": (
                    "Database connection details are printed to standard output "
                    "and may land in logs accessible to unintended parties."
                ),
                "snippet": "print(db_url)",
                "suggested_fix": "Remove debug logging of secrets. Use structured logging with redaction.",
                "owasp_top_10": {"A09:2021": "Security Logging and Monitoring Failures"},
            },
            {
                "title": "Plaintext passwords copied into backup artifacts",
                "impact": "High",
                "location": "backup.py:118",
                "description": "User password fields are persisted into backup payloads in cleartext.",
                "snippet": "password=user.password,",
                "suggested_fix": "Exclude credential fields from backups. Store only hashed secrets.",
            },
            {
                "title": "Hard-coded restore path reduces environment isolation",
                "impact": "Medium",
                "location": "restore.py:23",
                "description": (
                    "A fixed backup path is embedded in source, which can cause "
                    "incorrect restores across environments."
                ),
                "snippet": 'sqlite_file_name = "backups/26-11-2025-Backup.db"',
                "suggested_fix": "Load restore paths from configuration or environment variables.",
            },
            {
                "title": "Verbose exception details returned to clients",
                "impact": "Low",
                "location": "api/errors.py:55",
                "description": "Raw exception strings are returned in API responses and may leak internals.",
                "snippet": 'return JSONResponse({"detail": str(exc)}, status_code=500)',
                "suggested_fix": "Return generic client errors; log full details server-side only.",
            },
        ],
    }
]

sbom_mock = [
    {
        "title": "Vulnerable dependency: pillow@10.2.0",
        "impact": "Critical",
        "description": "pillow 10.2.0 is affected by a known vulnerability. Upgrade to a fixed release.",
        "suggested_fix": "Upgrade pillow to a patched version (>=10.3.0 recommended).",
        "dependencies": ["pillow@10.2.0"],
        "cves": {"CVE-2024-28219": "Buffer overflow in pillow image processing"},
        "owasp_top_10": {"A06:2021": "Vulnerable and Outdated Components"},
    },
    {
        "title": "Vulnerable dependency: cryptography@41.0.7",
        "impact": "High",
        "description": "cryptography 41.0.7 has a known high-severity advisory.",
        "suggested_fix": "Upgrade cryptography to the latest patched release.",
        "dependencies": ["cryptography@41.0.7"],
        "cves": {"CVE-2023-50782": "PKCS#12 timing side-channel"},
    },
    {
        "title": "Vulnerable dependency: urllib3@1.26.18",
        "impact": "Medium",
        "description": "urllib3 1.26.18 is affected by a medium-severity issue.",
        "suggested_fix": "Upgrade urllib3 to a fixed 1.26.x or 2.x release.",
        "dependencies": ["urllib3@1.26.18"],
        "cves": {"CVE-2024-37891": "Proxy-authorization header leakage"},
    },
]

sast_path = os.path.join(out_dir, "ZeroShield_SAST_Report_Sample.pdf")
sbom_path = os.path.join(out_dir, "ZeroShield_SBOM_Report_Sample.pdf")
print(sast.generate_pdf(sast_mock, sast_path))
print(sbom.generate_pdf(sbom_mock, sbom_path))
print("OK")
