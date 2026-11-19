"""Record the text of every code-lane PDF built with default report options.

The PDF export dialog (report options + team logo) must leave a default export
unchanged. This script captured the extracted text of each scan type's PDF on
dev 57459dcc, before the change, for the typical and worker-shaped payloads the
smoke tests use. ``test_pdf_report_options.py`` compares today's default output
with it. Clock-dependent text (dates, times, durations) is masked.

Run from the repository root with the backend environment::

    PYTHONPATH=. backend/.venv/bin/python backend/tests/fixtures/make_pdf_default_text.py
"""

from __future__ import annotations

import json
import re
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))
sys.path.insert(0, str(REPO / "backend" / "tests"))

from support.pdf_text import pdf_pages_text  # noqa: E402

FIXTURES = Path(__file__).resolve().parent
OUT = FIXTURES / "pdf_default_text.json"
SCAN_TYPES = ("sast", "sbom_sca", "dast", "iac", "mcp", "llm", "cbom", "ai_bom")

_CLOCK = [
    (re.compile(r"\b\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?( ?UTC)?\b"), "<DATE>"),
    (re.compile(r"\b(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{1,2},? \d{4}( \d{1,2}:\d{2}( ?[AP]M)?)?( UTC)?"), "<DATE>"),
    (re.compile(r"\b\d{1,2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]* \d{4}( \d{1,2}:\d{2})?( UTC)?"), "<DATE>"),
    (re.compile(r"\b\d{1,2}:\d{2}(:\d{2})?( ?[AP]M)?( UTC)?\b"), "<TIME>"),
]


def mask(text: str) -> str:
    for pattern, repl in _CLOCK:
        text = pattern.sub(repl, text)
    return text


def page_texts(path: str) -> list[str]:
    raw = Path(path).read_bytes()
    return [mask(page) for page in pdf_pages_text(raw)]


def build_all(generate) -> dict:
    """``generate(scan_type, payload, out_path)`` builds one PDF; returns {key: [page text]}."""
    import test_pdf_export_smoke as smoke  # noqa: PLC0415  (tests dir is on sys.path)

    result: dict = {}
    with tempfile.TemporaryDirectory() as tmp:
        for scan_type in SCAN_TYPES:
            for shape, payload in (("typical", smoke._typical_payload(scan_type)),
                                   ("worker", smoke._worker_persist_payload(scan_type))):
                out = str(Path(tmp) / f"{scan_type}-{shape}.pdf")
                generate(scan_type, payload, out)
                result[f"{scan_type}:{shape}"] = page_texts(out)
    return result


def _generate_base(scan_type: str, payload, out: str) -> None:
    from backend.utilities.pdf.combined import generate_pdf_for_type, prepare_pdf_export_payload  # noqa: PLC0415

    generate_pdf_for_type(scan_type, prepare_pdf_export_payload(scan_type, payload), out)


if __name__ == "__main__":
    data = build_all(_generate_base)
    OUT.write_text(json.dumps(data, indent=1, ensure_ascii=False, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {OUT} ({len(data)} documents)")
