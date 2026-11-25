"""The AI BOM's SPDX 3.0 and SARIF 2.1.0 files as the API serves them (SOW D5, review 6036875286).

The AI BOM scan stores both documents as the aibom reporters render them (``ai_bom_spdx``, ``ai_bom_sarif`` in
``scan_data``; ``aibom/integrations/devsecshield.py``). ``GET /{team}/ai_bom/scan/{id}/spdx`` and ``.../sarif`` and
the evidence pack serve these bytes: the stored document written as UTF-8 JSON with a two-space indent and a final
newline, the same bytes on every request, so the detached ES256 signature (``X-ZS-Signature``, the pack's ``.sig``)
covers exactly what is saved. Nothing is added to the documents: the SPDX file still conforms to the SPDX 3.0.1
SHACL model and the SARIF file to the SARIF 2.1.0 schema (``aibom/tests/test_aibom_served_artifacts.py``).

Standard library only, so the aibom test suite loads this file by path.
"""
from __future__ import annotations

import json
from typing import Any

# artifact -> (scan_data key, media type, file suffix, what the file is called in messages)
ARTIFACTS: dict[str, tuple[str, str, str, str]] = {
    "spdx": ("ai_bom_spdx", "application/ld+json", "spdx.json", "SPDX 3.0 document"),
    "sarif": ("ai_bom_sarif", "application/sarif+json", "sarif", "SARIF 2.1.0 log"),
}


def artifact_bytes(doc: Any) -> bytes:
    """The served bytes of a stored document."""
    return (json.dumps(doc, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def stored_artifact(scan_data: Any, artifact: str) -> bytes | None:
    """The served bytes of the scan's ``artifact`` (``spdx`` / ``sarif``), None when the scan stores none."""
    key = ARTIFACTS[artifact][0]
    doc = scan_data.get(key) if isinstance(scan_data, dict) else None
    return artifact_bytes(doc) if isinstance(doc, dict) and doc else None


def file_name(scan_id: int, artifact: str) -> str:
    """``ai_bom-{id}.spdx.json`` / ``ai_bom-{id}.sarif`` (the download's and the pack's name)."""
    return f"ai_bom-{int(scan_id)}.{ARTIFACTS[artifact][2]}"


__all__ = ["ARTIFACTS", "artifact_bytes", "file_name", "stored_artifact"]
