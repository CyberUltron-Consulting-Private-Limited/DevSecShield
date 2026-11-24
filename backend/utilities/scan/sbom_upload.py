"""Shape check for an uploaded SBOM file (review 6032108510 m4).

The SBOM scan worker converts SPDX 2.x JSON and SPDX 3.0 JSON-LD to CycloneDX and reads
CycloneDX JSON as is (RabbitMQ/worker/helpers/tools/sca_sbom_agent/main.py, spdx_convert.py).
Anything else, or a document whose top-level collections have the wrong JSON type (e.g.
``"packages": 5``), used to be accepted here and fail later in the worker with raw text such
as "'int' object is not iterable". The upload API now refuses it with 422 and a plain reason.

Only the top-level shape is checked: the worker still tolerates wrong-typed fields inside a
package and counts the entries it could not read (``dss:spdx_invalid_entries``).
"""
from __future__ import annotations

from typing import Any

# top-level collections each format must give as a JSON array, or the worker cannot read them
_SPDX2_LISTS = ("packages", "relationships", "files", "snippets", "externalDocumentRefs",
                "hasExtractedLicensingInfos", "documentDescribes")
_SPDX3_LISTS = ("@graph",)
_CDX_LISTS = ("components", "dependencies", "vulnerabilities", "services", "compositions")
_CDX_OBJECTS = ("metadata",)


def is_spdx(doc: Any) -> bool:
    """Same test as the worker's ``spdx_convert.is_spdx``: SPDX 2.x by ``spdxVersion``, SPDX 3 by
    its JSON-LD context."""
    if not isinstance(doc, dict):
        return False
    if str(doc.get("spdxVersion") or "").startswith("SPDX-"):
        return True
    ctx = doc.get("@context")
    ctx_text = " ".join(str(c) for c in ctx) if isinstance(ctx, list) else str(ctx or "")
    return "spdx.org/rdf/3" in ctx_text


def _wrong_types(doc: dict[str, Any], lists: tuple[str, ...], objects: tuple[str, ...] = ()) -> list[str]:
    bad = [f"'{k}' must be an array" for k in lists if k in doc and not isinstance(doc[k], list)]
    bad += [f"'{k}' must be an object" for k in objects if k in doc and not isinstance(doc[k], dict)]
    return bad


def sbom_shape_error(doc: Any) -> str | None:
    """None when the worker can read ``doc`` as an SBOM, else the reason it cannot."""
    if not isinstance(doc, dict):
        return "The uploaded SBOM must be a JSON object"
    if is_spdx(doc):
        if str(doc.get("spdxVersion") or "").startswith("SPDX-"):
            bad = _wrong_types(doc, _SPDX2_LISTS)
            kind = "SPDX 2 document"
        else:
            bad = _wrong_types(doc, _SPDX3_LISTS)
            kind = "SPDX 3 document"
    elif doc.get("bomFormat") == "CycloneDX":
        bad = _wrong_types(doc, _CDX_LISTS, _CDX_OBJECTS)
        kind = "CycloneDX document"
    else:
        return ("The uploaded file is neither a CycloneDX JSON SBOM (bomFormat \"CycloneDX\") nor an "
                "SPDX JSON SBOM (spdxVersion \"SPDX-2.x\", or an SPDX 3.0 JSON-LD @context)")
    if bad:
        return f"The uploaded {kind} is malformed: " + "; ".join(bad)
    return None
