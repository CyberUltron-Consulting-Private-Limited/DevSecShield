"""Who produced a BOM, and when: the document identity every reporter stamps.

One place for the tool name, the product version, the supplier and the creation
time, so the CycloneDX, SPDX and SARIF outputs of one scan always agree.

* Tool name: ``DevSecShield AI BOM`` for an AI BOM, ``DevSecShield CBOM`` for a
  cryptographic BOM (``ScanResult.document_kind``).
* Version: the release the scanning image was built from. ``DSS_BUILD_VERSION``
  (scripts/deploy/build_images.sh bakes it into the images), else the 12-character
  ``DSS_BUILD_SHA``, else this package's own version (tests, local runs).
* Time: ``ScanResult.generated_at`` (the host stamps the real scan time), else a
  pinned timestamp so the committed golden BOMs stay byte-stable.
"""

from __future__ import annotations

import datetime as _dt
import os
import re
from dataclasses import dataclass
from typing import Any

PRODUCT = "DevSecShield"
SUPPLIER = "Zero Shield"
SUPPLIER_URL = "https://zeroshield.ai"
TOOL_NAMES = {"aibom": "DevSecShield AI BOM", "cbom": "DevSecShield CBOM"}
#: Namespace for SPDX element IRIs (a domain the supplier controls).
SPDX_NAMESPACE = "https://zeroshield.ai/spdx"
#: Pinned creation time when the host supplies none (golden-file stability only).
PINNED_TIMESTAMP = "2026-06-21T00:00:00Z"

_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z._+-]{0,63}")
_SHA = re.compile(r"[0-9a-f]{40}")


def product_version() -> str:
    """The product release this engine runs as (see the module docstring)."""
    value = (os.environ.get("DSS_BUILD_VERSION") or "").strip()
    if _VERSION.fullmatch(value) and value.lower() != "unknown":
        return value
    sha = (os.environ.get("DSS_BUILD_SHA") or "").strip().lower()
    if _SHA.fullmatch(sha):
        return sha[:12]
    from aibom import __version__

    return __version__


def utc_now() -> str:
    """The current time as an ISO 8601 UTC timestamp (seconds, ``Z``)."""
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


@dataclass(frozen=True)
class DocumentIdentity:
    tool_name: str
    tool_version: str
    timestamp: str
    kind: str

    def cyclonedx_tools(self) -> dict[str, Any]:
        """CycloneDX 1.6 ``metadata.tools`` (the non-deprecated components form)."""
        return {
            "components": [
                {
                    "type": "application",
                    "supplier": {"name": SUPPLIER, "url": [SUPPLIER_URL]},
                    "name": self.tool_name,
                    "version": self.tool_version,
                }
            ]
        }


def identity_for(result: Any) -> DocumentIdentity:
    kind = getattr(result, "document_kind", "aibom")
    return DocumentIdentity(
        tool_name=TOOL_NAMES.get(kind, TOOL_NAMES["aibom"]),
        tool_version=product_version(),
        timestamp=getattr(result, "generated_at", None) or PINNED_TIMESTAMP,
        kind=kind,
    )


__all__ = [
    "PINNED_TIMESTAMP",
    "PRODUCT",
    "SPDX_NAMESPACE",
    "SUPPLIER",
    "SUPPLIER_URL",
    "TOOL_NAMES",
    "DocumentIdentity",
    "identity_for",
    "product_version",
    "utc_now",
]
