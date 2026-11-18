"""MCP scan request headers at rest (issue #44).

An MCP scan's headers usually carry the MCP server's credential (``Authorization: Bearer ...``). ``scan_metadata`` kept
them as given, so a database dump or backup exposed it. The row now keeps:

* ``headers``: the header names, each value replaced by ``SECRET_PLACEHOLDER`` (whoever reads the row sees which
  headers the scan sent, never a value);
* ``headers_encrypted``: the values, as one Fernet token over a JSON object, made by ``encrypt_secrets``: the helper
  CBOM sources store their credentials with (``backend/utilities/db/encryption.py``, key ``ENCRYPTION_KEY``).

Nothing decrypts the token on a request path: the worker gets the headers in the task it is sent (the payload of that
start or reinitialize), and no API returns ``headers`` or ``headers_encrypted`` (``dashboard/scan_metadata.py`` returns
an allow-list of MCP fields). Rows stored before are rewritten by migration d44mcphdr001 (``seal_stored_metadata``).
"""
from __future__ import annotations

import json
from typing import Any

from backend.utilities.cbom_sources.crypto import encrypt_secrets
from backend.utilities.db.encryption import SECRET_PLACEHOLDER

ENCRYPTED = "headers_encrypted"


def seal_headers(headers: Any) -> dict[str, Any]:
    """``{"headers": {name: SECRET_PLACEHOLDER, ...}, "headers_encrypted": <token>}``; both None without headers."""
    if not headers:
        return {"headers": None, ENCRYPTED: None}
    if isinstance(headers, dict):
        names: dict[str, str] | None = {str(name): SECRET_PLACEHOLDER for name in headers}
        items = list(headers.items())
    else:  # the API takes a JSON object, so this is never stored; whatever it is, it is kept only encrypted
        names, items = None, [("value", headers)]
    values = {str(name): value if isinstance(value, str) else json.dumps(value, default=str)
              for name, value in items if value is not None}
    return {"headers": names, ENCRYPTED: encrypt_secrets(values)}


def seal_stored_metadata(meta: Any) -> dict[str, Any] | None:
    """The MCP ``scan_metadata`` to store instead of ``meta``, its headers sealed and every other key kept; None when
    there is nothing to seal (no headers, or already sealed: ``headers_encrypted`` is present)."""
    if not isinstance(meta, dict) or ENCRYPTED in meta or not meta.get("headers"):
        return None
    return {**meta, **seal_headers(meta["headers"])}
