"""Keyfactor Command, read only.

GET ``{KeyfactorAPI}/Certificates`` with the certificate query parameters (QueryString, PageReturned, ReturnLimit).
Docs: GET Certificates (Keyfactor Command, current). Each row's ``ContentBytes`` is the certificate. The bearer token
is sent as ``Authorization: Bearer``, and every call sends ``x-keyfactor-requested-with: APIClient`` (required by
Authenticating to the Keyfactor API). ``includeHasPrivateKey`` stays false, so a stored private key is not requested.

The saved API address is the Keyfactor API base (``https://keyfactor.example.com/KeyfactorAPI``).
"""
from __future__ import annotations

from typing import Any

from zs_scan_node.collectors.ca_http import (
    Api,
    api_base,
    emit_certificate,
    holds_private_key,
    rows_of,
)

PAGE = 100


def _bytes(value: Any) -> bytes:
    if isinstance(value, str):
        return value.encode()
    return b""


def collect_keyfactor(ctx: Any, config: dict, token: str) -> tuple[Any, int]:
    from zs_scan_node.collectors.ca import MAX_ITEMS, CaFail

    base = api_base(str(config["api_url"]), "/KeyfactorAPI")
    api = Api(ctx, base, "Keyfactor", {
        "Authorization": f"Bearer {token}",
        "x-keyfactor-requested-with": "APIClient",
    }, config.get("ca_pem"))
    n = 0
    seen: set[Any] = set()
    skipped_key = False
    skipped_body = False
    try:
        page = 1
        while n < MAX_ITEMS:
            status, parsed, _body = api.request("GET", "Certificates", params={
                "QueryString": "", "PageReturned": page, "ReturnLimit": PAGE,
                "includeExpired": "true", "includeRevoked": "true", "includeMetadata": "false",
                "includeLocations": "false", "includeHasPrivateKey": "false",
            })
            if status in (401, 403):
                raise CaFail("auth_failed", f"Keyfactor refused the API token ({status})")
            if status != 200:
                raise CaFail("error", f"Keyfactor answered {status} to Certificates")
            rows = rows_of(parsed, "Keyfactor")
            if not rows:
                break
            fresh = 0
            for row in rows:
                ident = row.get("Id")
                if ident is not None:
                    if ident in seen:
                        continue
                    seen.add(ident)
                fresh += 1
                raw = _bytes(row.get("ContentBytes"))
                if holds_private_key(raw):
                    skipped_key = True
                    continue
                if not raw:
                    skipped_body = True
                    continue
                loc = f"{base}/Certificates/{ident}"
                if emit_certificate(ctx, api.target, loc, raw, "keyfactor"):
                    n += 1
                else:
                    skipped_body = True
                if n >= MAX_ITEMS:
                    break
            if fresh == 0 or len(rows) < PAGE:
                break
            page += 1
        if skipped_key:
            ctx.coverage(api.target.label, "Keyfactor private key", "denied",
                         "a response included a private key; it was not stored", once=True)
        if skipped_body:
            ctx.coverage(api.target.label, "Keyfactor certificate bytes", "not_supported",
                         "a certificate row did not include certificate bytes", once=True)
        return api.target, n
    finally:
        api.close()
