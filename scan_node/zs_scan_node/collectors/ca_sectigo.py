"""Sectigo Certificate Manager, read only.

List (the certificate search): GET ``{api}/ssl/v1`` with ``size``, ``position`` and ``status``.
Docs: Sectigo Certificate Manager REST API 25.8, "List SSL certificates" ("match the requested filter").
Download: GET ``{api}/ssl/v1/collect/{sslId}?format=pemco`` (certificate only, PEM). The keystore download is not called.

Authentication is the password style on every request: headers ``login``, ``password`` and ``customerUri``.
The saved API address is the API base (``https://cert-manager.com/api``).
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

PAGE = 200
# Issued and expired are the certificates. Revoked ones are still certificates. Requests that were never issued are not.
STATUSES = ("Issued", "Expired", "Revoked")


def collect_sectigo(ctx: Any, config: dict, password: str) -> tuple[Any, int]:
    from zs_scan_node.collectors.ca import MAX_ITEMS, CaFail

    base = api_base(str(config["api_url"]), "/api")
    login = str(config.get("login") or "")
    customer = str(config.get("customer_uri") or "")
    api = Api(ctx, base, "Sectigo", {"login": login, "password": password, "customerUri": customer}, config.get("ca_pem"))
    n = 0
    seen: set[int] = set()
    skipped = False
    try:
        for status_name in STATUSES:
            position = 0
            while n < MAX_ITEMS:
                status, parsed, _body = api.request("GET", "ssl/v1", params={
                    "size": PAGE, "position": position, "status": status_name})
                if status in (401, 403):
                    raise CaFail("auth_failed", f"Sectigo refused the login ({status})")
                if status != 200:
                    raise CaFail("error", f"Sectigo answered {status} to ssl/v1")
                rows = rows_of(parsed, "Sectigo")
                if not rows:
                    break
                fresh = 0
                for row in rows:
                    ssl_id = row.get("sslId")
                    if not isinstance(ssl_id, int) or ssl_id in seen:
                        continue
                    seen.add(ssl_id)
                    fresh += 1
                    got, _parsed, body = api.request(
                        "GET", f"ssl/v1/collect/{ssl_id}", params={"format": "pemco"}, json_body=False,
                        headers={"Accept": "application/x-pem-file"})
                    if got in (401, 403):
                        raise CaFail("auth_failed", f"Sectigo refused the login ({got})")
                    if got != 200 or holds_private_key(body) or not emit_certificate(
                            ctx, api.target, f"{base}/ssl/v1/{ssl_id}", body, "sectigo"):
                        skipped = True
                        continue
                    n += 1
                    if n >= MAX_ITEMS:
                        break
                if fresh == 0 or len(rows) < PAGE:
                    break
                position += len(rows)
        if skipped:
            ctx.coverage(api.target.label, "Sectigo certificate download", "not_supported",
                         "a listed certificate did not download as a certificate", once=True)
        return api.target, n
    finally:
        api.close()
