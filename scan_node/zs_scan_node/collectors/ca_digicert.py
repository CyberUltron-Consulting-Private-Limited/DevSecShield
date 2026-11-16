"""DigiCert CertCentral, read only.

List issued orders: GET ``{services/v2}/order/certificate`` with ``filters[status]=issued``.
Docs: List orders. The API key is sent as the ``X-DC-DEVKEY`` header (Authentication).
Then the end-entity certificate: GET ``{services/v2}/certificate/{id}/download/format/pem_nointermediate``.
Docs: Download certificate by format; glossary format ``pem_nointermediate`` is the end-entity PEM only.

The saved API address is the Services API base (``https://www.digicert.com/services/v2``).
"""
from __future__ import annotations

from typing import Any

from zs_scan_node.collectors.ca_http import (
    Api,
    api_base,
    emit_certificate,
    holds_private_key,
)

PAGE = 100


def collect_digicert(ctx: Any, config: dict, api_key: str) -> tuple[Any, int]:
    from zs_scan_node.collectors.ca import MAX_ITEMS, CaFail

    base = api_base(str(config["api_url"]), "/services/v2")
    api = Api(ctx, base, "DigiCert", {"X-DC-DEVKEY": api_key}, config.get("ca_pem"))
    n = 0
    skipped = False
    seen: set[int] = set()
    try:
        offset = 0
        while n < MAX_ITEMS:
            status, parsed, _body = api.request("GET", "order/certificate", params={
                "filters[status]": "issued", "limit": PAGE, "offset": offset})
            if status in (401, 403):
                raise CaFail("auth_failed", f"DigiCert refused the API key ({status})")
            if status != 200:
                raise CaFail("error", f"DigiCert answered {status} to order/certificate")
            orders = parsed.get("orders") if isinstance(parsed, dict) else None
            page = parsed.get("page") if isinstance(parsed, dict) else None
            if orders is None and isinstance(page, dict) and page.get("total") == 0:
                # An account with no matching orders: CertCentral leaves "orders" out and sends only
                # {"page": {"total": 0, ...}} (recorded live). That is an empty estate, not an error.
                break
            if not isinstance(orders, list):
                raise CaFail("error", "DigiCert answered with something that is not a certificate list")
            if not orders:
                break
            fresh = 0
            for order in orders:
                if n >= MAX_ITEMS or not isinstance(order, dict):
                    continue
                cert = order.get("certificate") if isinstance(order.get("certificate"), dict) else {}
                cert_id = cert.get("id")
                if not isinstance(cert_id, int) or cert_id in seen:
                    continue
                seen.add(cert_id)
                fresh += 1
                status, _parsed, body = api.request(
                    "GET", f"certificate/{cert_id}/download/format/pem_nointermediate", json_body=False,
                    headers={"Accept": "application/x-pem-file"})
                if status in (401, 403):
                    raise CaFail("auth_failed", f"DigiCert refused the API key ({status})")
                if status != 200 or holds_private_key(body) or not emit_certificate(
                        ctx, api.target, f"{base}/certificate/{cert_id}", body, "digicert"):
                    skipped = True
                    continue
                n += 1
            offset += len(orders)
            total = (parsed.get("page") or {}).get("total") if isinstance(parsed.get("page"), dict) else None
            if fresh == 0 or len(orders) < PAGE or (isinstance(total, int) and offset >= total):
                break
        if skipped:
            ctx.coverage(api.target.label, "DigiCert certificate download", "not_supported",
                         "an issued order did not download as a certificate", once=True)
        return api.target, n
    finally:
        api.close()
