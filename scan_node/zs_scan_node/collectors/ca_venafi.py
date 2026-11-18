"""Venafi Trust Protection Platform, read only.

Authorize: POST ``{origin}/vedauth/authorize/oauth`` with the API integration ``client_id``, the user name and the
password, scope ``certificate`` (read). Docs: POST Authorize/OAuth (Trust Protection Platform 25.3 Web SDK).
Then list: GET ``{vedsdk}/certificates/`` with ``OptionalFields=KeyAlgorithm,KeySize,Subject,Issuer``.
Docs: GET Certificates. The list returns X.509 fields when the caller has Read permission. POST Certificates/Retrieve
is not called: that method requires Private Key Read and the Certificate:Manage scope, and it can return a private key.

The saved API address is the Web SDK base (``https://tpp.example.com/vedsdk``). The password is sent only to authorize.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import quote

from zs_scan_node.collectors.ca_http import Api, _stamp, api_base, origin_of
from zs_scan_node.scrub import printable

PAGE = 100


def _facts(item: dict) -> dict[str, Any] | None:
    x509 = item.get("X509")
    if not isinstance(x509, dict):
        return None
    subject = str(x509.get("Subject") or x509.get("CN") or "").strip()
    issuer = str(x509.get("Issuer") or "").strip()
    serial = str(x509.get("Serial") or "").strip()
    if not subject and not serial:
        return None
    key_size = x509.get("KeySize")
    if isinstance(key_size, str) and key_size.isdigit():
        key_size = int(key_size)
    if not isinstance(key_size, int) or isinstance(key_size, bool):
        key_size = None
    # The published example returns KeySize 2048 (the bit length). The prose on the same page says "bytes"; the example wins.
    facts: dict[str, Any] = {
        "source": "venafi", "provider": "venafi", "subject": subject, "serial": serial or None,
        "not_before": _stamp(x509.get("ValidFrom")), "not_after": _stamp(x509.get("ValidTo")),
        "key_alg": str(x509.get("KeyAlgorithm") or "").strip() or None, "key_size": key_size,
        "name": printable(str(item.get("Name") or subject), 128),
        "guid": str(item.get("Guid") or ""), "dn": str(item.get("DN") or ""),
    }
    if issuer:
        facts["issuer"] = issuer
    if subject and issuer:
        facts["self_signed"] = subject == issuer
    return facts


def collect_venafi(ctx: Any, config: dict, password: str) -> tuple[Any, int]:
    from zs_scan_node.collectors.ca import MAX_ITEMS, CaFail

    sdk = api_base(str(config["api_url"]), "/vedsdk")
    origin = origin_of(sdk)
    username = str(config.get("login") or "")
    client_id = str(config.get("client_id") or "")
    api = Api(ctx, origin, "Venafi", {}, config.get("ca_pem"))
    n = 0
    try:
        status, parsed, _body = api.request(
            "POST", "vedauth/authorize/oauth",
            body={"client_id": client_id, "username": username, "password": password, "scope": "certificate"})
        if status in (401, 403):
            raise CaFail("auth_failed", f"Venafi refused the user name or password ({status})")
        token = parsed.get("access_token") if isinstance(parsed, dict) else None
        if status != 200 or not isinstance(token, str) or not token:
            detail = ""
            if isinstance(parsed, dict) and isinstance(parsed.get("error"), str):
                detail = f": {parsed['error']}"
            kind = "auth_failed" if status in (400, 401, 403) else "error"
            raise CaFail(kind, f"Venafi authorize answered {status}{detail}")
        api.close()
        api = Api(ctx, origin, "Venafi", {"Authorization": f"Bearer {token}"}, config.get("ca_pem"))
        path = sdk.split("://", 1)[-1].split("/", 1)[-1].strip("/") + "/certificates/"
        offset = 0
        missing = False
        seen: set[str] = set()
        while n < MAX_ITEMS:
            status, parsed, _body = api.request(
                "GET", path, params={"Limit": PAGE, "Offset": offset,
                                     "OptionalFields": "KeyAlgorithm,KeySize,Subject,Issuer"})
            if status in (401, 403):
                raise CaFail("auth_failed", f"Venafi refused the token ({status})")
            if status != 200:
                raise CaFail("error", f"Venafi answered {status} to certificates")
            rows = parsed.get("Certificates") if isinstance(parsed, dict) else None
            if not isinstance(rows, list):
                raise CaFail("error", "Venafi answered with something that is not a certificate list")
            if not rows:
                break
            fresh = 0
            for item in rows:
                if n >= MAX_ITEMS or not isinstance(item, dict):
                    continue
                ident = str(item.get("Guid") or item.get("DN") or "")
                if ident and ident in seen:
                    continue
                if ident:
                    seen.add(ident)
                fresh += 1
                facts = _facts(item)
                if facts is None:
                    missing = True
                    continue
                guid = quote(str(item.get("Guid") or item.get("DN") or facts.get("name") or n), safe="")
                ctx.emit("certificate", api.target.label, f"{sdk}/certificates/{guid}",
                         name=str(facts.get("subject") or facts.get("name") or ""),
                         algorithm=facts.get("key_alg"), key_size=facts.get("key_size"), facts=facts)
                n += 1
            offset += len(rows)
            total = parsed.get("TotalCount") if isinstance(parsed, dict) else None
            if fresh == 0 or len(rows) < PAGE or (isinstance(total, int) and offset >= total):
                break
        if missing:
            ctx.coverage(api.target.label, "Venafi certificate values", "denied",
                         "a certificate object had no X.509 values; Read permission on the certificate is required "
                         "for those fields", once=True)
        return api.target, n
    finally:
        api.close()
