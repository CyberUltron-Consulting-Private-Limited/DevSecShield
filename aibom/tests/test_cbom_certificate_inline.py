"""C2 detection gaps: inline BEGIN CERTIFICATE in source + non-PEM DER .crt.

The certificate scanner docstring claims both are inventoried; these tests lock
that contract so an empty Certificate-expiry chart cannot hide a miss on a repo
that only embeds certs in code or ships DER-as-.crt without PEM armor.
"""

from __future__ import annotations

import os

from aibom.cbom.pipeline import scan_crypto
from aibom.model.result import ScanResult

_HERE = os.path.dirname(os.path.abspath(__file__))
_FX = os.path.join(_HERE, "fixtures", "synthetic-crypto-inline-cert")


def _scan() -> ScanResult:
    return scan_crypto(_FX)


def _certs(result: ScanResult) -> list:
    return [
        c
        for c in result.components
        if c.kind == "crypto_asset"
        and (c.properties or {}).get("crypto:assetType") == "certificate"
    ]


def test_inline_begin_certificate_in_source_is_inventoried() -> None:
    certs = _certs(_scan())
    sources = {(c.properties or {}).get("discovery:source") for c in certs}
    assert "app.py" in sources, f"inline cert in app.py not inventoried (got {sources})"
    inline = next(
        c for c in certs if (c.properties or {}).get("discovery:source") == "app.py"
    )
    props = inline.properties or {}
    assert props.get("crypto:notValidAfter", "").startswith("2027-06-29")
    assert props.get("crypto:subjectName") == "synthetic-crypto-app.test"


def test_der_crt_without_pem_armor_is_inventoried() -> None:
    certs = _certs(_scan())
    sources = {(c.properties or {}).get("discovery:source") for c in certs}
    assert "binary.crt" in sources, f"DER .crt not inventoried (got {sources})"
    der = next(
        c
        for c in certs
        if (c.properties or {}).get("discovery:source") == "binary.crt"
    )
    assert (der.properties or {}).get("crypto:notValidAfter", "").startswith(
        "2027-06-29"
    )


def test_cert_extension_alias_is_inventoried() -> None:
    certs = _certs(_scan())
    sources = {(c.properties or {}).get("discovery:source") for c in certs}
    assert "alias.cert" in sources, f".cert alias not inventoried (got {sources})"
