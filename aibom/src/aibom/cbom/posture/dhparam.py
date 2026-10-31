"""PKCS#3 Diffie-Hellman prime size. Malformed DER returns None."""

from __future__ import annotations

import binascii
from collections.abc import Iterable
from pathlib import PurePosixPath

from aibom.cbom.posture.context import PostureSink
from aibom.cbom.posture.model import BasisEntry, EncryptionFact
from aibom.cbom.rules import ALGORITHM_NORMALIZE, algo_info
from aibom.cbom.x509 import _read_len, _read_tlv
from aibom.model.component import CryptoAssetComponent
from aibom.scan.registry import ScanContext

_SEQUENCE = 0x30
_INTEGER = 0x02
_MIN_BITS = 64
_MAX_PEM = 65_536
_BEGIN = {
    "-----BEGIN DH PARAMETERS-----",
    "-----BEGIN X9.42 DH PARAMETERS-----",
}
_END = {
    "-----END DH PARAMETERS-----",
    "-----END X9.42 DH PARAMETERS-----",
}


def prime_bits(der: bytes) -> int | None:
    """Bit length of the PKCS#3 prime, or None when ``der`` is not one."""
    return _prime_bits(der)


def _prime_bits(der: bytes) -> int | None:
    """Total reader. The prime is the first INTEGER of the outer SEQUENCE."""
    try:
        tag, value, raw, _end = _read_tlv(der, 0)
        if tag != _SEQUENCE:
            return None
        length, after = _read_len(raw, 1)
        if after + length != len(raw):
            return None
        prime_tag, prime, _prime_raw, _next = _read_tlv(value, 0)
        if prime_tag != _INTEGER or not prime:
            return None
        bits = int.from_bytes(prime, "big").bit_length()
    except Exception:
        return None
    if bits < _MIN_BITS:
        return None
    return bits


def pem_prime_bits(text: str) -> int | None:
    """Prime size of the first DH PARAMETERS block, or None."""
    if len(text.encode("utf-8")) > _MAX_PEM:
        return None
    body: list[str] = []
    inside = False
    for line in text.splitlines():
        token = line.strip()
        if token in _BEGIN:
            inside = True
            body = []
            continue
        if inside and token in _END:
            try:
                der = binascii.a2b_base64("".join(body))
            except binascii.Error:
                return None
            return _prime_bits(der)
        if inside:
            body.append(token)
    return None


def relative_dh(config: str, declared: str) -> str | None:
    """Repository-relative DH path. Absolute paths and ``..`` are refused."""
    raw = declared.replace("\\", "/").strip()
    if not raw or raw.startswith("/") or any(part == ".." for part in raw.split("/")):
        return None
    parent = PurePosixPath(config).parent
    rel = PurePosixPath(raw) if str(parent) == "." else parent / raw
    text = rel.as_posix()
    if text.startswith("../") or text == ".." or text.startswith("/"):
        return None
    return text


def with_dh_file(
    fact: EncryptionFact, text: str | None
) -> tuple[EncryptionFact, CryptoAssetComponent | None, str | None]:
    """Attach a DH asset, or an unresolved basis entry when the file is unusable."""
    if text is None or pem_prime_bits(text) is None:
        code = None if text is None else "parse_error"
        updated = _basis(fact, BasisEntry("dh_file", None, "unresolved_reference"))
        return updated, None, code
    bits = pem_prime_bits(text)
    assert bits is not None
    updated = _basis(fact, BasisEntry("dh_bits", str(bits)))
    return updated, dh_asset(updated, bits), None


def dh_asset(fact: EncryptionFact, bits: int) -> CryptoAssetComponent:
    """Diffie-Hellman algorithm asset. The prime value is not copied."""
    info = algo_info("dh") or {}
    return CryptoAssetComponent(
        bom_ref=f"crypto-algo-dh-{fact.id}",
        name=ALGORITHM_NORMALIZE["dh"],
        properties={
            "crypto:assetType": "algorithm",
            "crypto:factId": fact.id,
            "crypto:keySize": str(bits),
            "crypto:primitive": str(info.get("primitive") or "key-agree"),
            "crypto:quantumVulnerable": "true",
            "discovery:source": fact.path,
        },
    )


def resolve_dh(
    sink: PostureSink, facts: Iterable[EncryptionFact]
) -> tuple[EncryptionFact, ...]:
    """Read each declared DH file once and record its prime size or a gap."""
    updated: list[EncryptionFact] = []
    for fact in facts:
        declared = _named(fact, "dh_path")
        if declared is None:
            updated.append(fact)
            continue
        rel = relative_dh(fact.path, declared)
        decoded = None if rel is None else sink.read_included(rel, "web-server")
        text = None if decoded is None else decoded.text
        revised, _asset, code = with_dh_file(fact, text)
        if code is not None and rel is not None:
            sink.diagnostics.add(code, rel, 0)
        updated.append(revised)
    return tuple(updated)


def emit_dh(ctx: ScanContext, facts: Iterable[EncryptionFact]) -> None:
    """Add the Diffie-Hellman asset and a ``depends_on`` edge for each size."""
    for fact in facts:
        raw = _named(fact, "dh_bits")
        if raw is None:
            continue
        ref = f"crypto-algo-dh-{fact.id}"
        if not ctx.has_ref(ref):
            ctx.add_component(dh_asset(fact, int(raw)))
        ctx.add_edge(f"crypto-cfg_{fact.id}", "depends_on", ref)


def _named(fact: EncryptionFact, name: str) -> str | None:
    return next(
        (item.value for item in fact.basis if item.name == name and item.value),
        None,
    )


def _basis(fact: EncryptionFact, entry: BasisEntry) -> EncryptionFact:
    from dataclasses import replace

    return replace(fact, basis=(*fact.basis, entry))
