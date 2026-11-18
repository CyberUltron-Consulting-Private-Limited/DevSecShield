"""Pure comparisons for the CB-02 follow-up targets (issue #93).

The generator writes the oracle with OpenSSL. These functions decode a served JWKS, a kubectl secret list, a
receiver log and a file mode without calling OpenSSL and without importing the product (rule O-1). A dropped key,
a swapped certificate or a login that can still read a root-owned file shows up here as a mismatch.
"""
from __future__ import annotations

import base64
import hashlib

import labread as R

_EC_BITS = {"P-256": 256, "P-384": 384, "P-521": 521}
_EC_LEN = {"P-256": 32, "P-384": 48, "P-521": 66}


def b64url_uint(n: int) -> str:
    raw = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def b64url_fixed(n: int, length: int) -> str:
    return base64.urlsafe_b64encode(n.to_bytes(length, "big")).decode().rstrip("=")


def _b64url_int(text: str) -> int:
    pad = "=" * (-len(text) % 4)
    return int.from_bytes(base64.urlsafe_b64decode(text + pad), "big")


def public_numbers(der: bytes) -> dict:
    """RSA modulus/exponent or an uncompressed EC point, from a SubjectPublicKeyInfo DER."""
    _tag, value, end = R.der_read(der, 0)
    if end != len(der):
        raise ValueError("trailing bytes after SubjectPublicKeyInfo")
    items = R.der_items(value)
    alg = R.der_items(items[0][1])
    oid = R.der_oid(alg[0][1])
    bit = items[1][1]
    if not bit or bit[0] != 0:
        raise ValueError("subjectPublicKey is not a byte-aligned bit string")
    body = bit[1:]
    if oid == "1.2.840.113549.1.1.1":
        seq = R.der_items(R.der_read(body, 0)[1])
        n, e = R.der_int(seq[0][1]), R.der_int(seq[1][1])
        return {"kty": "RSA", "n": n, "e": e, "bits": n.bit_length()}
    if oid == "1.2.840.10045.2.1":
        name, bits = R.CURVE[R.der_oid(alg[1][1])]
        if not body or body[0] != 4:
            raise ValueError("EC point is compressed")
        half = (len(body) - 1) // 2
        return {"kty": "EC", "crv": name, "bits": bits,
                "x": int.from_bytes(body[1:1 + half], "big"),
                "y": int.from_bytes(body[1 + half:], "big")}
    raise ValueError(f"unsupported public key {oid}")


def jwk_from(kid: str, alg: str, use: str, numbers: dict) -> dict:
    jwk = {"kty": numbers["kty"], "kid": kid, "use": use, "alg": alg}
    if numbers["kty"] == "RSA":
        jwk["n"] = b64url_uint(numbers["n"])
        jwk["e"] = b64url_uint(numbers["e"])
    else:
        length = _EC_LEN[numbers["crv"]]
        jwk["crv"] = numbers["crv"]
        jwk["x"] = b64url_fixed(numbers["x"], length)
        jwk["y"] = b64url_fixed(numbers["y"], length)
    return jwk


def jwk_bits(jwk: dict) -> int | None:
    if jwk.get("kty") == "RSA" and isinstance(jwk.get("n"), str):
        return _b64url_int(jwk["n"]).bit_length()
    if jwk.get("kty") == "EC":
        return _EC_BITS.get(jwk.get("crv") or "")
    return None


def idp_mismatches(expected: list[dict], served: dict) -> list[str]:
    """Keys the oracle lists (kid, kty, alg, bits, crv) against a JWKS document fetched from the server."""
    by_kid = {k.get("kid"): k for k in (served.get("keys") or []) if isinstance(k, dict)}
    problems = []
    for exp in expected:
        got = by_kid.get(exp["kid"])
        if got is None:
            problems.append(f"missing {exp['kid']}")
            continue
        if got.get("kty") != exp["kty"] or got.get("alg") != exp["alg"]:
            problems.append(f"{exp['kid']} kty/alg {got.get('kty')}/{got.get('alg')}")
        if jwk_bits(got) != exp["bits"]:
            problems.append(f"{exp['kid']} bits {jwk_bits(got)} != {exp['bits']}")
        if exp.get("crv") and got.get("crv") != exp["crv"]:
            problems.append(f"{exp['kid']} crv {got.get('crv')}")
    extra = sorted(set(by_kid) - {e["kid"] for e in expected})
    if extra:
        problems.append("extra " + ",".join(extra))
    return problems


def receiver_missing(posted: list[str], rows: list[dict]) -> list[str]:
    """Delivery ids that were posted and are absent from the receiver log."""
    seen = {str(r.get("id")) for r in rows if isinstance(r, dict)}
    return [i for i in posted if i not in seen]


def secret_crt_sha256(item: dict) -> str | None:
    raw = (item.get("data") or {}).get("tls.crt")
    if not isinstance(raw, str) or not raw:
        return None
    return hashlib.sha256(base64.b64decode(raw)).hexdigest()


def k8s_mismatches(expect: dict, secrets: dict, configmaps: dict, ingresses: dict, accounts: dict) -> list[str]:
    """Cluster objects against the oracle. Certificate bytes are hashed, not parsed, so a swapped cert is caught
    even when its subject is unchanged."""
    problems = []
    by_secret = {i["metadata"]["name"]: i for i in (secrets.get("items") or [])}
    for exp in expect.get("secrets") or []:
        item = by_secret.get(exp["name"])
        if item is None:
            problems.append(f"missing secret {exp['name']}")
            continue
        if item.get("type") != "kubernetes.io/tls":
            problems.append(f"{exp['name']} type {item.get('type')}")
        if secret_crt_sha256(item) != exp["sha256"]:
            problems.append(f"{exp['name']} tls.crt")
    by_cm = {i["metadata"]["name"]: i for i in (configmaps.get("items") or [])}
    cm = by_cm.get((expect.get("configmap") or {}).get("name"))
    if expect.get("configmap"):
        if cm is None:
            problems.append("missing configmap")
        else:
            blob = (cm.get("data") or {}).get("app.key", "")
            if hashlib.sha256(blob.encode()).hexdigest() != expect["configmap"]["sha256"]:
                problems.append("configmap key")
    ing = next((i for i in (ingresses.get("items") or []) if i["metadata"]["name"] == "web"), None)
    if ing is None:
        problems.append("missing ingress web")
    else:
        tls = ((ing.get("spec") or {}).get("tls") or [{}])[0].get("secretName")
        if tls != expect.get("ingress_secret"):
            problems.append(f"ingress secret {tls}")
    have = {i["metadata"]["name"] for i in (accounts.get("items") or [])}
    for name in expect.get("service_accounts") or []:
        if name not in have:
            problems.append(f"missing service account {name}")
    return problems


def login_cannot_read(mode: str, owner: str, user: str = "zs-cbom") -> bool:
    """The login user is not the owner and the mode grants no permission to other users."""
    return owner != user and (int(mode, 8) & 0o007) == 0
