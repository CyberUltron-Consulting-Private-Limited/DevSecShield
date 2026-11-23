#!/usr/bin/env python3
"""ZeroShield BOM signature verifier: offline, standard library only (D11; also D4 / D5 evidence packs).

This one file is both the product's canonicalisation code (``bom_signing`` imports ``canonicalize`` from here) and the
verifier every evidence pack carries as ``verify/zs_bom_verify.py``. A pack's copy is a convenience, not a root of
trust: run a copy obtained independently (its SHA-256 is published with the keys). It needs Python 3.8+ and nothing
else; ECDSA is checked with the ``cryptography`` package when it is
installed, otherwise with the ``openssl`` command line (``openssl dgst -sha256 -verify``). It never uses the network.

What it checks
--------------
* ``bom FILE.cdx.json``: the CycloneDX JSON Signature Format (JSF 0.82) ``signature`` embedded in a CycloneDX JSON BOM:
  ES256 (ECDSA P-256 / SHA-256) over the RFC 8785 (JCS) canonical form of the whole document with ``signature.value``
  removed. The value is the JWA form (base64url of R || S, 64 bytes).
* ``detached FILE FILE.sig``: a detached signature (DER ECDSA, the form ``openssl dgst -sign`` writes) over the exact
  bytes of FILE (the XML BOM, ``manifest.json``, ``SHA256SUMS``).
* ``pack PACK.zip|DIR``: the evidence pack: ``manifest.json.sig`` over ``manifest.json``, then the SHA-256 and size of
  every file the manifest lists, then the embedded signature of each JSON BOM and the detached signature of each
  ``*.sig`` that names a file of the pack.

Which key
---------
``--keys`` takes the document ``GET /{team}/bom-signing-keys`` serves (a JWK set), a JWKS file, a single JWK or a PEM
public key: the key your ZeroShield deployment publishes, or one you were given out of band. Keep that file OUTSIDE the
pack. A pack carries a copy of the key (``keys/``) and of this verifier, and anyone who re-signs a pack can replace
both, so keys that come from inside the pack being checked (no ``--keys``, or a ``--keys`` file inside an unpacked
pack) prove nothing: the verifier then prints ``UNTRUSTED KEY`` and exits with status 3 even when every signature
matches, unless ``--trust-pack-keys`` says you have compared the fingerprints yourself. Use a copy of this verifier you
obtained independently too (its SHA-256 is the ``verifier`` field of ``GET /{team}/bom-signing-keys``).

Input rules
-----------
A signed JSON document must be I-JSON (RFC 7493), which RFC 8785 requires: a document with a duplicate member name,
NaN / Infinity, a number outside the double range or an integer beyond +-(2^53 - 1) is rejected, never verified, since
two JSON readers could disagree about what it says. A pack whose zip holds two entries of one name (or names that
differ only in case, absolute paths or ``..``) is rejected for the same reason.

Exit status 0 when every check passes with a trusted key, 1 when any fails, 2 on a usage error, 3 when every check
passes but the key came from inside the pack (``UNTRUSTED KEY``).
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import math
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

ALG = "ES256"
INT_LIMIT = 2 ** 53 - 1  # I-JSON (RFC 7493 2.2): integers a double holds exactly; RFC 8785 cannot canonicalise others
EXIT_OK, EXIT_FAILED, EXIT_USAGE, EXIT_UNTRUSTED = 0, 1, 2, 3
JSF_MEMBERS = frozenset({"algorithm", "keyId", "publicKey", "value"})  # what ZeroShield signs with; nothing else
UNTRUSTED_WARNING = (
    "UNTRUSTED KEY: the key came from inside the pack being checked. Anyone who re-signs a pack can replace its keys/ "
    "and verify/ too, so this result proves nothing about who made it. Verify with the key your ZeroShield deployment "
    "publishes (GET /{team}/bom-signing-keys, saved outside the pack) or one received out of band: "
    "--keys <that file>. Pass --trust-pack-keys only after comparing the fingerprints below yourself.")


class InputError(ValueError):
    """The input is not what a signature can be checked over (not I-JSON, a malformed signature member, a bad pack)."""


class NotJSON(InputError):
    """Not JSON at all (a syntax error, not UTF-8): a corrupted or non-JSON file, rather than JSON two readers could
    read differently."""
# DER SubjectPublicKeyInfo prefix of an uncompressed P-256 public key (id-ecPublicKey, prime256v1, BIT STRING)
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


# ----------------------------------------------------------------------------------------------- RFC 8785 (JCS)
def _no_duplicates(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise InputError(f"duplicate member name {key[:64]!r}: not I-JSON (RFC 7493), refused")
        out[key] = value
    return out


def _no_constant(name: str) -> Any:
    raise InputError(f"{name} is not a JSON number: not I-JSON (RFC 7493), refused")


def _finite(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise InputError(f"the number {text[:32]} is outside the IEEE 754 double range: not I-JSON, refused")
    return value


def _bounded_int(text: str) -> int:
    if len(text.lstrip("-")) > 16:  # 2^53 has 16 digits; anything longer is out of range (and never a 4300-digit int)
        raise InputError(f"the integer {text[:32]} is beyond +-(2^53 - 1): not I-JSON, refused")
    value = int(text)
    if abs(value) > INT_LIMIT:
        raise InputError(f"the integer {text} is beyond +-(2^53 - 1): not I-JSON, refused")
    return value


def loads(data: "bytes | str") -> Any:
    """Parse JSON as I-JSON (RFC 7493): UTF-8, no duplicate member names, no NaN / Infinity, numbers inside the double
    range, integers inside +-(2^53 - 1). Raises ``InputError`` otherwise (the strict reading every check here uses)."""
    try:
        text = data.decode("utf-8") if isinstance(data, (bytes, bytearray)) else data
        return json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constant, parse_float=_finite,
                          parse_int=_bounded_int)
    except InputError:
        raise
    except RecursionError:
        raise InputError("the JSON is nested too deeply") from None
    except (ValueError, TypeError) as exc:  # JSONDecodeError and UnicodeDecodeError are ValueErrors
        raise NotJSON(f"not JSON: {str(exc)[:200]}") from None


def loads_file(fh: Any) -> Any:
    """``loads`` of a whole binary file object (from its start): the bytes are dropped once decoded, so only the text
    and then the parsed document are held, never the bytes as well."""
    fh.seek(0)
    try:
        text = fh.read().decode("utf-8")  # the bytes object is released as soon as it is decoded
    except UnicodeDecodeError as exc:
        raise NotJSON(f"not JSON: {str(exc)[:200]}") from None
    return loads(text)


def _number(value: Any) -> str:
    """An ECMAScript Number.prototype.toString of ``value`` (RFC 8785 section 3.2.2.3). An integer beyond
    +-(2^53 - 1) is refused (``ValueError``), as RFC 8785 implementations do: its canonical form would be a rounded
    double, so a signature would not protect its exact value."""
    if isinstance(value, int):
        if abs(value) > INT_LIMIT:
            raise ValueError(f"JCS: the integer {value} is beyond +-(2^53 - 1) (I-JSON); write it as a string")
        return str(value)
    if value != value or value in (float("inf"), float("-inf")):
        raise ValueError("JCS: NaN and Infinity are not JSON numbers")
    if value == 0:
        return "0"
    sign = "-" if value < 0 else ""
    text = repr(abs(value))  # the shortest text that reads back as the same double, as ECMAScript chooses
    mantissa, _, exp = text.partition("e")
    whole, _, frac = mantissa.partition(".")
    digits, point = whole + frac, len(whole) + (int(exp) if exp else 0)
    stripped = digits.lstrip("0")
    point -= len(digits) - len(stripped)
    digits = stripped.rstrip("0") or "0"
    k, n = len(digits), point
    if k <= n <= 21:
        out = digits + "0" * (n - k)
    elif 0 < n <= 21:
        out = digits[:n] + "." + digits[n:]
    elif -6 < n <= 0:
        out = "0." + "0" * (-n) + digits
    else:
        e = n - 1
        out = (digits[0] + ("." + digits[1:] if k > 1 else "")) + "e" + ("+" if e >= 0 else "-") + str(abs(e))
    return sign + out


def _string(value: str) -> str:
    # json.dumps(ensure_ascii=False) escapes exactly what JCS escapes: " \\ \b \f \n \r \t and other controls as \u00xx
    return json.dumps(value, ensure_ascii=False)


def _utf16_key(key: str) -> bytes:
    return key.encode("utf-16-be", "surrogatepass")


def canonicalize(value: Any) -> bytes:
    """RFC 8785 JSON Canonicalization Scheme: UTF-8 bytes of ``value`` with object members sorted by their UTF-16
    code units, no whitespace, ECMAScript number text and minimal string escaping."""
    return _canonical_text(value).encode("utf-8", "surrogatepass")


def _canonical_pieces(value: Any) -> Iterable[str]:
    """``_canonical_text`` as a stream of pieces: big arrays and objects never become one string."""
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError("JCS: object keys must be strings")
        yield "{"
        for index, key in enumerate(sorted(value, key=_utf16_key)):
            yield ("," if index else "") + _string(key) + ":"
            yield from _canonical_pieces(value[key])
        yield "}"
    elif isinstance(value, (list, tuple)):
        yield "["
        for index, item in enumerate(value):
            if index:
                yield ","
            yield from _canonical_pieces(item)
        yield "]"
    else:
        yield _canonical_text(value)


def canonical_sha256(value: Any, sink: Optional[List[bytes]] = None) -> bytes:
    """SHA-256 of ``canonicalize(value)``, hashed while it is produced (about 1 MB is held at a time). ``sink`` also
    collects the bytes (only the openssl fallback needs them)."""
    sha, buf, held = hashlib.sha256(), [], 0
    for piece in _canonical_pieces(value):
        buf.append(piece)
        held += len(piece)
        if held >= 1 << 20:
            block = "".join(buf).encode("utf-8", "surrogatepass")
            sha.update(block)
            if sink is not None:
                sink.append(block)
            buf, held = [], 0
    block = "".join(buf).encode("utf-8", "surrogatepass")
    sha.update(block)
    if sink is not None:
        sink.append(block)
    return sha.digest()


def _canonical_text(value: Any) -> str:
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _string(value)
    if isinstance(value, (int, float)):
        return _number(value)
    if isinstance(value, dict):
        for key in value:
            if not isinstance(key, str):
                raise TypeError("JCS: object keys must be strings")
        return "{" + ",".join(_string(k) + ":" + _canonical_text(value[k])
                              for k in sorted(value, key=_utf16_key)) + "}"
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_canonical_text(v) for v in value) + "]"
    raise TypeError(f"JCS: {type(value).__name__} is not a JSON value")


# ----------------------------------------------------------------------------------------------- encodings
def b64url_decode(text: str) -> bytes:
    if not isinstance(text, str):
        raise ValueError("base64url: not a string")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"not base64url: {exc}") from None


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _der_int(value: int) -> bytes:
    body = value.to_bytes((value.bit_length() + 8) // 8 or 1, "big")
    return b"\x02" + bytes([len(body)]) + body


def raw_to_der(raw: bytes) -> bytes:
    """JWA ECDSA signature (R || S) to the DER SEQUENCE openssl reads."""
    if len(raw) != 64:
        raise ValueError("an ES256 signature is 64 bytes (R || S)")
    body = _der_int(int.from_bytes(raw[:32], "big")) + _der_int(int.from_bytes(raw[32:], "big"))
    return b"\x30" + bytes([len(body)]) + body


def der_to_raw(der: bytes) -> bytes:
    """DER ECDSA signature to JWA R || S (32 bytes each)."""
    if len(der) < 8 or der[0] != 0x30 or der[1] != len(der) - 2:
        raise ValueError("not a DER ECDSA signature")
    out, i = b"", 2
    for _ in range(2):
        if der[i] != 0x02:
            raise ValueError("not a DER ECDSA signature")
        size = der[i + 1]
        value = int.from_bytes(der[i + 2:i + 2 + size], "big")
        if value.bit_length() > 256:
            raise ValueError("not a P-256 signature")
        out += value.to_bytes(32, "big")
        i += 2 + size
    if i != len(der):
        raise ValueError("trailing bytes after the DER signature")
    return out


def jwk_point(jwk: Dict[str, Any]) -> bytes:
    """The uncompressed point (0x04 || X || Y) of a P-256 JWK."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are used")
    if not isinstance(jwk.get("x"), str) or not isinstance(jwk.get("y"), str):
        raise ValueError("a P-256 JWK needs x and y as base64url strings")
    x, y = b64url_decode(jwk["x"]), b64url_decode(jwk["y"])
    if len(x) != 32 or len(y) != 32:
        raise ValueError("a P-256 coordinate is 32 bytes")
    return b"\x04" + x + y


def jwk_to_pem(jwk: Dict[str, Any]) -> str:
    der = _P256_SPKI_PREFIX + jwk_point(jwk)
    body = base64.b64encode(der).decode("ascii")
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def pem_to_jwk(pem: str) -> Dict[str, str]:
    body = "".join(line for line in pem.strip().splitlines() if not line.startswith("-----"))
    der = base64.b64decode(body)
    if not der.startswith(_P256_SPKI_PREFIX) or len(der) != len(_P256_SPKI_PREFIX) + 65:
        raise ValueError("not an uncompressed EC P-256 public key (SubjectPublicKeyInfo PEM)")
    point = der[len(_P256_SPKI_PREFIX):]
    return {"kty": "EC", "crv": "P-256", "x": b64url(point[1:33]), "y": b64url(point[33:])}


def thumbprint(jwk: Dict[str, Any]) -> str:
    """RFC 7638 JWK thumbprint (SHA-256, base64url) of a P-256 key: the key's fingerprint."""
    jwk_point(jwk)  # a well-formed P-256 key, or ValueError
    members = {"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}
    return b64url(hashlib.sha256(canonicalize(members)).digest())


# ----------------------------------------------------------------------------------------------- ECDSA check
def verify_digest(jwk: Dict[str, Any], digest: bytes, der_signature: bytes, message: Optional[bytes] = None) -> bool:
    """ES256 check of ``der_signature`` over a SHA-256 ``digest``. ``message`` (the signed bytes) is needed only when
    the ``openssl`` command line does the check, since it hashes the message itself."""
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils
    except ImportError:
        return _openssl_verify(jwk, digest, der_signature, message)
    key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), jwk_point(jwk))
    try:
        key.verify(der_signature, digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
        return True
    except InvalidSignature:
        return False


def _openssl_verify(jwk: Dict[str, Any], digest: bytes, der_signature: bytes, message: Optional[bytes]) -> bool:
    binary = shutil.which("openssl")
    if binary is None or message is None:
        raise RuntimeError("install the Python 'cryptography' package or the openssl command line to check ECDSA")
    if hashlib.sha256(message).digest() != digest:
        return False
    with tempfile.TemporaryDirectory() as tmp:
        paths = {name: os.path.join(tmp, name) for name in ("key.pem", "sig.der", "data.bin")}
        for name, data in (("key.pem", jwk_to_pem(jwk).encode()), ("sig.der", der_signature), ("data.bin", message)):
            with open(paths[name], "wb") as fh:
                fh.write(data)
        done = subprocess.run([binary, "dgst", "-sha256", "-verify", paths["key.pem"], "-signature",
                               paths["sig.der"], paths["data.bin"]], capture_output=True, check=False)
    return done.returncode == 0


# ----------------------------------------------------------------------------------------------- keys
def load_keys(text: str) -> Dict[str, Dict[str, Any]]:
    """kid -> JWK from a JWKS document (also what ``GET /{team}/bom-signing-keys`` serves), a single JWK or a PEM
    public key (kid = its thumbprint-based id). Raises ``InputError`` when no P-256 key can be read from it."""
    stripped = text.strip()
    if stripped.startswith("-----BEGIN"):
        try:
            jwk = pem_to_jwk(stripped)
        except (ValueError, binascii.Error) as exc:
            raise InputError(f"not a P-256 public key PEM: {exc}") from None
        return {key_id(jwk): jwk}
    doc = loads(stripped)
    keys = doc.get("keys") if isinstance(doc, dict) and "keys" in doc else [doc]
    out: Dict[str, Dict[str, Any]] = {}
    for jwk in keys if isinstance(keys, list) else []:
        if not isinstance(jwk, dict) or jwk.get("kty") != "EC":
            continue
        try:
            jwk_point(jwk)
        except ValueError:
            continue
        kid = jwk.get("kid") if isinstance(jwk.get("kid"), str) and jwk.get("kid") else key_id(jwk)
        if kid in out and thumbprint(out[kid]) != thumbprint(jwk):
            kid = key_id(jwk)  # two keys under one kid: the key's own thumbprint id keeps both
        out[kid] = jwk
    if not out:
        raise InputError("no EC P-256 public key in the key file")
    return out


def key_id(jwk: Dict[str, Any]) -> str:
    """The key id ZeroShield gives a key it did not name: ``zs-`` and the first 16 characters of its thumbprint."""
    return "zs-" + thumbprint(jwk)[:16]


def _pick(keys: Dict[str, Dict[str, Any]], kid: Optional[str], embedded: Optional[Dict[str, Any]] = None
          ) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
    """(trusted kid, trusted JWK, why not) of a signature that names ``kid`` and may carry its public key.

    The key is chosen by its bytes, not its name: a signature that carries ``publicKey`` is checked with the trusted
    key of the same RFC 7638 thumbprint (the one named ``kid`` when two share it), and refused when no trusted key has
    it, whatever its ``keyId`` says. So a key id reused across a rotation still finds the old key, and a ``keyId`` of a
    trusted key never lends its trust to another key. Without ``publicKey`` the ``kid`` alone names the key."""
    if embedded is not None:
        try:
            theirs = thumbprint(embedded)
        except (KeyError, TypeError, ValueError):
            return kid, None, "signature.publicKey is not an EC P-256 JWK"
        same = [k for k, v in keys.items() if thumbprint(v) == theirs]
        if not same:
            return kid, None, "the signing key (signature.publicKey) is not one of the trusted keys"
        chosen = kid if kid in same else same[0]
        return chosen, keys[chosen], None
    if kid is not None and kid in keys:
        return kid, keys[kid], None
    return kid, None, "the signing key is not one of the trusted keys"


# ----------------------------------------------------------------------------------------------- checks
def _invalid(reason: str, **extra: Any) -> Dict[str, Any]:
    return {"valid": False, **extra, "reason": reason}


def _have_cryptography() -> bool:
    try:
        import cryptography.hazmat.primitives.asymmetric.ec  # noqa: F401
        return True
    except ImportError:
        return False


def verify_document(doc: Any, keys: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Check the JSF ``signature`` embedded in an already parsed (``loads``) CycloneDX JSON document against ``keys``.
    Never raises on what the document holds: a malformed signature member is ``valid: false`` with a reason."""
    if not isinstance(doc, dict):
        return _invalid("not a JSON object")
    sig = doc.get("signature")
    if not isinstance(sig, dict) or "value" not in sig:
        return _invalid("the document has no JSF signature")
    if sig.get("algorithm") != ALG:
        return _invalid(f"unsupported algorithm {str(sig.get('algorithm'))[:40]!r}")
    unknown = sorted(set(sig) - JSF_MEMBERS)
    if unknown:
        return _invalid(f"unsupported JSF signature member(s) {', '.join(m[:32] for m in unknown[:5])}", malformed=True)
    kid, embedded, value = sig.get("keyId"), sig.get("publicKey"), sig.get("value")
    if kid is not None and not isinstance(kid, str):
        return _invalid("signature.keyId is not a string", malformed=True)
    if embedded is not None and not isinstance(embedded, dict):
        return _invalid("signature.publicKey is not a JWK object", malformed=True)
    if not isinstance(value, str):
        return _invalid("signature.value is not a string", malformed=True)
    kid, jwk, why = _pick(keys, kid, embedded)
    if jwk is None:
        return _invalid(why or "the signing key is not one of the trusted keys", kid=kid)
    try:
        der = raw_to_der(b64url_decode(value))
    except ValueError as exc:
        return _invalid(str(exc), kid=kid, malformed=True)
    unsigned = dict(doc)  # shallow: only the signature member is replaced
    unsigned["signature"] = {k: v for k, v in sig.items() if k != "value"}
    sink: Optional[List[bytes]] = None if _have_cryptography() else []
    try:
        digest = canonical_sha256(unsigned, sink)
        ok = verify_digest(jwk, digest, der, b"".join(sink) if sink is not None else None)
    except (TypeError, ValueError, RecursionError) as exc:
        return _invalid(f"cannot be canonicalised (RFC 8785): {str(exc)[:200]}", kid=kid, malformed=True)
    return {"valid": ok, "kid": kid, "alg": ALG, "canonical_sha256": digest.hex(),
            **({} if ok else {"reason": "the signature does not match the document"})}


def verify_bom(data: bytes, keys: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Check the JSF ``signature`` embedded in a CycloneDX JSON BOM (its bytes) against ``keys``: parsed as I-JSON
    (``loads``), so a duplicate member name, NaN or an out-of-range number is ``valid: false``, never verified."""
    try:
        doc = loads(data)
    except InputError as exc:
        return _invalid(str(exc), malformed=True)
    return verify_document(doc, keys)


def verify_detached(data: bytes, der_signature: bytes, keys: Dict[str, Dict[str, Any]],
                    kid: Optional[str] = None) -> Dict[str, Any]:
    """Check a detached DER signature over ``data`` against ``kid`` (else every key)."""
    return verify_detached_digest(hashlib.sha256(data).digest(), der_signature, keys, kid, data)


def verify_detached_digest(digest: bytes, der_signature: bytes, keys: Dict[str, Dict[str, Any]],
                           kid: Optional[str] = None, data: Optional[bytes] = None) -> Dict[str, Any]:
    """``verify_detached`` for a file already hashed (SHA-256 ``digest``); ``data`` is needed only by openssl."""
    candidates = [(kid, keys[kid])] if kid and kid in keys else list(keys.items())
    for name, jwk in candidates:
        try:
            if verify_digest(jwk, digest, der_signature, data):
                return {"valid": True, "kid": name, "alg": ALG, "sha256": digest.hex()}
        except (TypeError, ValueError):
            continue
    return {"valid": False, "sha256": digest.hex(), "reason": "no trusted key verifies this signature"}


def subject_of(doc: Any) -> Dict[str, Any]:
    """What a ZeroShield document says it belongs to: ``serial`` (CycloneDX ``serialNumber``), ``run_id`` /
    ``scan_id`` / ``bom_serial`` (``zs:`` metadata properties of a BOM or VEX) and, for an evidence pack's
    ``manifest.json``, its ``subject`` (``kind``, ``run_id`` / ``scan_id``). Missing parts are left out."""
    out: Dict[str, Any] = {}
    if not isinstance(doc, dict):
        return out
    if isinstance(doc.get("serialNumber"), str):
        out["serial"] = doc["serialNumber"]
    meta = doc.get("metadata")
    props = meta.get("properties") if isinstance(meta, dict) else None
    for prop in props if isinstance(props, list) else []:
        if not isinstance(prop, dict) or not isinstance(prop.get("value"), str):
            continue
        name, value = prop.get("name"), prop["value"]
        if name in ("zs:run_id", "zs:scan_id") and value.isdigit() and name[3:] not in out:
            out[name[3:]] = int(value)
        elif name == "zs:bom_serial" and "bom_serial" not in out:
            out["bom_serial"] = value
    subject = doc.get("subject")
    if isinstance(doc.get("format"), str) and "evidence-pack" in doc["format"] and isinstance(subject, dict):
        out["pack"] = True
        if isinstance(subject.get("kind"), str):
            out["kind"] = subject["kind"]
        for name in ("run_id", "scan_id"):
            if isinstance(subject.get(name), int) and not isinstance(subject.get(name), bool):
                out[name] = subject[name]
        if isinstance(subject.get("bom_serial"), str):
            out["bom_serial"] = subject["bom_serial"]
    return out


def _bad_name(name: str) -> Optional[str]:
    if not name or "\x00" in name or "\\" in name:
        return "empty name, NUL or backslash"
    if name.startswith("/") or (len(name) > 1 and name[1] == ":"):
        return "absolute path"
    if any(part == ".." for part in name.split("/")):
        return "'..' in the path"
    return None


class _Pack:
    """A pack as a zip file or an unpacked directory."""

    def __init__(self, path: str):
        self.path = path
        self.zip = zipfile.ZipFile(path) if os.path.isfile(path) else None

    def problems(self) -> List[Dict[str, Any]]:
        """Entries a first-wins and a last-wins reader would disagree on (two entries of one name, names equal but
        for case) or that point outside the pack (absolute, ``..``, a symbolic link): each one fails the pack."""
        out: List[Dict[str, Any]] = []
        if self.zip is not None:
            names = self.zip.namelist()
        else:
            names = []
            for root, dirs, files in os.walk(self.path):
                for entry in dirs + files:
                    full = os.path.join(root, entry)
                    rel = os.path.relpath(full, self.path).replace(os.sep, "/")
                    if os.path.islink(full):
                        out.append({"check": f"entry {rel}", "valid": False, "reason": "a symbolic link"})
                    elif entry in files:
                        names.append(rel)
        seen: Dict[str, str] = {}
        for name in names:
            why = _bad_name(name)
            if why:
                out.append({"check": f"entry {name[:200]}", "valid": False, "reason": why})
            folded = name.casefold()
            if folded in seen:
                reason = ("two zip entries with this name: extractors disagree on which one is the file"
                          if seen[folded] == name else f"differs from {seen[folded][:200]!r} only in case")
                out.append({"check": f"entry {name[:200]}", "valid": False, "reason": reason})
            else:
                seen[folded] = name
        return out

    def names(self) -> List[str]:
        if self.zip is not None:
            return [n for n in self.zip.namelist() if not n.endswith("/")]
        out = []
        for root, _dirs, files in os.walk(self.path):
            out += [os.path.relpath(os.path.join(root, f), self.path).replace(os.sep, "/") for f in files]
        return sorted(out)

    def read(self, name: str) -> bytes:
        if self.zip is not None:
            return self.zip.read(name)
        with open(os.path.join(self.path, *name.split("/")), "rb") as fh:
            return fh.read()

    def chunks(self, name: str) -> Iterable[bytes]:
        if self.zip is not None:
            with self.zip.open(name) as fh:
                while block := fh.read(1 << 20):
                    yield block
            return
        with open(os.path.join(self.path, *name.split("/")), "rb") as fh:
            while block := fh.read(1 << 20):
                yield block


def verify_pack(path: str, keys: Optional[Dict[str, Dict[str, Any]]] = None, *,
                keys_from_pack: bool = False) -> Dict[str, Any]:
    """Every check of a pack (module docstring); ``keys`` default to the pack's own ``keys/jwks.json``.
    ``keys_from_pack``: the given keys were read from inside this pack. Either way the result says
    ``trusted_keys: false``: the signatures check out against keys the pack itself carries, which proves nothing."""
    try:
        pack = _Pack(path)
    except (zipfile.BadZipFile, OSError) as exc:
        return {"valid": False, "checks": [{"check": "zip", "valid": False, "reason": f"not a readable pack: {exc}"}]}
    problems = pack.problems()
    if problems:
        return {"valid": False, "checks": problems}
    names = set(pack.names())
    checks: List[Dict[str, Any]] = []
    own = keys is None
    if own:
        if "keys/jwks.json" not in names:
            return {"valid": False, "checks": [{"check": "keys", "valid": False,
                                                "reason": "no keys/jwks.json in the pack and no --keys given"}]}
        try:
            keys = load_keys(pack.read("keys/jwks.json").decode("utf-8"))
        except (InputError, UnicodeDecodeError) as exc:
            return {"valid": False, "checks": [{"check": "keys", "valid": False, "reason": str(exc)}]}
    assert keys is not None
    if "manifest.json" not in names or "manifest.json.sig" not in names:
        return {"valid": False, "checks": [{"check": "manifest", "valid": False,
                                            "reason": "manifest.json or manifest.json.sig is missing"}]}
    manifest_bytes = pack.read("manifest.json")
    res = verify_detached(manifest_bytes, pack.read("manifest.json.sig"), keys)
    checks.append({"check": "manifest.json.sig", **res})
    try:
        manifest = loads(manifest_bytes)
    except InputError as exc:
        return {"valid": False, "checks": checks + [{"check": "manifest.json", "valid": False, "reason": str(exc)}]}
    listed = manifest.get("files") if isinstance(manifest, dict) else None
    listed = [e for e in listed if isinstance(e, dict) and isinstance(e.get("name"), str)] \
        if isinstance(listed, list) else []
    for entry in listed:
        name = entry["name"]
        if name not in names:
            checks.append({"check": f"sha256 {name}", "valid": False, "reason": "listed in the manifest, not in the pack"})
            continue
        sha, size = hashlib.sha256(), 0
        for block in pack.chunks(name):
            sha.update(block)
            size += len(block)
        ok = sha.hexdigest() == entry.get("sha256") and (entry.get("bytes") is None or entry.get("bytes") == size)
        checks.append({"check": f"sha256 {name}", "valid": ok, **({} if ok else {"reason": "hash or size differs"})})
    covered = {e["name"] for e in listed} | {"manifest.json", "manifest.json.sig", "SHA256SUMS", "SHA256SUMS.sig"}
    for name in sorted(names - covered):
        checks.append({"check": f"listed {name}", "valid": False, "reason": "in the pack but not in the manifest"})
    for name in sorted(names):
        if name.endswith(".json") and name != "manifest.json" and not name.startswith("keys/"):
            try:
                doc = loads(pack.read(name))
            except InputError as exc:  # a BOM or VEX must be I-JSON; other files are covered by their manifest hash
                if name.endswith(".cdx.json") or name.endswith("vex.json"):
                    checks.append({"check": f"jsf {name}", "valid": False, "reason": str(exc)})
                continue
            signed = isinstance(doc, dict) and isinstance(doc.get("signature"), dict)
            if signed:
                checks.append({"check": f"jsf {name}", **verify_document(doc, keys)})
            elif name.endswith(".cdx.json"):
                checks.append({"check": f"jsf {name}", "valid": False,
                               "reason": "a CycloneDX JSON BOM of a signed pack without its JSF signature"})
            del doc
        if name.endswith(".sig") and name != "manifest.json.sig" and name[:-4] in names:
            checks.append({"check": f"detached {name}", **verify_detached(pack.read(name[:-4]), pack.read(name), keys)})
    out: Dict[str, Any] = {"valid": all(c.get("valid") for c in checks), "checks": checks,
                           "trusted_keys": not (own or keys_from_pack)}
    if own or keys_from_pack:
        out["keys"] = {kid: "sha256:" + thumbprint(jwk) for kid, jwk in keys.items()}
        out["note"] = UNTRUSTED_WARNING
    return out


# ----------------------------------------------------------------------------------------------- command line
def _looks_like_pack(directory: str) -> bool:
    return os.path.isfile(os.path.join(directory, "manifest.json")) and (
        os.path.isdir(os.path.join(directory, "keys")) or os.path.isdir(os.path.join(directory, "verify")))


def keys_inside_pack(keys_path: str, pack_path: Optional[str] = None) -> bool:
    """The ``--keys`` file lies inside the pack being checked (an unpacked one, or any unpacked pack around it)."""
    real = os.path.realpath(keys_path)
    if pack_path is not None and os.path.isdir(pack_path):
        root = os.path.realpath(pack_path)
        if os.path.commonpath([root, real]) == root:
            return True
    directory = os.path.dirname(real)
    while True:
        if _looks_like_pack(directory):
            return True
        parent = os.path.dirname(directory)
        if parent == directory:
            return False
        directory = parent


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ZeroShield BOM signatures offline.")
    parser.add_argument("--keys", help="the key your deployment publishes (GET /{team}/bom-signing-keys saved to a "
                                       "file outside the pack), a JWKS, a JWK or a PEM public key")
    parser.add_argument("--trust-pack-keys", action="store_true",
                        help="accept keys from inside the pack (only after comparing their fingerprints yourself)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("bom", help="the JSF signature embedded in a CycloneDX JSON BOM")
    one.add_argument("file")
    two = sub.add_parser("detached", help="a detached DER signature over a file's bytes")
    two.add_argument("file")
    two.add_argument("signature")
    three = sub.add_parser("pack", help="an evidence pack (zip or unpacked directory)")
    three.add_argument("path")
    args = parser.parse_args(argv)
    try:
        return _run(args, parser)
    except (OSError, InputError, UnicodeDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("NOT VERIFIED", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # fail closed, without a traceback
        print(f"error: {exc.__class__.__name__}: {exc}", file=sys.stderr)
        print("NOT VERIFIED", file=sys.stderr)
        return EXIT_FAILED


def _run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    keys = None
    from_pack = False
    if args.keys:
        with open(args.keys, encoding="utf-8") as fh:
            keys = load_keys(fh.read())
        from_pack = keys_inside_pack(args.keys, args.path if args.cmd == "pack" else None)
    elif args.cmd != "pack":
        parser.error("--keys is required for bom and detached")
    else:
        from_pack = True
    if args.cmd == "bom":
        with open(args.file, "rb") as fh:
            result = verify_bom(fh.read(), keys or {})
    elif args.cmd == "detached":
        with open(args.file, "rb") as fh, open(args.signature, "rb") as sg:
            result = verify_detached(fh.read(), sg.read(), keys or {})
    else:
        result = verify_pack(args.path, keys, keys_from_pack=from_pack)
    if args.cmd != "pack":
        result["trusted_keys"] = not from_pack
        if from_pack:
            result["keys"] = {kid: "sha256:" + thumbprint(jwk) for kid, jwk in (keys or {}).items()}
            result["note"] = UNTRUSTED_WARNING
    out = io.StringIO()
    json.dump(result, out, indent=2)
    print(out.getvalue())
    if not result.get("valid"):
        print("NOT VERIFIED", file=sys.stderr)
        return EXIT_FAILED
    if from_pack and not args.trust_pack_keys:
        print("!" * 100, file=sys.stderr)
        print("!!! " + UNTRUSTED_WARNING, file=sys.stderr)
        for kid, fp in result.get("keys", {}).items():
            print(f"!!!   {kid}: {fp}", file=sys.stderr)
        print("!" * 100, file=sys.stderr)
        print("NOT VERIFIED (UNTRUSTED KEY): the signatures match keys that came with the pack", file=sys.stderr)
        return EXIT_UNTRUSTED
    print("VERIFIED" + (" (with keys from the pack, accepted by --trust-pack-keys)" if from_pack else ""),
          file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
