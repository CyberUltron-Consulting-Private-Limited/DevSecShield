#!/usr/bin/env python3
"""ZeroShield BOM signature verifier: offline, standard library only (D11; also D4 / D5 evidence packs).

This one file is both the product's canonicalisation code (``bom_signing`` imports ``canonicalize`` from here) and the
verifier every evidence pack carries as ``verify/zs_bom_verify.py``, so the bytes a client runs are the bytes that
signed the pack. It needs Python 3.8+ and nothing else; ECDSA is checked with the ``cryptography`` package when it is
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
``--keys`` takes a JWKS file (``keys/jwks.json`` in a pack, or what ``GET /{team}/bom-signing-keys`` serves) or a PEM
public key. Without ``--keys``, ``pack`` uses the pack's own ``keys/jwks.json`` and prints each key's SHA-256
fingerprint: compare it with the key your ZeroShield deployment publishes (Settings, or ``GET
/{team}/bom-signing-keys``) or the one you were given out of band, because a pack can only vouch for itself.

Exit status 0 when every check passes, 1 when any fails, 2 on a usage error.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from typing import Any, Dict, Iterable, List, Optional, Tuple

ALG = "ES256"
# DER SubjectPublicKeyInfo prefix of an uncompressed P-256 public key (id-ecPublicKey, prime256v1, BIT STRING)
_P256_SPKI_PREFIX = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")


# ----------------------------------------------------------------------------------------------- RFC 8785 (JCS)
def _number(value: Any) -> str:
    """An ECMAScript Number.prototype.toString of ``value`` (RFC 8785 section 3.2.2.3)."""
    if isinstance(value, int):
        if abs(value) <= 2 ** 53:
            return str(value)
        value = float(value)
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
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


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
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("only EC P-256 keys are used")
    x, y = b64url_decode(str(jwk["x"])), b64url_decode(str(jwk["y"]))
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
    """kid -> JWK from a JWKS document, a single JWK or a PEM public key (kid = its thumbprint-based id)."""
    stripped = text.strip()
    if stripped.startswith("-----BEGIN"):
        jwk = pem_to_jwk(stripped)
        return {key_id(jwk): jwk}
    doc = json.loads(stripped)
    keys = doc.get("keys") if isinstance(doc, dict) and "keys" in doc else [doc]
    out = {}
    for jwk in keys:
        if isinstance(jwk, dict) and jwk.get("kty") == "EC":
            out[str(jwk.get("kid") or key_id(jwk))] = jwk
    return out


def key_id(jwk: Dict[str, Any]) -> str:
    """The key id ZeroShield gives a key it did not name: ``zs-`` and the first 16 characters of its thumbprint."""
    return "zs-" + thumbprint(jwk)[:16]


def _pick(keys: Dict[str, Dict[str, Any]], kid: Optional[str],
          embedded: Optional[Dict[str, Any]] = None) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    if kid and kid in keys:
        return kid, keys[kid]
    if embedded is not None:  # a signature that carries its public key: trusted only when it IS one of the keys
        mine = {k: thumbprint(v) for k, v in keys.items()}
        try:
            theirs = thumbprint(embedded)
        except (KeyError, ValueError):
            theirs = None
        for k, tp in mine.items():
            if tp == theirs:
                return k, keys[k]
    return kid, None


# ----------------------------------------------------------------------------------------------- checks
def verify_bom(data: bytes, keys: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
    """Check the JSF ``signature`` embedded in a CycloneDX JSON BOM against ``keys``."""
    doc = json.loads(data.decode("utf-8"))
    sig = doc.get("signature") if isinstance(doc, dict) else None
    if not isinstance(sig, dict) or "value" not in sig:
        return {"valid": False, "reason": "the document has no JSF signature"}
    if sig.get("algorithm") != ALG:
        return {"valid": False, "reason": f"unsupported algorithm {sig.get('algorithm')!r}"}
    kid, jwk = _pick(keys, sig.get("keyId"), sig.get("publicKey"))
    if jwk is None:
        return {"valid": False, "kid": kid, "reason": "the signing key is not one of the trusted keys"}
    unsigned = dict(doc)
    unsigned["signature"] = {k: v for k, v in sig.items() if k != "value"}
    payload = canonicalize(unsigned)
    try:
        der = raw_to_der(b64url_decode(str(sig["value"])))
    except ValueError as exc:
        return {"valid": False, "kid": kid, "reason": str(exc)}
    ok = verify_digest(jwk, hashlib.sha256(payload).digest(), der, payload)
    return {"valid": ok, "kid": kid, "alg": ALG, "canonical_sha256": hashlib.sha256(payload).hexdigest(),
            **({} if ok else {"reason": "the signature does not match the document"})}


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
        except ValueError:
            continue
    return {"valid": False, "sha256": digest.hex(), "reason": "no trusted key verifies this signature"}


class _Pack:
    """A pack as a zip file or an unpacked directory."""

    def __init__(self, path: str):
        self.path = path
        self.zip = zipfile.ZipFile(path) if os.path.isfile(path) else None

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


def verify_pack(path: str, keys: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Every check of a pack (module docstring); ``keys`` default to the pack's own ``keys/jwks.json``."""
    pack = _Pack(path)
    names = set(pack.names())
    checks: List[Dict[str, Any]] = []
    own = keys is None
    if own:
        if "keys/jwks.json" not in names:
            return {"valid": False, "checks": [{"check": "keys", "valid": False,
                                                "reason": "no keys/jwks.json in the pack and no --keys given"}]}
        keys = load_keys(pack.read("keys/jwks.json").decode("utf-8"))
    assert keys is not None
    if "manifest.json" not in names or "manifest.json.sig" not in names:
        return {"valid": False, "checks": [{"check": "manifest", "valid": False,
                                            "reason": "manifest.json or manifest.json.sig is missing"}]}
    manifest_bytes = pack.read("manifest.json")
    res = verify_detached(manifest_bytes, pack.read("manifest.json.sig"), keys)
    checks.append({"check": "manifest.json.sig", **res})
    manifest = json.loads(manifest_bytes.decode("utf-8"))
    listed = manifest.get("files") or []
    for entry in listed:
        name = str(entry.get("name"))
        if name not in names:
            checks.append({"check": f"sha256 {name}", "valid": False, "reason": "listed in the manifest, not in the pack"})
            continue
        sha, size = hashlib.sha256(), 0
        for block in pack.chunks(name):
            sha.update(block)
            size += len(block)
        ok = sha.hexdigest() == entry.get("sha256") and (entry.get("bytes") is None or entry.get("bytes") == size)
        checks.append({"check": f"sha256 {name}", "valid": ok, **({} if ok else {"reason": "hash or size differs"})})
    covered = {str(e.get("name")) for e in listed} | {"manifest.json", "manifest.json.sig", "SHA256SUMS", "SHA256SUMS.sig"}
    for name in sorted(names - covered):
        checks.append({"check": f"listed {name}", "valid": False, "reason": "in the pack but not in the manifest"})
    for name in sorted(names):
        if name.endswith(".cdx.json"):
            doc = pack.read(name)
            try:
                signed = isinstance(json.loads(doc.decode("utf-8")).get("signature"), dict)
            except (ValueError, AttributeError):
                signed = False
            if signed:
                checks.append({"check": f"jsf {name}", **verify_bom(doc, keys)})
        if name.endswith(".sig") and name != "manifest.json.sig" and name[:-4] in names:
            checks.append({"check": f"detached {name}", **verify_detached(pack.read(name[:-4]), pack.read(name), keys)})
    out: Dict[str, Any] = {"valid": all(c.get("valid") for c in checks), "checks": checks}
    if own:
        out["keys"] = {kid: "sha256:" + thumbprint(jwk) for kid, jwk in keys.items()}
        out["note"] = ("The keys came from the pack itself: compare these fingerprints with the key your ZeroShield "
                       "deployment publishes (GET /{team}/bom-signing-keys) before trusting the result.")
    return out


# ----------------------------------------------------------------------------------------------- command line
def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Verify ZeroShield BOM signatures offline.")
    parser.add_argument("--keys", help="JWKS file, single JWK or PEM public key (pack: defaults to keys/jwks.json)")
    sub = parser.add_subparsers(dest="cmd", required=True)
    one = sub.add_parser("bom", help="the JSF signature embedded in a CycloneDX JSON BOM")
    one.add_argument("file")
    two = sub.add_parser("detached", help="a detached DER signature over a file's bytes")
    two.add_argument("file")
    two.add_argument("signature")
    three = sub.add_parser("pack", help="an evidence pack (zip or unpacked directory)")
    three.add_argument("path")
    args = parser.parse_args(argv)
    keys = None
    if args.keys:
        with open(args.keys, encoding="utf-8") as fh:
            keys = load_keys(fh.read())
    elif args.cmd != "pack":
        parser.error("--keys is required for bom and detached")
    if args.cmd == "bom":
        with open(args.file, "rb") as fh:
            result = verify_bom(fh.read(), keys or {})
    elif args.cmd == "detached":
        with open(args.file, "rb") as fh, open(args.signature, "rb") as sg:
            result = verify_detached(fh.read(), sg.read(), keys or {})
    else:
        result = verify_pack(args.path, keys)
    out = io.StringIO()
    json.dump(result, out, indent=2)
    print(out.getvalue())
    print("VERIFIED" if result.get("valid") else "NOT VERIFIED", file=sys.stderr)
    return 0 if result.get("valid") else 1


if __name__ == "__main__":
    sys.exit(main())
