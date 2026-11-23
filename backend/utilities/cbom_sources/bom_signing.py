"""Signatures a client can verify (SOW D11; the D4 SBOM and D5 AIBOM evidence packs use the same module).

Every BOM ZeroShield hands out is signed with ONE asymmetric key per deployment, ES256 (ECDSA P-256 / SHA-256,
deterministic RFC 6979 nonces, so a document signs to the same bytes every time), and the public key is published:

* **CycloneDX JSON**: an embedded JSON Signature Format (JSF 0.82) ``signature`` (``algorithm`` ES256, ``keyId``,
  ``publicKey`` JWK, ``value``), the form the CycloneDX 1.6 schema defines. It covers the RFC 8785 (JCS) canonical form
  of the whole document without ``signature.value`` (``bom_verify.canonicalize``).
* **Everything else** (CycloneDX XML, VEX, PDF, SPDX, SARIF): a detached DER signature (``<file>.sig``, what
  ``openssl dgst -sha256 -sign`` writes) over the exact bytes; an evidence pack signs its ``manifest.json`` (SHA-256 and
  size of every file) and ``SHA256SUMS`` the same way (``pack_files``).
* **The key** is published at ``GET /{team}/bom-signing-keys`` (JWKS + PEM, ``routers/bom_signing_keys.py``) and in
  every evidence pack (``keys/jwks.json``, ``keys/<kid>.pem``) with the offline verifier ``verify/zs_bom_verify.py``
  (``bom_verify``: stdlib, ``cryptography`` or the ``openssl`` CLI) and ``verify/README.txt``.

Where the key comes from (``keyring``; first match wins, nothing reaches the network, so it works air-gapped)
1. ``CBOM_SIGNING_KEY_PEM``: a PKCS#8 / SEC1 PEM EC P-256 private key in the environment (e.g. loaded from AWS Secrets
   Manager into the env by the deploy script).
2. ``CBOM_SIGNING_KEY_PATH``: a PEM file; when the file does not exist it is generated once (0600, written atomically,
   the first writer wins) and kept: put it on a persistent volume.
3. Derived per deployment (HKDF-SHA256, domain-separated) from ``CERTIN_HMAC_SECRET``, else ``ENCRYPTION_KEY``: a
   key that needs no storage, is the same on every worker and replica and survives restarts; never stored anywhere.
   ``CBOM_SIGNING_KEY_GENERATION`` (default 1) rotates it; the public keys of earlier generations stay published as
   ``retired`` so files signed before a rotation still verify.
Optional: ``CBOM_SIGNING_KEY_ID`` names the active key (default ``zs-`` + 16 characters of its RFC 7638 thumbprint);
``CBOM_SIGNING_RETIRED_PUBLIC_KEYS``: a file of PEM public keys (concatenated) that stay published after a rotation of
a configured key. With none of 1-3 the BOMs are served unsigned and say so (``SigningUnavailable``).

Small API (other lanes call these; keep it small)
-------------------------------------------------
``keyring()`` -> ``KeyRing`` (``.active``, ``.all()``, ``.find(kid)``); raises ``SigningUnavailable``.
``sign_bom(bom) -> dict``: a copy of an in-memory CycloneDX JSON BOM with the JSF ``signature`` (replacing any).
``bom_bytes(bom, indent=None) -> bytes``: ``sign_bom`` serialised (what a download serves).
``write_json(out, head, components, tail, sign=True)``: a streamed CycloneDX JSON BOM, signed while it is written.
``detached(data) -> bytes`` / ``detached_digest(sha256_digest) -> bytes``: DER signature for ``<file>.sig``.
``verify_bom(data) / verify_detached(data, sig)``: ``bom_verify``'s checks against this deployment's keys.
``pack_files(files, subject) -> list[(name, bytes)]``: what an evidence pack adds: ``keys/``, ``verify/``,
``manifest.json`` (+``.sig``), ``SHA256SUMS`` (+``.sig``) and the ``.sig`` of every name in ``detached_for``.
``jwks()`` / ``public_keys_document()``: the published keys.
"""
from __future__ import annotations

import base64
import datetime as _dt
import hashlib
import json
import os
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, BinaryIO, Callable, Iterable, Iterator, Sequence

from backend.utilities.cbom_sources import bom_verify as V

ALG = "ES256"
VERIFIER_NAME = "verify/zs_bom_verify.py"
VERIFIER_PATH = Path(V.__file__).resolve()
KEYS_ROUTE = "/{team_id}/bom-signing-keys"
_HKDF_SALT = b"zeroshield-bom-signing-v1"
# the order of each of these inputs matters: a change of one is a different key
_ENV = ("CBOM_SIGNING_KEY_PEM", "CBOM_SIGNING_KEY_PATH", "CBOM_SIGNING_KEY_ID", "CBOM_SIGNING_KEY_GENERATION",
        "CBOM_SIGNING_RETIRED_PUBLIC_KEYS", "CERTIN_HMAC_SECRET", "ENCRYPTION_KEY")


class SigningUnavailable(RuntimeError):
    """No signing key is configured (none of CBOM_SIGNING_KEY_PEM / _PATH, CERTIN_HMAC_SECRET, ENCRYPTION_KEY)."""


# ----------------------------------------------------------------------------------------------- keys
@dataclass(frozen=True)
class SigningKey:
    kid: str
    public_jwk: dict[str, str]
    status: str  # active | retired
    source: str  # where it came from (never the secret)
    _private: Any = field(default=None, repr=False, compare=False)

    def jwk(self) -> dict[str, str]:
        """The JWK the JSF ``publicKey`` carries (the schema allows only kty, crv, x, y there)."""
        return dict(self.public_jwk)

    def published(self) -> dict[str, str]:
        return {**self.public_jwk, "kid": self.kid, "use": "sig", "alg": ALG, "status": self.status}

    def pem(self) -> str:
        return V.jwk_to_pem(self.public_jwk)

    def fingerprint(self) -> str:
        return "sha256:" + V.thumbprint(self.public_jwk)

    def sign_digest(self, digest: bytes) -> bytes:
        """DER ES256 signature over a SHA-256 digest, deterministic (RFC 6979): same input, same bytes."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, utils

        if self._private is None:
            raise SigningUnavailable(f"key {self.kid} is retired: it verifies, it does not sign")
        return self._private.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256()), deterministic_signing=True))


@dataclass(frozen=True)
class KeyRing:
    active: SigningKey
    retired: tuple[SigningKey, ...] = ()

    def all(self) -> list[SigningKey]:
        return [self.active, *self.retired]

    def find(self, kid: str | None) -> SigningKey | None:
        return next((k for k in self.all() if k.kid == kid), None)

    def verifier_keys(self) -> dict[str, dict[str, Any]]:
        return {k.kid: k.public_jwk for k in self.all()}


def _jwk_of(private_or_public: Any) -> dict[str, str]:
    from cryptography.hazmat.primitives.asymmetric import ec

    public = private_or_public.public_key() if hasattr(private_or_public, "public_key") else private_or_public
    if not isinstance(public, ec.EllipticCurvePublicKey) or public.curve.name != "secp256r1":
        raise ValueError("the BOM signing key must be an EC P-256 key")
    nums = public.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": V.b64url(nums.x.to_bytes(32, "big")),
            "y": V.b64url(nums.y.to_bytes(32, "big"))}


def _load_private_pem(data: bytes) -> Any:
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_private_key(data, password=None)
    _jwk_of(key)  # checks the curve
    return key


def _generate_at(path: Path) -> Any:
    """Load the PEM at ``path``; generate it first when it does not exist (0600, O_EXCL: the first worker wins)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    if not path.exists():
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)
        try:
            os.link(tmp, path)  # atomic and fails if another worker made it first: its key is the key
        except FileExistsError:
            pass
        finally:
            tmp.unlink(missing_ok=True)
    return _load_private_pem(path.read_bytes())


def _derive(secret: str, generation: int) -> Any:
    """A P-256 private key from a deployment secret: HKDF-SHA256 (salt and info are fixed labels), 48 bytes reduced
    into [1, n-1] (bias below 2^-128)."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    okm = HKDF(algorithm=hashes.SHA256(), length=48, salt=_HKDF_SALT,
               info=f"zeroshield bom signing ES256 generation {generation}".encode()).derive(secret.encode("utf-8"))
    return ec.derive_private_key(int.from_bytes(okm, "big") % (order - 1) + 1, ec.SECP256R1())


def _retired_from_file(path: str) -> list[SigningKey]:
    text = Path(path).read_text(encoding="utf-8")
    out = []
    for block in text.split("-----END PUBLIC KEY-----"):
        if "-----BEGIN PUBLIC KEY-----" in block:
            pem = block[block.index("-----BEGIN PUBLIC KEY-----"):] + "-----END PUBLIC KEY-----\n"
            jwk = V.pem_to_jwk(pem)
            out.append(SigningKey(V.key_id(jwk), jwk, "retired", "CBOM_SIGNING_RETIRED_PUBLIC_KEYS"))
    return out


_CACHE: dict[str, KeyRing | SigningUnavailable] = {}
_LOCK = threading.Lock()


def keyring() -> KeyRing:
    """This deployment's signing keys (module docstring for the order of sources). Cached per configuration."""
    env = {name: os.environ.get(name) or "" for name in _ENV}
    fingerprint = hashlib.sha256(json.dumps(env, sort_keys=True).encode()).hexdigest()
    with _LOCK:
        hit = _CACHE.get(fingerprint)
        if hit is None:
            try:
                hit = _build(env)
            except SigningUnavailable as exc:
                hit = exc
            _CACHE.clear()
            _CACHE[fingerprint] = hit
    if isinstance(hit, SigningUnavailable):
        raise hit
    return hit


def _build(env: dict[str, str]) -> KeyRing:
    retired: list[SigningKey] = []
    if env["CBOM_SIGNING_KEY_PEM"].strip():
        private, source = _load_private_pem(env["CBOM_SIGNING_KEY_PEM"].strip().encode()), "CBOM_SIGNING_KEY_PEM"
    elif env["CBOM_SIGNING_KEY_PATH"].strip():
        private, source = _generate_at(Path(env["CBOM_SIGNING_KEY_PATH"].strip())), "CBOM_SIGNING_KEY_PATH"
    else:
        name = next((n for n in ("CERTIN_HMAC_SECRET", "ENCRYPTION_KEY") if env[n]), None)
        if name is None:
            raise SigningUnavailable("no BOM signing key: set CBOM_SIGNING_KEY_PEM or CBOM_SIGNING_KEY_PATH, or "
                                     "CERTIN_HMAC_SECRET to derive one")
        try:
            generation = max(1, int(env["CBOM_SIGNING_KEY_GENERATION"] or 1))
        except ValueError:
            generation = 1
        private, source = _derive(env[name], generation), f"derived from {name} (generation {generation})"
        for older in range(generation - 1, 0, -1):
            jwk = _jwk_of(_derive(env[name], older))
            retired.append(SigningKey(V.key_id(jwk), jwk, "retired", f"derived from {name} (generation {older})"))
    jwk = _jwk_of(private)
    kid = env["CBOM_SIGNING_KEY_ID"].strip() or V.key_id(jwk)
    if env["CBOM_SIGNING_RETIRED_PUBLIC_KEYS"].strip():
        retired += _retired_from_file(env["CBOM_SIGNING_RETIRED_PUBLIC_KEYS"].strip())
    retired = [k for k in retired if k.public_jwk != jwk]
    return KeyRing(SigningKey(kid, jwk, "active", source, private), tuple(retired))


def available() -> bool:
    try:
        keyring()
        return True
    except SigningUnavailable:
        return False


# ----------------------------------------------------------------------------------------------- JSON BOMs (JSF)
def skeleton(key: SigningKey) -> dict[str, Any]:
    """The JSF signer object without ``value`` (what is canonicalised and signed)."""
    return {"algorithm": ALG, "keyId": key.kid, "publicKey": key.jwk()}


def _jsf_value(key: SigningKey, digest: bytes) -> str:
    return V.b64url(V.der_to_raw(key.sign_digest(digest)))


def sign_bom(bom: dict[str, Any], key: SigningKey | None = None) -> dict[str, Any]:
    """A copy of ``bom`` with an embedded JSF ``signature`` (any earlier one is replaced)."""
    key = key or keyring().active
    unsigned = {k: v for k, v in bom.items() if k != "signature"}
    unsigned["signature"] = skeleton(key)
    digest = hashlib.sha256(V.canonicalize(unsigned)).digest()
    unsigned["signature"] = {**skeleton(key), "value": _jsf_value(key, digest)}
    return unsigned


def bom_bytes(bom: dict[str, Any], *, indent: int | None = None) -> bytes:
    """``sign_bom(bom)`` as the UTF-8 JSON a download serves."""
    seps = (",", ":") if indent is None else (",", ": ")
    return json.dumps(sign_bom(bom), ensure_ascii=False, allow_nan=False, indent=indent,
                      separators=seps).encode("utf-8")


def _dumps(value: Any) -> bytes:  # the bytes the streamed exports have always written (starlette's JSON encoding)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=None, separators=(",", ":")).encode()


def write_json(out: Any, head: dict[str, Any], components: Iterable[dict[str, Any]],
               tail: Sequence[tuple[str, Callable[[], Any]]], *, sign: bool = True) -> dict[str, Any] | None:
    """Write a CycloneDX JSON document piece by piece: ``head`` (the keys before ``components``), the components one
    at a time, then each ``(key, value())`` of ``tail`` (called once the components are written; an empty list is
    left out) and, when ``sign`` and a key is configured, the JSF ``signature`` last.

    The signature needs the whole document, which is never held: the JCS form is hashed while the bytes are written.
    JCS sorts members, so the canonical stream is: head members that sort before "components", the components (each
    canonicalised), then every other member in sorted order (head members after "components", the tail, and the
    signature without its value), all of which are known once the components are written. Returns the signature
    written (None when unsigned)."""
    key = None
    if sign:
        try:
            key = keyring().active
        except SigningUnavailable:
            key = None
    canon = hashlib.sha256() if key is not None else None
    if canon is not None:
        before = sorted((k for k in head if V._utf16_key(k) < V._utf16_key("components")), key=V._utf16_key)
        canon.update(b"{" + b"".join(V.canonicalize(k) + b":" + V.canonicalize(head[k]) + b"," for k in before)
                     + b'"components":[')
    out.write(_dumps(head)[:-1] + b',"components":[')
    for index, component in enumerate(components):
        out.write((b"," if index else b"") + _dumps(component))
        if canon is not None:
            canon.update((b"," if index else b"") + V.canonicalize(component))
    out.write(b"]")
    after: dict[str, Any] = {}
    for name, value_of in tail:
        value = value_of()
        if isinstance(value, list) and not value and name != "vulnerabilities":
            continue
        after[name] = value
        out.write(b',"' + name.encode() + b'":' + _dumps(value))
    if canon is None:
        out.write(b"}")
        return None
    rest = {k: v for k, v in head.items() if V._utf16_key(k) > V._utf16_key("components")}
    rest.update(after)
    rest["signature"] = skeleton(key)
    canon.update(b"]" + b"".join(b"," + V.canonicalize(k) + b":" + V.canonicalize(rest[k])
                                 for k in sorted(rest, key=V._utf16_key)) + b"}")
    signature = {**skeleton(key), "value": _jsf_value(key, canon.digest())}
    out.write(b',"signature":' + _dumps(signature) + b"}")
    return signature


# ----------------------------------------------------------------------------------------------- detached
def detached_digest(digest: bytes, key: SigningKey | None = None) -> bytes:
    """DER ES256 signature over a SHA-256 digest of a file's bytes (``<file>.sig``)."""
    return (key or keyring().active).sign_digest(digest)


def detached(data: bytes, key: SigningKey | None = None) -> bytes:
    return detached_digest(hashlib.sha256(data).digest(), key)


def verify_bom(data: bytes) -> dict[str, Any]:
    """The embedded JSF signature of a JSON BOM against this deployment's published keys."""
    return V.verify_bom(data, keyring().verifier_keys())


def verify_detached(data: bytes, signature: bytes, kid: str | None = None) -> dict[str, Any]:
    return V.verify_detached(data, signature, keyring().verifier_keys(), kid)


# ----------------------------------------------------------------------------------------------- publication
def jwks() -> dict[str, Any]:
    return {"keys": [k.published() for k in keyring().all()]}


def public_keys_document() -> dict[str, Any]:
    """What ``GET /{team}/bom-signing-keys`` serves: the JWKS, each key's PEM and fingerprint, and how to verify."""
    ring = keyring()
    return {
        **jwks(),
        "active_kid": ring.active.kid,
        "algorithm": ALG,
        "pem": {k.kid: k.pem() for k in ring.all()},
        "fingerprints": {k.kid: k.fingerprint() for k in ring.all()},
        "sources": {k.kid: k.source for k in ring.all()},
        "verify": readme_text(ring.active).splitlines(),
    }


def readme_text(key: SigningKey) -> str:
    return f"""ZeroShield BOM signatures: how to verify this pack offline
==========================================================

Signing key: {key.kid} (ES256 = ECDSA P-256 with SHA-256), fingerprint {key.fingerprint()}
(RFC 7638 JWK thumbprint). Before trusting anything below, compare this fingerprint with the key your ZeroShield
deployment publishes (GET /{{team}}/bom-signing-keys, field "fingerprints") or the one you were given out of band:
the copy in keys/ came with the pack and can only vouch for itself.

Files
  keys/jwks.json, keys/{key.kid}.pem   the public key(s), JWK set and PEM
  manifest.json                        SHA-256 and size of every other file of the pack
  manifest.json.sig, SHA256SUMS.sig    detached DER signatures (openssl format) of manifest.json and SHA256SUMS
  *.cdx.xml.sig, *.cdx.json.sig        detached signatures of the BOM files (exact bytes)
  *.cdx.json                           CycloneDX JSON with an embedded JSF signature (JCS / RFC 8785, ES256)
  verify/zs_bom_verify.py              this verifier (Python 3.8+, standard library; uses the 'cryptography'
                                       package when installed, else the openssl command line)

1. Everything at once (unzip first, or pass the zip):
     python3 verify/zs_bom_verify.py --keys keys/jwks.json pack .

2. With openssl and coreutils only:
     openssl dgst -sha256 -verify keys/{key.kid}.pem -signature SHA256SUMS.sig SHA256SUMS
     sha256sum -c SHA256SUMS
     openssl dgst -sha256 -verify keys/{key.kid}.pem -signature manifest.json.sig manifest.json
     openssl dgst -sha256 -verify keys/{key.kid}.pem -signature bom.cdx.xml.sig bom.cdx.xml
   Each openssl line prints "Verified OK".

3. The JSF signature inside a CycloneDX JSON BOM (a downloaded file on its own):
     python3 verify/zs_bom_verify.py --keys keys/jwks.json bom bom.cdx.json
   It removes signature.value, canonicalises the document with RFC 8785 (JCS) and checks the ES256 value
   (base64url R||S) against the key named by signature.keyId. Any JSF 0.82 verifier gives the same answer.

A file signed before a key rotation names its key id; the published key set keeps retired keys so it still
verifies. Nothing here needs network access.
"""


def pack_files(files: Sequence[tuple[str, "bytes | tuple[str, int]"]], *, subject: dict[str, Any],
               generated_at: _dt.datetime | str | None = None, detached_for: Iterable[str] = (),
               manifest_extra: dict[str, Any] | None = None) -> list[tuple[str, bytes]]:
    """What an evidence pack adds to its ``files`` so a client can verify it offline.

    ``files``: (name, bytes) or (name, (sha256 hex, size)) for a large file already hashed while written. Returns, in
    zip order: ``keys/jwks.json``, ``keys/<kid>.pem``, ``verify/zs_bom_verify.py``, ``verify/README.txt``, the
    ``<name>.sig`` of each name in ``detached_for``, ``manifest.json`` (``manifest_extra`` merged in; ``files`` lists
    every file above and every input file with its SHA-256 and size), ``manifest.json.sig``, ``SHA256SUMS`` and
    ``SHA256SUMS.sig``. Raises ``SigningUnavailable`` without a key."""
    key = keyring().active
    hashed: dict[str, tuple[str, int]] = {}
    for name, body in files:
        hashed[name] = (hashlib.sha256(body).hexdigest(), len(body)) if isinstance(body, bytes) else body
    extra: list[tuple[str, bytes]] = [
        ("keys/jwks.json", json.dumps(jwks(), indent=2).encode("utf-8")),
        *[(f"keys/{k.kid}.pem", k.pem().encode("ascii")) for k in keyring().all()],
        (VERIFIER_NAME, VERIFIER_PATH.read_bytes()),
        ("verify/README.txt", readme_text(key).encode("utf-8")),
    ]
    for name in detached_for:
        if name in hashed:
            extra.append((f"{name}.sig", detached_digest(bytes.fromhex(hashed[name][0]), key)))
    for name, body in extra:
        hashed[name] = (hashlib.sha256(body).hexdigest(), len(body))
    when = generated_at if isinstance(generated_at, str) or generated_at is None else \
        generated_at.strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "format": "zeroshield-evidence-pack/2",
        **({"generated_at": when} if when else {}),
        "subject": subject,
        "signing": {"alg": ALG, "kid": key.kid, "fingerprint": key.fingerprint(),
                    "manifest_signature": "manifest.json.sig", "sums_signature": "SHA256SUMS.sig",
                    "keys_route": KEYS_ROUTE, "verifier": VERIFIER_NAME},
        **(manifest_extra or {}),
    }
    listed = manifest.get("files") if isinstance(manifest.get("files"), list) else []
    known = {e.get("name") for e in listed if isinstance(e, dict)}
    listed = [{**e, "sha256": hashed[e["name"]][0], "bytes": hashed[e["name"]][1]} if e.get("name") in hashed else e
              for e in listed]
    listed += [{"name": n, "sha256": h, "bytes": s} for n, (h, s) in hashed.items() if n not in known]
    manifest["files"] = listed
    manifest_bytes = json.dumps(manifest, indent=2, ensure_ascii=False).encode("utf-8")
    sums = "".join(f"{h}  {n}\n" for n, (h, _s) in hashed.items()).encode("utf-8")
    return [*extra, ("manifest.json", manifest_bytes), ("manifest.json.sig", detached(manifest_bytes, key)),
            ("SHA256SUMS", sums), ("SHA256SUMS.sig", detached(sums, key))]


def signature_headers(sha256_digest: bytes) -> dict[str, str]:
    """Response headers of a signed download: ``X-ZS-Signature`` (base64 of the DER ES256 signature over the exact
    bytes served), its algorithm and key id, and ``X-Cbom-Sha256``; ``X-ZS-Signature: unsigned`` without a key."""
    headers = {"X-Cbom-Sha256": sha256_digest.hex()}
    try:
        key = keyring().active
    except SigningUnavailable:
        return {**headers, "X-ZS-Signature": "unsigned", "X-Cbom-Signature": "unsigned"}
    return {**headers, "X-ZS-Signature": base64.b64encode(detached_digest(sha256_digest, key)).decode("ascii"),
            "X-ZS-Signature-Alg": ALG, "X-ZS-Signature-Key-Id": key.kid, "X-Cbom-Signature": f"{ALG} {key.kid}"}


def signature_property(signed: dict[str, Any] | None) -> str:
    """``zs:signature`` metadata value: how the document is signed."""
    return f"JSF ES256 {signed['keyId']}" if signed else "unsigned"


def iter_chunks(out: BinaryIO, size: int = 1 << 20) -> Iterator[bytes]:
    while block := out.read(size):
        yield block


__all__ = ["ALG", "KeyRing", "signature_headers", "SigningKey", "SigningUnavailable", "available", "bom_bytes", "detached",
           "detached_digest", "jwks", "keyring", "pack_files", "public_keys_document", "readme_text", "sign_bom",
           "skeleton", "verify_bom", "verify_detached", "write_json"]
