"""D11 / G-X-3 (audits A-01, C G-X-3): BOM signatures a client can verify offline.

Failing first on dev 214d3ca1e: there is no asymmetric key, no JSF signature, no published key and no offline verifier
(``backend/utilities/cbom_sources/bom_signing.py`` / ``bom_verify.py`` do not exist; every signature is HMAC-SHA256 with
a server-held key).

Independent oracles: RFC 8785's own example (JCS), the published CycloneDX 1.6 + JSF 0.82 JSON schemas
(``support/cyclonedx_schema``), and the ``openssl`` command line for the detached signatures.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from backend.utilities.cbom_sources import bom_signing as SIGN
from backend.utilities.cbom_sources import bom_verify as V
from tests.support.cyclonedx_schema import json_errors

SECRET = "test-certin-secret-0123456789abcdef0123456789abcdef"


@pytest.fixture(autouse=True)
def _key_env(monkeypatch):
    for name in SIGN._ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CERTIN_HMAC_SECRET", SECRET)
    SIGN._CACHE.clear()
    yield
    SIGN._CACHE.clear()


def _bom(n: int = 3) -> dict:
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
        "version": 1,
        "metadata": {"timestamp": "2026-11-23T10:00:00Z", "properties": [{"name": "zs:x", "value": "€ \u0007 ü"}]},
        "components": [{"type": "cryptographic-asset", "bom-ref": f"zs-asset-{i}", "name": f"RSA-{1024 * (i + 1)}",
                        "cryptoProperties": {"assetType": "algorithm", "oid": "1.2.840.113549.1.1.1",
                                             "algorithmProperties": {"primitive": "pke",
                                                                     "nistQuantumSecurityLevel": 0}}}
                       for i in range(n)],
        "vulnerabilities": [],
    }


# ----------------------------------------------------------------------------------------------- JCS
def test_jcs_matches_rfc8785_example():
    raw = ('{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],'
           '"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}')
    expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
    assert V.canonicalize(json.loads(raw)).decode("utf-8") == expected


@pytest.mark.parametrize("value,text", [
    (0.0, "0"), (-0.0, "0"), (1.0, "1"), (1e20, "100000000000000000000"), (1e21, "1e+21"), (1e-6, "0.000001"),
    (1e-7, "1e-7"), (5e-324, "5e-324"), (1.7976931348623157e308, "1.7976931348623157e+308"), (-1.5, "-1.5"),
    (123456789012345680000.0, "123456789012345680000"), (2 ** 53, "9007199254740992"), (0.1, "0.1")])
def test_jcs_numbers_follow_ecmascript(value, text):
    assert V._number(value) == text


def test_jcs_sorts_by_utf16_code_units():
    # U+10000 (surrogate pair D800 DC00) sorts before U+FB33 in UTF-16, after it in code points
    assert V.canonicalize({"דּ": 1, "\U00010000": 2}).decode() == '{"\U00010000":2,"דּ":1}'


# ----------------------------------------------------------------------------------------------- keys
def test_key_is_derived_per_deployment_stable_and_rotatable(monkeypatch):
    first = SIGN.keyring().active
    SIGN._CACHE.clear()
    assert SIGN.keyring().active.public_jwk == first.public_jwk  # same secret: same key, on every worker
    assert first.kid == V.key_id(first.public_jwk) and first.kid.startswith("zs-")
    assert "derived from CERTIN_HMAC_SECRET" in first.source and SECRET not in json.dumps(SIGN.public_keys_document())
    monkeypatch.setenv("CBOM_SIGNING_KEY_GENERATION", "2")
    ring = SIGN.keyring()
    assert ring.active.kid != first.kid
    assert [k.kid for k in ring.retired] == [first.kid] and ring.retired[0].status == "retired"
    assert {k["kid"] for k in SIGN.jwks()["keys"]} == {first.kid, ring.active.kid}


def test_key_from_pem_env_and_explicit_kid(monkeypatch):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    key = ec.generate_private_key(ec.SECP256R1())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.NoEncryption()).decode()
    monkeypatch.setenv("CBOM_SIGNING_KEY_PEM", pem)
    monkeypatch.setenv("CBOM_SIGNING_KEY_ID", "bank-cbom-2026")
    ring = SIGN.keyring()
    assert ring.active.kid == "bank-cbom-2026" and ring.active.source == "CBOM_SIGNING_KEY_PEM"
    assert ring.active.public_jwk == SIGN._jwk_of(key)


def test_key_path_is_generated_once_and_persisted(monkeypatch, tmp_path):
    path = tmp_path / "keys" / "cbom-signing.pem"
    monkeypatch.setenv("CBOM_SIGNING_KEY_PATH", str(path))
    first = SIGN.keyring().active
    assert path.exists() and (path.stat().st_mode & 0o777) == 0o600
    SIGN._CACHE.clear()
    assert SIGN.keyring().active.public_jwk == first.public_jwk  # a restart reads the same key


def test_retired_public_keys_file_is_published(monkeypatch, tmp_path):
    monkeypatch.setenv("CBOM_SIGNING_KEY_GENERATION", "1")
    old = SIGN.keyring().active
    monkeypatch.setenv("CERTIN_HMAC_SECRET", SECRET + "-rotated")
    bundle = tmp_path / "retired.pem"
    bundle.write_text(old.pem())
    monkeypatch.setenv("CBOM_SIGNING_RETIRED_PUBLIC_KEYS", str(bundle))
    ring = SIGN.keyring()
    assert ring.active.kid != old.kid and ring.find(old.kid) is not None


def test_no_secret_means_unsigned_not_a_crash(monkeypatch):
    monkeypatch.delenv("CERTIN_HMAC_SECRET")
    monkeypatch.setenv("JWT_SECRET_KEY", "x" * 40)  # never a source: it signs sessions
    SIGN._CACHE.clear()
    assert SIGN.available() is False
    with pytest.raises(SIGN.SigningUnavailable):
        SIGN.keyring()
    out = io.BytesIO()
    assert SIGN.write_json(out, {"bomFormat": "CycloneDX", "specVersion": "1.6"}, iter([]),
                           [("vulnerabilities", list)]) is None
    assert "signature" not in json.loads(out.getvalue())


# ----------------------------------------------------------------------------------------------- JSF
def test_signed_bom_is_schema_valid_and_verifies():
    signed = SIGN.sign_bom(_bom())
    assert json_errors(signed) == []
    sig = signed["signature"]
    assert sig["algorithm"] == "ES256" and sig["keyId"] == SIGN.keyring().active.kid
    assert len(V.b64url_decode(sig["value"])) == 64  # JWA R || S
    data = json.dumps(signed).encode()
    assert SIGN.verify_bom(data)["valid"] is True
    assert SIGN.sign_bom(_bom()) == signed  # deterministic (RFC 6979): the same document signs to the same bytes


def test_tampered_or_foreign_bom_fails():
    signed = SIGN.sign_bom(_bom())
    tampered = json.loads(json.dumps(signed))
    tampered["components"][0]["name"] = "RSA-4096"
    assert SIGN.verify_bom(json.dumps(tampered).encode())["valid"] is False
    from cryptography.hazmat.primitives.asymmetric import ec

    stranger = SIGN.SigningKey("zs-stranger", {}, "active", "test", ec.generate_private_key(ec.SECP256R1()))
    stranger = SIGN.SigningKey("zs-stranger", SIGN._jwk_of(stranger._private), "active", "test", stranger._private)
    foreign = SIGN.sign_bom(_bom(), stranger)  # carries its own publicKey: not trusted for that
    out = SIGN.verify_bom(json.dumps(foreign).encode())
    assert out["valid"] is False and "not one of the trusted keys" in out["reason"]


def test_streamed_writer_signs_what_a_jsf_verifier_reads():
    """write_json never holds the document; its signature must equal the in-memory JCS signature of the parsed file."""
    bom = _bom(50)
    head = {k: bom[k] for k in ("bomFormat", "specVersion", "serialNumber", "version", "metadata")}
    deps = [{"ref": "zs-asset-0", "dependsOn": ["zs-asset-1"]}]
    out = io.BytesIO()
    written = SIGN.write_json(out, head, iter(bom["components"]), [("dependencies", lambda: deps),
                                                                  ("vulnerabilities", lambda: [])])
    doc = json.loads(out.getvalue())
    assert list(doc)[-1] == "signature" and doc["signature"] == written and doc["dependencies"] == deps
    assert json_errors(doc) == []
    assert SIGN.verify_bom(out.getvalue())["valid"] is True
    unsigned = {k: v for k, v in doc.items() if k != "signature"}
    assert SIGN.sign_bom(unsigned)["signature"] == written


# ----------------------------------------------------------------------------------------------- detached + openssl
needs_openssl = pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl CLI not installed")


@needs_openssl
def test_detached_signature_verifies_with_openssl(tmp_path):
    data = b"<bom>any bytes, e.g. the XML BOM</bom>\n"
    (tmp_path / "f.xml").write_bytes(data)
    (tmp_path / "f.xml.sig").write_bytes(SIGN.detached(data))
    (tmp_path / "k.pem").write_text(SIGN.keyring().active.pem())
    ok = subprocess.run(["openssl", "dgst", "-sha256", "-verify", "k.pem", "-signature", "f.xml.sig", "f.xml"],
                        cwd=tmp_path, capture_output=True, text=True)
    assert ok.returncode == 0 and "Verified OK" in ok.stdout
    (tmp_path / "f.xml").write_bytes(data + b" ")
    bad = subprocess.run(["openssl", "dgst", "-sha256", "-verify", "k.pem", "-signature", "f.xml.sig", "f.xml"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert bad.returncode != 0
    assert SIGN.verify_detached(data, SIGN.detached(data))["valid"] is True


@needs_openssl
def test_verifier_falls_back_to_openssl_without_cryptography(monkeypatch):
    import builtins

    real = builtins.__import__

    def no_cryptography(name, *a, **k):
        if name.startswith("cryptography"):
            raise ImportError(name)
        return real(name, *a, **k)

    signed = json.dumps(SIGN.sign_bom(_bom())).encode()
    keys = SIGN.keyring().verifier_keys()
    monkeypatch.setattr(builtins, "__import__", no_cryptography)
    assert V.verify_bom(signed, keys)["valid"] is True
    assert V.verify_bom(signed.replace(b"RSA-1024", b"RSA-1025"), keys)["valid"] is False


def _pack(tmp_path: Path) -> Path:
    bom = SIGN.bom_bytes(_bom(), indent=2)
    xml = b"<?xml version='1.0'?><bom/>\n"
    files = [("bom.cdx.json", bom), ("bom.cdx.xml", xml), ("report.pdf", b"%PDF-1.4 test")]
    added = SIGN.pack_files(files, subject={"kind": "test"}, detached_for=["bom.cdx.json", "bom.cdx.xml"])
    path = tmp_path / "pack.zip"
    with zipfile.ZipFile(path, "w") as zf:
        for name, body in [*files, *added]:
            zf.writestr(name, body)
    return path


def test_pack_manifest_covers_every_file_and_the_shipped_verifier_passes(tmp_path):
    path = _pack(tmp_path)
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        manifest = json.loads(zf.read("manifest.json"))
        assert zf.read(SIGN.VERIFIER_NAME) == SIGN.VERIFIER_PATH.read_bytes()
        sums = zf.read("SHA256SUMS").decode()
    listed = {e["name"] for e in manifest["files"]}
    assert listed == names - {"manifest.json", "manifest.json.sig", "SHA256SUMS", "SHA256SUMS.sig"}
    assert {"bom.cdx.xml.sig", "bom.cdx.json.sig", "keys/jwks.json", "verify/README.txt"} <= listed
    assert manifest["signing"]["kid"] == SIGN.keyring().active.kid
    assert sums.count("\n") == len(listed)
    # the verifier the client gets, run as the client would: isolated interpreter, the pack's own keys
    run = subprocess.run([sys.executable, "-I", str(SIGN.VERIFIER_PATH), "pack", str(path)],
                         capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    result = json.loads(run.stdout)
    assert result["valid"] is True and SIGN.keyring().active.kid in result["keys"]
    assert {c["check"] for c in result["checks"]} >= {"manifest.json.sig", "jsf bom.cdx.json",
                                                      "detached bom.cdx.xml.sig", "sha256 report.pdf"}


def test_pack_verifier_catches_a_changed_or_added_file(tmp_path):
    path = _pack(tmp_path)
    changed = tmp_path / "changed.zip"
    with zipfile.ZipFile(path) as src, zipfile.ZipFile(changed, "w") as dst:
        for name in src.namelist():
            body = src.read(name)
            dst.writestr(name, body + b" " if name == "report.pdf" else body)
        dst.writestr("extra.txt", b"smuggled")
    result = V.verify_pack(str(changed), SIGN.keyring().verifier_keys())
    failed = {c["check"] for c in result["checks"] if not c["valid"]}
    assert result["valid"] is False and failed == {"sha256 report.pdf", "listed extra.txt"}


@needs_openssl
def test_readme_openssl_steps_work_on_an_unzipped_pack(tmp_path):
    path = _pack(tmp_path)
    out = tmp_path / "unzipped"
    zipfile.ZipFile(path).extractall(out)
    kid = SIGN.keyring().active.kid
    for target in ("SHA256SUMS", "manifest.json", "bom.cdx.xml"):
        done = subprocess.run(["openssl", "dgst", "-sha256", "-verify", f"keys/{kid}.pem", "-signature",
                               f"{target}.sig", target], cwd=out, capture_output=True, text=True)
        assert done.returncode == 0 and "Verified OK" in done.stdout, target
    for line in (out / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split("  ", 1)
        assert hashlib.sha256((out / name).read_bytes()).hexdigest() == digest
    assert f"keys/{kid}.pem" in SIGN.readme_text(SIGN.keyring().active)


def test_public_keys_document_has_pem_jwk_and_fingerprint():
    doc = SIGN.public_keys_document()
    key = SIGN.keyring().active
    assert doc["active_kid"] == key.kid and doc["algorithm"] == "ES256"
    assert V.pem_to_jwk(doc["pem"][key.kid]) == key.public_jwk
    assert doc["fingerprints"][key.kid] == "sha256:" + V.thumbprint(key.public_jwk)
    jwk = doc["keys"][0]
    assert {jwk["kty"], jwk["crv"], jwk["use"], jwk["alg"]} == {"EC", "P-256", "sig", "ES256"}
    assert len(base64.urlsafe_b64decode(jwk["x"] + "=")) == 32
