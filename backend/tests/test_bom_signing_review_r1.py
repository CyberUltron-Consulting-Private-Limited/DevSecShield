"""PR #484 review 6026853603 (R1): the offline verifier and both verify routes, hardened.

Failing first on b71dd8d3a + dev (1b33b675; runs recorded in /home/claude/cb38/fa1/failing-first-r1.txt):
* D1 a duplicate JSON member (parser differential), NaN or 1e400 verified as valid, or crashed the route;
* D2 a pack zip holding two entries of one name verified, while first-wins extractors read the forged one;
* D3 the README verified a pack with its own key, and the verifier exited 0 with the pack's keys;
* D4 any file this deployment signed verified for any scan / run;
* D5 ``change-me`` and 1-character secrets derived a signing key;
* D6 the verify routes parsed the upload twice, buffered it twice and took up to 256 MB / 128 MB of JSON;
* D7 the run and code-scan ``/vex`` downloads carried no signature;
* minors: 500 / traceback on malformed signatures, ``write_json`` mis-signing a tail that sorts before
  "components", ``_pick`` by kid alone, ``sources`` in the published keys, rotation undocumented, a 0644 key file,
  integers beyond 2^53 signed as rounded doubles.

Oracles: hand-built tamper files (the reviewer's repros), the shipped verifier run as a separate, isolated
interpreter, ``openssl``-format DER signatures, and the published keys document.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_cbom_d11_signed_outputs import _add_scans  # noqa: E402
from test_cbom_posture import ASSETS, _store  # noqa: E402
import test_cbom_sources_api as SOURCES_API  # noqa: E402
import test_cbom_wp9_outputs as WP9  # noqa: E402

from backend.utilities.cbom_sources import bom_signing as SIGN  # noqa: E402
from backend.utilities.cbom_sources import bom_verify as V  # noqa: E402

globals().update(api=SOURCES_API.api, world=SOURCES_API.world, http=WP9.http)
REPO = Path(__file__).resolve().parents[2]
HDR = {"Authorization": "Bearer t"}


@pytest.fixture(autouse=True)
def _key(bom_signing_fixture_key):
    yield bom_signing_fixture_key


def _bom(n: int = 2, serial: str = "urn:uuid:11111111-2222-4333-8444-555555555555", **extra) -> dict:
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": serial, "version": 1,
            "metadata": {"timestamp": "2026-11-24T00:00:00Z"},
            "components": [{"type": "cryptographic-asset", "bom-ref": f"zs-asset-{i}", "name": f"RSA-{2048 + i}"}
                           for i in range(n)], **extra}


def _keys() -> dict:
    return SIGN.keyring().verifier_keys()


def _verifier(tmp_path: Path, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """The verifier a pack ships, in an isolated interpreter (no repo on sys.path)."""
    script = tmp_path / "zs_bom_verify.py"
    script.write_bytes(Path(V.__file__).read_bytes())
    return subprocess.run([sys.executable, "-I", str(script), *args], input=stdin, capture_output=True, text=True,
                          cwd=tmp_path)


def _forged_duplicate(raw: bytes) -> bytes:
    """The reviewer's D1 repro: a first-wins reader sees FORGED, a last-wins verifier the signed document."""
    assert raw.startswith(b"{")
    return b'{"components":[{"type":"library","bom-ref":"x","name":"FORGED"}],' + raw[1:]


# ----------------------------------------------------------------------------------------------- D1
@pytest.mark.parametrize("mutate,word", [
    (_forged_duplicate, "duplicate"),
    (lambda raw: raw.replace(b'"version":1', b'"version":NaN', 1), "NaN"),
    (lambda raw: raw.replace(b'"version":1', b'"version":1e400', 1), "double range"),
    (lambda raw: raw.replace(b'"version":1', b'"version":9007199254740993', 1), "2^53"),
])
def test_d1_verifier_refuses_what_is_not_i_json(mutate, word, tmp_path):
    raw = SIGN.bom_bytes(_bom())
    assert V.verify_bom(raw, _keys())["valid"] is True
    bad = mutate(raw)
    out = V.verify_bom(bad, _keys())
    assert out["valid"] is False and word in out["reason"], out
    (tmp_path / "bad.cdx.json").write_bytes(bad)
    (tmp_path / "trusted").mkdir()
    (tmp_path / "trusted" / "keys.json").write_text(json.dumps(SIGN.public_keys_document()))
    done = _verifier(tmp_path, "--keys", "trusted/keys.json", "bom", "bad.cdx.json")
    assert done.returncode == 1 and "Traceback" not in done.stderr, done.stderr


def test_d1_scan_route_refuses_a_duplicate_member_file(http):
    client, _engine, _calls = http
    raw = client.get("/1/cbom/scan/2/bom?format=json", headers=HDR).content
    verify = "/1/cbom/scan/2/signature/verify"
    assert client.post(verify, headers=HDR, content=raw).json()["valid"] is True
    forged = _forged_duplicate(raw)
    r = client.post(verify, headers=HDR, content=forged)
    assert r.status_code == 400 and r.json()["detail"].startswith("Not verified: duplicate"), r.text
    nan = raw.replace(b'"version":1', b'"version":NaN', 1)
    assert nan != raw and client.post(verify, headers=HDR, content=nan).status_code == 400


def test_d1_run_route_refuses_a_duplicate_member_file(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    verify = f"/1/cbom/sources/runs/{run['id']}/signature/verify"
    raw = api("GET", f"/1/cbom/sources/runs/{run['id']}/cbom").content
    assert api("POST", verify, content=raw).json()["valid"] is True
    r = api("POST", verify, content=_forged_duplicate(raw))
    assert r.status_code == 400 and "duplicate" in r.text, r.text


# ----------------------------------------------------------------------------------------------- D2
def _pack(files: dict[str, bytes]) -> list[tuple[str, bytes]]:
    members = list(files.items())
    return members + SIGN.pack_files(members, subject={"kind": "test", "scan_id": 1},
                                     detached_for=[n for n in files if n.endswith(".cdx.json")])


def _zip(path: Path, members: list[tuple[str, bytes]]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, body in members:
            zf.writestr(name, body)
    return path


def test_d2_pack_with_a_duplicate_entry_is_refused(tmp_path):
    genuine = _pack({"bom.cdx.json": SIGN.bom_bytes(_bom(3))})
    forged = SIGN.bom_bytes(_bom(1))  # what `unzip -n` and other first-wins readers extract
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # zipfile warns about the duplicate name: that is the attack
        path = _zip(tmp_path / "dup.zip", [("bom.cdx.json", forged), *genuine])
    assert V.verify_pack(str(_zip(tmp_path / "ok.zip", genuine)), _keys())["valid"] is True
    out = V.verify_pack(str(path), _keys())
    assert out["valid"] is False and any("two zip entries" in c.get("reason", "") for c in out["checks"]), out
    (tmp_path / "k").mkdir()
    (tmp_path / "k" / "keys.json").write_text(json.dumps(SIGN.jwks()))
    done = _verifier(tmp_path, "--keys", "k/keys.json", "pack", "dup.zip")
    assert done.returncode == 1 and "NOT VERIFIED" in done.stderr and "Traceback" not in done.stderr


@pytest.mark.parametrize("name", ["../evil.txt", "/etc/evil", "BOM.cdx.json"])
def test_d2_pack_names_outside_or_case_colliding_are_refused(tmp_path, name):
    genuine = _pack({"bom.cdx.json": SIGN.bom_bytes(_bom())})
    path = _zip(tmp_path / "p.zip", [*genuine, (name, b"x")])
    out = V.verify_pack(str(path), _keys())
    assert out["valid"] is False and out["checks"][0]["check"].startswith("entry"), out


# ----------------------------------------------------------------------------------------------- D3
def test_d3_readme_step_one_uses_the_deployment_key_not_the_pack_copy():
    text = SIGN.readme_text(SIGN.keyring().active)
    assert "--keys keys/jwks.json" not in text and "--keys keys/" not in text
    step1 = text.split("\n1. ", 1)[1].split("\n2. ", 1)[0]
    assert "bom-signing-keys" in step1 and "--keys ~/zeroshield-bom-keys.json pack ." in step1
    assert "UNTRUSTED KEY" in step1


def test_d3_keys_from_inside_the_pack_never_exit_zero(tmp_path):
    members = _pack({"bom.cdx.json": SIGN.bom_bytes(_bom())})
    unpacked = tmp_path / "pack"
    for name, body in members:
        (unpacked / name).parent.mkdir(parents=True, exist_ok=True)
        (unpacked / name).write_bytes(body)
    _zip(tmp_path / "pack.zip", members)
    (tmp_path / "trusted.json").write_text(json.dumps(SIGN.public_keys_document()))
    no_keys = _verifier(tmp_path, "pack", "pack.zip")
    assert no_keys.returncode == 3 and "UNTRUSTED KEY" in no_keys.stderr, (no_keys.returncode, no_keys.stderr)
    inside = _verifier(tmp_path, "--keys", "pack/keys/jwks.json", "pack", "pack")
    assert inside.returncode == 3 and "UNTRUSTED KEY" in inside.stderr
    bom_inside = _verifier(tmp_path, "--keys", "pack/keys/jwks.json", "bom", "pack/bom.cdx.json")
    assert bom_inside.returncode == 3
    trusted = _verifier(tmp_path, "--keys", "trusted.json", "pack", "pack.zip")
    assert trusted.returncode == 0 and "VERIFIED" in trusted.stderr and json.loads(trusted.stdout)["trusted_keys"]
    accepted = _verifier(tmp_path, "--trust-pack-keys", "pack", "pack.zip")
    assert accepted.returncode == 0


def test_d3_keys_document_publishes_the_verifier_digest():
    doc = SIGN.public_keys_document()
    assert doc["verifier"]["sha256"] == hashlib.sha256(Path(V.__file__).read_bytes()).hexdigest()


# ----------------------------------------------------------------------------------------------- D4
def test_d4_scan_verify_refuses_another_scans_file(http):
    client, engine, _calls = http
    _add_scans(engine)
    verify = "/1/cbom/scan/2/signature/verify"
    aibom = client.get("/1/ai_bom/scan/21/bom?format=json", headers=HDR)
    assert aibom.status_code == 200
    out = client.post(verify, headers=HDR, content=aibom.content).json()
    assert (out["valid"], out["signed_by_deployment"]) == (False, True), out
    assert "not this scan" in out["reason"]
    own = client.post("/1/ai_bom/scan/21/signature/verify", headers=HDR, content=aibom.content).json()
    assert own["valid"] is True and own["bound"] is True
    sbom = client.get("/1/sbom_sca/scan/22/bom?format=json", headers=HDR)
    det = client.post(verify, headers={**HDR, "X-ZS-Signature-B64": sbom.headers["x-zs-signature"]},
                      content=sbom.content).json()
    assert (det["valid"], det["signed_by_deployment"], det["method"]) == (False, True, "detached ES256"), det
    xml = client.get("/1/cbom/scan/2/bom?format=xml", headers=HDR)
    det_xml = client.post(verify, headers={**HDR, "X-ZS-Signature-B64": xml.headers["x-zs-signature"]},
                          content=xml.content).json()
    assert det_xml["valid"] is True and det_xml["bound"] is True, det_xml


def test_d4_run_verify_refuses_another_runs_file(api, world):
    engine, _ = world
    _s1, first = _store(api, engine, ASSETS[:2])
    second = {"id": _another_run(engine, first["id"])}
    a = api("GET", f"/1/cbom/sources/runs/{first['id']}/cbom")
    verify_b = f"/1/cbom/sources/runs/{second['id']}/signature/verify"
    det = api("POST", verify_b, content=a.content, headers={"X-ZS-Signature-B64": a.headers["x-zs-signature"]}).json()
    assert (det["valid"], det["signed_by_deployment"]) == (False, True), det
    emb = api("POST", verify_b, content=a.content).json()
    assert (emb["valid"], emb["signed_by_deployment"]) == (False, True), emb
    own = api("POST", f"/1/cbom/sources/runs/{first['id']}/signature/verify", content=a.content,
              headers={"X-ZS-Signature-B64": a.headers["x-zs-signature"]}).json()
    assert own["valid"] is True
    xml = api("GET", f"/1/cbom/sources/runs/{first['id']}/cbom?format=xml")
    xml_b = api("POST", verify_b, content=xml.content, headers={"X-ZS-Signature-B64": xml.headers["x-zs-signature"]})
    assert (xml_b.json()["valid"], xml_b.json()["signed_by_deployment"]) == (False, True), xml_b.text
    xml_a = api("POST", f"/1/cbom/sources/runs/{first['id']}/signature/verify", content=xml.content,
                headers={"X-ZS-Signature-B64": xml.headers["x-zs-signature"]})
    assert xml_a.json()["valid"] is True, xml_a.text


def _another_run(engine, run_id: int) -> int:
    """A second run of team 1 (same source, no assets): its own run id, so its own files."""
    from sqlmodel import Session

    from backend.new_models import CbomCollectionRun

    with Session(engine) as s:
        first = s.get(CbomCollectionRun, run_id)
        other = CbomCollectionRun(**{**first.model_dump(exclude={"id"}), "client_request_id": f"r1-other-of-{run_id}"})
        s.add(other)
        s.commit()
        return other.id


# ----------------------------------------------------------------------------------------------- D5
@pytest.mark.parametrize("secret", ["change-me", "x", "a" * 31, "ab" * 40, "change-me-change-me-change-me-change-me",
                                    "generate_a_fernet_key", "zeroshield-tests-only-bom-signing-fixture-seed-v1-public"])
@pytest.mark.parametrize("name", ["CERTIN_HMAC_SECRET", "ENCRYPTION_KEY"])
def test_d5_weak_or_default_seeds_are_refused(monkeypatch, secret, name):
    for var in SIGN._ENV:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv(name, secret)
    SIGN._CACHE.clear()
    with pytest.raises(SIGN.SigningUnavailable) as err:
        SIGN.keyring()
    assert name in str(err.value) and (len(secret) < 4 or secret not in str(err.value))  # never the value
    assert SIGN.signature_headers(b"\0" * 32)["X-ZS-Signature"] == "unsigned"


def test_d5_a_strong_seed_still_derives_and_ci_has_its_fixture_key(monkeypatch, bom_signing_fixture_key):
    assert bom_signing_fixture_key.active.kid == "zs-tests-fixture"
    monkeypatch.delenv("CBOM_SIGNING_KEY_PEM")
    monkeypatch.delenv("CBOM_SIGNING_KEY_ID")
    monkeypatch.setenv("CERTIN_HMAC_SECRET", base64.b16encode(hashlib.sha256(b"r1").digest()).decode())
    SIGN._CACHE.clear()
    assert SIGN.keyring().active.source.startswith("derived from CERTIN_HMAC_SECRET")


def test_d5_every_deploy_generator_yields_a_seed_the_backend_accepts():
    """The code paths that make the staging / production / local values (never the values themselves)."""
    sys.path.insert(0, str(REPO / "deploy" / "chola-prod"))
    import kit  # noqa: E402

    assert SIGN.weak_seed(kit.generate(kit.GENERATED["CERTIN_HMAC_SECRET"])) is None
    assert SIGN.weak_seed(kit.generate(kit.GENERATED["ENCRYPTION_KEY"])) is None
    init_env = (REPO / "deploy" / "local" / "init-env.sh").read_text()
    assert "*) openssl rand -hex 20 ;;" in init_env  # 40 hex characters for CERTIN_HMAC_SECRET
    assert SIGN.weak_seed(os.urandom(20).hex()) is None
    staging = (REPO / "scripts" / "deploy" / "staging.sh").read_text()
    assert "check_bom_signing_seed" in staging.split("require_host_files() {", 1)[1].split("\n}\n", 1)[0]


# ----------------------------------------------------------------------------------------------- D6
def test_d6_verify_caps_and_parses_once(http, monkeypatch):
    from backend.routers import cbom_run_deliverables as RUNS
    from backend.routers import certin

    assert certin.VERIFY_MAX_BYTES <= 64 * 1024 * 1024 and RUNS.EMBEDDED_MAX_BYTES <= 64 * 1024 * 1024
    client, _engine, _calls = http
    raw = client.get("/1/cbom/scan/2/bom?format=json", headers=HDR).content
    calls = []
    real = json.loads

    def counting(*a, **k):
        calls.append(len(a[0]) if a else 0)
        return real(*a, **k)

    monkeypatch.setattr(json, "loads", counting)
    assert client.post("/1/cbom/scan/2/signature/verify", headers=HDR, content=raw).json()["valid"] is True
    assert sum(1 for n in calls if n >= len(raw) // 2) == 1, calls  # the upload is parsed once
    too_big = client.post("/1/cbom/scan/2/signature/verify", headers=HDR, content=b" " * (64 * 1024 * 1024 + 1))
    assert too_big.status_code == 413


def test_d6_canonical_digest_is_streamed_and_equal():
    doc = _bom(500)
    assert V.canonical_sha256(doc) == hashlib.sha256(V.canonicalize(doc)).digest()


# ----------------------------------------------------------------------------------------------- D7
def test_d7_run_vex_download_is_signed_inside_and_detached(api, world):
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:2])
    r = api("GET", f"/1/cbom/sources/runs/{run['id']}/vex")
    assert r.status_code == 200
    assert SIGN.verify_detached(r.content, base64.b64decode(r.headers["x-zs-signature"]))["valid"] is True
    assert SIGN.verify_bom(r.content)["valid"] is True
    from tests.support.cyclonedx_schema import json_errors

    assert json_errors(json.loads(r.content)) == []  # the JSF member is the CycloneDX 1.6 one
    out = api("POST", f"/1/cbom/sources/runs/{run['id']}/signature/verify", content=r.content,
              headers={"X-ZS-Signature-B64": r.headers["x-zs-signature"]}).json()
    assert out["valid"] is True, out


def test_d7_code_scan_vex_download_and_pack_copy_are_signed(http):
    client, engine, _calls = http
    _add_scans(engine)
    for scan_type, scan_id in (("cbom", 2), ("sbom_sca", 22)):
        r = client.get(f"/1/{scan_type}/scan/{scan_id}/vex", headers=HDR)
        assert r.status_code == 200, r.text
        assert SIGN.verify_detached(r.content, base64.b64decode(r.headers["x-zs-signature"]))["valid"] is True
        assert SIGN.verify_bom(r.content)["valid"] is True
        ok = client.post(f"/1/{scan_type}/scan/{scan_id}/signature/verify", headers=HDR, content=r.content).json()
        assert ok["valid"] is True, ok
        pack = zipfile.ZipFile(io.BytesIO(client.get(f"/1/{scan_type}/scan/{scan_id}/evidence-pack",
                                                     headers=HDR).content))
        assert "vex.json.sig" in pack.namelist() and SIGN.verify_bom(pack.read("vex.json"))["valid"] is True


# ----------------------------------------------------------------------------------------------- minors
@pytest.mark.parametrize("signature", [
    {"algorithm": "ES256", "keyId": ["k"], "value": "AA"},
    {"algorithm": "ES256", "keyId": "k", "publicKey": "not a jwk", "value": "AA"},
    {"algorithm": "ES256", "keyId": "k", "value": 5},
])
def test_minor1_malformed_signatures_are_4xx_and_no_traceback(http, api, world, tmp_path, signature):
    doc = {**_bom(), "signature": signature}
    body = json.dumps(doc).encode()
    out = V.verify_bom(body, _keys())
    assert out["valid"] is False
    client, _engine, _calls = http
    r = client.post("/1/cbom/scan/2/signature/verify", headers=HDR, content=body)
    assert r.status_code == 400, r.text
    engine, _ = world
    _src, run = _store(api, engine, ASSETS[:1])
    rr = api("POST", f"/1/cbom/sources/runs/{run['id']}/signature/verify", content=body)
    assert rr.status_code == 400, rr.text
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "keys.json").write_text(json.dumps(SIGN.jwks()))
    (tmp_path / "f.cdx.json").write_bytes(body)
    done = _verifier(tmp_path, "--keys", "t/keys.json", "bom", "f.cdx.json")
    assert done.returncode == 1 and "Traceback" not in done.stderr


def test_minor2_write_json_refuses_a_tail_that_would_mis_sign():
    out = io.BytesIO()
    with pytest.raises(ValueError):
        SIGN.write_json(out, {"bomFormat": "CycloneDX"}, iter([]), [("annotations", lambda: [{"x": 1}])])
    assert out.getvalue() == b""
    out = io.BytesIO()
    SIGN.write_json(out, {"bomFormat": "CycloneDX"}, iter([{"bom-ref": "a"}]), [("vulnerabilities", lambda: [])])
    assert SIGN.verify_bom(out.getvalue())["valid"] is True


def test_minor3_reused_key_id_after_rotation_finds_the_old_key(monkeypatch, tmp_path):
    old_ring = SIGN.keyring()
    old_file = SIGN.bom_bytes(_bom())
    assert json.loads(old_file)["signature"]["keyId"] == "zs-tests-fixture"
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    new = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    bundle = tmp_path / "retired.pem"
    bundle.write_text(old_ring.active.pem())
    monkeypatch.setenv("CBOM_SIGNING_KEY_PEM", new)  # the same CBOM_SIGNING_KEY_ID, a new key
    monkeypatch.setenv("CBOM_SIGNING_RETIRED_PUBLIC_KEYS", str(bundle))
    SIGN._CACHE.clear()
    ring = SIGN.keyring()
    assert ring.active.kid == "zs-tests-fixture" and len({k.kid for k in ring.all()}) == len(ring.all()) == 2
    assert SIGN.verify_bom(old_file)["valid"] is True
    # and a keyId of a trusted key never lends its trust to another key
    forged = json.loads(SIGN.bom_bytes(_bom()))
    forged["signature"]["publicKey"] = SIGN._jwk_of(ec.generate_private_key(ec.SECP256R1()))
    assert SIGN.verify_bom(json.dumps(forged).encode())["valid"] is False


def test_minor4_keys_document_does_not_say_where_the_key_comes_from():
    doc = SIGN.public_keys_document()
    assert "sources" not in doc and "CERTIN_HMAC_SECRET" not in json.dumps(doc)


def test_minor5_rotation_is_documented():
    text = (REPO / "docs" / "security" / "secret-rotation.md").read_text()
    assert "BOM signing key" in text and "CBOM_SIGNING_RETIRED_PUBLIC_KEYS" in text
    assert "CBOM_SIGNING_KEY_GENERATION" in text


def test_minor6_an_existing_0644_key_file_is_tightened_and_new_ones_are_fsynced(monkeypatch, tmp_path):
    for var in SIGN._ENV:
        monkeypatch.delenv(var, raising=False)
    synced = []
    real = os.fsync
    monkeypatch.setattr(os, "fsync", lambda fd: (synced.append(fd), real(fd))[1])
    path = tmp_path / "k.pem"
    monkeypatch.setenv("CBOM_SIGNING_KEY_PATH", str(path))
    SIGN._CACHE.clear()
    SIGN.keyring()
    assert synced and stat.S_IMODE(path.stat().st_mode) == 0o600
    os.chmod(path, 0o644)
    SIGN._CACHE.clear()
    monkeypatch.setenv("CBOM_SIGNING_KEY_ID", "again")  # a new configuration: the file is read again
    SIGN.keyring()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_minor7_integers_beyond_2_53_are_refused_when_signing():
    with pytest.raises(ValueError):
        V.canonicalize({"n": 9007199254740993})
    with pytest.raises(ValueError):
        SIGN.sign_bom(_bom(serialNumberInt=2 ** 60))
    assert V.canonicalize({"n": 9007199254740991}) == b'{"n":9007199254740991}'


def test_minor10_aibom_golden_label_names_this_pr():
    golden = json.loads((REPO / "aibom" / "tests" / "fixtures" / "frozen_goldens" / "base_commit_digests.json").read_text())
    assert "#484" in golden["digests_from"] and golden["base_commit"].startswith("f7385517")


def test_minor12_readme_explains_the_uri_format_of_the_jsf_schema():
    text = SIGN.readme_text(SIGN.keyring().active)
    assert '"format": "uri"' in text and "ES256" in text


