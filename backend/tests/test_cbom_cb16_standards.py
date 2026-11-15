"""CB-16: standards status per asset (FIPS 203/204/205, NSA CNSA 2.0, NIST SP 800-131A).

DEVILS-ADVOCATE CB-16 failing-first:
* a Sources RSA-2048 certificate -> SP 800-131A acceptable, CNSA 2.0 not compliant;
* ML-KEM-768 -> FIPS 203 category 3, CNSA 2.0 not compliant;
* the same algorithm in the code lane and the Sources lane gets identical statuses (one module, two byte-identical
  copies: backend/utilities/cbom_sources/standards.py and aibom/src/aibom/cbom/standards.py; the categories also agree
  with the code lane's own pqc.py grader);
and the statuses reach the classifier output, its digest, the asset drawer (asset detail API) and the export.

    cd backend && PYTHONPATH=.. python -m pytest tests/test_cbom_cb16_standards.py -q
"""
from __future__ import annotations

import ast
import datetime as dt
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_cbom_cb19_run_grades as GR  # noqa: E402

from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import standards as S  # noqa: E402

ROOT = Path(__file__).resolve().parents[2]
BACKEND_COPY = ROOT / "backend/utilities/cbom_sources/standards.py"
CODE_COPY = ROOT / "aibom/src/aibom/cbom/standards.py"
NOW = dt.datetime(2026, 11, 14, 9, 0)
api, world = GR.api, GR.world


def _code_lane_standards():
    """The code lane's copy, imported inside a private package built on aibom/src/aibom/cbom (so its relative
    ``from . import algid`` reads the code lane's vendored algid, as the worker does)."""
    pkg = "cb16_code_lane"
    if f"{pkg}.standards" in sys.modules:
        return sys.modules[f"{pkg}.standards"]
    folder = ROOT / "aibom/src/aibom/cbom"
    spec = importlib.util.spec_from_file_location(pkg, folder / "__init__.py", submodule_search_locations=[str(folder)])
    module = importlib.util.module_from_spec(spec)
    sys.modules[pkg] = module
    spec.loader.exec_module(module)
    return importlib.import_module(f"{pkg}.standards")


def _status(result: dict, standard: str) -> str:
    return result[standard]["status"]


def test_a_sources_rsa_2048_certificate_is_800_131a_acceptable_and_not_cnsa_2_0():
    v = C.classify("certificate", "RSA", 2048, None, {"subject": "CN=web", "issuer": "CN=CA", "key_alg": "RSA",
                                                      "key_size": 2048, "sig_alg": "sha256WithRSAEncryption",
                                                      "not_after": "2030-01-01T00:00:00Z"}, NOW)
    st = v["standards"]
    assert _status(st, "sp800_131a") == "acceptable" and _status(st, "cnsa_2_0") == "not_compliant"
    assert _status(st, "fips_203_204_205") == "not_applicable"
    assert any("2030" in r for r in st["sp800_131a"]["reasons"])  # IR 8547: 112-bit deprecated after 2030


def test_ml_kem_768_is_fips_203_category_3_and_not_cnsa_2_0_while_1024_is():
    v = C.classify("public_key", "ML-KEM-768", None, None, {}, NOW)["standards"]
    assert _status(v, "fips_203_204_205") == "approved"
    assert v["fips_203_204_205"]["standard"] == "FIPS 203" and v["fips_203_204_205"]["category"] == 3
    assert _status(v, "cnsa_2_0") == "not_compliant"
    top = C.classify("public_key", "ML-KEM-1024", None, None, {}, NOW)["standards"]
    assert _status(top, "cnsa_2_0") == "compliant" and top["fips_203_204_205"]["category"] == 5
    assert _status(C.classify("signing_key", "ML-DSA-87", None, None, {}, NOW)["standards"], "cnsa_2_0") == "compliant"
    assert _status(C.classify("signing_key", "SLH-DSA-SHA2-256s", None, None, {}, NOW)["standards"],
                   "cnsa_2_0") == "not_compliant"  # FIPS 205 is approved, but not a CNSA 2.0 algorithm


def test_disallowed_keys_and_signatures_fail_800_131a():
    assert _status(C.classify("certificate", "RSA", 1024, None, {"sig_alg": "sha256WithRSAEncryption"}, NOW)
                   ["standards"], "sp800_131a") == "disallowed"
    sha1 = C.classify("certificate", "RSA", 2048, None, {"sig_alg": "sha1WithRSAEncryption"}, NOW)["standards"]
    assert _status(sha1, "sp800_131a") == "disallowed" and any("SHA-1" in r for r in sha1["sp800_131a"]["reasons"])
    assert _status(C.classify("private_key", "EC", 160, None, {}, NOW)["standards"], "sp800_131a") == "disallowed"
    unread = C.classify("private_key", "RSA", None, None, {}, NOW)["standards"]
    assert _status(unread, "sp800_131a") == "unknown"  # a key size not read is never "acceptable"


def test_tls_endpoint_standards_read_the_cipher_and_the_group():
    v = C.classify("tls_endpoint", "TLS_AES_256_GCM_SHA384", None, "TLSv1.3",
                   {"protocols": ["TLSv1.3"], "negotiated_cipher": "TLS_AES_256_GCM_SHA384", "group": "secp384r1"},
                   NOW)["standards"]
    assert _status(v, "sp800_131a") == "acceptable"
    assert _status(v, "cnsa_2_0") == "not_compliant"  # a classical ECDH group
    old = C.classify("tls_endpoint", "DES-CBC3-SHA", None, "TLSv1.2",
                     {"protocols": ["TLSv1.2"], "negotiated_cipher": "DES-CBC3-SHA"}, NOW)["standards"]
    assert _status(old, "sp800_131a") == "disallowed"
    hybrid = C.classify("tls_endpoint", "TLS_AES_256_GCM_SHA384", None, "TLSv1.3",
                        {"protocols": ["TLSv1.3"], "negotiated_cipher": "TLS_AES_256_GCM_SHA384",
                         "group": "X25519MLKEM768"}, NOW)["standards"]
    assert hybrid["fips_203_204_205"]["category"] == 3 and _status(hybrid, "cnsa_2_0") == "not_compliant"


def test_assets_without_cryptographic_material_have_no_standards_row():
    assert C.classify("coverage", None, None, None, {"check": "x", "status": "error"}, NOW)["standards"] is None
    assert C.classify("database_config", None, None, None, {"ssl": True}, NOW)["standards"] is None


CORPUS = [("RSA", 2048), ("RSA", 1024), ("RSA", 4096), ("EC", 256), ("EC", 384), ("Ed25519", None), ("DSA", 2048),
          ("ML-KEM-512", None), ("ML-KEM-768", None), ("ML-KEM-1024", None), ("ML-DSA-44", None),
          ("ML-DSA-65", None), ("ML-DSA-87", None), ("SLH-DSA-SHA2-128s", None), ("X25519MLKEM768", None),
          ("AES-128-GCM", None), ("AES-256-GCM", None), ("3DES", None), ("RC4", None), ("sha1WithRSAEncryption", None),
          ("ecdsa-with-SHA384", None), ("SHA-256", None), ("SHA-384", None), ("LMS", None), ("Kyber512", None)]


def test_the_code_lane_and_the_sources_lane_copies_are_byte_identical():
    assert BACKEND_COPY.read_bytes() == CODE_COPY.read_bytes(), "re-copy standards.py to aibom/src/aibom/cbom/"
    assert hashlib.sha256(BACKEND_COPY.read_bytes()).hexdigest() == hashlib.sha256(CODE_COPY.read_bytes()).hexdigest()


@pytest.mark.parametrize("name,size", CORPUS)
def test_the_same_algorithm_gets_identical_statuses_in_both_lanes(name, size):
    code = _code_lane_standards()
    for role in ("key", "signature", "cipher", "group"):
        assert S.grade([(role, name, size)]) == code.grade([(role, name, size)]), (role, name)


def _code_lane_levels() -> dict[str, dict[str, int]]:
    """pqc.py's own parameter-set -> category tables (the code lane's grader), read without importing it."""
    tree = ast.parse((ROOT / "aibom/src/aibom/cbom/pqc.py").read_text(encoding="utf-8"))
    out = {}
    for node in tree.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id.endswith("_LEVEL"):
            if isinstance(node.value, ast.Dict):
                out[node.target.id] = ast.literal_eval(node.value)
    return out


def test_fips_categories_agree_with_the_code_lane_pqc_grader():
    levels = _code_lane_levels()
    for table, prefix in (("_MLKEM_LEVEL", "ML-KEM-"), ("_MLDSA_LEVEL", "ML-DSA-")):
        for param, level in levels[table].items():
            got = S.grade([("key", prefix + param, None)])["fips_203_204_205"]
            assert got["category"] == level, (prefix + param, got)


def test_the_classifier_digest_covers_the_standards_module():
    assert str(BACKEND_COPY) in {str(Path(p).resolve()) for p in C._rules_files()}


# ------------------------------------------------------------------------------------------- drawer and export
ASSETS = [GR._asset("certificate", "/etc/pki/web.pem", algorithm="RSA", key_size=2048, name="web",
                    facts={"subject": "CN=web", "issuer": "CN=CA", "key_alg": "RSA", "key_size": 2048,
                           "sig_alg": "sha256WithRSAEncryption", "not_after": "2030-01-01T00:00:00Z",
                           "fingerprint_sha256": "ef" * 32}),
          GR._asset("public_key", "/etc/pki/kem.pub", algorithm="ML-KEM-768", name="kem")]


def test_the_asset_drawer_and_the_export_show_the_standards(api, world):
    w = GR.seed(world[0], sources=[{"name": "S-std", "assets": ASSETS}])
    ids = w["S-std"]["assets"]
    cert = api("GET", f"/1/cbom/sources/assets/{ids['/etc/pki/web.pem']}").json()["asset"]
    rows = {r["id"]: r for r in cert["standards"]}
    assert rows["sp800_131a"]["status"] == "acceptable" and rows["cnsa_2_0"]["status"] == "not_compliant"
    assert rows["sp800_131a"]["label"] == "NIST SP 800-131A" and rows["sp800_131a"]["reasons"]
    kem = {r["id"]: r for r in api("GET", f"/1/cbom/sources/assets/{ids['/etc/pki/kem.pub']}").json()["asset"]
           ["standards"]}
    assert kem["fips_203_204_205"]["status"] == "approved" and kem["fips_203_204_205"]["category"] == 3
    r = api("GET", f"/1/cbom/sources/runs/{w['run']}/cbom")
    assert r.status_code == 200, r.text
    comps = {c["bom-ref"]: {p["name"]: p["value"] for p in c.get("properties") or []}
             for c in r.json()["components"]}
    web = comps[f"zs-asset-{ids['/etc/pki/web.pem']}"]
    assert web["zs:standard:sp800_131a"] == "acceptable" and web["zs:standard:cnsa_2_0"] == "not_compliant"
    assert comps[f"zs-asset-{ids['/etc/pki/kem.pub']}"]["zs:standard:fips_203_204_205"] == "approved (FIPS 203 category 3)"
    xml = api("GET", f"/1/cbom/sources/runs/{w['run']}/cbom?format=xml")
    assert xml.status_code == 200 and b"zs:standard:cnsa_2_0" in xml.content
    json.dumps(cert)  # the drawer payload is plain JSON
