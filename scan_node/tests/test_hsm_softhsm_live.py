"""PKCS#11 collector against a real SoftHSM2 token (skipped unless SoftHSM2 is available).

Set ZS_TEST_SOFTHSM_LIB (libsofthsm2.so) and ZS_TEST_SOFTHSM_UTIL (softhsm2-util), or install softhsm2.  The test
creates its own token in a temporary directory, seeds RSA-1024, an extractable AES-128, an AES-256 whose value it
knows (CKA_SENSITIVE false), 3DES and EC P-256 keys, runs the collector and checks that no key value and no PIN
reached the collected assets.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time

import pytest

LIB = os.environ.get("ZS_TEST_SOFTHSM_LIB") or next(
    (p for p in ("/usr/lib/softhsm/libsofthsm2.so", "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so") if os.path.isfile(p)),
    None)
UTIL = os.environ.get("ZS_TEST_SOFTHSM_UTIL") or shutil.which("softhsm2-util")
pkcs11 = pytest.importorskip("pkcs11")
pytestmark = pytest.mark.skipif(not (LIB and UTIL and os.path.isfile(LIB)), reason="SoftHSM2 not available")

USER_PIN = "73914286"
SO_PIN = "51907342"
KNOWN_AES = bytes.fromhex("8f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0")


@pytest.fixture()
def token(tmp_path, monkeypatch):
    (tmp_path / "tokens").mkdir()
    conf = tmp_path / "softhsm2.conf"
    conf.write_text(f"directories.tokendir = {tmp_path / 'tokens'}\nobjectstore.backend = file\nlog.level = ERROR\n")
    monkeypatch.setenv("SOFTHSM2_CONF", str(conf))
    subprocess.run([UTIL, "--module", LIB, "--init-token", "--free", "--label", "zs-wp6", "--so-pin", SO_PIN, "--pin", USER_PIN],
                   check=True, capture_output=True, env={**os.environ, "SOFTHSM2_CONF": str(conf)})
    from pkcs11 import Attribute, KeyType, Mechanism, ObjectClass

    lib = pkcs11.lib(LIB)
    tok = lib.get_token(token_label="zs-wp6")
    with tok.open(rw=True, user_pin=USER_PIN) as s:
        s.generate_keypair(KeyType.RSA, 1024, label="rsa-1024", store=True)
        s.generate_key(KeyType.AES, 128, label="aes-128-extractable", store=True,
                       template={Attribute.EXTRACTABLE: True, Attribute.SENSITIVE: True})
        s.create_object({Attribute.CLASS: ObjectClass.SECRET_KEY, Attribute.KEY_TYPE: KeyType.AES,
                         Attribute.VALUE: KNOWN_AES, Attribute.TOKEN: True, Attribute.LABEL: "aes-256-readable",
                         Attribute.SENSITIVE: False, Attribute.EXTRACTABLE: True, Attribute.ENCRYPT: True,
                         Attribute.DECRYPT: True})
        s.generate_key(KeyType.DES3, label="des3-legacy", store=True,
                       template={Attribute.EXTRACTABLE: False, Attribute.SENSITIVE: True})
        params = s.create_domain_parameters(KeyType.EC, {Attribute.EC_PARAMS: bytes.fromhex("06082a8648ce3d030107")},
                                            local=True)
        params.generate_keypair(label="ec-p256", store=True, mechanism=Mechanism.EC_KEY_PAIR_GEN)
    monkeypatch.setenv("ZS_PKCS11_MODULES", f"softhsm={LIB}")
    return tmp_path


def _ctx():
    from zs_scan_node.jobctx import JobContext
    from zs_scan_node.netutil import NeverScan
    from zs_scan_node.scrub import Scrubber

    return JobContext(job_id=1, attempt=1, run_id=None, kind="collect", source_kind="key_manager",
                      scrubber=Scrubber([USER_PIN]), never_scan=NeverScan(), deadline=time.monotonic() + 120)


def test_softhsm_token_is_inventoried_without_values(token):
    from zs_scan_node.collectors import hsm_pkcs11

    ctx = _ctx()
    summary = hsm_pkcs11.collect(ctx, {"provider": "pkcs11", "module": "softhsm", "token_label": "zs-wp6"},
                                 {"pin": USER_PIN}, {})
    ctx.flush()
    assert "1 token" in summary
    assert [o.status for o in ctx.outcomes] == ["ok"]
    keys = {a["name"]: a for a in ctx.collected if a["type"] == "managed_key"}
    assert keys["rsa-1024"]["algorithm"] == "RSA" and keys["rsa-1024"]["key_size"] == 1024
    assert keys["rsa-1024"]["facts"]["key_class"] in ("private", "public")
    aes = keys["aes-128-extractable"]
    assert aes["key_size"] == 128 and aes["facts"]["extractable"] is True and aes["facts"]["sensitive"] is True
    readable = keys["aes-256-readable"]
    assert readable["key_size"] == 256 and readable["facts"]["sensitive"] is False
    assert keys["des3-legacy"]["algorithm"] == "DES3" and keys["des3-legacy"]["key_size"] == 168
    ec = [a for a in ctx.collected if a["type"] == "managed_key" and a["name"] == "ec-p256"]
    assert ec and all(a["facts"]["curve"] == "P-256" and a["key_size"] == 256 for a in ec)
    store = [a for a in ctx.collected if a["type"] == "key_store"]
    assert store and store[0]["facts"]["token_label"] == "zs-wp6" and store[0]["facts"]["logged_in"] is True
    blob = json.dumps(ctx.collected)
    # no key value and no PIN anywhere in what the node would send
    assert KNOWN_AES.hex() not in blob and KNOWN_AES.hex().upper() not in blob
    import base64

    assert base64.b64encode(KNOWN_AES).decode() not in blob
    assert USER_PIN not in blob and SO_PIN not in blob


def test_softhsm_without_pin_reads_public_objects_and_says_so(token):
    from zs_scan_node.collectors import hsm_pkcs11

    ctx = _ctx()
    hsm_pkcs11.collect(ctx, {"provider": "pkcs11", "module": "softhsm"}, {}, {})
    ctx.flush()
    gaps = [a for a in ctx.collected if a["type"] == "coverage"]
    assert gaps and "no PIN" in gaps[0]["facts"]["detail"]
    assert not [a for a in ctx.collected if a["type"] == "managed_key" and a["facts"]["key_class"] == "secret"]


def test_softhsm_wrong_pin_is_auth_failed(token):
    from zs_scan_node.collectors import hsm_pkcs11

    ctx = _ctx()
    hsm_pkcs11.collect(ctx, {"provider": "pkcs11", "module": "softhsm"}, {"pin": "00000000"}, {})
    assert [o.status for o in ctx.outcomes] == ["auth_failed"]


def test_classified_findings_on_the_real_token(token):
    """The server-side rules turn the SoftHSM facts into the expected findings."""
    import sys
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root))
    classify = pytest.importorskip("backend.utilities.cbom_sources.classify")
    from zs_scan_node.collectors import hsm_pkcs11

    ctx = _ctx()
    hsm_pkcs11.collect(ctx, {"provider": "pkcs11", "module": "softhsm"}, {"pin": USER_PIN}, {})
    ctx.flush()
    codes = {}
    for a in ctx.collected:
        if a["type"] == "managed_key":
            r = classify.classify(a["type"], a["algorithm"], a["key_size"], a["protocol"], a["facts"])
            codes.setdefault(a["name"], set()).update(r["finding_codes"])
    assert "RSA_LT_2048" in codes["rsa-1024"]
    assert "KEY_EXTRACTABLE" in codes["aes-128-extractable"]
    assert "KEY_PLAINTEXT_EXPORT" in codes["aes-256-readable"]
    assert "KEY_WEAK_SYMMETRIC" in codes["des3-legacy"]
    assert "QUANTUM_VULNERABLE" in codes["ec-p256"]
