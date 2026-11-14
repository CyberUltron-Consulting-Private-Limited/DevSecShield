#!/usr/bin/env python3
"""Record the classifier's verdicts BEFORE CB-04 PR-3a for test_cbom_algid_classify.test_verdict_corpus_diff (T-B3).

The corpus holds the inputs the identity switch can affect, each with the verdict the classifier gave at the base
commit (dev's classify.family/quantum_vulnerable, before algid): quantum_vulnerable, finding codes, impact and the
posture class. The test re-judges every input with the current code; a difference passes only when it is listed in
algid_intended_changes.json with its oracle. Record it with the BASE classifier (dev's classify.py, classify_ext/ and
posture.py) and the current algid, which only supplies the identifier lists; never after the change it guards. For
example, mount dev's files over the checkout:

    git archive origin/dev backend/utilities/cbom_sources/{classify.py,classify_ext,posture.py} | tar -x -C /tmp/dev
    docker run ... -v /tmp/dev/.../classify.py:/repo/backend/utilities/cbom_sources/classify.py:ro ... \
        python backend/tests/fixtures/make_algid_verdict_corpus.py
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(REPO))

from backend.utilities.cbom_sources import algid  # noqa: E402
from backend.utilities.cbom_sources.classify import classify  # noqa: E402
from backend.utilities.cbom_sources.posture import pqc_class  # noqa: E402

NOW = dt.datetime(2026, 11, 12)
BASE = "dev 3011dc7 classify.py, classify_ext/, posture.py (unchanged since 3df26fd)"
OUT = Path(__file__).resolve().parent / "algid_verdict_corpus.json"
EVIDENCE = Path(__file__).resolve().parent / "algid_lab_assets.json"
CERT = {"sig_alg": "sha256WithRSAEncryption", "not_after": "2030-01-01T00:00:00Z", "self_signed": False,
        "is_ca": False, "source": "tls"}
# KMIP 2.x Cryptographic Algorithm names as the scan node reports them (scan_node/zs_scan_node/kmip_ttlv.py ALGORITHM)
KMIP = ["DES", "3DES", "AES", "RSA", "DSA", "ECDSA", "HMAC-SHA1", "HMAC-SHA224", "HMAC-SHA256", "HMAC-SHA384",
        "HMAC-SHA512", "HMAC-MD5", "DH", "ECDH", "ECMQV", "Blowfish", "Camellia", "CAST5", "IDEA", "MARS", "RC2", "RC4",
        "RC5", "SKIPJACK", "Twofish", "EC", "One Time Pad", "ChaCha20", "Poly1305", "ChaCha20Poly1305", "SHA3-224",
        "SHA3-256", "SHA3-384", "SHA3-512", "HMAC-SHA3-224", "HMAC-SHA3-256", "HMAC-SHA3-384", "HMAC-SHA3-512",
        "SHAKE-128", "SHAKE-256", "ARIA", "SEED", "SM2", "SM3", "SM4", "GOST R 34.10-2012", "GOST R 34.11-2012",
        "GOST R 34.13-2015", "GOST 28147-89", "XMSS", "SPHINCS-256", "McEliece", "McEliece-6960119",
        "McEliece-8192128", "Ed25519", "Ed448", "GOSTR3410", "GOST28147"]
# Spellings collectors and reviewers have seen (CB-04 contradiction reviews p3/p4/p7, DA D3)
EXTRA = ["FN-DSA-512", "FN-DSA-1024", "FNDSA1024", "ML DSA 65", "ml_dsa_65", "rsa3072_dilithium2", "Falcon-512",
         "HSS/LMS", "LMS", "XMSS^MT", "Kyber768", "CRYSTALS-Kyber", "Dilithium3", "SPHINCS+", "sntrup761",
         "X-Wing", "KEM_XWING", "Unknown OID", "<NULL>", "(NONE)", "ECC_NIST_P256", "ECC_NIST_EDWARDS25519",
         "ECC_SECG_P256K1", "SYMMETRIC_DEFAULT", "HMAC_256", "SM2", "ML_DSA_65", "ED25519", "id-ecPublicKey",
         "brainpoolP256r1", "secp256k1", "curve25519", "CURVE25519", "MODP-2048", "1.2.3.4.5",
         # PR-1b review 5878915217: XDH became a named row, and the GOST spellings without a year moved to the
         # version-neutral rows; T-B3 must judge each of them explicitly.
         "XDH", "GOST R 34.10", "GOST R 34.11", "GOSTR3410", "GOSTR3411", "GOST3410", "gostr3410", "gostr3411",
         "gost3410"]


def _names() -> list[str]:
    names = set(algid._ALGS) | set(algid._OIDS) | set(algid._SSH_KEX) | set(EXTRA) | set(KMIP) | set(algid._GCP)
    for table in algid._AWS.values():
        names |= set(table)
    return sorted(names)


def _row(key: str, asset_type: str, algorithm, facts: dict, protocol=None, key_size=None) -> dict:
    return {"key": key, "type": asset_type, "algorithm": algorithm, "key_size": key_size, "protocol": protocol,
            "facts": facts}


def inputs() -> list[dict]:
    """Every corpus input, each with a stable ``key``. The test rebuilds this list; a key with no recorded
    verdict (an identifier added after the base) is not judged by the diff."""
    rows: list[dict] = []
    for s in _names():
        rows.append(_row(f"cert|{s}", "certificate", s, {**CERT, "key_alg": s}))
        rows.append(_row(f"managed|{s}", "managed_key", s, {"key_class": "private", "store": "kmip"}))
        rows.append(_row(f"tls|{s}", "tls_endpoint", "TLS_AES_256_GCM_SHA384",
                         {"versions": {"TLSv1.3": True}, "negotiated_group": s}, "TLSv1.3"))
        rows.append(_row(f"ssh|{s}", "ssh_endpoint", None, {"kex": [s, "ext-info-s"]}))
    for spec in algid._AWS["kms.KeySpec"]:
        rows.append(_row(f"kms|{spec}", "kms_key", spec, {"key_spec": spec, "key_manager": "CUSTOMER",
                                                          "key_state": "Enabled", "rotation_enabled": True}))
    for key_alg in algid._AWS["acm-pca.KeyAlgorithm"]:  # the shape aws_collect.pca() stored before CB-04
        rows.append(_row(f"pca-old|{key_alg}", "cloud_ca", "RSA" if key_alg.startswith("RSA") else "ECDSA",
                         {"key_alg": key_alg, "is_ca": True, "source": "aws", "status": "ACTIVE"}))
    for groups in (["ML-KEM-768"], ["MODP-2048", "ML-KEM-768"], ["group 36"], ["MODP-2048"], ["ECP-256"]):
        rows.append(_row(f"ike|{'+'.join(groups)}", "appliance_config", None,
                         {"kind": "ike_policy", "vendor": "lab", "groups": groups, "version": 2}))
    rows.append(_row("tls|<NULL> group, pq_hybrid false", "tls_endpoint", None,
                     {"negotiated_group": "<NULL>", "pq_hybrid": False, "versions": {"TLSv1.3": True}}))
    for asset in json.loads(EVIDENCE.read_text())["assets"]:
        rows.append(_row(f"lab|{asset['label']}", asset["type"], asset.get("algorithm"), asset["facts"],
                         asset.get("protocol"), asset.get("key_size")))
    return rows


def judge(row: dict) -> list:
    """[quantum_vulnerable, finding codes, impact, posture class] of one input."""
    v = classify(row["type"], row["algorithm"], row["key_size"], row["protocol"], row["facts"], NOW)
    return [v["quantum_vulnerable"], v["finding_codes"], v["impact"],
            pqc_class(row["type"], v["quantum_vulnerable"], v["finding_codes"], row["facts"])]


def main() -> None:
    before = {row["key"]: judge(row) for row in inputs()}
    lines = [f"  {json.dumps(k)}: {json.dumps(before[k])}" for k in sorted(before)]
    OUT.write_text('{"base": "dev classify before algid (%s)", "now": "%s", "verdicts": {\n%s\n}}\n'
                   % (BASE, NOW.isoformat(), ",\n".join(lines)))
    print(f"{len(before)} rows -> {OUT.name}")


if __name__ == "__main__":
    main()
