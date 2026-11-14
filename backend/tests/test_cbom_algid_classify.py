"""CB-04 PR-3a: the backend rules read algorithm identity from algid, and the state rules keep old runs consistent.

T-B3 re-judges a corpus of inputs whose verdict the classifier gave BEFORE algid (fixtures/algid_verdict_corpus.json,
recorded at dev 3df26fd with make_algid_verdict_corpus.py) and accepts a difference only when
fixtures/algid_intended_changes.json lists it with the same before and after (each row tied to its oracle and DA
category by make_algid_intended_changes.py, which refuses a difference that fits no intended category). The other
tests are the DA's T-B4 and T-B6..T-B13 (round6/cbom/cb-04/DEVILS-ADVOCATE.md §7).

    cd backend && PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y \
      AWS_DEFAULT_REGION=us-east-1 .venv/bin/python -m pytest tests/test_cbom_algid_classify.py -q -p no:cacheprovider
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(TESTS))
sys.path.insert(0, str(TESTS / "fixtures"))

import make_algid_verdict_corpus as corpus  # noqa: E402
from sqlmodel import Session, select  # noqa: E402
from test_cbom_sources_api import _collect_job, api, world  # noqa: E402,F401  (shared fixtures)

from backend.new_models import CbomCollectedAsset, CbomCollectionRun  # noqa: E402
from backend.utilities.cbom_sources import algid  # noqa: E402
from backend.utilities.cbom_sources import classify as C  # noqa: E402
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import posture as P  # noqa: E402
from backend.utilities.cbom_sources.heatmap import algorithm_family  # noqa: E402

FIXTURES = TESTS / "fixtures"
NOW = corpus.NOW
DEV_CLASSIFIER_VERSION = "rules-9b4b32ed36c3"  # CLASSIFIER_VERSION at dev 3df26fd (G0: a run must not carry it)


def _lab(label: str) -> dict:
    for asset in json.loads((FIXTURES / "algid_lab_assets.json").read_text())["assets"]:
        if asset["label"] == label:
            return asset
    raise KeyError(label)


# ----------------------------------------------------------------------------- T-B3
def test_verdict_corpus_diff():
    recorded = json.loads((FIXTURES / "algid_verdict_corpus.json").read_text())["verdicts"]
    allow = json.loads((FIXTURES / "algid_intended_changes.json").read_text())
    intended, oracles = allow["changes"], allow["oracles"]
    rows = {row["key"]: row for row in corpus.inputs()}
    assert set(recorded) <= set(rows), "a recorded corpus input is no longer built"
    unexpected, stale = [], []
    for key, before in recorded.items():
        after = corpus.judge(rows[key])
        entry = intended.get(key)
        if entry is None:
            if after != before:
                unexpected.append(f"{key}: {before} -> {after}")
        elif entry[0] != before or entry[1] != after:
            stale.append(f"{key}: listed {entry[0]} -> {entry[1]}, actual {before} -> {after}")
    assert not unexpected, "verdicts changed without an intended-change entry:\n" + "\n".join(unexpected[:40])
    assert not stale, "intended-change entries that no longer match:\n" + "\n".join(stale[:40])
    assert set(intended) <= set(recorded)
    for key, (_before, _after, category, subject) in intended.items():
        assert category in allow["categories"], key
        assert subject is None or oracles.get(subject), f"{key}: no oracle for {subject}"
    # the DA's must-flip rows (§7 T-B3) are among them, with the direction the oracle gives
    must = {
        "cert|FN-DSA-512": False, "cert|ML DSA 65": False, "cert|rsa3072_dilithium2": False,
        "managed|FNDSA1024": False,
        "cert|2.16.840.1.101.3.4.3.18": False,  # ML-DSA-65 (CSOR)
        "cert|1.3.6.1.5.5.7.6.34": False,  # XMSS (PKIX)
        "cert|1.2.840.113549.1.9.16.3.17": False,  # HSS/LMS (RFC 8708)
        "managed|GOST R 34.10-2012": True, "managed|GOSTR3410": True,
        "tls|brainpoolP256r1": True, "tls|sect283k1": True, "tls|MODP-2048": True, "tls|curve25519": True,
        "cert|brainpoolP384r1": True,
        "pca-old|ML_DSA_65": False,
        "tls|<NULL> group, pq_hybrid false": True,
        "lab|lab :4432 tls_endpoint (dev node)": False,
        "ike|group 36": False, "ike|MODP-2048+ML-KEM-768": False,
        # PR-1b (#106 review 5878915217): XDH is a named row now (None -> ECDH, quantum vulnerable), and the GOST
        # R 34.10 spellings without a year resolve to the version-neutral elliptic-curve signature row
        "cert|XDH": True, "managed|XDH": True, "tls|XDH": True,
        **{f"{shape}|{name}": True for shape in ("cert", "managed", "tls")
           for name in ("GOST R 34.10", "GOSTR3410", "GOST3410", "gostr3410", "gost3410")},
    }
    for key, qv in must.items():
        assert key in intended and intended[key][1][0] is qv, key
    # ... and the GOST R 34.11 spellings (a hash, no public-key verdict) are judged and keep their verdict
    for name in ("GOST R 34.11", "GOSTR3411", "gostr3411"):
        for shape in ("cert", "managed", "tls", "ssh"):
            key = f"{shape}|{name}"
            assert key in recorded and key not in intended and corpus.judge(rows[key]) == recorded[key], key
    assert "NO_PQ_KEX" in intended["tls|brainpoolP256r1"][1][1]
    for code in ("DSA", "QUANTUM_VULNERABLE"):
        assert code in intended["cert|FN-DSA-512"][0][1] and code not in intended["cert|FN-DSA-512"][1][1]
    # classical rows the old rules already judged stay exactly as they were
    for key in ("cert|RSA", "cert|EC", "tls|X25519", "tls|secp256r1", "ssh|curve25519-sha256",
                "managed|AES", "managed|ECDSA", "kms|RSA_2048", "kms|SYMMETRIC_DEFAULT",
                "lab|lab :4440 tls_endpoint (dev node)", "lab|lab :4442 tls_endpoint (dev node)"):
        assert key not in intended and corpus.judge(rows[key]) == recorded[key], key


# ----------------------------------------------------------------------------- T-B4
def _store(call, engine, assets):
    _src, run, claim, hdr = _collect_job(call, engine)
    job, lease = claim["job"], claim["job"]["lease_id"]
    r = call("POST", f"/cbom/node/jobs/{job['id']}/assets", None, headers=hdr,
            json={"lease_id": lease, "batch_id": "lab", "assets": assets})
    assert r.status_code == 200, r.text
    return run


LAB_ROWS = {  # label -> (location, posture class expected, NO_PQ_KEX expected)
    "lab :4432 tls_endpoint (dev node)": ("10.20.0.1:4432", "hybrid", False),
    "lab :4432 certificate (dev node)": ("10.20.0.1:4432/cert", "quantum-safe", False),
    "lab :4432 tls_endpoint (CB-04 node)": ("10.20.0.2:4432", "hybrid", False),
    "lab :4432 certificate (CB-04 node)": ("10.20.0.2:4432/cert", "quantum-safe", False),
    "lab :4440 tls_endpoint (dev node)": ("10.20.0.1:4440", "quantum-vulnerable", True),
    "lab :4442 tls_endpoint (dev node)": ("10.20.0.1:4442", "quantum-vulnerable", True),
}


def test_lab_assets_through_views(api, world):  # noqa: F811  (the shared fixtures)
    """Old- and new-node :4432 shapes through the product path: node ingest (classify), the run posture, the asset
    panel and drift's views, each reading the raw stored facts."""
    engine, _ids = world
    assets = []
    for label, (location, _cls, _no_pq) in LAB_ROWS.items():
        lab = _lab(label)
        assets.append({"type": lab["type"], "target": location.split(":")[0], "location": location, "name": label,
                       "algorithm": lab.get("algorithm"), "key_size": lab.get("key_size"),
                       "protocol": lab.get("protocol"), "facts": lab["facts"]})
    run = _store(api, engine, assets)
    with Session(engine) as s:
        rows = s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run["id"])).all()
        by_name = {r.name: r for r in rows}
        assert set(LAB_ROWS) <= set(by_name)
        views = D.node_views(rows, "src:lab", reclassify=False)
        drift_class = {v.label.split(" · ")[0]: v.extra["pqc_class"] for v in views.values()}
        posture = P.run_posture(s, team_id=1, run_id=run["id"], risk_model=None)
    for label, (_location, cls, no_pq) in LAB_ROWS.items():
        row = by_name[label]
        assert ("NO_PQ_KEX" in (row.finding_codes or [])) is no_pq, label
        assert "QUANTUM_VULNERABLE" not in (row.finding_codes or []) or cls == "quantum-vulnerable", label
        assert P.asset_detail(row, None)["pqc_class"] == cls, label
        assert drift_class[label] == cls, label
    assert posture["pqc_classes"]["hybrid"] == 2 and posture["pqc_classes"]["quantum-safe"] == 2
    assert posture["pqc_classes"]["quantum-vulnerable"] == 2


# ----------------------------------------------------------------------------- T-B6 (+ CB-18 contradiction-3 ST-B)
HYBRID_ROW = (b'    0x11EC: "X25519MLKEM768",\n', b'    0x11EC: "X25519",\n')  # one TLS_GROUPS row, nothing else


def _algid_copy(folder: Path, edits: dict[str, tuple[bytes, bytes]] | None = None,
                extra: dict[str, bytes] | None = None) -> Path:
    """Every ``algid*.py`` beside algid copied into ``folder``, ``edits[name] = (old, new)`` applied exactly once."""
    folder.mkdir()
    for path in sorted(Path(algid.__file__).parent.glob("algid*.py")):
        data = path.read_bytes()
        if edits and path.name in edits:
            old, new = edits[path.name]
            assert data.count(old) == 1, (path.name, old)
            data = data.replace(old, new)
        (folder / path.name).write_bytes(data)
    for name, data in (extra or {}).items():
        (folder / name).write_bytes(data)
    return folder / "algid.py"


def test_classifier_version_hashes_algid(tmp_path, monkeypatch):
    import importlib.util

    assert C.CLASSIFIER_VERSION.startswith("rules-") and C.CLASSIFIER_VERSION != DEV_CLASSIFIER_VERSION
    assert C._rules_version() == C.CLASSIFIER_VERSION
    # The same bytes somewhere else keep the label: the digest reads content, not paths.
    monkeypatch.setattr(algid, "__file__", str(_algid_copy(tmp_path / "same")))
    assert C._rules_version() == C.CLASSIFIER_VERSION

    # A table-only release: one generated row changes, algid.py does not. The row decides a verdict (the negotiated
    # hybrid group stops reading as post-quantum), so the label must change; otherwise drift reports the rule change
    # as "resolved"/"opened" findings with rules_changed false (CB-18 cx-3 probe B).
    table = _algid_copy(tmp_path / "table_row", {"algid_tables.py": HYBRID_ROW}).parent / "algid_tables.py"
    spec = importlib.util.spec_from_file_location("algid_tables_row_edit", table)
    edited = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(edited)
    assert algid.tls_group(0x11EC).quantum == "hybrid"
    monkeypatch.setattr(algid, "_TLS_GROUPS", edited.TLS_GROUPS)
    assert algid.tls_group(0x11EC).quantum != "hybrid"  # the verdict input changed with the row
    monkeypatch.undo()
    assert algid.tls_group(0x11EC).quantum == "hybrid"
    monkeypatch.setattr(algid, "__file__", str(table.parent / "algid.py"))
    assert C._rules_version() != C.CLASSIFIER_VERSION, "a table row changed and the rules label did not"

    # The resolver alone, and a third identity file added beside them later, count as well.
    resolver = _algid_copy(tmp_path / "resolver", {"algid.py": (b"\ndef is_sentinel(", b"\n\ndef is_sentinel(")})
    monkeypatch.setattr(algid, "__file__", str(resolver))
    assert C._rules_version() != C.CLASSIFIER_VERSION
    third = _algid_copy(tmp_path / "third", extra={"algid_oids.py": b'OIDS = {"1.2.3": "X"}\n'})
    monkeypatch.setattr(algid, "__file__", str(third))
    assert C._rules_version() != C.CLASSIFIER_VERSION


def test_rules_digest_covers_every_module_algid_reads():
    """algid reads its identities from sibling modules (today algid_tables.py). Each one it imports must be in the
    digest, so a module added outside the ``algid*.py`` pattern fails here instead of silently missing the label."""
    import ast

    tree = ast.parse(Path(algid.__file__).read_text(encoding="utf-8"))
    siblings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level >= 1:
            siblings.update([node.module.split(".")[0]] if node.module else [a.name for a in node.names])
    assert "algid_tables" in siblings
    hashed = {Path(p).name for p in C._rules_files()}
    assert {f"{name}.py" for name in siblings} <= hashed, siblings
    assert {"classify.py", "algid.py", "algid_tables.py"} <= hashed


# ----------------------------------------------------------------------------- T-B7 / T-B7b / T-B10
def _row(i: int, *, algorithm, facts, codes, qv, impact=None, asset_type="certificate", created=NOW, key="k"):
    """One stored asset; the same ``key`` in two runs is the same asset (a node's asset_key is stable)."""
    return CbomCollectedAsset(id=i, team_id=1, job_id=i, asset_key=key, asset_type=asset_type, cdx_type="x",
                              target="10.20.0.1", location="10.20.0.1:4432", name="lab", algorithm=algorithm,
                              quantum_vulnerable=qv, impact=impact, finding_codes=codes, facts=facts,
                              created_at=created)


CERT = {"subject": "CN=mldsa65.lab", "issuer": "CN=mldsa65.lab", "not_after": "2030-01-01T00:00:00Z",
        "self_signed": True, "is_ca": True, "source": "tls", "fingerprint_sha256": "ab" * 32}


def _run(label: str | None, kb: str | None = None) -> CbomCollectionRun:
    return CbomCollectionRun(team_id=1, owner_user_id=1, client_request_id="r", classifier_version=label,
                             kb_version=kb if kb is not None else C.crypto_kb.version())


def test_drift_oid_to_name_not_changed():
    """A node upgrade names the ML-DSA key it reported as an OID: the same certificate, not a changed one (S-2)."""
    before = D.node_views([_row(1, algorithm="2.16.840.1.101.3.4.3.18", facts={**CERT, "key_alg": "2.16.840.1.101.3.4.3.18",
                                                                                "sig_alg": "Unknown OID"},
                                codes=[], qv=False)], "src", reclassify=True)
    after = D.node_views([_row(2, algorithm="ML-DSA-65", facts={**CERT, "key_alg": "ML-DSA-65", "sig_alg": "ML-DSA-65",
                                                                 "key_alg_oid": "2.16.840.1.101.3.4.3.18"},
                               codes=[], qv=False)], "src", reclassify=True)
    diff = D.compare(before, after)
    assert not diff["changed"] and not diff["added"] and not diff["removed"]
    assert not diff["opened"] and not diff["resolved"]
    # a real change still shows: a different algorithm on the same certificate identity
    other = D.node_views([_row(3, algorithm="RSA", facts={**CERT, "key_alg": "RSA"}, codes=["QUANTUM_VULNERABLE"],
                               qv=True)], "src", reclassify=True)
    assert D.compare(before, other)["changed"]


def test_drift_pca_old_shape_no_event():
    """An AWS Private CA row stored before CB-04 (ECDSA next to ML_DSA_65, judged quantum-vulnerable then) compared with
    the same CA judged by the current rules: no resolved QUANTUM_VULNERABLE, no estate event (ST-2)."""
    facts = {"key_alg": "ML_DSA_65", "is_ca": True, "source": "aws", "status": "ACTIVE", "subject": "CN=pca",
             "issuer": "CN=pca"}
    old = _row(1, algorithm="ECDSA", facts=facts, codes=["QUANTUM_VULNERABLE"], qv=True, asset_type="cloud_ca")
    verdict = C.classify("cloud_ca", "ECDSA", None, None, facts, NOW)
    assert verdict["quantum_vulnerable"] is False and verdict["finding_codes"] == []
    new = _row(2, algorithm="ECDSA", facts=facts, codes=verdict["finding_codes"], qv=False, asset_type="cloud_ca")
    reclassify = D.rules_differ(_run(DEV_CLASSIFIER_VERSION), _run(C.CLASSIFIER_VERSION))
    assert reclassify is True
    diff = D.compare(D.node_views([old], "src", reclassify=reclassify), D.node_views([new], "src", reclassify=reclassify))
    assert not any(diff[k] for k in ("added", "removed", "changed", "opened", "resolved"))
    assert D.diff_events(1, NOW, diff, scope="node", source_ref="src", source_name="pca", anchor="run:2") == []
    # as stored, the comparison would have read as a fix: that is what rule_changes lists instead
    stored = D.compare(D.node_views([old], "src", reclassify=False), D.node_views([new], "src", reclassify=False))
    assert [r["code"] for r in D.rule_only_changes(stored, diff)] == ["QUANTUM_VULNERABLE"]


def test_rules_differ_stale_label():
    """ST-1: a run created before a deploy and ingested after it carries the old label while its assets were judged by
    the new rules. Equal labels are not enough: either side not judged by the current rules means re-judge both."""
    old_label = DEV_CLASSIFIER_VERSION
    assert D.rules_differ(_run(old_label), _run(old_label)) is True
    assert D.rules_differ(_run(C.CLASSIFIER_VERSION), _run(C.CLASSIFIER_VERSION)) is False
    assert D.rules_differ(_run(C.CLASSIFIER_VERSION), _run(C.CLASSIFIER_VERSION, kb="kb-old")) is True
    assert D.rules_differ(_run(None), _run(C.CLASSIFIER_VERSION)) is True
    assert D.rules_differ(None, _run(C.CLASSIFIER_VERSION)) is True
    # the :4432 endpoint: base judged by the old rules (NO_PQ_KEX), the later run (old label) by the new ones
    lab = _lab("lab :4432 tls_endpoint (dev node)")
    base = _row(1, algorithm=lab["algorithm"], facts=lab["facts"], codes=["NO_PQ_KEX"], qv=False, impact="Low",
                asset_type="tls_endpoint")
    now_v = C.classify("tls_endpoint", lab["algorithm"], None, None, lab["facts"], NOW)
    later = _row(2, algorithm=lab["algorithm"], facts=lab["facts"], codes=now_v["finding_codes"],
                 qv=now_v["quantum_vulnerable"], asset_type="tls_endpoint")
    reclassify = D.rules_differ(_run(old_label), _run(old_label))
    diff = D.compare(D.node_views([base], "src", reclassify=reclassify), D.node_views([later], "src",
                                                                                     reclassify=reclassify))
    assert not diff["resolved"], "a rule change must not read as a fixed NO_PQ_KEX"


# ----------------------------------------------------------------------------- T-B12
def _stored(asset_type, algorithm, facts, codes, qv, impact, finding, created):
    return SimpleNamespace(asset_type=asset_type, algorithm=algorithm, key_size=None, protocol=None, facts=facts,
                           created_at=created, finding_codes=codes, impact=impact, finding=finding,
                           quantum_vulnerable=qv)


def test_shown_keeps_stored_identity_codes():
    """H-9/ST-3: an old run whose certificate crosses its expiry window shows the date change only; identity codes the
    current rules would add (or drop) stay as the run judged them, next to the run's stored quantum verdict."""
    run_day = dt.datetime(2026, 10, 1)
    today = dt.datetime(2026, 11, 12)
    gost = {**CERT, "key_alg": "1.2.643.7.1.1.1.1", "sig_alg": "GOST R 34.10-2012 with GOST R 34.11-2012 (256 bit)",
            "not_after": "2026-11-30T00:00:00Z", "self_signed": False, "is_ca": False}
    row = _stored("certificate", "1.2.643.7.1.1.1.1", gost, [], None, None, None, run_day)  # judged before algid
    view = C.shown(row, today)
    assert view["finding_codes"] == ["CERT_EXPIRES_30D"] and view["impact"] == "Medium"
    assert "QUANTUM_VULNERABLE" not in view["finding_codes"]
    assert view["as_of_run"]["finding_codes"] == [] and view["finding"].startswith("Certificate expires in")
    # the other direction: a stored identity code the current rules no longer raise stays too
    pca = {"key_alg": "ML_DSA_65", "is_ca": True, "source": "aws", "not_after": "2026-10-20T00:00:00Z"}
    row = _stored("cloud_ca", "ECDSA", pca, ["CERT_EXPIRES_30D", "QUANTUM_VULNERABLE"], True, "Medium",
                  "Certificate expires in 19 days; Uses public-key cryptography that a quantum computer can break",
                  run_day)
    view = C.shown(row, today)
    assert view["finding_codes"] == ["QUANTUM_VULNERABLE", "CERT_EXPIRED"] and view["impact"] == "High"
    assert view["finding"] == ("Certificate expired on 2026-10-20; Uses public-key cryptography that a quantum "
                               "computer can break")
    assert view["impacts"]["CERT_EXPIRED"] == "High"
    # rules unchanged since the run: exactly today's verdict, as before
    rsa = {**CERT, "key_alg": "RSA", "sig_alg": "sha256WithRSAEncryption", "not_after": "2026-11-30T00:00:00Z",
           "self_signed": False, "is_ca": False}
    then_v = C.classify("certificate", "RSA", None, None, rsa, run_day)
    row = _stored("certificate", "RSA", rsa, then_v["finding_codes"], True, then_v["impact"], then_v["finding"], run_day)
    view = C.shown(row, today)
    now_v = C.classify("certificate", "RSA", None, None, rsa, today)
    assert (view["finding_codes"], view["impact"], view["finding"], view["impacts"]) == \
        (now_v["finding_codes"], now_v["impact"], now_v["finding"], now_v["impacts"])
    # and nothing date-based moved: the stored verdict, untouched
    still = _stored("certificate", "RSA", {**rsa, "not_after": "2030-01-01T00:00:00Z"}, ["X"], True, "Low", "x", run_day)
    assert C.shown(still, today) == {"impact": "Low", "finding_codes": ["X"], "finding": "x", "impacts": None,
                                     "as_of_run": None}


# ----------------------------------------------------------------------------- T-B11 / T-B13
@pytest.mark.parametrize("algorithm,qv,codes", [
    ("GOST R 34.10-2012", True, ["QUANTUM_VULNERABLE"]),
    ("GOSTR3410", True, ["QUANTUM_VULNERABLE"]),  # PKCS#11 CKK_GOSTR3410
    ("GOST 28147-89", False, []),  # a block cipher (RFC 5830): symmetric, as before
    ("GOST28147", False, []),
    ("GOST R 34.13-2015", False, []),
    ("AES", False, []),
    ("ECDSA", True, ["QUANTUM_VULNERABLE"]),
])
def test_gost_managed_key(algorithm, qv, codes):
    v = C.classify("managed_key", algorithm, 256, None, {"key_class": "private", "store": "kmip"}, NOW)
    assert (v["quantum_vulnerable"], v["finding_codes"]) == (qv, codes)


@pytest.mark.parametrize("groups,pq,qv,codes", [
    (["MODP-2048", "ML-KEM-768"], None, False, []),
    (["group 36"], False, False, []),  # the parser did not see RFC 9370 syntax; the group says ML-KEM
    (["ECP-256", "group 35"], None, False, []),
    (["ML-KEM-1024"], False, False, []),
    (["MODP-2048"], False, True, ["IKE_NO_PQ"]),
    (["ECP-256"], None, True, ["QUANTUM_VULNERABLE"]),
    (["group 14"], False, True, ["IKE_NO_PQ"]),
    # a post-quantum signature is not a key exchange (review m2): no ML-KEM exchange is configured
    (["ML-DSA-65"], None, True, ["QUANTUM_VULNERABLE"]),
    (["ML-DSA-65"], False, True, ["IKE_NO_PQ"]),
])
def test_appliance_ike_mlkem_group_no_ike_no_pq(groups, pq, qv, codes):
    """T-B13: an ML-KEM group gives qv False and no IKE_NO_PQ. The posture class of such a policy (and of a classical
    group next to it) is "quantum-safe" until CB-18 defines "hybrid" (OA-CB04-1): this test pins no class."""
    facts = {"kind": "ike_policy", "vendor": "lab", "groups": groups, "version": 2}
    if pq is not None:
        facts["pq"] = pq
    v = C.classify("appliance_config", None, None, None, facts, NOW)
    assert (v["quantum_vulnerable"], v["finding_codes"]) == (qv, codes)


# ----------------------------------------------------------------------------- T-B9
@pytest.mark.parametrize("algorithm,asset_type,facts,family", [
    ("ML_DSA_65", "kms_key", {}, "Post-quantum"),  # KMS enum: was DSA
    ("2.16.840.1.101.3.4.3.18", "certificate", {}, "Post-quantum"),  # ML-DSA-65 OID: was Other
    ("FN-DSA-512", "certificate", {}, "Post-quantum"),
    ("ECC_NIST_EDWARDS25519", "kms_key", {}, "EdDSA"),
    ("SM2", "kms_key", {}, "Elliptic curve"),
    ("GOST R 34.10-2012", "managed_key", {}, "Elliptic curve"),
    ("id-ecPublicKey", "certificate", {}, "Elliptic curve"),
    # unchanged: cipher suites and generic names keep today's token rules
    ("ECDHE-RSA-AES256-GCM-SHA384", "tls_endpoint", {}, "RSA"),
    ("TLS_AES_256_GCM_SHA384", "tls_endpoint", {"group": "X25519MLKEM768"}, "AES"),
    (None, "tls_endpoint", {"group": "X25519MLKEM768"}, "Post-quantum"),
    ("ssh-dss", "ssh_host_key", {}, "DSA"),
    ("RSA", "certificate", {}, "RSA"),
    ("HMAC_256", "kms_key", {}, "HMAC"),
    ("SYMMETRIC_DEFAULT", "kms_key", {}, "AES"),  # the KMS enum names AES-256-GCM: was Other
    (None, "crypto_library", {}, "Library"),
    # post-quantum names come from algid's markers, not from a token list of the heat map's own (review n2)
    ("dilithium3", "certificate", {}, "Post-quantum"),
    ("p256_frodo640aes", "tls_endpoint", {}, "Post-quantum"),
    ("hqc128", "managed_key", {}, "Post-quantum"),
    ("SPHINCS+-SHA2-128s", "certificate", {}, "Post-quantum"),
    ("ntruhps2048509", "managed_key", {}, "Post-quantum"),  # NTRU is no algid marker: the heat map's one PQ token
])
def test_heatmap_algid_first(algorithm, asset_type, facts, family):
    assert algorithm_family(algorithm, asset_type, facts) == family


def test_heatmap_reads_no_pq_name_algid_knows():
    """DA §10: each PR removes its single-source entries. A heat-map token algid already reads as post-quantum is a
    second copy of algid's markers (and is reached only for text algid does not know)."""
    from backend.utilities.cbom_sources.heatmap import FAMILY_RULES

    shadowed = [w for _family, words in FAMILY_RULES for w in words if algid.family_label(w) == "PQ"]
    assert shadowed == []


# ----------------------------------------------------------------------------- T-B8
def test_unknown_identifier_logged_once(monkeypatch):
    lines: list[tuple[str, dict]] = []
    monkeypatch.setattr(C, "log", lambda action, **fields: lines.append((action, fields)))
    monkeypatch.setattr(C, "_unknown_seen", set())
    private_arc = "1.3.6.1.4.1.99999.1.2"
    for _ in range(3):
        C.classify("certificate", private_arc, None, None, {"key_alg": private_arc}, NOW)
    C.classify("private_key", "made-up-key-type", None, None, {}, NOW)
    C.classify("kms_key", "FUTURE_SPEC", None, None, {"key_spec": "FUTURE_SPEC"}, NOW)
    for quiet in (("certificate", "Unknown OID"), ("certificate", "<NULL>"), ("certificate", "RSA"),
                  ("certificate", "2.16.840.1.101.3.4.3.18"), ("tls_endpoint", private_arc),
                  ("managed_key", "AES"), ("managed_key", "HMAC-SHA256"), ("kms_key", "HMAC_256")):
        C.classify(quiet[0], quiet[1], None, None, {"key_spec": quiet[1]} if quiet[0] == "kms_key" else {}, NOW)
    assert lines == [("classify unknown identifier", {"type": "certificate", "value": json.dumps(private_arc)}),
                     ("classify unknown identifier", {"type": "private_key", "value": '"made-up-key-type"'}),
                     ("classify unknown identifier", {"type": "kms_key", "value": '"FUTURE_SPEC"'})]
    # a value with a line break stays one line; the set is bounded
    lines.clear()
    C.classify("certificate", "x\ny", None, None, {}, NOW)
    assert lines[0][1]["value"] == '"x\\ny"'
    for i in range(C._UNKNOWN_LIMIT + 50):
        C.note_unknown("certificate", f"1.3.6.1.4.1.99999.9.{i}")
    assert len(C._unknown_seen) == C._UNKNOWN_LIMIT
    assert len(lines) == C._UNKNOWN_LIMIT - 4 + 1  # 4 values seen above; then the cap


# ----------------------------------------------------------------------------- pq_kex_evidence / placeholders
@pytest.mark.parametrize("facts,expected", [
    ({"pq_group_supported": False, "negotiated_group": "X25519MLKEM768"}, False),  # explicit answer wins
    ({"pq_group_supported": True}, True),
    ({"pq_hybrid": True}, True),
    ({"pq_hybrid": False, "negotiated_group": "X25519MLKEM768"}, True),  # the old-node :4432 shape
    ({"pq_hybrid": False, "negotiated_group": "MLKEM1024"}, True),
    ({"pq_hybrid": False, "negotiated_group": "X25519"}, False),
    ({"pq_hybrid": False, "negotiated_group": "<NULL>"}, False),
    ({"negotiated_group": "X25519"}, None),
    ({"negotiated_group": "<NULL>"}, None),
    ({}, None),
    # a post-quantum signature in the group slot is no key exchange (review m1)
    ({"pq_hybrid": False, "negotiated_group": "ML-DSA-65"}, False),
    ({"negotiated_group": "ML-DSA-65"}, None),
    ({"pq_hybrid": False, "negotiated_group": "PQ_SIGN_ML_DSA_87"}, False),
    ({"pq_hybrid": False, "negotiated_group": "1.3.6.1.5.5.7.6.34"}, False),  # XMSS
    ({"pq_hybrid": False, "pq_group": "XMSS^MT"}, False),
    ({"pq_hybrid": False, "negotiated_group": "p256_kyber768"}, True),  # an oqs-provider hybrid KEM
    ({"pq_hybrid": False, "negotiated_group": "SecP256r1MLKEM768"}, True),
])
def test_pq_kex_evidence(facts, expected):
    assert C.pq_kex_evidence(facts) is expected


@pytest.mark.parametrize("group,pq_hybrid,qv,codes,cls", [
    ("ML-DSA-65", None, None, [], "not-applicable"),  # as an unknown group: no verdict, never PQ credit
    ("PQ_SIGN_ML_DSA_87", None, None, [], "not-applicable"),
    ("ML-DSA-65", False, None, ["NO_PQ_KEX"], "not-applicable"),
    ("X25519MLKEM768", None, False, [], "hybrid"),
    ("X25519MLKEM768", False, False, [], "hybrid"),
    ("MLKEM1024", None, False, [], "hybrid"),
    ("x25519", None, True, ["NO_PQ_KEX"], "quantum-vulnerable"),
    ("secp256r1", None, True, ["NO_PQ_KEX"], "quantum-vulnerable"),  # P-256 names an ECDH group too
])
def test_tls_group_slot_needs_a_key_exchange(group, pq_hybrid, qv, codes, cls):
    facts = {"versions": {"TLSv1.3": True}, "negotiated_group": group}
    if pq_hybrid is not None:
        facts["pq_hybrid"] = pq_hybrid
    v = C.classify("tls_endpoint", "TLS_AES_256_GCM_SHA384", None, "TLSv1.3", facts, NOW)
    assert (v["quantum_vulnerable"], v["finding_codes"]) == (qv, codes)
    assert P.pqc_class("tls_endpoint", v["quantum_vulnerable"], v["finding_codes"], facts) == cls


@pytest.mark.parametrize("kex,qv,codes", [
    (["Dilithium5", "ext-info-s"], True, ["SSH_NO_PQ_KEX"]),  # review m2: a signature is no key exchange
    (["2.16.840.1.101.3.4.3.19", "curve25519-sha256"], True, ["SSH_NO_PQ_KEX"]),
    (["XMSS^MT"], True, ["SSH_NO_PQ_KEX"]),
    (["mlkem768x25519-sha256", "curve25519-sha256"], False, []),
    (["sntrup761x25519-sha512@openssh.com", "curve25519-sha256"], False, []),
    (["curve25519-sha256"], True, ["SSH_NO_PQ_KEX"]),
])
def test_ssh_kex_needs_a_key_exchange(kex, qv, codes):
    v = C.classify("ssh_endpoint", None, None, None, {"kex": kex}, NOW)
    assert (v["quantum_vulnerable"], v["finding_codes"]) == (qv, codes)


def test_intended_changes_check_the_primitive():
    """Review m1/m2: the allowlist generator may never file a post-quantum signature in a key-exchange slot (a TLS
    group, an SSH kex method) as post-quantum key-exchange evidence, whatever the classifier does."""
    import make_algid_intended_changes as gen

    rows = {row["key"]: row for row in corpus.inputs()}
    vuln_ssh = [True, ["SSH_NO_PQ_KEX"], "Low", "quantum-vulnerable"]
    assert gen._category(rows["ssh|Dilithium5"], vuln_ssh, [False, [], None, "quantum-safe"]) is None
    assert gen._category(rows["ssh|2.16.840.1.101.3.4.3.19"], vuln_ssh, [False, [], None, "quantum-safe"]) is None
    assert gen._category(rows["tls|ML-DSA-65"], [False, [], None, "quantum-safe"],
                         [False, [], None, "hybrid"]) is None
    assert gen._category(rows["tls|X25519MLKEM768"], [False, [], None, "quantum-safe"],
                         [False, [], None, "hybrid"]) == "tls-pq-group-evidence"
    # a symmetric identifier never becomes quantum-vulnerable through a category either
    assert gen._category(rows["managed|AES"], [None, [], None, "not-applicable"],
                         [True, ["QUANTUM_VULNERABLE"], None, "quantum-vulnerable"]) is None


def test_classify_resolves_each_identifier_once():
    """Review M1: classify asks algid about the same identifier ~4 times per asset; the memo answers all but the
    first, so re-judging a run costs no more than dev did (AC #11)."""
    lab = _lab("lab :4432 tls_endpoint (dev node)")
    args = ("tls_endpoint", lab["algorithm"], lab.get("key_size"), lab.get("protocol"), lab["facts"], NOW)
    algid._resolve_memo.cache_clear()
    C.classify(*args)
    misses = algid._resolve_memo.cache_info().misses
    for _ in range(5):
        C.classify(*args)
    assert algid._resolve_memo.cache_info().misses == misses


def test_placeholder_group_is_absent():
    """FP-6: "<NULL>" is no group. A TLS 1.2 server that negotiated no TLS 1.3 group is judged by its protocols."""
    facts = {"versions": {"TLSv1.2": True, "TLSv1.3": False}, "negotiated_group": "<NULL>", "pq_hybrid": False}
    v = C.classify("tls_endpoint", "AES256-GCM-SHA384", None, None, facts, NOW)
    assert v["quantum_vulnerable"] is True and "NO_PQ_KEX" in v["finding_codes"]
    silent = {"versions": {"TLSv1.2": False, "TLSv1.3": False}, "negotiated_group": "<NULL>"}
    assert C.classify("tls_endpoint", None, None, None, silent, NOW)["quantum_vulnerable"] is None
