"""Staging QA round 2, Q1-09 (S4 phantom drift): run #54 against run #52 showed the AWS Private CA with the SAME ARN as
removed + added, and its QUANTUM_VULNERABLE resolved and opened again, because the certificate identity read the
free-text subject (``identity.node_identity``) and #481 changed how the AWS collector spells it
(``{"CommonName": "ZeroShield-AWS-PCA-Test"}`` -> ``CN=ZeroShield-AWS-PCA-Test``).

Now: a certificate at a cloud resource id is identified by (target, id); every other certificate compares its subject
and issuer as normalised DNs (an attribute map as the DN it denotes); a label-only change is a ``collector_changes``
entry. The stored per-source keys that change move along (``identity_migration`` in the estate write), so the next
run reads nothing as removed and added. Fixture: q1/runs/t1-run54/diff.json, the PCA entries (account id replaced).
"""
from __future__ import annotations

import datetime as dt
import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.new_models import (  # noqa: E402
    CbomCollectionJob,
    CbomQ0Gap,
    CbomRemediationAssignment,
)
from backend.utilities.cbom_sources import drift as D  # noqa: E402
from backend.utilities.cbom_sources import estate as E  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import identity_migration as M  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

FIXTURE = json.loads((Path(__file__).parent / "fixtures" / "qa2_run54_vs_run52_pca.json").read_text())
CREATED = dt.datetime(2026, 11, 20, 9, 0, tzinfo=dt.timezone.utc).replace(tzinfo=None)  # stored naive UTC


def _row(entry: dict, asset_id: int) -> SimpleNamespace:
    """A stored ``CbomCollectedAsset`` as the diff entry describes it: the label is ``<subject> · <where>``."""
    subject = entry["label"].split(" · ")[0]
    return SimpleNamespace(
        id=asset_id, asset_type=entry["type"], cdx_type="certificate", target=entry["target"],
        location=entry["location"], name=subject, algorithm="RSA", key_size=2048, protocol=None,
        quantum_vulnerable=True, impact=None, finding_codes=list(entry["finding_codes"]),
        facts={"subject": subject, "issuer": subject, "is_ca": True, "key_alg": "RSA_2048", "not_after": "2036-11-01"},
        asset_key=f"row-{asset_id}", created_at=CREATED, attempt=1)


def _sides(source_name: str):
    before = [_row(e, 100 + i) for i, e in enumerate(FIXTURE["removed"]) if e["source_name"] == source_name]
    after = [_row(e, 200 + i) for i, e in enumerate(FIXTURE["added"]) if e["source_name"] == source_name]
    return before, after


@pytest.mark.parametrize("source_name", ["aws-pca-test", "stgqa-aws-ap-south-1"])
def test_run54_vs_run52_the_private_ca_is_one_asset_not_removed_and_added(source_name):
    before, after = _sides(source_name)
    assert len(before) == len(after) == 1
    assert before[0].facts["subject"].startswith("{") and after[0].facts["subject"].startswith("CN=")
    diff = D.compare(D.node_views(before, "ref", reclassify=False), D.node_views(after, "ref", reclassify=False))
    assert diff["removed"] == [] and diff["added"] == []
    assert diff["resolved"] == [] and diff["opened"] == []  # QUANTUM_VULNERABLE neither resolved nor opened again
    assert diff["changed"] == []
    (label,) = diff["collector_changes"]
    assert label["code"] == "label" and label["label_change"] == "collector change"
    assert label["label_before"].startswith('{"CommonName": "ZeroShield-AWS-PCA-Test"}')
    assert label["label"].startswith("CN=ZeroShield-AWS-PCA-Test")


def test_the_legacy_identity_is_what_made_the_phantom_drift():
    before, after = _sides("aws-pca-test")
    assert ID.legacy_node_identity(before[0]) != ID.legacy_node_identity(after[0])
    assert ID.node_identity(before[0]) == ID.node_identity(after[0])


def test_canonical_dn_reads_an_attribute_map_as_the_dn_it_denotes():
    aws = {"Country": "IN", "Organization": "Bank One", "CommonName": "Bank One Root CA"}
    assert ID.canonical_dn(aws) == ID.canonical_dn(json.dumps(aws)) == ID.canonical_dn(
        "CN=Bank One Root CA,O=Bank One,C=IN") == "cn=bank one root ca,o=bank one,c=in"
    assert ID.canonical_dn("CN=x, O=y") == "cn=x, o=y"  # a DN text compares exactly as before (no re-key)
    assert ID.canonical_dn("{not json") == "{not json"
    assert ID.canonical_dn(None) == ""


def _cert(location: str, subject: str, **extra) -> SimpleNamespace:
    return SimpleNamespace(asset_type="certificate", cdx_type="certificate", target="10.0.0.5", location=location,
                           facts={"subject": subject, "issuer": "CN=Issuing CA,O=Bank", **extra}, asset_key="k")


def test_a_dn_text_certificate_off_the_cloud_keeps_its_stored_key():
    """No mass re-key: a prober / file / store certificate's identity (and so every key stored from it) is unchanged."""
    for row in (_cert("10.0.0.5:443#chain[0]", "CN=pay.example.com,O=Bank,C=IN"),
                _cert("/etc/ssl/pay.pem", "CN=pay.example.com, O=Bank"),
                _cert("LocalMachine\\My", "CN=win")):
        assert ID.node_identity(row) == ID.legacy_node_identity(row)
    assert ID.rekeyed_observations([_cert("10.0.0.5:443#chain[0]", "CN=a")], "ref") == {}


def test_a_cloud_certificate_is_its_resource_id_and_a_renewal_stays_renewed():
    arn = "arn:aws:acm:ap-south-1:111122223333:certificate/0f1e"
    old = _cert(arn, "pay.example.com", fingerprint_sha256="aa" * 32, not_after="2026-12-01")
    new = _cert(arn, "CN=pay.example.com", fingerprint_sha256="bb" * 32, not_after="2027-12-01")
    assert ID.node_identity(old) == ID.node_identity(new) == f"cert|10.0.0.5|{arn}"
    moves = ID.rekeyed_observations([new], "ref")
    assert moves == {ID.stable_key("node", "ref", ID.legacy_node_identity(new)):
                     ID.stable_key("node", "ref", ID.node_identity(new))}


# ----------------------------------------------------------------------------- the stored keys move (estate write)
from test_cbom_cb20_estate import World, _sqlite, cert  # noqa: E402


@pytest.fixture
def estate(tmp_path):
    engine = _sqlite(tmp_path / "estate.db")
    yield World(engine)
    engine.dispose()


ARN = "arn:aws:acm-pca:ap-south-1:111122223333:certificate-authority/ca429b08"


def _pca(subject: str) -> dict:
    # subject only: no serial, fingerprint or notAfter, so the estate keys it per source (``obs:<observation key>``)
    return {**cert("aws:111122223333", ARN, subject=subject, issuer=subject), "type": "cloud_ca", "name": subject,
            "codes": ["QUANTUM_VULNERABLE"], "qv": True}


def test_the_first_run_after_the_change_moves_every_stored_key_and_removes_nothing(estate: World, monkeypatch):
    """Runs #52 (JSON subject) and #53 (``CN=`` subject, after #481) were stored with the identity before the change;
    the first run after it (#54) moves the stored keys and the remediation assignment, and removes nothing."""
    world = estate
    src = world.source("aws_account", "aws-pca-test")
    with monkeypatch.context() as patch:  # before this change
        patch.setattr(ID, "node_identity", ID.legacy_node_identity)
        run52 = world.run({src: {"rows": [_pca('{"CommonName": "ZeroShield-AWS-PCA-Test"}')]}})
        world.finalise(run52)
        run53 = world.run({src: {"rows": [_pca("CN=ZeroShield-AWS-PCA-Test")]}})
        world.finalise(run53)
    E._INDEXES.clear()  # a deploy restarts the process: no key cached from before
    present = [o for o in world.observations() if o.presence == "present"]
    assert len(present) == 1 and present[0].asset_key.startswith("obs:")
    old_key = present[0].observation_key
    with Session(world.engine) as s:
        ref = ID.job_source_ref(s.exec(select(CbomCollectionJob).where(CbomCollectionJob.run_id == run53)).one(), None)
        s.add(CbomRemediationAssignment(team_id=1, asset_key=old_key, status="in_progress", owner="pki-team"))
        s.commit()
    seen = []
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        run54 = world.run({src: {"rows": [_pca("CN=ZeroShield-AWS-PCA-Test")]}})
        world.finalise(run54)
    finally:
        E.unregister_hook(hook)
    new_key = ID.stable_key("node", ref, f"cert|aws:111122223333|{ARN.lower()}")
    assert f"obs:{old_key}" not in world.assets() and world.assets()[f"obs:{new_key}"].presence == "present"
    assert [o.observation_key for o in world.observations() if o.presence == "present"] == [new_key]
    write = seen[0]
    assert write.rekeyed == [(f"obs:{old_key}", f"obs:{new_key}", ref)]  # moved, never read as removed
    assert write.counts["removed"] == 0 and write.identity_moves["assignments"] == 1
    with Session(world.engine) as s:
        assert [(a.asset_key, a.owner) for a in s.exec(select(CbomRemediationAssignment))] == [(new_key, "pki-team")]
        assert not [g for g in s.exec(select(CbomQ0Gap))
                    if g.item_key == f"asset:obs:{old_key}" and g.closed_at is None]
        from backend.new_models import CbomCollectionRun

        # S4: run 54 against run 52 (JSON subject before, CN= after) is one asset, no drift
        diff = D.run_diff(s, s.get(CbomCollectionRun, run54), s.get(CbomCollectionRun, run52))
    assert (diff["counts"]["added"], diff["counts"]["removed"], diff["counts"]["opened"],
            diff["counts"]["resolved"]) == (0, 0, 0, 0)
    assert diff["counts"]["collector_changes"] == 1
    # idempotent: the next run and a second remap move nothing more
    E._INDEXES.clear()
    world.finalise(world.run({src: {"rows": [_pca("CN=ZeroShield-AWS-PCA-Test")]}}))
    with Session(world.engine) as s:
        assert M.remap(s, 1, {ref: {old_key: new_key}}) == {"observations": 0, "assignments": 0}
    assert [o.observation_key for o in world.observations() if o.presence == "present"] == [new_key]
