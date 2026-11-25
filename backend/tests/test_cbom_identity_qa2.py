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
        "CN=Bank One Root CA,O=Bank One,C=IN") == "c=in,cn=bank one root ca,o=bank one"
    # review 6057627810 nit: spacing and attribute order are not part of the name (the key migration moves them)
    assert ID.canonical_dn("CN=x, O=y") == ID.canonical_dn("O=y,CN=x") == "cn=x,o=y"
    assert ID.canonical_dn("{not json") == "{not json"
    assert ID.canonical_dn(None) == ""


def _cert(location: str, subject: str, **extra) -> SimpleNamespace:
    return SimpleNamespace(asset_type="certificate", cdx_type="certificate", target="10.0.0.5", location=location,
                           facts={"subject": subject, "issuer": "CN=Issuing CA,O=Bank", **extra}, asset_key="k")


def test_a_dn_off_the_cloud_is_compared_whatever_its_spacing_and_attribute_order():
    """Review 6057627810 nit: ``CN=Corp Issuing CA, O=Corp, C=IN``, the same without spaces and in reverse order are
    one identity (an AD CS / prober / Windows-store CA whose spelling changes is no longer removed and added). A DN
    whose canonical form equals its old text keeps its key; one whose spelling the rule now reads differently is moved
    by the key migration (``identity_migration.keys_of``)."""
    where = "10.0.0.5:443#chain[1]"
    spellings = ("CN=Corp Issuing CA, O=Corp, C=IN", "CN=Corp Issuing CA,O=Corp,C=IN", "C=IN, O=Corp, CN=Corp Issuing CA",
                 "cn=corp issuing ca,  o=corp,c=in")
    assert len({ID.node_identity(_cert(where, s)) for s in spellings}) == 1
    assert len({ID.legacy_node_identity(_cert(where, s)) for s in spellings}) == 4  # what made the phantom drift
    assert ID.rekeyed_observations([_cert(where, "CN=a")], "ref") == {}  # one attribute: the same text either way
    assert M.keys_of(_cert(where, "CN=a"), "ref") is None
    assert M.keys_of(_cert(where, "CN=Corp Issuing CA, O=Corp, C=IN"), "ref") is not None


def test_the_migrations_frozen_rule_is_the_live_rule_today():
    """m4: ``identity_migration`` keeps its own copy of the rule, so a later release cannot change what q109 moves;
    today both give the same identity for every kind of certificate row."""
    rows = [_cert("10.0.0.5:443#chain[0]", "CN=pay.example.com, O=Bank"), _cert("/etc/ssl/a.pem", "O=B,CN=a"),
            _cert("arn:aws:acm:ap-south-1:111122223333:certificate/0f1e", '{"CommonName": "x"}'),
            _cert("LocalMachine\\My", '{"CommonName": "win", "Organization": "Corp"}'),
            SimpleNamespace(asset_type="tls_endpoint", cdx_type="protocol", target="t", location="l", facts={},
                            asset_key="k1")]
    for row in rows:
        assert M.node_identity(row) == ID.node_identity(row)
        assert M.legacy_node_identity(row) == ID.legacy_node_identity(row)


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
    M._DONE.clear()  # review 6057627810 m3: a scheduler tick in an earlier suite must not mark this team done
    yield World(engine)
    M._DONE.clear()
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
        patch.setattr(M, "node_identity", M.legacy_node_identity)  # the migration's frozen rule too
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
    # #497 review M1: moved IN PLACE before the store is read, so the write itself re-keys, removes and inserts nothing
    assert write.rekeyed == [] and write.counts["removed"] == 0 and write.counts["inserted"] == 0
    # the CN= observation (run 53) is renamed and the JSON one (run 52, removed then) merges into it: one asset
    assert write.identity_moves["assignments"] == 1 and write.identity_moves["estate"] == 2
    assert world.assets()[f"obs:{new_key}"].first_seen_run_id == run52  # the earlier first seen wins
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


# ----------------------------------------------------------------------------- #497 review M1: stored spelling, at deploy
JSON_SUBJECT = '{"CommonName": "ZeroShield-AWS-PCA-Test", "Organization": "ZeroShield"}'
CN_SUBJECT = "CN=ZeroShield-AWS-PCA-Test,O=ZeroShield"


def _pca_row(subject: str, dated: bool) -> dict:
    row = _pca(subject)
    if dated:  # a notAfter gives it a CB-21 cross key (cn/dn: the name), else it is keyed per source (obs:)
        row["facts"] = {**row["facts"], "not_after": "2036-11-01T00:00:00Z"}
    return row


def _store(world: World, ref_source: int, dated: bool, monkeypatch) -> tuple[int, str, str]:
    """Run #52 written with the identity before this change, the subject spelt as JSON (before #481); an accepted risk
    on its key. Returns (run, old estate key, old node key)."""
    with monkeypatch.context() as patch:
        patch.setattr(ID, "node_identity", ID.legacy_node_identity)
        patch.setattr(M, "node_identity", M.legacy_node_identity)  # the migration's frozen rule too
        patch.setattr(E.AK, "asset_key", E.AK.legacy_asset_key)
        patch.setattr(E.AK, "_cert_analysis_of", lambda fields, raw_names=True: _LEGACY(fields, True))
        E.AK._cert_analysed.cache_clear()
        run52 = world.run({ref_source: {"rows": [_pca_row(JSON_SUBJECT, dated)]}})
        world.finalise(run52)
    E.AK._cert_analysed.cache_clear()
    E._INDEXES.clear()
    (old_asset,) = world.assets()
    old_obs = world.observations()[0].observation_key
    with Session(world.engine) as s:
        s.add(CbomRemediationAssignment(team_id=1, asset_key=old_obs, status="accepted_risk", owner="risk-office"))
        s.commit()
    return run52, old_asset, old_obs


_LEGACY = E.AK._cert_analysis_of


def _expected_keys(world: World, dated: bool) -> tuple[str, str]:
    with Session(world.engine) as s:
        job = s.exec(select(CbomCollectionJob)).first()
        ref = ID.job_source_ref(job, None)
    row = SimpleNamespace(**{**_pca_row(CN_SUBJECT, dated), "asset_type": "cloud_ca", "asset_key": "k"})
    okey = ID.stable_key("node", ref, f"cert|aws:111122223333|{ARN.lower()}")
    obs = E.AK.Observation(kind="cloud_ca", facts=row.facts, location=ARN, target="aws:111122223333",
                           cdx_type="certificate", scope=ref)
    cross = E.AK.asset_key(obs)
    return (cross if isinstance(cross, str) else "obs:" + okey), okey


@pytest.mark.parametrize("dated", [True, False], ids=["cross key", "per-source key"])
def test_the_backfill_moves_every_stored_key_at_deploy_before_any_run(estate: World, monkeypatch, dated):
    """Stored as JSON only (a source last collected before #481); the scheduler's backfill runs before any new run."""
    from backend.new_models import CbomRiskRegister
    from backend.utilities.cbom_sources.risk_register import public_row

    src = estate.source("aws_account", "stgqa-aws-ap-south-1")
    run52, old_asset, old_obs = _store(estate, src, dated, monkeypatch)
    new_asset, new_obs = _expected_keys(estate, dated)
    assert old_asset != new_asset and old_obs != new_obs
    first_seen = estate.assets()[old_asset].first_seen_run_id
    assert M.backfill_due(estate.engine)["teams"] == 1
    # readers see the moved keys before any run: the asset, its observation, its register row, the accepted risk
    assert set(estate.assets()) == {new_asset} and estate.assets()[new_asset].first_seen_run_id == first_seen == run52
    assert [o.observation_key for o in estate.observations()] == [new_obs]
    with Session(estate.engine) as s:
        assert [(a.asset_key, a.status) for a in s.exec(select(CbomRemediationAssignment))] == [
            (new_obs, "accepted_risk")]
        assert [public_row(r)["item_key"] for r in s.execute(select(CbomRiskRegister)).scalars()] in ([new_asset], [])
    # safe twice: nothing more moves (and a second process's pass is a no-op)
    M._DONE.clear()
    with Session(estate.engine) as s:
        assert M.backfill_team(s, 1)["estate"] == 0
    # the first run after deploy reads CN=: nothing removed, nothing inserted
    seen = []
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        estate.finalise(estate.run({src: {"rows": [_pca_row(CN_SUBJECT, dated)]}}))
    finally:
        E.unregister_hook(hook)
    assert seen[0].counts["removed"] == 0 and seen[0].counts["inserted"] == 0 and seen[0].rekeyed == []
    assert set(estate.assets()) == {new_asset} and estate.assets()[new_asset].first_seen_run_id == run52


@pytest.mark.parametrize("dated", [True, False], ids=["cross key", "per-source key"])
def test_stored_as_json_only_the_first_run_with_cn_moves_the_keys_without_the_backfill(estate: World, monkeypatch,
                                                                                        dated):
    src = estate.source("aws_account", "stgqa-aws-ap-south-1")
    run52, old_asset, old_obs = _store(estate, src, dated, monkeypatch)
    new_asset, new_obs = _expected_keys(estate, dated)
    seen = []
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        estate.finalise(estate.run({src: {"rows": [_pca_row(CN_SUBJECT, dated)]}}))
    finally:
        E.unregister_hook(hook)
    write = seen[0]
    assert write.counts["removed"] == 0 and write.counts["inserted"] == 0
    assert write.identity_moves["assignments"] == 1 and write.identity_moves["estate"] == 1
    assert set(estate.assets()) == {new_asset} and estate.assets()[new_asset].first_seen_run_id == run52
    with Session(estate.engine) as s:
        assert [(a.asset_key, a.status, a.owner) for a in s.exec(select(CbomRemediationAssignment))] == [
            (new_obs, "accepted_risk", "risk-office")]


def test_a_json_map_name_and_its_dn_give_one_cross_key():
    facts = {"not_after": "2036-11-01T00:00:00Z", "issuer": JSON_SUBJECT}
    json_obs = E.AK.Observation(kind="certificate", facts={**facts, "subject": JSON_SUBJECT}, location="x", target="t")
    dn_obs = E.AK.Observation(kind="certificate", facts={**facts, "subject": CN_SUBJECT, "issuer": CN_SUBJECT},
                              location="y", target="t")
    assert E.AK.asset_key(json_obs) == E.AK.asset_key(dn_obs)
    assert E.AK.legacy_asset_key(json_obs) != E.AK.asset_key(json_obs)
    plain = E.AK.Observation(kind="certificate", facts={**facts, "subject": CN_SUBJECT, "issuer": CN_SUBJECT},
                             location="z", target="t")
    assert E.AK.legacy_asset_key(plain) == E.AK.asset_key(plain)  # a DN-text name keys as before: no KEY_VERSION bump


# ----------------------------------------------------------------------------- the deploy migration (q109certkey001)
VERSIONS = _REPO_ROOT / "prod_database_migrations/migrations/versions"


def _migration(name: str):
    import importlib.util

    spec = importlib.util.spec_from_file_location(name.split("_")[0], VERSIONS / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _step(engine, name: str, direction: str) -> None:
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(_migration(name), direction)()


def _held(world: World) -> tuple[set[str], list[str], list[tuple[str, str]], set[str]]:
    from backend.new_models import CbomOpsCounter

    with Session(world.engine) as s:
        assignments = [(a.asset_key, a.status) for a in s.exec(select(CbomRemediationAssignment))]
        marks = {c.name for c in s.exec(select(CbomOpsCounter)) if c.name.startswith(M.MARK)}
    return set(world.assets()), [o.observation_key for o in world.observations()], assignments, marks


@pytest.fixture(params=["sqlite", pytest.param("postgresql", marks=pytest.mark.skipif(
    not __import__("os").environ.get("CBOM_TEST_PG_URL"), reason="set CBOM_TEST_PG_URL to run against PostgreSQL"))])
def deployed(request, tmp_path):
    import os

    from sqlmodel import SQLModel, create_engine

    if request.param == "sqlite":
        engine = _sqlite(tmp_path / "deploy.db")
    else:
        engine = create_engine(os.environ["CBOM_TEST_PG_URL"])
        SQLModel.metadata.drop_all(engine)
        SQLModel.metadata.create_all(engine)
    M._DONE.clear()
    yield World(engine)
    M._DONE.clear()
    if request.param != "sqlite":
        SQLModel.metadata.drop_all(engine)
    engine.dispose()


@pytest.mark.parametrize("dated", [True, False], ids=["cross key", "per-source key"])
def test_the_deploy_migration_moves_every_stored_key_and_its_downgrade_moves_them_back(deployed: World, monkeypatch,
                                                                                         dated):
    """Q1-09 / tracker D1: the keys move in the deploy migration, before the release serves a request and before any
    run, for a source last collected before #481 (stored as JSON): the accepted risk and the first-seen run stay with
    the asset. The downgrade moves them back; up again moves them again."""
    src = deployed.source("aws_account", "stgqa-aws-ap-south-1")
    run52, old_asset, old_obs = _store(deployed, src, dated, monkeypatch)
    new_asset, new_obs = _expected_keys(deployed, dated)
    assert old_asset != new_asset and old_obs != new_obs
    mark = {f"{M.MARK}1"}

    _step(deployed.engine, "q109certkey001_cert_identity_keys", "upgrade")
    assert _held(deployed) == ({new_asset}, [new_obs], [(new_obs, "accepted_risk")], mark)
    assert deployed.assets()[new_asset].first_seen_run_id == run52
    assert M.backfill_due(deployed.engine)["teams"] == 0  # marked: the scheduler's fallback has nothing to do

    _step(deployed.engine, "q109certkey001_cert_identity_keys", "downgrade")
    assert _held(deployed) == ({old_asset}, [old_obs], [(old_obs, "accepted_risk")], set())
    assert deployed.assets()[old_asset].first_seen_run_id == run52

    _step(deployed.engine, "q109certkey001_cert_identity_keys", "upgrade")
    _step(deployed.engine, "q109certkey001_cert_identity_keys", "upgrade")  # idempotent
    assert _held(deployed) == ({new_asset}, [new_obs], [(new_obs, "accepted_risk")], mark)
    seen = []  # the first run after deploy reads CN=: nothing removed, nothing inserted, nothing left to move
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        deployed.finalise(deployed.run({src: {"rows": [_pca_row(CN_SUBJECT, dated)]}}))
    finally:
        E.unregister_hook(hook)
    assert seen[0].counts["removed"] == 0 and seen[0].counts["inserted"] == 0 and seen[0].rekeyed == []
    assert not any(seen[0].identity_moves.values())
    assert set(deployed.assets()) == {new_asset} and deployed.assets()[new_asset].first_seen_run_id == run52


def test_a_team_the_migration_cannot_move_never_blocks_the_deploy_and_the_scheduler_moves_it(deployed: World,
                                                                                            monkeypatch):
    src = deployed.source("aws_account", "stgqa-aws-ap-south-1")
    _run52, old_asset, old_obs = _store(deployed, src, False, monkeypatch)
    new_asset, new_obs = _expected_keys(deployed, False)
    real = M.migrate_team

    def broken(session, team_id, **kw):
        real(session, team_id, **kw)  # writes, then fails: the team's savepoint must undo them
        raise RuntimeError("boom")

    with monkeypatch.context() as patch:
        patch.setattr(M, "migrate_team", broken)
        _step(deployed.engine, "q109certkey001_cert_identity_keys", "upgrade")  # no exception: the deploy goes on
    assert _held(deployed) == ({old_asset}, [old_obs], [(old_obs, "accepted_risk")], set())
    assert M.backfill_due(deployed.engine)["teams"] == 1
    assert _held(deployed) == ({new_asset}, [new_obs], [(new_obs, "accepted_risk")], {f"{M.MARK}1"})


def test_the_history_index_migration_round_trips(tmp_path):
    import sqlalchemy as sa

    engine = sa.create_engine(f"sqlite:///{tmp_path / 'h.db'}")
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE cbomcollectionjob (id integer PRIMARY KEY, team_id integer, source_id integer,"
                             " run_id integer, kind varchar(16), status varchar(16), created_at datetime,"
                             " finished_at datetime)"))

    def names() -> set[str]:
        with engine.begin() as conn:
            return {i["name"] for i in sa.inspect(conn).get_indexes("cbomcollectionjob")}

    for direction, held in (("upgrade", True), ("downgrade", False), ("upgrade", True)):
        _step(engine, "q102hist001_collect_history_index", direction)
        assert ("ix_cbomcollectionjob_team_source_hist" in names()) is held
    engine.dispose()
    chain = {(_migration(n).revision, _migration(n).down_revision) for n in (
        "q102hist001_collect_history_index", "q109certkey001_cert_identity_keys")}
    assert chain == {("q102hist001", "rsched1trig001"), ("q109certkey001", "q102hist001")}


def test_a_source_whose_latest_run_failed_moves_at_deploy_and_its_first_success_removes_nothing(deployed: World,
                                                                                             monkeypatch):
    """Review 6057627810 M1: run #1 stored the PCA (JSON subject, before #481) and a dated ACM certificate with the
    old identity; run #2 failed (no rows, both observations ``not_read``), so the source's latest job holds nothing.
    The move is driven by the observations' own rows: the migration moves both, the accepted risk follows, and the
    first successful run after deploy removes 0 and inserts 0, with the first-seen run kept."""
    src = deployed.source("aws_account", "stgqa-aws-ap-south-1")
    acm_arn = "arn:aws:acm:ap-south-1:111122223333:certificate/0f1e"
    acm = {**cert("aws:111122223333", acm_arn, serial="7a" * 16, not_after="2027-03-01T00:00:00Z",
                  subject='{"CommonName": "pay.bank.in"}', issuer='{"CommonName": "Amazon RSA 2048 M02"}'),
           "codes": ["QUANTUM_VULNERABLE"], "qv": True}
    with monkeypatch.context() as patch:  # stored before this change
        patch.setattr(ID, "node_identity", ID.legacy_node_identity)
        patch.setattr(M, "node_identity", M.legacy_node_identity)
        patch.setattr(E.AK, "asset_key", E.AK.legacy_asset_key)
        patch.setattr(E.AK, "_cert_analysis_of", lambda fields, raw_names=True: _LEGACY(fields, True))
        E.AK._cert_analysed.cache_clear()
        run1 = deployed.run({src: {"rows": [_pca_row(JSON_SUBJECT, True), acm]}})
        deployed.finalise(run1)
        deployed.finalise(deployed.run({src: {"rows": [], "status": "failed", "outcome": "failed",
                                              "counts": {"ok": 0, "failed": 1}}}))
    E.AK._cert_analysed.cache_clear()
    E._INDEXES.clear()
    old_assets = set(deployed.assets())
    observations = deployed.observations()
    assert len(old_assets) == 2 and {o.presence for o in observations} == {"not_read"}
    pca = next(o for o in observations if o.location == ARN)
    pca_obs, pca_asset = pca.observation_key, pca.asset_key
    assert pca_asset.startswith("cert:")  # a cross key made from the name: it moves too
    with Session(deployed.engine) as s:
        s.add(CbomRemediationAssignment(team_id=1, asset_key=pca_obs, status="accepted_risk", owner="risk-office"))
        s.commit()

    _step(deployed.engine, "q109certkey001_cert_identity_keys", "upgrade")
    moved_assets = set(deployed.assets())
    assert pca_asset not in moved_assets and len(moved_assets) == 2
    assert all(a.first_seen_run_id == run1 for a in deployed.assets().values())
    new_pca_obs = next(o for o in deployed.observations() if o.location == ARN).observation_key
    assert new_pca_obs != pca_obs
    with Session(deployed.engine) as s:
        assert [(a.asset_key, a.status) for a in s.exec(select(CbomRemediationAssignment))] == [
            (new_pca_obs, "accepted_risk")]

    seen = []
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        acm_now = {**acm, "facts": {**acm["facts"], "subject": "CN=pay.bank.in", "issuer": "CN=Amazon RSA 2048 M02"}}
        deployed.finalise(deployed.run({src: {"rows": [_pca_row(CN_SUBJECT, True), acm_now]}}))
    finally:
        E.unregister_hook(hook)
    write = seen[0]
    assert write.counts["removed"] == 0 and write.counts["inserted"] == 0 and write.rekeyed == []
    assert set(deployed.assets()) == moved_assets
    assert {o.presence for o in deployed.observations()} == {"present"}
    assert all(a.first_seen_run_id == run1 for a in deployed.assets().values())
    with Session(deployed.engine) as s:
        assert [(a.asset_key, a.status, a.owner) for a in s.exec(select(CbomRemediationAssignment))] == [
            (new_pca_obs, "accepted_risk", "risk-office")]


def test_the_scheduler_fallback_skips_a_failing_team_and_moves_the_next(deployed: World, monkeypatch, capsys):
    """m4: a team that fails every time never stops the scheduler from moving a later unmarked team; the log says
    why (class and first line, no values)."""
    src = deployed.source("aws_account", "stgqa-aws-ap-south-1")
    _store(deployed, src, False, monkeypatch)
    other = deployed.source("aws_account", "team-2-aws", team_id=2)
    deployed.finalise(deployed.run({other: {"rows": [_pca(CN_SUBJECT)]}}, team_id=2))
    real = M.migrate_team

    def team1_fails(session, team_id, **kw):
        if team_id == 1:
            raise RuntimeError("relation cbomestateobservation is locked\nDETAIL: second line never logged")
        return real(session, team_id, **kw)

    with monkeypatch.context() as patch:
        patch.setattr(M, "migrate_team", team1_fails)
        out = M.backfill_due(deployed.engine)
    assert out["failed"] == 1 and out["teams"] == 1
    logged = capsys.readouterr().out
    assert "team=1" in logged and "RuntimeError: relation cbomestateobservation is locked" in logged
    assert "second line" not in logged
    _held_marks = _held(deployed)[3]
    assert _held_marks == {f"{M.MARK}2"}  # team 2 moved and marked; team 1 left for the next start
    assert M.backfill_due(deployed.engine)["teams"] == 1  # team 1 moves once it can
    assert _held(deployed)[3] == {f"{M.MARK}1", f"{M.MARK}2"}


def test_the_history_index_is_built_concurrently_on_postgresql():
    """m1: as ``cb19grade002``: CONCURRENTLY, outside the revision's transaction, retry-safe."""
    text = (VERSIONS / "q102hist001_collect_history_index.py").read_text()
    assert text.count("autocommit_block()") == 2 and text.count("postgresql_concurrently=True") == 2
    assert "if_not_exists=True" in text and "if_exists=True" in text
