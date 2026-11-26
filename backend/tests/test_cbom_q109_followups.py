"""#497 review 6060766322 follow-ups to the certificate identity migration (q109certkey001).

1. The first store write after deploy re-graded each changed certificate with one query per row (the read-elsewhere
   rule, ``posture.JudgedElsewhere``): ~7 ms per asset, 110 s for 20,000 certificates. Now one read per batch.
2. m1: ``estate.record_run`` step 0b re-read every certificate of the written sources on every run, forever. Now only
   during the rolling-deploy window; the scheduler closes it with a last pass (``identity_migration.close_due``).
3. m2: an asset q109 merged away kept its open Q0 item until the team's next store write. Now closed in the move.
4. nit: a merge could leave two identical estate links. Now dropped in the move, and a unique index holds it.

PostgreSQL variants: CBOM_TEST_PG_URL=postgresql+psycopg2://... (skipped without it).
"""
from __future__ import annotations

import datetime as dt
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import sqlalchemy as sa  # noqa: E402
from sqlmodel import Session, select  # noqa: E402

from backend.tests.support.pg_test_db import cbom_test_pg_url  # noqa: E402  (review 6065677758 n1)
from backend.new_models import (  # noqa: E402
    CbomCollectedAsset,
    CbomEstateLink,
    CbomOpsCounter,
    CbomQ0Gap,
    CbomRemediationAssignment,
)
from backend.utilities.cbom_sources import estate as E  # noqa: E402
from backend.utilities.cbom_sources import estate_links as LINKS  # noqa: E402
from backend.utilities.cbom_sources import identity as ID  # noqa: E402
from backend.utilities.cbom_sources import identity_migration as M  # noqa: E402
from backend.utilities.cbom_sources import posture as P  # noqa: E402
from backend.utilities.cbom_sources import risk_register as RR  # noqa: E402
from test_cbom_cb20_estate import NOW, World, cert  # noqa: E402
import test_cbom_identity_qa2 as QA2  # noqa: E402
from test_cbom_identity_qa2 import (  # noqa: E402
    CN_SUBJECT,
    JSON_SUBJECT,
    _LEGACY,
    _expected_keys,
    _pca_row,
    _step,
    _store,
)

deployed = QA2.deployed  # the sqlite / PostgreSQL fixture of the identity suite

Q109 = "q109certkey001_cert_identity_keys"
Q110 = "q110linkuq001_estate_link_unique"


def _step_tx(engine, name: str, direction: str, module=None) -> None:
    """As alembic's ``env.py`` runs a revision (``begin_transaction``), so ``autocommit_block`` works on PostgreSQL.
    ``module``: an already loaded (patched) revision module."""
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    from test_cbom_identity_qa2 import _migration

    with engine.connect() as conn:
        ctx = MigrationContext.configure(conn)
        with ctx.begin_transaction():
            with Operations.context(ctx):
                getattr(module or _migration(name), direction)()
        if conn.in_transaction():  # SQLite (no transactional DDL): what alembic's run commits
            conn.commit()


@pytest.fixture(autouse=True)
def _fresh_process_state():
    """The per-process state of the window close (back-off, warned settings) starts empty in every test."""
    M._CLOSE_FAILS.clear() if hasattr(M, "_CLOSE_FAILS") else None
    M._WARNED.clear() if hasattr(M, "_WARNED") else None
    yield
    M._CLOSE_FAILS.clear() if hasattr(M, "_CLOSE_FAILS") else None
    M._WARNED.clear() if hasattr(M, "_WARNED") else None


class Statements:
    """Counts the statements an engine runs inside the block."""

    def __init__(self, engine):
        self.engine, self.n = engine, 0

    def _count(self, *_a, **_k):
        self.n += 1

    def __enter__(self):
        sa.event.listen(self.engine, "before_cursor_execute", self._count)
        return self

    def __exit__(self, *exc):
        sa.event.remove(self.engine, "before_cursor_execute", self._count)


class Legacy:
    """The identity rule before Q1-09, as an older release writes it."""

    def __init__(self, monkeypatch):
        self.mp = monkeypatch

    def __enter__(self):
        self.ctx = self.mp.context()
        patch = self.ctx.__enter__()
        patch.setattr(ID, "node_identity", ID.legacy_node_identity)
        patch.setattr(M, "node_identity", M.legacy_node_identity)
        patch.setattr(E.AK, "asset_key", E.AK.legacy_asset_key)
        patch.setattr(E.AK, "_cert_analysis_of", lambda fields, raw_names=True: _LEGACY(fields, True))
        E.AK._cert_analysed.cache_clear()
        return self

    def __exit__(self, *exc):
        self.ctx.__exit__(*exc)
        E.AK._cert_analysed.cache_clear()
        E._INDEXES.clear()


def _unread(i: int, subject: str = "CN=h{i}.bank.in, O=Bank, C=IN") -> dict:
    """A prober certificate whose key was not read: class ``unknown`` unless another job of the run judged it."""
    host = f"10.1.{i // 250}.{i % 250}"
    return cert(host, f"{host}:443#chain[0]", subject=subject.format(i=i), issuer="CN=Bank CA, O=Bank, C=IN")


# ----------------------------------------------------------------------------- 1. the re-grade reads in batches
@pytest.mark.parametrize("n", [5, 60])
def test_grading_unread_certificates_reads_the_database_a_constant_number_of_times(deployed: World, n):
    """Review 6060766322 open item: ``risk_register.grade`` asked the database once per certificate whose class would
    be ``unknown`` (``JudgedElsewhere``). The statements of a full re-grade no longer grow with the certificates."""
    world = deployed
    src = world.source("network", "prober")
    world.finalise(world.run({src: {"rows": [_unread(i) for i in range(n)]}}))
    counts = {}
    for size in (n, 1):
        keys = sorted(world.assets())[:size]
        with Session(world.engine) as s:
            with Statements(world.engine) as st:
                out = RR.refresh(s, 1, keys, NOW, force=True)
            s.rollback()
        assert out.graded == size
        counts[size] = st.n
    assert counts[n] == counts[1], counts  # before: counts[n] == counts[1] + n - 1


def test_the_batched_read_elsewhere_rule_gives_exactly_the_per_row_answers(deployed: World):
    """The prefetch is the per-row query, set-based: same run, type, target (None and "" alike) and location, a
    verdict, a sibling of ANOTHER job only, the lowest id first."""
    world = deployed
    a, b = world.source("network", "prober"), world.source("linux_servers", "host")
    judged = {**_unread(1), "qv": True}  # source b read the same object with a verdict: a's copy is read elsewhere
    no_target = {**_unread(2), "target": ""}
    no_target_judged = {**no_target, "qv": False}
    run = world.run({a: {"rows": [_unread(1), _unread(2), no_target, _unread(3)]},
                     b: {"rows": [judged, no_target_judged, {**_unread(3), "qv": None}]}})
    with Session(world.engine) as s:
        rows = list(s.exec(select(CbomCollectedAsset).where(CbomCollectedAsset.run_id == run)))
        per_row = P.JudgedElsewhere(session=s, team_id=1, run_id=run)
        batched = P.JudgedElsewhere(session=s, team_id=1, run_id=run)
        unread = [r for r in rows if r.quantum_vulnerable is None]  # the rows the rule is asked about
        assert batched.prefetch(rows) == 4  # four distinct unread objects (the two copies of _unread(3) are one)
        with Statements(world.engine) as st:
            answers = [batched(r) for r in unread]
        assert st.n == 0
        assert answers == [per_row(r) for r in unread]
        assert sum(x is not None for x in answers) == 2  # _unread(1) and the target-less one


# ----------------------------------------------------------------------------- 2. m1: the re-key pass is bounded
def _write(world: World, src: int, rows: list[dict], seen: list) -> int:
    E.register_hook(hook := (lambda s, write: seen.append(write)))
    try:
        run = world.run({src: {"rows": rows}})
        world.finalise(run)
    finally:
        E.unregister_hook(hook)
    return run


def _mark_time(world: World) -> dt.datetime:
    with Session(world.engine) as s:
        return s.get(CbomOpsCounter, f"{M.MARK}1").updated_at


def test_after_the_rolling_deploy_window_a_store_write_skips_the_rekey_pass(deployed: World, monkeypatch):
    """m1: during the window every write re-reads the written sources' certificates newer than the mark (an older
    worker may still write the old identity); once the scheduler closed it, a write reads one counter row instead."""
    world = deployed
    src = world.source("network", "prober")
    with Legacy(monkeypatch):
        world.finalise(world.run({src: {"rows": [_unread(i) for i in range(4)]}}))
    _step(world.engine, Q109, "upgrade")
    calls = []
    real = M.migrate_team
    monkeypatch.setattr(M, "migrate_team", lambda *a, **k: calls.append(k) or real(*a, **k))
    seen: list = []
    _write(world, src, [_unread(i) for i in range(4)], seen)
    assert len(calls) == 1 and calls[0]["since_job"] > 0  # in the window: step 0b ran
    assert M.close_due(world.engine, _mark_time(world) + M.window() - dt.timedelta(minutes=1))["teams"] == 0
    closed = M.close_due(world.engine, _mark_time(world) + M.window())
    assert closed["teams"] == 1 and len(calls) == 2  # the closing pass
    assert M.close_due(world.engine, _mark_time(world) + 2 * M.window())["teams"] == 0  # once
    with Session(world.engine) as s:
        assert M.pending_since(s, 1) is None
    _write(world, src, [_unread(i) for i in range(4)], seen)
    assert len(calls) == 2  # after the window: no pass
    assert seen[-1].counts["removed"] == 0 and seen[-1].counts["inserted"] == 0
    # the downgrade clears the window with the mark: an upgrade after it opens a new one
    _step(world.engine, Q109, "downgrade")
    with Session(world.engine) as s:
        assert not [c for c in s.exec(select(CbomOpsCounter)) if c.name.startswith("identity_migration_qa2:")]


def test_an_older_workers_write_in_the_window_is_moved_by_the_closing_pass(deployed: World, monkeypatch):
    """m1, correctness at the end of the window: an older-release process wrote a source after the deploy migration
    (old identity) and nobody wrote that source since; the closing pass moves its keys and its accepted risk, so the
    first write after the window removes and inserts nothing."""
    world = deployed
    src = world.source("aws_account", "stgqa-aws-ap-south-1")
    _store(world, src, False, monkeypatch)  # stored before the deploy, with an accepted risk
    _new_asset, new_obs = _expected_keys(world, False)
    _step(world.engine, Q109, "upgrade")
    with Legacy(monkeypatch):  # an older worker, during the rolling deploy
        world.finalise(world.run({src: {"rows": [_pca_row(JSON_SUBJECT, False)]}}))
    present = [o.observation_key for o in world.observations() if o.presence == "present"]
    assert present and new_obs not in present  # written under the old identity
    assert M.close_due(world.engine, _mark_time(world) + M.window())["teams"] == 1
    assert [o.observation_key for o in world.observations()] == [new_obs]
    with Session(world.engine) as s:
        assert [(a.asset_key, a.status) for a in s.exec(select(CbomRemediationAssignment))] == [
            (new_obs, "accepted_risk")]
    seen: list = []
    _write(world, src, [_pca_row(CN_SUBJECT, False)], seen)
    assert seen[0].counts["removed"] == 0 and seen[0].counts["inserted"] == 0 and seen[0].rekeyed == []
    assert [o.observation_key for o in world.observations()] == [new_obs]


def test_in_the_window_an_older_workers_write_is_moved_by_the_next_write(deployed: World, monkeypatch):
    world = deployed
    src = world.source("aws_account", "stgqa-aws-ap-south-1")
    _store(world, src, False, monkeypatch)
    _step(world.engine, Q109, "upgrade")
    with Legacy(monkeypatch):
        world.finalise(world.run({src: {"rows": [_pca_row(JSON_SUBJECT, False)]}}))
    seen: list = []
    _write(world, src, [_pca_row(CN_SUBJECT, False)], seen)
    assert seen[0].identity_moves.get("observations")  # moved by step 0b, in the window
    assert seen[0].counts["removed"] == 0 and seen[0].counts["inserted"] == 0


# ----------------------------------------------------------------------------- 3. m2 and 4. nit: the merge
def _two_spellings(world: World, monkeypatch) -> tuple[str, str]:
    """One dated certificate held by two sources, spelt as JSON by one and as a DN by the other, stored with the old
    identity: two cross keys (old JSON key, DN key) that the new identity merges. Returns (old key, new key)."""
    a = world.source("aws_account", "aws-json")
    b = world.source("aws_account", "aws-dn")
    with Legacy(monkeypatch):
        world.finalise(world.run({a: {"rows": [_pca_row(JSON_SUBJECT, True)]},
                                  b: {"rows": [_pca_row(CN_SUBJECT, True)]}}))
    keys = {o.asset_key for o in world.observations()}
    new = _dn_key(world)
    assert len(keys) == 2 and new in keys
    (old,) = keys - {new}
    return old, new


def _dn_key(world: World) -> str:
    row = _pca_row(CN_SUBJECT, True)
    obs = E.AK.Observation(kind=row["type"], facts=row["facts"], location=row["location"], target=row["target"],
                           cdx_type="certificate")
    return E.AK.asset_key(obs)


def _gap(key: str) -> CbomQ0Gap:
    return CbomQ0Gap(team_id=1, item_kind="asset", item_key=f"asset:{key}", reason="unknown_verdict",
                     detail={"estate": True, "asset_key": key}, opened_at=NOW)


def test_a_merged_away_assets_open_q0_item_closes_in_the_migration(deployed: World, monkeypatch):
    """m2: both keys had an open Q0 item; q109 merges the old key into the new one (which keeps its own item). The old
    key's item closes in the migration (``model_change``), so D12's open Q0 count is right with no further run."""
    world = deployed
    old, new = _two_spellings(world, monkeypatch)
    with Session(world.engine) as s:
        s.add(_gap(old))
        s.add(_gap(new))
        s.commit()
    _step(world.engine, Q109, "upgrade")
    assert set(world.assets()) == {new}
    with Session(world.engine) as s:
        gaps = {g.item_key: g for g in s.exec(select(CbomQ0Gap))}
    assert gaps[f"asset:{new}"].closed_at is None
    assert gaps[f"asset:{old}"].closed_at is not None and gaps[f"asset:{old}"].close_cause == "model_change"
    assert gaps[f"asset:{old}"].closed_grade is None
    # downgrade-safe: back and up again; the history stays, one open item, on a live key
    _step(world.engine, Q109, "downgrade")
    _step(world.engine, Q109, "upgrade")
    with Session(world.engine) as s:
        open_items = [g.item_key for g in s.exec(select(CbomQ0Gap).where(CbomQ0Gap.closed_at.is_(None)))]
    assert open_items == [f"asset:{new}"] and set(world.assets()) == {new}


def test_a_merge_leaves_one_link_per_peer(deployed: World, monkeypatch):
    """nit: both keys were linked to the same component of the same scan; after the merge the new key holds it once.
    A link only the old key had moves; the unique index (q110) would refuse a duplicate."""
    world = deployed
    old, new = _two_spellings(world, monkeypatch)

    def link(key: str, component: str) -> CbomEstateLink:
        return CbomEstateLink(team_id=1, asset_key=key, kind="code", scan_id=7, component=component,
                              match="cert_key")

    with Session(world.engine) as s:
        s.add_all([link(old, "pay-api"), link(new, "pay-api"), link(old, "billing")])
        s.commit()
    _step(world.engine, Q109, "upgrade")
    with Session(world.engine) as s:
        held = sorted((x.asset_key, x.component) for x in s.exec(select(CbomEstateLink)))
    assert held == [(new, "billing"), (new, "pay-api")]
    with Session(world.engine) as s, pytest.raises(sa.exc.IntegrityError):
        s.add(link(new, "pay-api"))
        s.commit()


def test_the_link_builder_keeps_one_link_per_asset_scan_and_component():
    links = [{"asset_key": "k", "kind": "sbom", "scan_id": 1, "component": "openssl@3", "match": "purl"},
             {"asset_key": "k", "kind": "sbom", "scan_id": 1, "component": "openssl@3", "match": "name"},
             {"asset_key": "k", "kind": "code", "scan_id": 1, "component": "openssl@3", "match": "name"}]
    assert LINKS.unique_links(links) == [links[0], links[2]]


def test_q110_removes_duplicate_links_closes_orphan_q0_items_and_round_trips(deployed: World):
    """A database that ran q109 before this release: duplicate links and the open Q0 item of an asset merged away.
    q110 keeps the lowest-id link, builds the unique index (CONCURRENTLY on PostgreSQL), closes the orphan estate item
    (not a pre-estate one, not a live asset's); the downgrade drops the index and the upgrade runs again."""
    world = deployed
    src = world.source("network", "prober")
    world.finalise(world.run({src: {"rows": [_unread(1)]}}))
    (live,) = world.assets()
    with world.engine.begin() as conn:  # the table as q109 left it: no unique index
        conn.execute(sa.text("DROP INDEX uq_cbomestatelink_link"))
    with Session(world.engine) as s:
        for _ in range(3):
            s.add(CbomEstateLink(team_id=1, asset_key=live, kind="sbom", scan_id=3, component="c", match="name"))
        s.add(CbomEstateLink(team_id=1, asset_key=live, kind="sbom", scan_id=4, component="c", match="name"))
        s.add(_gap("cert:gone"))  # (the live asset's own item is open already: the store's hook opened it)
        s.add(CbomQ0Gap(team_id=1, item_kind="asset", item_key="asset:obs-per-run", reason="unknown_verdict",
                        detail={"source_id": src}, opened_at=NOW))
        s.commit()
    _step_tx(world.engine, Q110, "upgrade")

    def state():
        with Session(world.engine) as s:
            links = sorted((x.scan_id, x.id) for x in s.exec(select(CbomEstateLink)))
            open_items = sorted(g.item_key for g in s.exec(select(CbomQ0Gap).where(CbomQ0Gap.closed_at.is_(None))))
        return links, open_items, {i["name"] for i in sa.inspect(world.engine).get_indexes("cbomestatelink")}

    links, open_items, indexes = state()
    assert [scan for scan, _id in links] == [3, 4] and links[0][1] == min(i for _s, i in links)
    assert open_items == sorted([f"asset:{live}", "asset:obs-per-run"])
    assert "uq_cbomestatelink_link" in indexes
    with Session(world.engine) as s:
        closed = s.exec(select(CbomQ0Gap).where(CbomQ0Gap.item_key == "asset:cert:gone")).one()
    assert closed.close_cause == "model_change"
    _step_tx(world.engine, Q110, "downgrade")
    assert "uq_cbomestatelink_link" not in state()[2]
    _step_tx(world.engine, Q110, "upgrade")
    _step_tx(world.engine, Q110, "upgrade")  # retry-safe
    assert state()[:2] == (links, open_items) and "uq_cbomestatelink_link" in state()[2]
    if world.engine.dialect.name == "postgresql":
        with world.engine.connect() as conn:
            assert conn.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                        "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar() is True


def test_the_migration_chain_has_one_head():
    from alembic.script import ScriptDirectory

    script = ScriptDirectory(str(_REPO_ROOT / "prod_database_migrations/migrations"))
    # PR #499 chains q111remgroup001 (the remediation group-key backfill) after q110: still one head
    assert script.get_heads() == ["q111remgroup001"]
    assert script.get_revision("q111remgroup001").down_revision == "q110linkuq001"
    assert script.get_revision("q110linkuq001").down_revision == "q109certkey001"


@pytest.mark.skipif(not cbom_test_pg_url(), reason="set CBOM_TEST_PG_URL")
def test_q110_retries_after_an_interrupted_concurrent_build(deployed: World):
    """An earlier attempt left an INVALID index (a build interrupted, or failed on a duplicate written meanwhile):
    the upgrade drops it, removes the duplicates again and builds a valid one."""
    world = deployed
    if world.engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL only")
    src = world.source("network", "prober")
    world.finalise(world.run({src: {"rows": [_unread(1)]}}))
    (live,) = world.assets()
    with world.engine.begin() as conn:
        conn.execute(sa.text("DROP INDEX uq_cbomestatelink_link"))
    with Session(world.engine) as s:
        s.add_all([CbomEstateLink(team_id=1, asset_key=live, kind="sbom", scan_id=3, component="c", match="name")
                   for _ in range(2)])
        s.commit()
    with world.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as conn:
        with pytest.raises(sa.exc.IntegrityError):  # what a failed CONCURRENTLY build leaves: an invalid index
            conn.execute(sa.text("CREATE UNIQUE INDEX CONCURRENTLY uq_cbomestatelink_link ON cbomestatelink "
                                 "(team_id, asset_key, kind, scan_id, component)"))
        assert conn.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                    "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar() is False
    _step_tx(world.engine, Q110, "upgrade")
    with world.engine.connect() as conn:
        assert conn.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                    "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar() is True
        assert conn.execute(sa.text("SELECT count(*) FROM cbomestatelink")).scalar() == 1


# ----------------------------------------------------------------------------- #504 review 6062542062
def test_the_window_setting_is_documented_where_operators_set_cbom_settings():
    """Minor 1: the setting, what an older writer after the window does, and that compose deploys recreate every
    container, in the env examples and the staging and chola-prod READMEs; the CONCURRENTLY runbook note."""
    for rel in ("deploy/staging/backend.env.example", "deploy/local/.env.example", "backend/.env.example",
                "deploy/staging/README.md", "deploy/chola-prod/README.md"):
        text = (_REPO_ROOT / rel).read_text()
        assert "CBOM_IDENTITY_WINDOW_HOURS" in text, rel
        flat = " ".join(text.split())
        assert "removed" in flat and "observation" in flat and "recreate" in flat, rel
    staging = (_REPO_ROOT / "deploy/staging/README.md").read_text()
    assert "## Migrations that build an index CONCURRENTLY" in staging and "idle in transaction" in staging


@pytest.mark.parametrize("raw, hours", [("", 24), ("48", 48), ("0.1", 1), ("0", 1), ("1e12", 720), ("721", 720),
                                         ("inf", 24), ("-inf", 24), ("nan", 24), ("-5", 24), ("abc", 24)])
def test_the_window_is_clamped_and_bad_values_are_refused(monkeypatch, raw, hours):
    """Minor 2: ``inf`` (or anything above ~2.4e10 h) overflowed ``timedelta`` and made every tick fail."""
    monkeypatch.setenv("CBOM_IDENTITY_WINDOW_HOURS", raw)
    assert M.window() == dt.timedelta(hours=hours)


def test_a_refused_window_setting_is_logged_once_and_close_due_still_works(deployed: World, monkeypatch, capsys):
    monkeypatch.setenv("CBOM_IDENTITY_WINDOW_HOURS", "inf")
    with Session(deployed.engine) as s:
        s.add(CbomOpsCounter(name=f"{M.MARK}1", value=0, updated_at=NOW - dt.timedelta(days=2)))
        s.commit()
    outs = [M.close_due(deployed.engine, NOW) for _ in range(3)]
    assert [o["teams"] for o in outs] == [1, 0, 0] and not any(o["failed"] for o in outs)
    assert capsys.readouterr().out.count("identity window setting REFUSED") == 1


def _marks(world: World, teams, *, age=dt.timedelta(days=2)) -> None:
    with Session(world.engine) as s:
        for t in teams:
            s.add(CbomOpsCounter(name=f"{M.MARK}{t}", value=0, updated_at=NOW - age))
        s.commit()


def _closed(world: World) -> set[int]:
    with Session(world.engine) as s:
        return {int(c.name[len(M.CLOSED):]) for c in s.exec(select(CbomOpsCounter)) if c.name.startswith(M.CLOSED)}


def test_teams_that_keep_failing_do_not_starve_the_teams_after_them(deployed: World, monkeypatch):
    """Nit: ``due[:20]`` by team id retried the same 20 failing teams every tick, so team 21 never closed. A failed
    team backs off (1, 2, 4 ... 60 minutes) and the others go first meanwhile; it is retried once its back-off ends."""
    _marks(deployed, range(1, 22))
    real = M.migrate_team

    def fails(session, team_id, **kw):
        if team_id <= 20:
            raise RuntimeError("source locked by an older worker")
        return real(session, team_id, **kw)

    monkeypatch.setattr(M, "migrate_team", fails)
    first = M.close_due(deployed.engine, NOW)
    assert first["failed"] == 20 and first["teams"] == 0
    second = M.close_due(deployed.engine, NOW + dt.timedelta(seconds=30))  # the next tick
    assert second["teams"] == 1 and _closed(deployed) == {21}
    monkeypatch.setattr(M, "migrate_team", real)  # the older worker is gone: after the back-off they all close
    assert M.close_due(deployed.engine, NOW + dt.timedelta(seconds=60))["teams"] == 20
    assert _closed(deployed) == set(range(1, 22))


def test_when_two_schedulers_close_a_team_only_the_one_that_wrote_closed_reports_it(deployed: World, monkeypatch):
    """Nit: the closer that lost the race (the other committed CLOSED while this one ran its pass) reported the team
    too. It now writes CLOSED itself or reports nothing."""
    _marks(deployed, [1])
    real = M.migrate_team

    def other_scheduler_wins(session, team_id, **kw):
        found = real(session, team_id, **kw)
        with Session(deployed.engine) as other:
            other.add(CbomOpsCounter(name=f"{M.CLOSED}{team_id}", value=0, updated_at=NOW))
            other.commit()
        return found

    monkeypatch.setattr(M, "migrate_team", other_scheduler_wins)
    out = M.close_due(deployed.engine, NOW)
    assert out["teams"] == 0 and out["failed"] == 0 and _closed(deployed) == {1}


def test_two_racing_schedulers_report_the_team_once(deployed: World):
    import threading

    world = deployed
    world.source("network", "prober")
    _marks(world, [1])
    barrier, outs = threading.Barrier(2), []

    def closer():
        barrier.wait()
        try:
            outs.append(M.close_due(world.engine, NOW))
        except Exception as exc:  # noqa: BLE001
            outs.append({"teams": 0, "error": repr(exc)})

    threads = [threading.Thread(target=closer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert sum(o["teams"] for o in outs) == 1 and _closed(world) == {1}


def test_q110_labels_an_operator_removed_assets_item_removed(deployed: World):
    """Info: an orphan estate item whose register row is still there was removed by a store write without hooks (the
    ``estate backfill`` operator path): ``removed``; one with no register row was merged away by q109:
    ``model_change``."""
    from backend.new_models import CbomRiskRegister

    world = deployed
    with Session(world.engine) as s:
        s.add(_gap("cert:merged-away"))
        s.add(_gap("cert:backfilled-away"))
        s.add(CbomRiskRegister(team_id=1, item_key="cert:backfilled-away", q_reason="unknown_verdict", q_grade="Q0",
                               q_rank=5, model_version="m", inputs_digest="i", grade_digest="g", updated_at=NOW))
        s.commit()
    _step_tx(world.engine, Q110, "upgrade")
    with Session(world.engine) as s:
        causes = {g.item_key: g.close_cause for g in s.exec(select(CbomQ0Gap))}
    assert causes == {"asset:cert:merged-away": "model_change", "asset:cert:backfilled-away": "removed"}


@pytest.mark.skipif(not cbom_test_pg_url(), reason="set CBOM_TEST_PG_URL")
def test_q110_gives_up_on_an_idle_transaction_after_its_lock_timeout_and_retries(deployed: World, monkeypatch):
    """Nit: the CONCURRENTLY build waits for every older transaction. Each attempt now waits at most
    ``LOCK_TIMEOUT``; after ``ATTEMPTS`` it raises (no invalid index left), and the deploy run again builds it."""
    from test_cbom_identity_qa2 import _migration

    world = deployed
    if world.engine.dialect.name != "postgresql":
        pytest.skip("PostgreSQL only")
    with world.engine.begin() as conn:
        conn.execute(sa.text("DROP INDEX uq_cbomestatelink_link"))
    module = _migration(Q110)
    monkeypatch.setattr(module, "LOCK_TIMEOUT", "1s")
    monkeypatch.setattr(module, "RETRY_SECONDS", 0)
    idle = world.engine.connect()
    idle.execute(sa.text("INSERT INTO cbomestatelink (team_id, asset_key, kind, scan_id, component, match) "  # a writer
                         "VALUES (1, 'k', 'sbom', 1, 'c', 'name')"))  # of the table, idle in its transaction
    try:
        started = dt.datetime.now()
        with pytest.raises(sa.exc.OperationalError):
            _step_tx(world.engine, Q110, "upgrade", module)
        assert (dt.datetime.now() - started).total_seconds() < 30
        with world.engine.connect() as conn:  # never a valid index built over the writer's transaction: none, or
            assert conn.execute(sa.text(  # an INVALID one the next run drops
                "SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar() in (None, False)
    finally:
        idle.rollback()
        idle.close()
    _step_tx(world.engine, Q110, "upgrade", module)
    with world.engine.connect() as conn:
        assert conn.execute(sa.text("SELECT i.indisvalid FROM pg_index i JOIN pg_class c ON c.oid = i.indexrelid "
                                    "WHERE c.relname = 'uq_cbomestatelink_link'")).scalar() is True
