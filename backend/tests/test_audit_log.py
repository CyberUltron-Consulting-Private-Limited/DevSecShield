"""The audit log (F4 RBAC): who did what, to which object, from which address, when; append-only.

* a successful team write is recorded once (middleware), with the route's object, the client address (never a
  spoofed X-Forwarded-For), the user agent and the status; reads and failed requests are not;
* refusals are recorded as "denied"; sign-ins (accepted and refused) are recorded without any secret;
* the ORM refuses to change or delete an event; the hash chain finds a changed or removed row;
* GET /team/{id}/audit is for that team's admins and shows only that team; GET /admin/audit for superusers;
* on PostgreSQL (AUTH_TEST_PG_URL) triggers refuse UPDATE, DELETE and TRUNCATE, and 16 concurrent writers keep
  one unbroken chain.

    cd backend && PYTHON_DOTENV_DISABLED=1 PYTHONPATH=.. JWT_SECRET_KEY=t JWT_REFRESH_SECRET_KEY=r \
      AWS_ACCESS_KEY_ID=x AWS_SECRET_ACCESS_KEY=y AWS_DEFAULT_REGION=us-east-1 \
      python -m pytest tests/test_audit_log.py -q -p no:cacheprovider
"""
import os
import sys
import threading
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.schema import CreateSchema, DropSchema

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))
os.environ.setdefault("JWT_SECRET_KEY", "audit-log-test-access-secret-0123456789")
os.environ.setdefault("JWT_REFRESH_SECRET_KEY", "audit-log-test-refresh-secret-0123456789")

from fastapi.testclient import TestClient  # noqa: E402
from sqlmodel import Session, SQLModel, create_engine, select  # noqa: E402

from backend.main import app  # noqa: E402
from backend.access_models import AuditEvent  # noqa: E402
from backend.new_models import Team  # noqa: E402
from backend.routers import auth as auth_router  # noqa: E402
from backend.utilities import ratelimit  # noqa: E402
from backend.utilities.auth.auth_utils import get_hashed_password  # noqa: E402
from backend.utilities.rbac import audit  # noqa: E402
from backend.tests.support.rbac import bearer, join, make_user, patch_all_get_db  # noqa: E402

PASSWORD = "Correct-Horse-Battery-9"
ADMIN, MEMBER, OTHER_ADMIN, ROOT = "ann@acme.test", "mo@acme.test", "zed@other.test", "root@zeroshield.test"


@pytest.fixture()
def world(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'audit.db'}", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    patch_all_get_db(monkeypatch, engine)
    codes: dict[str, str] = {}
    monkeypatch.setattr(auth_router, "send_verification_email", lambda email, code: codes.__setitem__(email, code))
    ratelimit.reset_all()
    ids = {}
    with Session(engine) as s:
        for name in ("Acme", "Other"):
            t = Team(name=name)
            s.add(t)
            s.commit()
            s.refresh(t)
            ids[name] = t.id
        for email, team, role in ((ADMIN, "Acme", "owner"), (MEMBER, "Acme", "member"), (OTHER_ADMIN, "Other", "owner")):
            u = make_user(s, email, password_hash=get_hashed_password(PASSWORD))
            ids[email] = u.id
            join(s, ids[team], u.id, role)
        ids[ROOT] = make_user(s, ROOT, superuser=True).id
    yield engine, ids, codes
    ratelimit.reset_all()


@pytest.fixture()
def client(world):
    return TestClient(app)


def rows(engine, **where):
    with Session(engine) as s:
        q = select(AuditEvent).order_by(AuditEvent.id)
        for key, value in where.items():
            q = q.where(getattr(AuditEvent, key) == value)
        return s.exec(q).all()


def test_a_successful_team_write_is_recorded_once_with_who_what_where_and_when(world, client):
    engine, ids, _ = world
    team = ids["Acme"]
    response = client.put(f"/team/{team}", headers={**bearer(ADMIN), "X-Forwarded-For": "6.6.6.6",
                                                     "User-Agent": "pytest-agent/1"},
                          json={"name": "Acme Security", "description": "d"})
    assert response.status_code == 200, response.text
    written = rows(engine, action="team.update")
    assert len(written) == 1
    event = written[0]
    assert (event.team_id, event.actor_user_id, event.actor_email, event.actor_type) == (team, ids[ADMIN], ADMIN, "user")
    assert (event.object_type, event.object_id, event.outcome) == ("team", str(team), "success")
    assert event.ip == "testclient"  # the client address, never the header the client sent
    assert event.user_agent == "pytest-agent/1"
    assert event.details["route"] == "/team/{team_id}" and event.details["status"] == 200
    assert event.at is not None and len(event.hash) == 64


def test_reads_and_failed_writes_are_not_recorded_as_done(world, client):
    engine, ids, _ = world
    team = ids["Acme"]
    assert client.get(f"/team/{team}", headers=bearer(ADMIN)).status_code == 200
    assert client.get(f"/{team}/cbom/sources/settings", headers=bearer(MEMBER)).status_code == 200
    ratelimit.reset_all()
    bad = client.put(f"/team/{team}", headers=bearer(ADMIN), json={"name": 5})  # validation error
    assert bad.status_code in (400, 422)
    assert [e for e in rows(engine) if e.outcome == "success"] == []


def test_the_object_is_the_most_specific_path_parameter(world, client):
    engine, ids, _ = world
    team = ids["Acme"]
    ratelimit.reset_all()
    created = client.post(f"/{team}/cbom/sources/nodes", headers=bearer(MEMBER), json={"name": "edge-1"})
    assert created.status_code in (200, 201), created.text
    node_id = created.json()["node"]["id"]
    ratelimit.reset_all()
    assert client.delete(f"/{team}/cbom/sources/nodes/{node_id}", headers=bearer(MEMBER)).status_code in (200, 204)
    deleted = rows(engine, action="cbom.write")[-1]
    assert (deleted.object_type, deleted.object_id, deleted.details["method"]) == ("node", str(node_id), "DELETE")


def test_refusals_are_recorded_as_denied(world, client):
    engine, ids, _ = world
    team = ids["Acme"]
    assert client.patch(f"/{team}/cbom/sources/settings", headers=bearer(MEMBER), json={}).status_code == 403
    assert client.put(f"/team/{ids['Other']}", headers=bearer(MEMBER), json={"name": "x"}).status_code == 403
    denied = rows(engine, outcome="denied")
    assert [(e.action, e.team_id, e.actor_user_id) for e in denied] == [
        ("cbom.settings", team, ids[MEMBER]), ("team.update", ids["Other"], ids[MEMBER])]


def test_sign_ins_are_recorded_without_secrets(world, client):
    engine, ids, codes = world
    assert client.post("/send_code", json={"email": MEMBER}).status_code == 200
    ratelimit.reset_all()
    bad = client.post("/login", json={"email": MEMBER, "verification_code": codes[MEMBER], "password": "Wrong-Password-1"})
    assert bad.status_code == 400
    ratelimit.reset_all()
    assert client.post("/send_code", json={"email": MEMBER}).status_code == 200
    ratelimit.reset_all()
    good = client.post("/login", json={"email": MEMBER, "verification_code": codes[MEMBER], "password": PASSWORD})
    assert good.status_code == 200, good.text
    events = rows(engine, actor_email=MEMBER)
    assert [(e.action, e.outcome) for e in events if e.action.startswith("auth.")] == [
        ("auth.login", "denied"), ("auth.login", "success")]
    for event in events:
        text = str(event.details)
        assert PASSWORD not in text and "Wrong-Password-1" not in text and codes[MEMBER] not in text
    ratelimit.reset_all()
    assert client.get("/logout", headers={"Authorization": f"Bearer {good.json()['access_token']}"}).status_code == 200
    assert rows(engine, action="auth.logout")[-1].actor_user_id == ids[MEMBER]


def test_the_orm_never_changes_or_deletes_an_event(world):
    engine, _, _ = world
    audit.record_now(engine, action="test.event", team_id=1, details={"a": 1})
    with Session(engine) as s:
        event = s.exec(select(AuditEvent)).one()
        event.action = "edited"
        s.add(event)
        with pytest.raises(audit.AuditLogIsAppendOnly):
            s.commit()
    with Session(engine) as s:
        event = s.exec(select(AuditEvent)).one()
        s.delete(event)
        with pytest.raises(audit.AuditLogIsAppendOnly):
            s.commit()
    with Session(engine) as s:
        with pytest.raises(audit.AuditLogIsAppendOnly):
            s.exec(sa.update(AuditEvent).values(action="bulk"))
        with pytest.raises(audit.AuditLogIsAppendOnly):
            s.exec(sa.delete(AuditEvent))
    assert rows(engine)[0].action == "test.event"


def test_the_chain_finds_a_changed_and_a_removed_event(world):
    engine, _, _ = world
    for i in range(5):
        audit.record_now(engine, action=f"test.{i}", team_id=1, details={"i": i})
    assert audit.verify_chain(engine) == {"ok": True, "checked": 5, "first_bad_id": None, "reason": None}
    ids = [e.id for e in rows(engine)]
    with engine.begin() as conn:  # behind the application's back (SQLite has no trigger)
        conn.execute(sa.text("UPDATE auditevent SET actor_email = 'someone-else@acme.test' WHERE id = :i"), {"i": ids[2]})
    changed = audit.verify_chain(engine)
    assert changed["ok"] is False and changed["first_bad_id"] == ids[2] and "changed" in changed["reason"]
    with engine.begin() as conn:
        conn.execute(sa.text("DELETE FROM auditevent WHERE id IN (:a, :b)"), {"a": ids[1], "b": ids[2]})
    removed = audit.verify_chain(engine)
    assert removed["ok"] is False and removed["first_bad_id"] == ids[3] and "removed" in removed["reason"]


def test_team_admins_read_their_own_teams_events_only(world, client):
    engine, ids, _ = world
    team, other = ids["Acme"], ids["Other"]
    audit.record_now(engine, action="secret.other.team", team_id=other, details={})
    for i in range(3):
        ratelimit.reset_all()
        client.put(f"/team/{team}", headers=bearer(ADMIN), json={"name": f"Acme {i}", "description": "d"})
    page = client.get(f"/team/{team}/audit?limit=2", headers=bearer(ADMIN))
    assert page.status_code == 200, page.text
    data = page.json()
    assert len(data["events"]) == 2 and data["next_before_id"] is not None
    assert all(e["team_id"] == team for e in data["events"])
    more = client.get(f"/team/{team}/audit?limit=50&before_id={data['next_before_id']}", headers=bearer(ADMIN)).json()
    assert {e["action"] for e in data["events"] + more["events"]} == {"team.update"}
    assert "secret.other.team" not in page.text + str(more)
    filtered = client.get(f"/team/{team}/audit?action=team.update&outcome=denied", headers=bearer(ADMIN)).json()
    assert filtered["events"] == []
    assert client.get(f"/team/{team}/audit", headers=bearer(MEMBER)).status_code == 403
    assert client.get(f"/team/{other}/audit", headers=bearer(ADMIN)).status_code == 403
    assert client.get(f"/team/{team}/audit?limit=100000", headers=bearer(ADMIN)).status_code == 422


def test_superusers_read_and_verify_the_whole_log(world, client):
    engine, ids, _ = world
    audit.record_now(engine, action="platform.event", team_id=None)
    assert client.get("/admin/audit", headers=bearer(ADMIN)).status_code == 403
    every = client.get("/admin/audit", headers=bearer(ROOT)).json()
    assert any(e["action"] == "platform.event" for e in every["events"])
    verified = client.get("/admin/audit/verify", headers=bearer(ROOT)).json()
    assert verified["ok"] is True and verified["checked"] >= 1


# ------------------------------------------------------------------------------------------------ PostgreSQL

PG_URL = os.environ.get("AUTH_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG_URL, reason="set AUTH_TEST_PG_URL (an empty PostgreSQL database) to run")


@pytest.fixture()
def pg_schema():
    """A schema of its own, so the migration and the triggers never touch other tests' tables."""
    schema = f"f4audit_{uuid.uuid4().hex[:10]}"
    admin = create_engine(PG_URL)
    with admin.begin() as conn:
        conn.execute(CreateSchema(schema))  # a quoted identifier, never interpolated SQL
    engine = create_engine(PG_URL, pool_size=20, max_overflow=0,
                           connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield engine, schema
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(DropSchema(schema, cascade=True))
        admin.dispose()


def _migrate(engine, direction: str):
    import importlib.util

    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    path = _REPO_ROOT / "prod_database_migrations" / "migrations" / "versions" / "r6f4rbac001_rbac_roles_audit_log.py"
    spec = importlib.util.spec_from_file_location("r6f4rbac001", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(module, direction)()


@needs_pg
def test_postgresql_refuses_update_delete_and_truncate(pg_schema):
    engine, _ = pg_schema
    _create_pre_rbac_tables(engine)
    _migrate(engine, "upgrade")  # the migration creates the table and its triggers
    audit.record_now(engine, action="pg.event", team_id=1)
    for statement in ("UPDATE auditevent SET action = 'x'", "DELETE FROM auditevent", "TRUNCATE auditevent"):
        with pytest.raises(sa.exc.DBAPIError) as refused, engine.begin() as conn:
            conn.execute(sa.text(statement))
        assert "append-only" in str(refused.value)
    assert rows(engine)[0].action == "pg.event"


@needs_pg
def test_concurrent_writers_keep_one_chain_on_postgresql(pg_schema):
    engine, _ = pg_schema
    SQLModel.metadata.create_all(engine, tables=[AuditEvent.__table__])
    errors: list[BaseException] = []

    def write(n):
        try:
            for i in range(5):
                audit.record_now(engine, action=f"race.{n}.{i}", team_id=n)
        except BaseException as exc:  # pragma: no cover - reported below
            errors.append(exc)

    threads = [threading.Thread(target=write, args=(n,)) for n in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    result = audit.verify_chain(engine)
    assert result == {"ok": True, "checked": 80, "first_bad_id": None, "reason": None}


def _create_pre_rbac_tables(engine):
    """The four tables the migration changes, as dev (rv6p1nodename001) has them."""
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE team (id serial PRIMARY KEY, name varchar NOT NULL)"))
        conn.execute(sa.text('CREATE TABLE "user" (id serial PRIMARY KEY, email varchar NOT NULL, '
                             'is_superuser boolean, default_team_id int REFERENCES team(id))'))
        conn.execute(sa.text("CREATE TABLE teammembership (team_id int REFERENCES team(id), user_id int "
                             'REFERENCES "user"(id), role varchar NOT NULL, PRIMARY KEY (team_id, user_id))'))
        conn.execute(sa.text("CREATE TABLE teaminvitation (id serial PRIMARY KEY, team_id int NOT NULL, "
                             "email varchar(254) NOT NULL, status varchar(16) NOT NULL)"))


@needs_pg
def test_the_migration_keeps_every_role_and_is_reversible_on_postgresql(pg_schema):
    engine, _ = pg_schema
    _create_pre_rbac_tables(engine)
    with engine.begin() as conn:
        conn.execute(sa.text("INSERT INTO team (id, name) VALUES (1, 'a'), (2, 'b')"))
        conn.execute(sa.text("INSERT INTO \"user\" (id, email, is_superuser, default_team_id) VALUES "
                             "(1, 'a@x.test', false, 1), (2, 'b@x.test', false, 2), (3, 'root@x.test', true, 2)"))
        conn.execute(sa.text("INSERT INTO teammembership VALUES (1, 1, 'admin'), (1, 2, 'member'), (2, 2, 'admin'), "
                             "(2, 3, 'member')"))
        conn.execute(sa.text("INSERT INTO teaminvitation (team_id, email, status) VALUES (1, 'c@x.test', 'pending')"))

    def snapshot():
        with engine.begin() as conn:
            members = sorted(conn.execute(sa.text("SELECT team_id, user_id, role FROM teammembership")).all())
            supers = sorted(conn.execute(sa.text('SELECT id, is_superuser FROM "user"')).all())
        return members, supers

    before = snapshot()
    _migrate(engine, "upgrade")
    assert snapshot() == before  # admin -> admin, member -> member, superusers unchanged
    with engine.begin() as conn:
        assert conn.execute(sa.text("SELECT role FROM teaminvitation")).scalar() == "member"
        with pytest.raises(sa.exc.IntegrityError), conn.begin_nested():
            conn.execute(sa.text("UPDATE teammembership SET role = 'superuser' WHERE user_id = 1"))
        conn.execute(sa.text("UPDATE teammembership SET role = 'owner' WHERE team_id = 1 AND user_id = 1"))
        conn.execute(sa.text("UPDATE teammembership SET role = 'viewer' WHERE team_id = 2 AND user_id = 3"))
    audit.record_now(engine, action="kept.across.downgrade", team_id=1)

    _migrate(engine, "downgrade")
    with engine.begin() as conn:
        assert sorted(conn.execute(sa.text("SELECT team_id, user_id, role FROM teammembership")).all()) == [
            (1, 1, "admin"), (1, 2, "member"), (2, 2, "admin"), (2, 3, "member")]  # owner -> admin, viewer -> member
        columns = {c["name"] for c in sa.inspect(conn).get_columns("teaminvitation")}
        assert "role" not in columns
        tables = set(sa.inspect(conn).get_table_names())
        assert "auditevent" not in tables and "auditevent_archive" in tables

    _migrate(engine, "upgrade")
    assert rows(engine)[0].action == "kept.across.downgrade"  # the archive came back
    assert audit.verify_chain(engine)["ok"] is True
