"""Migration r6f4sso001 (F4 SSO) on PostgreSQL: the five SSO tables, the one-team-per-verified-domain index,
upgrade -> downgrade -> upgrade, and the ORM models matching what the migration creates.

    AUTH_TEST_PG_URL=postgresql+psycopg2://... python -m pytest tests/test_sso_migration.py -q
"""
import datetime as dt
import importlib.util
import os
import sys
import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.schema import CreateSchema, DropSchema

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from sqlmodel import Session, create_engine  # noqa: E402

from backend.access_models import (SsoAssertionSeen, SsoHandoff, SsoLoginState, TeamSsoConfig,  # noqa: E402
                                   TeamSsoDomain)

PG_URL = os.environ.get("AUTH_TEST_PG_URL")
needs_pg = pytest.mark.skipif(not PG_URL, reason="set AUTH_TEST_PG_URL (an empty PostgreSQL database) to run")
VERSIONS = _REPO_ROOT / "prod_database_migrations" / "migrations" / "versions"
TABLES = {"teamssoconfig", "teamssodomain", "ssologinstate", "ssoassertionseen", "ssohandoff"}


def _module():
    path = VERSIONS / "r6f4sso001_sso_per_team.py"
    spec = importlib.util.spec_from_file_location("r6f4sso001", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_migration_chains_on_the_rbac_migration_and_is_the_only_head():
    module = _module()
    assert module.revision == "r6f4sso001" and module.down_revision == "r6f4rbac001"
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    cfg = Config(str(VERSIONS.parent.parent / "alembic.ini"))
    cfg.set_main_option("script_location", str(VERSIONS.parent))
    assert ScriptDirectory.from_config(cfg).get_heads() == ["r6f4sso001"]


@pytest.fixture()
def pg_schema():
    schema = f"f4sso_{uuid.uuid4().hex[:10]}"
    admin = create_engine(PG_URL)
    with admin.begin() as conn:
        conn.execute(CreateSchema(schema))
    engine = create_engine(PG_URL, connect_args={"options": f"-csearch_path={schema}"})
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(DropSchema(schema, cascade=True))
        admin.dispose()


def _migrate(engine, direction: str):
    from alembic.migration import MigrationContext
    from alembic.operations import Operations

    module = _module()
    with engine.begin() as conn:
        with Operations.context(MigrationContext.configure(conn)):
            getattr(module, direction)()


@needs_pg
def test_upgrade_downgrade_upgrade_and_the_orm_works_on_the_result(pg_schema):
    engine = pg_schema
    _migrate(engine, "upgrade")
    assert TABLES <= set(sa.inspect(engine).get_table_names())
    now = dt.datetime(2026, 11, 12, 5, 0, 0)
    with Session(engine) as s:  # every model reads and writes the migrated tables
        s.add(TeamSsoConfig(team_id=1, protocol="saml", enabled=True, saml_idp_certs=["pem"], saml_idp_entity_id="e"))
        s.add(TeamSsoDomain(team_id=1, domain="acme.test", verification_token="t", verified_at=now, verify_method="dns"))
        s.add(TeamSsoDomain(team_id=2, domain="acme.test", verification_token="u"))  # a claim, not verified: allowed
        s.add(SsoLoginState(id="s1", team_id=1, protocol="saml", binding_hash="0" * 64, client_nonce_hash="1" * 64,
                            saml_request_id="_r", expires_at=now))
        s.add(SsoAssertionSeen(key="k" * 64, team_id=1, expires_at=now))
        s.add(SsoHandoff(code_hash="c" * 64, user_id=1, team_id=1, client_nonce_hash="1" * 64, protocol="saml",
                         expires_at=now))
        s.commit()
    with pytest.raises(sa.exc.IntegrityError), Session(engine) as s:  # a second team cannot verify it
        row = s.exec(sa.select(TeamSsoDomain).where(TeamSsoDomain.team_id == 2)).scalar_one()
        row.verified_at = now
        s.add(row)
        s.commit()
    with pytest.raises(sa.exc.IntegrityError), Session(engine) as s:  # one configuration per team
        s.add(TeamSsoConfig(team_id=1, protocol="oidc"))
        s.commit()
    with pytest.raises(sa.exc.IntegrityError), Session(engine) as s:  # the same assertion twice
        s.add(SsoAssertionSeen(key="k" * 64, team_id=1, expires_at=now))
        s.commit()
    with pytest.raises(sa.exc.IntegrityError), engine.begin() as conn:  # protocol and JIT role are constrained
        conn.execute(sa.text("UPDATE teamssoconfig SET default_role = 'owner'"))

    _migrate(engine, "downgrade")
    tables = set(sa.inspect(engine).get_table_names())
    assert not (TABLES & tables)
    # what owners typed (IdP settings, verified domains) is archived, never dropped; the round-trip rows are dropped
    assert {"teamssoconfig_archive", "teamssodomain_archive"} <= tables
    _migrate(engine, "upgrade")
    assert TABLES <= set(sa.inspect(engine).get_table_names())
    with Session(engine) as s:
        assert s.exec(sa.select(TeamSsoConfig.saml_idp_entity_id)).scalar_one() == "e"
        assert sorted(s.exec(sa.select(TeamSsoDomain.team_id, TeamSsoDomain.verified_at.isnot(None))).all()) == [
            (1, True), (2, False)]
        s.add(TeamSsoConfig(team_id=3, protocol="oidc"))  # sequences continue after the restore
        s.add(TeamSsoDomain(team_id=3, domain="other.test", verification_token="v"))
        s.commit()
