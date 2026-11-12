"""single sign-on per team: IdP configuration, verified domains, sign-in round trip (F4 SSO)

Revision ID: r6f4sso001
Revises: r6f4rbac001
Create Date: 2026-11-12 06:00:00.000000

Five tables (models: backend/access_models.py):

* ``teamssoconfig``: one row per team (OIDC or SAML settings; the OIDC client secret only Fernet-encrypted);
* ``teamssodomain``: email domains a team claims; a partial unique index ``uq_teamssodomain_verified`` lets a domain
  be VERIFIED by at most one team (claims by several teams are allowed until one proves it);
* ``ssologinstate`` / ``ssohandoff`` / ``ssoassertionseen``: short-lived round-trip rows (10 min / 60 s / until
  the assertion expires), purged by the app.

No existing table changes, no data is migrated.  Downgrade: the round-trip tables are dropped (nothing in them
outlives a few minutes); what owners entered (``teamssoconfig``, ``teamssodomain``) is renamed to ``*_archive``,
never dropped, and the next upgrade renames it back.  Sign-in events stay in ``auditevent`` either way.
"""
from typing import Sequence, Union

import sqlalchemy as sa
import sqlmodel
from alembic import op

revision: str = 'r6f4sso001'
down_revision: Union[str, Sequence[str], None] = 'r6f4rbac001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ARCHIVED = ("teamssoconfig", "teamssodomain")


def _s(length: int):
    return sqlmodel.sql.sqltypes.AutoString(length=length)


def upgrade() -> None:
    bind = op.get_bind()
    tables = set(sa.inspect(bind).get_table_names())

    if "teamssoconfig_archive" in tables:
        op.rename_table("teamssoconfig_archive", "teamssoconfig")
        print("r6f4sso001: team SSO settings archived by a downgrade are back")
    else:
        op.create_table(
            'teamssoconfig',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('team_id', sa.Integer(), nullable=False),
            sa.Column('protocol', _s(8), nullable=False),
            sa.Column('enabled', sa.Boolean(), nullable=False),
            sa.Column('enforced', sa.Boolean(), nullable=False),
            sa.Column('jit', sa.Boolean(), nullable=False),
            sa.Column('default_role', _s(16), nullable=False),
            sa.Column('oidc_issuer', _s(512), nullable=True),
            sa.Column('oidc_client_id', _s(256), nullable=True),
            sa.Column('oidc_secret_encrypted', sa.Text(), nullable=True),
            sa.Column('oidc_scopes', _s(256), nullable=False),
            sa.Column('saml_idp_entity_id', _s(512), nullable=True),
            sa.Column('saml_idp_sso_url', _s(1024), nullable=True),
            sa.Column('saml_idp_certs', sa.JSON(), nullable=True),
            sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
            sa.Column('row_version', sa.Integer(), nullable=False),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.Column('last_updated', sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.CheckConstraint("protocol IN ('oidc', 'saml')", name="ck_teamssoconfig_protocol"),
            sa.CheckConstraint("default_role IN ('viewer', 'member')", name="ck_teamssoconfig_default_role"),
        )
        op.create_index(op.f('ix_teamssoconfig_team_id'), 'teamssoconfig', ['team_id'], unique=True)

    if "teamssodomain_archive" in tables:
        op.rename_table("teamssodomain_archive", "teamssodomain")
        print("r6f4sso001: team SSO domains archived by a downgrade are back")
    else:
        op.create_table(
            'teamssodomain',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('team_id', sa.Integer(), nullable=False),
            sa.Column('domain', _s(253), nullable=False),
            sa.Column('verification_token', _s(64), nullable=False),
            sa.Column('verified_at', sa.DateTime(), nullable=True),
            sa.Column('verified_by_user_id', sa.Integer(), nullable=True),
            sa.Column('verify_method', _s(16), nullable=True),
            sa.Column('created_at', sa.DateTime(), nullable=False),
            sa.PrimaryKeyConstraint('id'),
            sa.UniqueConstraint('team_id', 'domain', name='uq_teamssodomain_team_domain'),
        )
        op.create_index(op.f('ix_teamssodomain_team_id'), 'teamssodomain', ['team_id'], unique=False)
        op.create_index(op.f('ix_teamssodomain_domain'), 'teamssodomain', ['domain'], unique=False)
        # a domain is verified for at most one team
        op.create_index('uq_teamssodomain_verified', 'teamssodomain', ['domain'], unique=True,
                        postgresql_where=sa.text('verified_at IS NOT NULL'),
                        sqlite_where=sa.text('verified_at IS NOT NULL'))

    op.create_table(
        'ssologinstate',
        sa.Column('id', _s(64), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('protocol', _s(8), nullable=False),
        sa.Column('binding_hash', _s(64), nullable=False),
        sa.Column('client_nonce_hash', _s(64), nullable=False),
        sa.Column('nonce', _s(128), nullable=True),
        sa.Column('pkce_verifier', _s(128), nullable=True),
        sa.Column('saml_request_id', _s(64), nullable=True),
        sa.Column('redirect_path', _s(512), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_ssologinstate_team_id'), 'ssologinstate', ['team_id'], unique=False)
    op.create_index(op.f('ix_ssologinstate_expires_at'), 'ssologinstate', ['expires_at'], unique=False)

    op.create_table(
        'ssoassertionseen',
        sa.Column('key', _s(64), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('key'),
    )
    op.create_index(op.f('ix_ssoassertionseen_team_id'), 'ssoassertionseen', ['team_id'], unique=False)
    op.create_index(op.f('ix_ssoassertionseen_expires_at'), 'ssoassertionseen', ['expires_at'], unique=False)

    op.create_table(
        'ssohandoff',
        sa.Column('code_hash', _s(64), nullable=False),
        sa.Column('user_id', sa.Integer(), nullable=False),
        sa.Column('team_id', sa.Integer(), nullable=False),
        sa.Column('client_nonce_hash', _s(64), nullable=False),
        sa.Column('redirect_path', _s(512), nullable=False),
        sa.Column('protocol', _s(8), nullable=False),
        sa.Column('expires_at', sa.DateTime(), nullable=False),
        sa.Column('used_at', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('code_hash'),
    )
    op.create_index(op.f('ix_ssohandoff_expires_at'), 'ssohandoff', ['expires_at'], unique=False)


def downgrade() -> None:
    for table in ("ssohandoff", "ssoassertionseen", "ssologinstate"):
        op.drop_table(table)  # its indexes go with it
    for table in ARCHIVED:
        op.rename_table(table, f"{table}_archive")
    print("r6f4sso001 downgrade: round-trip tables dropped; team SSO settings and domains kept as *_archive")
