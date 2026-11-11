"""team roles owner / admin / member / viewer, invitation roles, append-only audit log (F4 RBAC)

Revision ID: r6f4rbac001
Revises: rv6p1nodename001
Create Date: 2026-11-11 14:00:00.000000

Roles: existing memberships keep their role (admin -> admin, member -> member); superusers are unchanged; no owner
is invented (a team without an owner is claimed by one of its admins, POST /team/{id}/ownership/claim, audited).
New teams give their creator the owner role.  A CHECK constraint keeps roles to the four names; a role stored in
another spelling ("Admin", " member") is normalised first, and anything else (none on dev) becomes member, counted
in the migration output.

Audit log: table ``auditevent`` (see backend/new_models.py AuditEvent) with PostgreSQL triggers that refuse UPDATE,
DELETE and TRUNCATE.

Downgrade keeps everybody's access: owner -> admin, viewer -> member (a viewer gains member rights on the old code,
which has no read-only role); the invitation role column and the CHECK constraint are dropped; the audit table is
renamed to ``auditevent_archive`` (evidence is never dropped by a downgrade) and renamed back by the next upgrade.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


revision: str = 'r6f4rbac001'
down_revision: Union[str, Sequence[str], None] = 'rv6p1nodename001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

ROLES = ("owner", "admin", "member", "viewer")
INVITE_ROLES = ("admin", "member", "viewer")


def _is_postgres(bind) -> bool:
    return bind.dialect.name == "postgresql"


def upgrade() -> None:
    bind = op.get_bind()

    # ---- memberships: identity mapping, then the constraint
    bind.execute(sa.text("UPDATE teammembership SET role = lower(trim(role)) WHERE role <> lower(trim(role))"))
    unknown = bind.execute(sa.text(
        "SELECT count(*) FROM teammembership WHERE role IS NULL OR role NOT IN ('owner', 'admin', 'member', 'viewer')"
    )).scalar() or 0
    if unknown:
        bind.execute(sa.text(
            "UPDATE teammembership SET role = 'member' "
            "WHERE role IS NULL OR role NOT IN ('owner', 'admin', 'member', 'viewer')"))
    print(f"r6f4rbac001: memberships kept their role; {unknown} with an unknown role became member")
    op.create_check_constraint("ck_teammembership_role", "teammembership",
                               "role IN ('owner', 'admin', 'member', 'viewer')")

    # ---- invitations carry the role the invitee joins with
    op.add_column('teaminvitation', sa.Column('role', sqlmodel.sql.sqltypes.AutoString(length=16),
                                              server_default='member', nullable=False))
    op.create_check_constraint("ck_teaminvitation_role", "teaminvitation", "role IN ('admin', 'member', 'viewer')")

    # ---- the audit log
    tables = set(sa.inspect(bind).get_table_names())
    if "auditevent_archive" in tables:
        op.rename_table("auditevent_archive", "auditevent")
        print("r6f4rbac001: the audit log archived by a downgrade is back in auditevent")
    else:
        op.create_table(
            'auditevent',
            sa.Column('id', sa.Integer(), nullable=False),
            sa.Column('at', sa.DateTime(), nullable=False),
            sa.Column('team_id', sa.Integer(), nullable=True),
            sa.Column('actor_user_id', sa.Integer(), nullable=True),
            sa.Column('actor_email', sqlmodel.sql.sqltypes.AutoString(length=254), nullable=True),
            sa.Column('actor_type', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
            sa.Column('action', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
            sa.Column('object_type', sqlmodel.sql.sqltypes.AutoString(length=32), nullable=True),
            sa.Column('object_id', sqlmodel.sql.sqltypes.AutoString(length=128), nullable=True),
            sa.Column('outcome', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
            sa.Column('ip', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
            sa.Column('user_agent', sqlmodel.sql.sqltypes.AutoString(length=200), nullable=True),
            sa.Column('details', sa.JSON(), nullable=True),
            sa.Column('prev_hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
            sa.Column('hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
            sa.PrimaryKeyConstraint('id'),
        )
        for column in ("at", "team_id", "actor_user_id", "action"):
            op.create_index(op.f(f'ix_auditevent_{column}'), 'auditevent', [column], unique=False)

    if _is_postgres(bind):
        bind.execute(sa.text(
            "CREATE OR REPLACE FUNCTION auditevent_append_only() RETURNS trigger LANGUAGE plpgsql AS $$ "
            "BEGIN RAISE EXCEPTION 'auditevent is append-only: % refused', TG_OP USING ERRCODE = 'insufficient_privilege'; END $$"))
        bind.execute(sa.text("CREATE TRIGGER auditevent_no_update_delete BEFORE UPDATE OR DELETE ON auditevent "
                             "FOR EACH ROW EXECUTE FUNCTION auditevent_append_only()"))
        bind.execute(sa.text("CREATE TRIGGER auditevent_no_truncate BEFORE TRUNCATE ON auditevent "
                             "FOR EACH STATEMENT EXECUTE FUNCTION auditevent_append_only()"))


def downgrade() -> None:
    bind = op.get_bind()
    if _is_postgres(bind):
        bind.execute(sa.text("DROP TRIGGER IF EXISTS auditevent_no_truncate ON auditevent"))
        bind.execute(sa.text("DROP TRIGGER IF EXISTS auditevent_no_update_delete ON auditevent"))
        bind.execute(sa.text("DROP FUNCTION IF EXISTS auditevent_append_only()"))
    op.rename_table("auditevent", "auditevent_archive")

    op.drop_constraint("ck_teaminvitation_role", "teaminvitation", type_="check")
    op.drop_column('teaminvitation', 'role')

    op.drop_constraint("ck_teammembership_role", "teammembership", type_="check")
    owners = bind.execute(sa.text("UPDATE teammembership SET role = 'admin' WHERE role = 'owner'")).rowcount
    viewers = bind.execute(sa.text("UPDATE teammembership SET role = 'member' WHERE role = 'viewer'")).rowcount
    print(f"r6f4rbac001 downgrade: {owners} owner(s) -> admin, {viewers} viewer(s) -> member; "
          "the audit log is kept as auditevent_archive")
