"""team roles owner / admin / member / viewer, invitation roles, append-only audit log (F4 RBAC)

Revision ID: r6f4rbac001
Revises: rv6p1nodename001
Create Date: 2026-11-11 14:00:00.000000

Roles: existing memberships keep their role (admin -> admin, member -> member); superusers are unchanged.  Every
team with an admin gets one owner, deterministically: the admin whose default team it is (the creator on dev), else
the only admin, else the admin with the lowest user id (counts printed).  Teams with members but no admin get theirs
from a superuser (POST /admin/teams/{id}/owner, audited).  New teams give their creator the owner role.  A CHECK constraint keeps roles to the four names; a role stored in
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
AUDIT_INDEXES = (("ix_auditevent_team_id_id", ("team_id", "id")),
                 ("ix_auditevent_actor_user_id_id", ("actor_user_id", "id")),
                 ("ix_auditevent_action_id", ("action", "id")))
# Append-only: UPDATE, DELETE and TRUNCATE raise, with one exception, the erasure of personal data
# (audit.erase_personal_data): inside a transaction that set zs.audit_erasure, an UPDATE may set actor_email, ip and
# user_agent to NULL and change nothing else (those three are outside the hash chain).
APPEND_ONLY_FUNCTION = """
CREATE OR REPLACE FUNCTION auditevent_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF TG_OP = 'UPDATE' AND coalesce(current_setting('zs.audit_erasure', true), '') = 'on'
     AND NEW.actor_email IS NULL AND NEW.ip IS NULL AND NEW.user_agent IS NULL
     AND (NEW.id, NEW.at, NEW.team_id, NEW.actor_user_id, NEW.actor_type, NEW.action, NEW.object_type, NEW.object_id,
          NEW.outcome, NEW.prev_hash, NEW.hash, NEW.details::text)
         IS NOT DISTINCT FROM
         (OLD.id, OLD.at, OLD.team_id, OLD.actor_user_id, OLD.actor_type, OLD.action, OLD.object_type, OLD.object_id,
          OLD.outcome, OLD.prev_hash, OLD.hash, OLD.details::text) THEN
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'auditevent is append-only: % refused', TG_OP USING ERRCODE = 'insufficient_privilege';
END $$
"""
# one admin per ownerless team: the one whose default team it is, else the lowest user id; ``why`` names the rule.
# Two complete SQL literals (no string building, not even of constants).
OWNER_PICK_COUNTS = """
WITH pick AS (
  SELECT team_id, user_id, why FROM (
    SELECT m.team_id, m.user_id,
           CASE WHEN u.default_team_id = m.team_id THEN 'default'
                WHEN count(*) OVER (PARTITION BY m.team_id) = 1 THEN 'only' ELSE 'lowest' END AS why,
           row_number() OVER (PARTITION BY m.team_id
                              ORDER BY CASE WHEN u.default_team_id = m.team_id THEN 0 ELSE 1 END, m.user_id) AS rn
    FROM teammembership m JOIN "user" u ON u.id = m.user_id
    WHERE m.role = 'admin'
      AND NOT EXISTS (SELECT 1 FROM teammembership o WHERE o.team_id = m.team_id AND o.role = 'owner')
  ) ranked WHERE rn = 1
)
SELECT why, count(*) FROM pick GROUP BY why
"""
OWNER_PICK_APPLY = """
WITH pick AS (
  SELECT team_id, user_id, why FROM (
    SELECT m.team_id, m.user_id,
           CASE WHEN u.default_team_id = m.team_id THEN 'default'
                WHEN count(*) OVER (PARTITION BY m.team_id) = 1 THEN 'only' ELSE 'lowest' END AS why,
           row_number() OVER (PARTITION BY m.team_id
                              ORDER BY CASE WHEN u.default_team_id = m.team_id THEN 0 ELSE 1 END, m.user_id) AS rn
    FROM teammembership m JOIN "user" u ON u.id = m.user_id
    WHERE m.role = 'admin'
      AND NOT EXISTS (SELECT 1 FROM teammembership o WHERE o.team_id = m.team_id AND o.role = 'owner')
  ) ranked WHERE rn = 1
)
UPDATE teammembership SET role = 'owner'
WHERE (team_id, user_id) IN (SELECT team_id, user_id FROM pick)
"""
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

    # ---- every team that has an admin gets exactly one owner, chosen deterministically (never a first-come claim):
    # the admin whose default team it is (its creator on dev), else the only admin, else the admin with the lowest
    # user id.  Teams with members but no admin are counted: a superuser assigns their owner (POST
    # /admin/teams/{id}/owner, audited).
    counts = {why: n for why, n in bind.execute(sa.text(OWNER_PICK_COUNTS)).all()}
    bind.execute(sa.text(OWNER_PICK_APPLY))
    no_admin = bind.execute(sa.text(
        "SELECT count(DISTINCT m.team_id) FROM teammembership m WHERE NOT EXISTS ("
        "SELECT 1 FROM teammembership o WHERE o.team_id = m.team_id AND o.role IN ('owner', 'admin'))")).scalar() or 0
    print(f"r6f4rbac001: owners backfilled: default team: {counts.get('default', 0)}, "
          f"only admin: {counts.get('only', 0)}, lowest admin id: {counts.get('lowest', 0)}; "
          f"no admin (a superuser assigns the owner): {no_admin}")

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
            sa.Column('id', sa.BigInteger(), autoincrement=True, nullable=False),  # never pruned: int8
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
        # what is read: a team's log and its chain head, one account's actions, one action platform-wide (id order
        # is time order, so no index on at); three indexes on an append-only table, no more
        for name, columns in AUDIT_INDEXES:
            op.create_index(name, 'auditevent', list(columns), unique=False)

    # ---- the account lookups every request makes: the policy by email, sign-in by lower(email)
    op.create_index('ix_user_email', 'user', ['email'], unique=False)
    op.create_index('ix_user_email_lower', 'user', [sa.text('lower(email)')], unique=False)

    if _is_postgres(bind):
        bind.execute(sa.text(APPEND_ONLY_FUNCTION))
        bind.execute(sa.text("CREATE TRIGGER auditevent_no_update_delete BEFORE UPDATE OR DELETE ON auditevent "
                             "FOR EACH ROW EXECUTE FUNCTION auditevent_append_only()"))
        bind.execute(sa.text("CREATE TRIGGER auditevent_no_truncate BEFORE TRUNCATE ON auditevent "
                             "FOR EACH STATEMENT EXECUTE FUNCTION auditevent_append_only()"))


    # ---- last: the role CHECK (ACCESS EXCLUSIVE on teammembership, which every request's policy reads, held only
    # to the end of this revision: env.py runs each revision in its own transaction)
    op.create_check_constraint("ck_teammembership_role", "teammembership",
                               "role IN ('owner', 'admin', 'member', 'viewer')")

def downgrade() -> None:
    bind = op.get_bind()
    op.drop_index('ix_user_email_lower', table_name='user')
    op.drop_index('ix_user_email', table_name='user')
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
