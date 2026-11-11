"""team invitations (single-use links, no mailed passwords); force a new password on accounts the old flow made

Revision ID: rv6s2invite001
Revises: wp8b0agent001
Create Date: 2026-11-11 12:00:00.000000

Before this revision, adding an address to a team created an account for it and mailed it a generated password
(backend/utilities/team/membership.py up to ansh 475c636).  Those accounts still sign in with a password that
travelled in a mail, so ``user.must_change_password`` is set for them: their next sign-in asks for a new password
before any session is issued.

How they are recognised: that flow, and only it, created the account with first_name = the part of the address
before "@", last_name = "user", and a default team named "<that part>'s Default Team" described as "Default team
for <that part>" (sign-up and the admin console use the names the person typed).  The only false positive is a
person who signed up typing exactly their address's local part as first name and "user" as last name; for them
the cost is one password change.  Accounts the old flow made whose owner has since reset the password are flagged
too (no column records when a password was last chosen); they also change it once.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'rv6s2invite001'
down_revision: Union[str, Sequence[str], None] = 'wp8b0agent001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def made_by_old_invite_flow(email: str | None, first_name: str | None, last_name: str | None,
                            team_name: str | None, team_description: str | None) -> bool:
    local = (email or "").split("@")[0]
    return bool(local) and first_name == local and last_name == "user" \
        and team_name == f"{local}'s Default Team" and team_description == f"Default team for {local}"


def old_invite_flow_user_ids(bind) -> list[int]:
    rows = bind.execute(sa.text(
        'SELECT u.id, u.email, u.first_name, u.last_name, t.name, t.description '
        'FROM "user" u JOIN team t ON t.id = u.default_team_id'
    )).fetchall()
    return [row[0] for row in rows if made_by_old_invite_flow(*row[1:])]


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('user', sa.Column('must_change_password', sa.Boolean(), server_default=sa.false(), nullable=False))
    op.create_table('teaminvitation',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('email', sqlmodel.sql.sqltypes.AutoString(length=254), nullable=False),
    sa.Column('token_hash', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=True),
    sa.Column('status', sqlmodel.sql.sqltypes.AutoString(length=16), nullable=False),
    sa.Column('invited_by_user_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('expires_at', sa.DateTime(), nullable=False),
    sa.Column('responded_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('team_id', 'email', name='uq_teaminvitation_team_email')
    )
    op.create_index(op.f('ix_teaminvitation_team_id'), 'teaminvitation', ['team_id'], unique=False)
    op.create_index(op.f('ix_teaminvitation_token_hash'), 'teaminvitation', ['token_hash'], unique=True)

    bind = op.get_bind()
    ids = old_invite_flow_user_ids(bind)
    if ids:
        bind.execute(sa.text('UPDATE "user" SET must_change_password = :yes WHERE id IN :ids')
                     .bindparams(sa.bindparam("ids", expanding=True)), {"yes": True, "ids": ids})
    print(f"rv6s2invite001: {len(ids)} account(s) made by the old invitation flow must choose a new password")


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_teaminvitation_token_hash'), table_name='teaminvitation')
    op.drop_index(op.f('ix_teaminvitation_team_id'), table_name='teaminvitation')
    op.drop_table('teaminvitation')
    op.drop_column('user', 'must_change_password')
