"""team report branding: one client logo per team for the PDF exports (table teambranding)

Revision ID: rpdf1brand001
Revises: r6f4rbac001
Create Date: 2026-11-19 12:00:00.000000

Upgrade: creates ``teambranding``, at most one row per team (``team_id`` is the primary key and a foreign key to
``team.id`` with ON DELETE CASCADE).  The row holds the normalised PNG the API stored (``logo_png``, bytea on
PostgreSQL, at most 300 KB; never the uploaded file) and its metadata: SHA-256, width, height, byte size, tone
("dark" | "light", a check constraint), whether it has an alpha channel, when and by whom it was set.  The uploader
is a plain int, so deleting that account is never blocked.  No data is written: every team starts without a logo,
and the PDF exports stay exactly as they were until an admin uploads one (``PUT /team/{team_id}/branding/logo``).

Downgrade: drops ``teambranding`` and with it every uploaded logo (they cannot be recovered; the audit log keeps
each logo's SHA-256, size and who set it, not the image).  Nothing else refers to the table.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'rpdf1brand001'
down_revision: Union[str, Sequence[str], None] = 'r6f4rbac001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('teambranding',
    sa.Column('team_id', sa.Integer(), nullable=False),
    sa.Column('logo_png', sa.LargeBinary(), nullable=False),
    sa.Column('logo_sha256', sqlmodel.sql.sqltypes.AutoString(length=64), nullable=False),
    sa.Column('logo_width', sa.Integer(), nullable=False),
    sa.Column('logo_height', sa.Integer(), nullable=False),
    sa.Column('logo_bytes', sa.Integer(), nullable=False),
    sa.Column('logo_tone', sqlmodel.sql.sqltypes.AutoString(length=8), nullable=False),
    sa.Column('has_alpha', sa.Boolean(), nullable=False),
    sa.Column('updated_at', sa.DateTime(), nullable=False),
    sa.Column('updated_by_user_id', sa.Integer(), nullable=True),
    sa.CheckConstraint("logo_tone IN ('dark', 'light')", name='ck_teambranding_logo_tone'),
    sa.ForeignKeyConstraint(['team_id'], ['team.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('team_id')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('teambranding')
