"""scan node proxy user (#199): the user name of a proxy that needs a login

Revision ID: cb199proxyuser001
Revises: i150hkreset001
Create Date: 2026-11-15 09:00:00.000000

* ``cbomscannode.proxy_user`` (nullable, 128): the proxy's user name, shown in the node's install command. The
  password is never stored: it stays on the node's host, in the file ZS_PROXY_AUTH_FILE names.

A nullable column: existing nodes keep NULL (no login), nothing is backfilled.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
import sqlmodel


# revision identifiers, used by Alembic.
revision: str = 'cb199proxyuser001'
down_revision: Union[str, Sequence[str], None] = 'i150hkreset001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('cbomscannode', sa.Column('proxy_user', sqlmodel.sql.sqltypes.AutoString(length=128), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('cbomscannode', 'proxy_user')
