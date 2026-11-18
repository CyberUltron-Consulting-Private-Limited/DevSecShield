"""#44: MCP scan headers at rest: the header names in the clear, their values encrypted

Revision ID: d44mcphdr001
Revises: r6f3repo001
Create Date: 2026-11-16 16:00:00.000000

``scan.scan_metadata`` of an MCP scan kept the request headers as given, usually the MCP server's credential
(``Authorization: Bearer ...``). New scans store the names with masked values plus the values as one Fernet token
(``backend/utilities/db/mcp_headers.py``); this data migration rewrites the rows stored before, ``BATCH`` rows at a
time. A row with no headers or already sealed (``headers_encrypted`` present) is not touched, so a second run changes
nothing. Encrypting needs the backend's key (``ENCRYPTION_KEY``, else the JWT secret), which the migrate one-shot has:
it runs the backend image with the backend's environment (``docker-entrypoint.sh``). A database with no such row
needs no key.

Downgrade keeps the rows sealed: no code reads the stored values back, and decrypting them into the clear again would
undo the fix.
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'd44mcphdr001'
down_revision: Union[str, Sequence[str], None] = 'r6f3repo001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

BATCH = 500

_scan = sa.table(
    'scan',
    sa.column('id', sa.Integer),
    sa.column('scan_type', sa.String),
    sa.column('scan_metadata', sa.JSON),
)


def upgrade() -> None:
    """Upgrade schema."""
    from backend.utilities.db.mcp_headers import seal_stored_metadata

    bind = op.get_bind()
    last_id = 0
    while True:
        rows = bind.execute(
            sa.select(_scan.c.id, _scan.c.scan_metadata)
            .where(_scan.c.scan_type == 'mcp', _scan.c.id > last_id)
            .order_by(_scan.c.id)
            .limit(BATCH)
        ).all()
        if not rows:
            break
        for scan_id, meta in rows:
            sealed = seal_stored_metadata(meta)
            if sealed is not None:
                bind.execute(_scan.update().where(_scan.c.id == scan_id).values(scan_metadata=sealed))
        last_id = rows[-1][0]


def downgrade() -> None:
    """Downgrade schema."""
    # Deliberately nothing: the rows stay sealed (see the module docstring).
