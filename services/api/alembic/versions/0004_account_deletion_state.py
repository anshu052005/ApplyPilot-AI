"""Account deletion state on app_users.

deletion_requested_at is set when the owner asks to delete the account. While it is set, every data endpoint
returns 423 Locked. The Auth account is removed last, only after Storage cleanup is verified, so a failed run
can be retried from the same state. deletion_last_error holds a short machine code, never personal data.

Revision ID: 0004_account_deletion_state
Revises: 0003_candidate_files
Create Date: 2026-11-02
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "0004_account_deletion_state"
down_revision: str | None = "0003_candidate_files"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column("app_users", sa.Column("deletion_requested_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("app_users", sa.Column("deletion_last_error", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("app_users", "deletion_last_error")
    op.drop_column("app_users", "deletion_requested_at")
